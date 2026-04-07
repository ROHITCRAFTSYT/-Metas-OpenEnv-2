"""
SOC-Triage-Gym Core Environment
=================================
Implements the SOCEnvironment class with reset(), step(), and state() methods.
This is the central state machine — all episode logic lives here.

All data access is from the in-memory ScenarioConfig; no disk I/O during episodes.
All tool functions are pure and imported from the tools/ package.
"""

import uuid
from typing import Dict, Optional

from models import (
    ActionType,
    AlertClassification,
    EnvironmentState,
    InvestigationState,
    ResponseActionType,
    ScenarioConfig,
    SOCAction,
    SOCObservation,
)
from tools.enrichment import enrich_indicator
from tools.log_query import query_logs
from tools.correlation import correlate_alerts
from tools.asset_lookup import lookup_asset
from tools.user_lookup import lookup_user
from scenarios import SCENARIO_REGISTRY
from graders import GRADER_REGISTRY
from data.mitre_attack import is_valid_technique


class SOCEnvironment:
    """
    Stateful SOC triage environment.

    Thread safety: callers are responsible for holding a lock when calling
    reset(), step(), or state() if accessed from multiple threads.
    """

    def __init__(self) -> None:
        self._config: Optional[ScenarioConfig] = None
        self._investigations: Dict[str, InvestigationState] = {}
        self._cumulative_reward: float = 0.0
        self._step: int = 0
        self._done: bool = False
        self._task_id: Optional[str] = None
        self._episode_id: Optional[str] = None
        self._action_history: list[str] = []  # For loop detection

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def reset(self, task_id: str, seed: int = 42) -> SOCObservation:
        """
        Start a new episode for the given task.

        Args:
            task_id: One of "phishing", "lateral_movement", "queue_management", "insider_threat".
            seed: RNG seed for deterministic scenario generation.

        Returns:
            Initial SOCObservation with full alert_queue.
        """
        if task_id not in SCENARIO_REGISTRY:
            raise ValueError(f"Unknown task_id '{task_id}'. Valid: {list(SCENARIO_REGISTRY.keys())}")

        # Generate scenario
        generator_cls = SCENARIO_REGISTRY[task_id]
        generator = generator_cls(seed=seed)
        self._config = generator.generate()

        # Initialize per-alert investigation states
        self._investigations = {
            alert.alert_id: InvestigationState(alert_id=alert.alert_id)
            for alert in self._config.alerts
        }

        self._cumulative_reward = 0.0
        self._step = 0
        self._done = False
        self._task_id = task_id
        self._episode_id = str(uuid.uuid4())[:8]
        self._action_history = []

        return self._build_observation(
            reward=0.0,
            enrichment_results=[],
            log_results=[],
            message=f"Episode started. Task: {task_id}. {len(self._config.alerts)} alert(s) in queue. Budget: {self._config.max_steps} steps.",
        )

    def step(self, action: SOCAction) -> SOCObservation:
        """
        Execute an action and return the new observation.

        Args:
            action: The SOCAction to execute.

        Returns:
            Updated SOCObservation.
        """
        if self._config is None:
            return self._build_observation(
                reward=-0.05,
                message="Error: call /reset before /step.",
            )

        if self._done:
            return self._build_observation(
                reward=0.0,
                message="Episode is already done. Call /reset to start a new episode.",
            )

        # Increment step
        self._step += 1

        # Loop detection: penalize repeated identical actions
        action_sig = self._action_signature(action)
        loop_penalty = 0.0
        repeat_count = self._action_history.count(action_sig)
        if repeat_count >= 2:
            loop_penalty = -0.05 * min(repeat_count - 1, 4)  # up to -0.20 for loops
        self._action_history.append(action_sig)

        # Dispatch action
        result = self._dispatch(action)
        step_reward = result["reward"] + loop_penalty
        if loop_penalty < 0:
            result["message"] += f" [Loop penalty: {loop_penalty:.2f}]"

        # Add to cumulative
        self._cumulative_reward += step_reward

        # Check budget exhaustion
        if self._step >= self._config.max_steps and not self._done:
            self._done = True
            # Auto-grade: penalize unclassified alerts
            auto_grade_reward = self._auto_grade_on_timeout()
            self._cumulative_reward += auto_grade_reward
            result["message"] += f" | Budget exhausted. Auto-graded: {auto_grade_reward:.3f}"

        return self._build_observation(
            reward=step_reward,
            enrichment_results=result.get("enrichment_results", []),
            log_results=result.get("log_results", []),
            asset_info=result.get("asset_info"),
            user_info=result.get("user_info"),
            correlated_events=result.get("correlated_events", []),
            message=result["message"],
            task_score=result.get("task_score"),
        )

    def grade(self) -> float:
        """Run the grader on current state without terminating the episode."""
        if self._config is None or self._task_id is None:
            return 0.0
        grader_cls = GRADER_REGISTRY.get(self._task_id)
        if grader_cls is None:
            return 0.0
        grader = grader_cls()
        return grader.grade(
            config=self._config,
            investigations=self._investigations,
            steps_used=self._step,
            max_steps=self._config.max_steps,
        )

    def grade_with_breakdown(self) -> tuple:
        """Run grader and return (score, breakdown_dict, feedback_str)."""
        if self._config is None or self._task_id is None:
            return 0.0, {}, "No active episode."
        grader_cls = GRADER_REGISTRY.get(self._task_id)
        if grader_cls is None:
            return 0.0, {}, "No grader registered."
        grader = grader_cls()
        return grader.grade_with_breakdown(
            config=self._config,
            investigations=self._investigations,
            steps_used=self._step,
            max_steps=self._config.max_steps,
        )

    def state(self) -> EnvironmentState:
        """Return current episode state metadata."""
        classified = sum(
            1 for inv in self._investigations.values()
            if inv.classification is not None
        )
        return EnvironmentState(
            episode_id=self._episode_id,
            task_id=self._task_id,
            step_count=self._step,
            max_steps=self._config.max_steps if self._config else 0,
            done=self._done,
            cumulative_reward=self._cumulative_reward,
            alert_count=len(self._config.alerts) if self._config else 0,
            classified_count=classified,
            seed=self._config.seed if self._config else None,
            metadata={
                "scenario_id": self._config.scenario_id if self._config else None,
                "description": self._config.description if self._config else None,
            },
        )

    # ------------------------------------------------------------------
    # Action Dispatcher
    # ------------------------------------------------------------------

    def _dispatch(self, action: SOCAction) -> dict:
        """Route action to the appropriate handler. Returns result dict."""

        match action.action_type:
            case ActionType.ENRICH_INDICATOR:
                return self._handle_enrich(action)
            case ActionType.QUERY_LOGS:
                return self._handle_query_logs(action)
            case ActionType.CORRELATE_ALERTS:
                return self._handle_correlate(action)
            case ActionType.CHECK_ASSET:
                return self._handle_check_asset(action)
            case ActionType.CHECK_USER:
                return self._handle_check_user(action)
            case ActionType.CLASSIFY_ALERT:
                return self._handle_classify(action)
            case ActionType.MAP_TECHNIQUE:
                return self._handle_map_technique(action)
            case ActionType.RECOMMEND_ACTION:
                return self._handle_recommend_action(action)
            case ActionType.ESCALATE:
                return self._handle_escalate(action)
            case ActionType.SUBMIT_INVESTIGATION:
                return self._handle_submit()
            case ActionType.NOOP:
                return {"reward": -0.01, "message": "No operation performed."}
            case _:
                return {"reward": -0.03, "message": f"Unknown action type: {action.action_type}"}

    # ------------------------------------------------------------------
    # Action Handlers
    # ------------------------------------------------------------------

    def _handle_enrich(self, action: SOCAction) -> dict:
        if not action.indicator or not action.indicator_type:
            return {"reward": -0.03, "message": "enrich_indicator requires 'indicator' and 'indicator_type'."}

        alert_id = action.query_alert_id or self._infer_alert_id(action.indicator)
        inv = self._investigations.get(alert_id) or self._get_any_investigation()
        if inv is None:
            return {"reward": -0.03, "message": "No active investigation found."}

        result, reward, message = enrich_indicator(
            self._config, inv, action.indicator, action.indicator_type
        )

        # Update investigation state
        inv.enriched_indicators[action.indicator] = result
        inv.reward_breakdown[f"enrich_{action.indicator[:20]}"] = reward
        inv.evidence_timeline.append(f"Step {self._step}: Enriched {action.indicator_type.value} '{action.indicator}'")

        return {
            "reward": reward,
            "enrichment_results": [result],
            "message": message,
        }

    def _handle_query_logs(self, action: SOCAction) -> dict:
        if not action.log_source:
            return {"reward": -0.03, "message": "query_logs requires 'log_source'."}

        alert_id = action.query_alert_id
        if not alert_id:
            # Default to first alert
            alert_id = self._config.alerts[0].alert_id if self._config.alerts else None
        if not alert_id or alert_id not in self._investigations:
            return {"reward": -0.03, "message": f"Invalid alert_id '{alert_id}' for log query."}

        inv = self._investigations[alert_id]
        entries, reward, message = query_logs(
            self._config, inv, action.log_source, alert_id,
            action.time_window_hours or 24
        )

        # Update investigation
        inv.queried_sources[action.log_source.value] = entries
        inv.reward_breakdown[f"query_{action.log_source.value}_{alert_id[:8]}"] = reward
        inv.evidence_timeline.append(
            f"Step {self._step}: Queried {action.log_source.value} for {alert_id} — {len(entries)} entries"
        )

        return {
            "reward": reward,
            "log_results": entries,
            "message": message,
        }

    def _handle_correlate(self, action: SOCAction) -> dict:
        if not action.alert_id_a or not action.alert_id_b:
            return {"reward": -0.03, "message": "correlate_alerts requires 'alert_id_a' and 'alert_id_b'."}

        event, reward, message = correlate_alerts(
            self._config, self._investigations,
            action.alert_id_a, action.alert_id_b
        )

        if event:
            # Add to both investigations
            for aid in [action.alert_id_a, action.alert_id_b]:
                inv = self._investigations.get(aid)
                if inv:
                    # Avoid duplicate entries
                    existing_pairs = {
                        tuple(sorted(e.alert_ids)) for e in inv.correlations_found
                    }
                    if tuple(sorted(event.alert_ids)) not in existing_pairs:
                        inv.correlations_found.append(event)
                        inv.evidence_timeline.append(
                            f"Step {self._step}: Correlated with {action.alert_id_b if aid == action.alert_id_a else action.alert_id_a}"
                        )

        return {
            "reward": reward,
            "correlated_events": [event] if event else [],
            "message": message,
        }

    def _handle_check_asset(self, action: SOCAction) -> dict:
        if not action.hostname:
            return {"reward": -0.03, "message": "check_asset requires 'hostname'."}

        # Find most relevant investigation (check all, use most evidence-rich)
        inv = self._get_most_relevant_investigation(hostname=action.hostname)
        if inv is None:
            inv = self._get_any_investigation()
        if inv is None:
            return {"reward": -0.03, "message": "No active investigation."}

        asset, reward, message = lookup_asset(self._config, inv, action.hostname)

        if asset:
            inv.assets_looked_up[action.hostname] = asset
            inv.evidence_timeline.append(f"Step {self._step}: Looked up asset '{action.hostname}'")

        return {
            "reward": reward,
            "asset_info": asset,
            "message": message,
        }

    def _handle_check_user(self, action: SOCAction) -> dict:
        if not action.username:
            return {"reward": -0.03, "message": "check_user requires 'username'."}

        inv = self._get_most_relevant_investigation(username=action.username)
        if inv is None:
            inv = self._get_any_investigation()
        if inv is None:
            return {"reward": -0.03, "message": "No active investigation."}

        user, reward, message = lookup_user(self._config, inv, action.username)

        if user:
            inv.users_looked_up[action.username] = user
            inv.evidence_timeline.append(f"Step {self._step}: Looked up user '{action.username}'")

        return {
            "reward": reward,
            "user_info": user,
            "message": message,
        }

    def _handle_classify(self, action: SOCAction) -> dict:
        if not action.alert_id or not action.classification:
            return {"reward": -0.03, "message": "classify_alert requires 'alert_id' and 'classification'."}

        if action.alert_id not in self._investigations:
            return {"reward": -0.03, "message": f"Alert '{action.alert_id}' not found."}

        inv = self._investigations[action.alert_id]

        # Penalize classifying without evidence
        evidence_count = (
            len(inv.enriched_indicators)
            + len(inv.queried_sources)
            + len(inv.correlations_found)
        )
        if evidence_count < 1:
            reward = -0.10  # Must gather at least some evidence first
            message = (
                f"Warning: Classified {action.alert_id} as {action.classification.value} "
                f"without gathering any evidence. (-0.10 penalty)"
            )
        else:
            # Check against ground truth for immediate feedback
            gt_class = self._config.ground_truth.alert_classifications.get(action.alert_id)
            if gt_class == action.classification:
                reward = 0.30
                message = f"Classified {action.alert_id} as {action.classification.value}. [Correct]"
            else:
                reward = -0.20
                message = f"Classified {action.alert_id} as {action.classification.value}. [Check your evidence]"

        # Record classification
        inv.classification = action.classification
        inv.classification_confidence = action.confidence or 0.8
        inv.reward_breakdown[f"classify_{action.alert_id[:8]}"] = reward
        inv.evidence_timeline.append(
            f"Step {self._step}: Classified '{action.alert_id}' as {action.classification.value}"
        )

        # Update alert meta for observation
        for alert in self._config.alerts:
            if alert.alert_id == action.alert_id:
                alert.classification = action.classification
                break

        # Check if all alerts classified → signal done
        if self._all_classified():
            message += " | All alerts classified. Call submit_investigation to finalize."

        return {"reward": reward, "message": message}

    def _handle_map_technique(self, action: SOCAction) -> dict:
        if not action.alert_id:
            action = action.model_copy(update={"alert_id": self._config.alerts[0].alert_id if self._config.alerts else None})

        if not action.alert_id or action.alert_id not in self._investigations:
            return {"reward": -0.02, "message": "map_technique requires a valid 'alert_id'."}

        if not action.technique_id:
            return {"reward": -0.02, "message": "map_technique requires 'technique_id' (e.g. T1566.001)."}

        inv = self._investigations[action.alert_id]

        # Validate technique ID
        if not is_valid_technique(action.technique_id):
            return {
                "reward": -0.02,
                "message": f"Unknown MITRE ATT&CK technique: '{action.technique_id}'. Use format T1234 or T1234.001.",
            }

        if action.technique_id not in inv.mapped_techniques:
            inv.mapped_techniques.append(action.technique_id)
            inv.evidence_timeline.append(
                f"Step {self._step}: Mapped technique {action.technique_id} to {action.alert_id}"
            )

        # Small positive reward for mapping — grader gives final credit
        expected = self._config.ground_truth.expected_techniques.get(action.alert_id, [])
        if action.technique_id in expected:
            reward = 0.05
            msg = f"Mapped technique {action.technique_id} to {action.alert_id}. [Relevant technique]"
        elif action.technique_id.split(".")[0] in [t.split(".")[0] for t in expected]:
            reward = 0.02  # Parent technique
            msg = f"Mapped technique {action.technique_id} to {action.alert_id}. [Related technique — consider sub-technique]"
        else:
            reward = -0.01
            msg = f"Mapped technique {action.technique_id} to {action.alert_id}."

        return {"reward": reward, "message": msg}

    def _handle_recommend_action(self, action: SOCAction) -> dict:
        if not action.alert_id:
            action = action.model_copy(update={"alert_id": self._config.alerts[0].alert_id if self._config.alerts else None})

        if not action.alert_id or action.alert_id not in self._investigations:
            return {"reward": -0.02, "message": "recommend_action requires a valid 'alert_id'."}

        if not action.response_action:
            return {"reward": -0.02, "message": "recommend_action requires 'response_action'."}

        inv = self._investigations[action.alert_id]
        gt_class = self._config.ground_truth.alert_classifications.get(action.alert_id)
        expected_actions = set(
            self._config.ground_truth.expected_response_actions.get(action.alert_id, [])
        )

        if action.response_action not in inv.recommended_actions:
            inv.recommended_actions.append(action.response_action)
            inv.evidence_timeline.append(
                f"Step {self._step}: Recommended {action.response_action.value} for {action.alert_id}"
            )

        # Score response relevance
        if action.response_action == ResponseActionType.NO_ACTION:
            if gt_class == AlertClassification.FALSE_POSITIVE:
                reward = 0.05
                msg = f"Recommended no_action for {action.alert_id}. [Correct for FP]"
            else:
                reward = -0.10
                msg = f"Recommended no_action for a true positive alert. [Insufficient response]"
        elif action.response_action in expected_actions:
            reward = 0.08
            msg = f"Recommended {action.response_action.value} for {action.alert_id}. [Appropriate]"
        else:
            reward = 0.02
            msg = f"Recommended {action.response_action.value} for {action.alert_id}."

        return {"reward": reward, "message": msg}

    def _handle_escalate(self, action: SOCAction) -> dict:
        alert_id = action.alert_id or (self._config.alerts[0].alert_id if self._config.alerts else None)
        if not alert_id or alert_id not in self._investigations:
            return {"reward": -0.02, "message": "escalate requires a valid 'alert_id'."}

        inv = self._investigations[alert_id]
        gt_class = self._config.ground_truth.alert_classifications.get(alert_id)

        inv.escalated = True
        inv.escalation_severity = action.escalation_severity or "high"
        inv.escalation_justification = action.justification or ""

        if gt_class == AlertClassification.TRUE_POSITIVE:
            reward = 0.05
            msg = f"Escalated {alert_id}. [Appropriate for TP]"
        elif gt_class == AlertClassification.FALSE_POSITIVE:
            reward = -0.10
            msg = f"Escalated {alert_id} — this appears to be a false positive. [Incorrect escalation]"
        else:
            reward = 0.02
            msg = f"Escalated {alert_id} for further review."

        return {"reward": reward, "message": msg}

    def _handle_submit(self) -> dict:
        """Run the grader and finalize the episode."""
        grader_cls = GRADER_REGISTRY.get(self._task_id)
        if grader_cls is None:
            return {"reward": 0.0, "message": "No grader registered for this task."}

        grader = grader_cls()
        raw_score = grader.grade(
            config=self._config,
            investigations=self._investigations,
            steps_used=self._step,
            max_steps=self._config.max_steps,
        )

        efficiency_mult = self._efficiency_multiplier()
        # Cap final_reward to (0.001, 0.999) — validator requires strictly (0, 1)
        final_reward = max(0.001, min(0.999, raw_score * efficiency_mult))

        self._done = True
        self._cumulative_reward += final_reward

        msg = (
            f"Investigation submitted. Grader score: {raw_score:.3f} × "
            f"efficiency {efficiency_mult:.2f} = {final_reward:.3f}. "
            f"Total episode reward: {self._cumulative_reward:.3f}"
        )

        return {
            "reward": final_reward,
            "task_score": final_reward,  # normalized (0,1) score for [END] logging
            "message": msg,
        }

    # ------------------------------------------------------------------
    # Helper Methods
    # ------------------------------------------------------------------

    def _build_observation(
        self,
        reward: float,
        enrichment_results=None,
        log_results=None,
        asset_info=None,
        user_info=None,
        correlated_events=None,
        message: str = "",
        task_score=None,
    ) -> SOCObservation:
        """Construct an SOCObservation from current state."""
        # Collect all correlations found so far
        all_correlations = []
        seen_pairs = set()
        for inv in self._investigations.values():
            for corr in inv.correlations_found:
                pair = tuple(sorted(corr.alert_ids))
                if pair not in seen_pairs:
                    all_correlations.append(corr)
                    seen_pairs.add(pair)

        return SOCObservation(
            alert_queue=self._config.alerts if self._config else [],
            investigations=self._investigations,
            enrichment_results=enrichment_results or [],
            log_results=log_results or [],
            correlated_events=correlated_events if correlated_events is not None else all_correlations,
            asset_info=asset_info,
            user_info=user_info,
            investigation_budget=max(0, (self._config.max_steps if self._config else 0) - self._step),
            step=self._step,
            done=self._done,
            reward=reward,
            cumulative_reward=self._cumulative_reward,
            message=message,
            task_id=self._task_id,
            episode_id=self._episode_id,
            task_score=task_score,
        )

    def _infer_alert_id(self, indicator: str) -> Optional[str]:
        """Infer which alert an indicator belongs to."""
        if not self._config:
            return None
        for alert in self._config.alerts:
            for itype_values in alert.indicators.values():
                if indicator in itype_values:
                    return alert.alert_id
        # Default to first alert
        return self._config.alerts[0].alert_id if self._config.alerts else None

    def _get_any_investigation(self) -> Optional[InvestigationState]:
        """Return the first investigation state (for single-alert tasks)."""
        if self._investigations:
            return next(iter(self._investigations.values()))
        return None

    def _get_most_relevant_investigation(
        self, hostname: str = None, username: str = None
    ) -> Optional[InvestigationState]:
        """Find the investigation most likely related to this hostname/username."""
        if not self._config:
            return None
        for alert in self._config.alerts:
            if hostname and hostname in alert.indicators.get("hostname", []):
                return self._investigations.get(alert.alert_id)
            if username and username in alert.indicators.get("user", []):
                return self._investigations.get(alert.alert_id)
        return None

    def _all_classified(self) -> bool:
        """Return True if all alerts have been classified."""
        return all(
            inv.classification is not None
            for inv in self._investigations.values()
        )

    def _efficiency_multiplier(self) -> float:
        """Reward multiplier based on steps used vs budget. Capped at 1.0 for (0,1) scoring."""
        if not self._config:
            return 1.0
        ratio = self._step / self._config.max_steps
        if ratio <= 0.50:
            return 1.0   # was 1.2 — capped to keep score < 1.0
        if ratio <= 0.75:
            return 1.0
        if ratio <= 0.90:
            return 0.85
        return 0.70

    def _auto_grade_on_timeout(self) -> float:
        """Apply penalties when budget is exhausted without submitting."""
        if not self._config:
            return 0.0
        gt = self._config.ground_truth
        missed_tps = sum(
            1 for aid in gt.true_positive_ids
            if self._investigations.get(aid, InvestigationState(alert_id=aid)).classification
            not in {AlertClassification.TRUE_POSITIVE, AlertClassification.BENIGN_TRUE_POSITIVE}
        )
        penalty = -0.5 * missed_tps
        return min(0.0, penalty)  # Always negative or zero

    def _action_signature(self, action: SOCAction) -> str:
        """Create a hashable signature for loop detection."""
        return (
            f"{action.action_type.value}|"
            f"{action.indicator or ''}|"
            f"{action.log_source.value if action.log_source else ''}|"
            f"{action.alert_id or ''}|"
            f"{action.query_alert_id or ''}|"
            f"{action.alert_id_a or ''}|"
            f"{action.alert_id_b or ''}|"
            f"{action.hostname or ''}|"
            f"{action.username or ''}"
        )
