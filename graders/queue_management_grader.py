"""
Queue Management Grader — Task 3 (Hard)
=========================================
Scores agent performance on the 20-alert mixed queue.

Weights:
  f1_score            0.30  — F1 on TP/FP classifications across all 20 alerts
  attack_chain_score  0.20  — identified the 2 hidden attack chains
  missed_tp_penalty   0.20  — heavy penalty per missed true positive
  efficiency_score    0.15  — steps used vs. budget
  response_score      0.15  — quality of response for actual TPs
"""

from typing import Dict, List, Set

from models import AlertClassification, InvestigationState, ResponseActionType, ScenarioConfig
from graders.base import BaseGrader


class QueueManagementGrader(BaseGrader):
    """Grader for Task 3: Alert Queue Management Under Noise."""

    def grade(
        self,
        config: ScenarioConfig,
        investigations: Dict[str, InvestigationState],
        steps_used: int,
        max_steps: int,
    ) -> float:
        """Grade a queue management episode. Returns 0.0–1.0."""

        gt = config.ground_truth

        # ---- F1 Score (0.30) ----
        f1 = self._compute_f1(investigations, gt)

        # ---- Attack Chain Score (0.20) ----
        chain_score = self._attack_chain_score(investigations, gt)

        # ---- Missed TP Penalty (0.20) ----
        # Base score starts at 0.20, subtract 0.04 per missed TP (max 5 TPs)
        missed_tp_score = self._missed_tp_score(investigations, gt)

        # ---- Efficiency Score (0.15) ----
        efficiency_score = self._efficiency_score(steps_used, max_steps)

        # ---- Response Score (0.15) ----
        response_score = self._response_quality(config, investigations)

        # ---- Weighted sum ----
        final = (
            0.30 * f1
            + 0.20 * chain_score
            + 0.20 * missed_tp_score
            + 0.15 * efficiency_score
            + 0.15 * response_score
        )

        return self._clamp(final)

    def _compute_f1(
        self,
        investigations: Dict[str, InvestigationState],
        gt,
    ) -> float:
        """Compute F1 score treating TP+BTP as positive, FP as negative."""
        actual_positives: Set[str] = set(gt.true_positive_ids + gt.benign_tp_ids)
        actual_negatives: Set[str] = set(gt.false_positive_ids)

        positive_classes = {AlertClassification.TRUE_POSITIVE, AlertClassification.BENIGN_TRUE_POSITIVE}
        negative_class = AlertClassification.FALSE_POSITIVE

        tp_count = 0  # correctly identified positives
        fp_count = 0  # FPs escalated as positives (wrong)
        fn_count = 0  # positives missed (classified as FP or unclassified)

        for alert_id in actual_positives:
            inv = investigations.get(alert_id)
            classified = inv.classification if inv else None
            if classified in positive_classes:
                tp_count += 1
            elif classified == negative_class:
                fn_count += 1
            else:
                # Unclassified = missed positive
                fn_count += 1

        for alert_id in actual_negatives:
            inv = investigations.get(alert_id)
            classified = inv.classification if inv else None
            if classified in positive_classes:
                fp_count += 1
            # If unclassified, neither helps nor hurts F1 for this metric

        precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0.0
        recall = tp_count / (tp_count + fn_count) if (tp_count + fn_count) > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )
        return f1

    def _attack_chain_score(
        self,
        investigations: Dict[str, InvestigationState],
        gt,
    ) -> float:
        """
        Score whether agent found both hidden attack chains.
        Each chain scores 0.5; combined = 1.0 if both found.
        A chain is "found" if all alerts in it were classified as TP.
        """
        if not gt.attack_chain_ids:
            return 1.0

        chains_found = 0
        positive_classes = {AlertClassification.TRUE_POSITIVE, AlertClassification.BENIGN_TRUE_POSITIVE}

        for chain in gt.attack_chain_ids:
            if not chain:
                continue
            # Chain is found if all its alerts are classified as positive
            all_found = all(
                investigations.get(aid, InvestigationState(alert_id=aid)).classification
                in positive_classes
                for aid in chain
            )
            if all_found:
                chains_found += 1

        return chains_found / len(gt.attack_chain_ids)

    def _missed_tp_score(
        self,
        investigations: Dict[str, InvestigationState],
        gt,
    ) -> float:
        """
        Compute missed TP penalty.
        Start at 1.0, subtract 0.2 per missed TRUE_POSITIVE (not BTP).
        BTP misses cost 0.1 each. Score floor is 0.0.
        """
        positive_classes = {AlertClassification.TRUE_POSITIVE, AlertClassification.BENIGN_TRUE_POSITIVE}
        score = 1.0

        for alert_id in gt.true_positive_ids:
            inv = investigations.get(alert_id)
            classified = inv.classification if inv else None
            if classified not in positive_classes:
                score -= 0.2  # -0.2 per missed TP (5 TPs → can zero out this component)

        for alert_id in gt.benign_tp_ids:
            inv = investigations.get(alert_id)
            classified = inv.classification if inv else None
            if classified not in positive_classes:
                score -= 0.1  # -0.1 per missed BTP

        return max(0.0, score)
