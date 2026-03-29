"""
SOC-Triage-Gym Baseline Inference Script
=========================================
MANDATORY
- Before submitting, ensure the following variables are defined:
    API_BASE_URL   The API endpoint for the LLM.
    MODEL_NAME     The model identifier to use for inference.
    HF_TOKEN       Your Hugging Face / API key.

- This script must be named `inference.py` and placed in the root directory
- Uses OpenAI Client for all LLM calls

Environment Variables:
    API_BASE_URL   OpenAI-compatible LLM endpoint
    HF_TOKEN       Hugging Face token (or use API_KEY)
    API_KEY        Alternative API key
    MODEL_NAME     Model identifier (e.g. "meta-llama/Llama-3-8b-instruct")
    SERVER_URL     SOC-Triage-Gym server URL (default: http://localhost:8000)
    MAX_STEPS      Override max steps per task (optional)
"""

import json
import os
import sys
import time
from typing import Optional

import httpx
try:
    from openai import OpenAI, APIError, APITimeoutError
except ImportError:
    OpenAI = None  # type: ignore[assignment,misc]
    APIError = Exception  # type: ignore[assignment,misc]
    APITimeoutError = Exception  # type: ignore[assignment,misc]

# ---------------------------------------------------------------------------
# Configuration (mandatory variable names per OpenEnv spec)
# ---------------------------------------------------------------------------

API_BASE_URL = os.getenv("API_BASE_URL")
API_KEY = os.getenv("HF_TOKEN") or os.getenv("OPENAI_API_KEY") or os.getenv("API_KEY")
MODEL_NAME = os.getenv("MODEL_NAME")
SERVER_URL = os.getenv("SERVER_URL", "http://localhost:8000")

# Per-task timeout in seconds (must finish all 3 tasks under 20 minutes total)
TASK_TIMEOUT_SECONDS = int(os.getenv("TASK_TIMEOUT_SECONDS", "360"))  # 6 min per task
SEED = int(os.getenv("SEED", "42"))

# ---------------------------------------------------------------------------
# System Prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a SOC (Security Operations Center) analyst AI agent. You investigate security alerts by gathering evidence and making classification decisions.

Available actions (respond with valid JSON):
- {"action_type": "enrich_indicator", "indicator_type": "ip|domain|file_hash|email|url", "indicator": "<value>", "query_alert_id": "<alert_id>"}
- {"action_type": "query_logs", "log_source": "firewall|proxy|dns|endpoint|auth|email_gateway|ids|cloud_trail", "query_alert_id": "<alert_id>", "time_window_hours": 24}
- {"action_type": "correlate_alerts", "alert_id_a": "<id>", "alert_id_b": "<id>"}
- {"action_type": "check_asset", "hostname": "<hostname>"}
- {"action_type": "check_user", "username": "<username>"}
- {"action_type": "classify_alert", "alert_id": "<id>", "classification": "true_positive|false_positive|benign_true_positive", "confidence": 0.0-1.0}
- {"action_type": "map_technique", "alert_id": "<id>", "technique_id": "T1234.001"}
- {"action_type": "recommend_action", "alert_id": "<id>", "response_action": "isolate_endpoint|disable_account|block_ip|block_domain|quarantine_file|reset_password|revoke_sessions|no_action"}
- {"action_type": "submit_investigation"}
- {"action_type": "noop"}

Investigation strategy:
1. Read all alerts in the queue first
2. For each alert: enrich IOCs → query relevant logs → correlate with other alerts
3. For true positives: classify → map MITRE ATT&CK technique → recommend containment
4. For false positives: classify as false_positive → recommend no_action
5. When done with all alerts: submit_investigation

Respond with ONLY a valid JSON action. No explanation. Investigate thoroughly before classifying."""

# ---------------------------------------------------------------------------
# Observation Formatter
# ---------------------------------------------------------------------------

def format_observation(obs: dict, step: int) -> str:
    """Format observation dict into a human-readable prompt for the LLM."""
    parts = [f"=== STEP {step} | Budget: {obs.get('investigation_budget', '?')} steps remaining ==="]

    # Alert queue summary
    alerts = obs.get("alert_queue", [])
    parts.append(f"\n[ALERT QUEUE] {len(alerts)} alert(s):")
    for alert in alerts:
        classification = alert.get("classification", "unclassified")
        severity = alert.get("severity", "?")
        parts.append(
            f"  • [{alert.get('alert_id')}] [{severity.upper()}] [{classification}] "
            f"{alert.get('title', '?')} | Source: {alert.get('source_system', '?')} | "
            f"Time: {alert.get('timestamp', '?')}"
        )
        indicators = alert.get("indicators", {})
        if indicators:
            ioc_summary = ", ".join(
                f"{k}: {v[:2]}" for k, v in indicators.items() if v
            )
            parts.append(f"    IOCs: {ioc_summary}")

    # Last action results
    if obs.get("enrichment_results"):
        parts.append("\n[ENRICHMENT RESULTS]")
        for r in obs["enrichment_results"]:
            status = "MALICIOUS" if r.get("malicious") else "CLEAN"
            parts.append(
                f"  {r.get('indicator')} ({r.get('indicator_type')}): {status} | "
                f"Score: {r.get('threat_score', 0)}/100 | "
                f"Type: {r.get('threat_type', 'N/A')} | Tags: {r.get('tags', [])}"
            )

    if obs.get("log_results"):
        parts.append(f"\n[LOG RESULTS] {len(obs['log_results'])} entries:")
        for entry in obs["log_results"][:5]:  # Show max 5
            parts.append(
                f"  [{entry.get('source')}] {entry.get('event_type')} | "
                f"User: {entry.get('user', 'N/A')} | Host: {entry.get('hostname', 'N/A')} | "
                f"SrcIP: {entry.get('src_ip', 'N/A')} | DstIP: {entry.get('dst_ip', 'N/A')}"
            )
            details = entry.get("details", {})
            if details:
                parts.append(f"    Details: {json.dumps(details)[:200]}")

    if obs.get("correlated_events"):
        parts.append(f"\n[CORRELATIONS] {len(obs['correlated_events'])} found:")
        for corr in obs["correlated_events"]:
            parts.append(
                f"  {corr.get('alert_ids')} via {corr.get('correlation_type')}: "
                f"'{corr.get('shared_indicator')}'"
            )

    if obs.get("asset_info"):
        a = obs["asset_info"]
        parts.append(
            f"\n[ASSET] {a.get('hostname')}: {a.get('asset_type')}, "
            f"criticality={a.get('criticality')}, owner={a.get('owner')}, dept={a.get('department')}"
        )

    if obs.get("user_info"):
        u = obs["user_info"]
        parts.append(
            f"\n[USER] {u.get('username')}: {u.get('role')}, {u.get('department')}, "
            f"risk_score={u.get('risk_score')}, privileged={u.get('is_privileged')}"
        )

    # Investigation summary
    invs = obs.get("investigations", {})
    classified_alerts = [
        (aid, inv.get("classification", "unclassified"))
        for aid, inv in invs.items()
        if inv.get("classification")
    ]
    if classified_alerts:
        parts.append(f"\n[CLASSIFICATIONS SO FAR]")
        for aid, cls in classified_alerts:
            parts.append(f"  {aid}: {cls}")

    parts.append(f"\n[STATUS] {obs.get('message', '')}")
    parts.append(f"Step reward: {obs.get('reward', 0):.3f} | Cumulative: {obs.get('cumulative_reward', 0):.3f}")
    parts.append("\nWhat is your next action? Respond with valid JSON only.")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Action Parser
# ---------------------------------------------------------------------------

NOOP_ACTION = {"action_type": "noop"}


def parse_action(response_text: str) -> dict:
    """
    Extract a valid JSON action from the LLM response.
    Falls back to noop on parse failure.
    """
    # Try to find JSON in the response
    text = response_text.strip()

    # Handle code blocks
    if "```json" in text:
        start = text.find("```json") + 7
        end = text.find("```", start)
        text = text[start:end].strip()
    elif "```" in text:
        start = text.find("```") + 3
        end = text.find("```", start)
        text = text[start:end].strip()

    # Find first { } block
    brace_start = text.find("{")
    brace_end = text.rfind("}") + 1
    if brace_start >= 0 and brace_end > brace_start:
        text = text[brace_start:brace_end]

    try:
        action = json.loads(text)
        # Validate required field
        if "action_type" not in action:
            return NOOP_ACTION
        return action
    except (json.JSONDecodeError, ValueError):
        return NOOP_ACTION


# ---------------------------------------------------------------------------
# Task Runner
# ---------------------------------------------------------------------------

def run_task(
    task_id: str,
    server_client: httpx.Client,
    llm_client: Optional[OpenAI],
    seed: int = SEED,
    verbose: bool = True,
) -> float:
    """
    Run one complete task episode.

    Returns:
        Final cumulative reward (float).
    """
    print(f"\n{'='*60}")
    print(f"TASK: {task_id.upper()} (seed={seed})")
    print(f"{'='*60}")

    # Reset environment
    try:
        reset_resp = server_client.post("/reset", json={"task_id": task_id, "seed": seed})
        reset_resp.raise_for_status()
        obs = reset_resp.json()
    except httpx.HTTPError as e:
        print(f"[ERROR] Failed to reset: {e}")
        return 0.0

    print(f"Episode started. Alerts: {len(obs.get('alert_queue', []))}. Budget: {obs.get('investigation_budget')} steps.")

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": format_observation(obs, step=0)},
    ]

    task_start = time.time()
    step = 0

    while not obs.get("done", False):
        step += 1

        # Check timeout
        elapsed = time.time() - task_start
        if elapsed > TASK_TIMEOUT_SECONDS:
            print(f"[TIMEOUT] Task exceeded {TASK_TIMEOUT_SECONDS}s. Submitting investigation.")
            try:
                final_resp = server_client.post("/step", json={"action_type": "submit_investigation"})
                obs = final_resp.json()
            except Exception:
                pass
            break

        # Check budget
        if obs.get("investigation_budget", 0) <= 0:
            break

        # Get LLM action
        action_dict = NOOP_ACTION
        if llm_client is not None:
            try:
                response = llm_client.chat.completions.create(
                    model=MODEL_NAME,
                    messages=messages,
                    temperature=0.0,
                    max_tokens=256,
                    timeout=30,
                )
                raw_text = response.choices[0].message.content or ""
                action_dict = parse_action(raw_text)

                if verbose:
                    print(f"  Step {step:3d}: {action_dict.get('action_type')}", end="")
                    if action_dict.get("indicator"):
                        print(f" [{action_dict['indicator']}]", end="")
                    if action_dict.get("log_source"):
                        print(f" [{action_dict['log_source']}]", end="")
                    if action_dict.get("alert_id"):
                        print(f" [{action_dict['alert_id']}]", end="")

            except (APIError, APITimeoutError) as e:
                print(f"\n  [API Error] {type(e).__name__}: {e}. Using noop.")
                action_dict = NOOP_ACTION
            except Exception as e:
                print(f"\n  [Error] {e}. Using noop.")
                action_dict = NOOP_ACTION
        else:
            # No LLM — use simple heuristic agent for local testing
            action_dict = _heuristic_action(obs, step)
            if verbose:
                print(f"  Step {step:3d}: [heuristic] {action_dict.get('action_type')}", end="")

        # Execute action
        try:
            step_resp = server_client.post(
                "/step",
                content=json.dumps(action_dict),
                headers={"Content-Type": "application/json"},
            )
            step_resp.raise_for_status()
            obs = step_resp.json()
        except httpx.HTTPError as e:
            print(f"\n  [HTTP Error] {e}")
            obs["done"] = True
            break

        reward = obs.get("reward", 0.0)
        cumulative = obs.get("cumulative_reward", 0.0)
        if verbose:
            print(f" -> reward={reward:+.3f} cumulative={cumulative:.3f}")

        # Update message history
        messages.append({"role": "assistant", "content": json.dumps(action_dict)})
        messages.append({
            "role": "user",
            "content": format_observation(obs, step=step),
        })

        # Keep message history manageable (last 20 exchanges)
        if len(messages) > 42:
            messages = [messages[0]] + messages[-40:]

    final_score = obs.get("cumulative_reward", 0.0)
    elapsed_total = time.time() - task_start
    print(f"\nTask complete in {elapsed_total:.1f}s | Steps: {step} | Final score: {final_score:.4f}")
    return final_score


# ---------------------------------------------------------------------------
# Heuristic Fallback Agent (for testing without LLM)
# ---------------------------------------------------------------------------

# Track correlation attempts across calls (reset on each task run)
_attempted_correlations: set = set()

def _heuristic_action(obs: dict, step: int) -> dict:
    """
    Simple rule-based agent for testing without an LLM.
    Systematically investigates each alert.
    """
    # Only enrich these valid IndicatorType values
    VALID_INDICATOR_TYPES = {"ip", "domain", "file_hash", "email", "url", "user"}

    alerts = obs.get("alert_queue", [])
    investigations = obs.get("investigations", {})
    budget = obs.get("investigation_budget", 0)

    # Find first unclassified alert
    unclassified_alerts = [
        a for a in alerts
        if investigations.get(a["alert_id"], {}).get("classification") is None
    ]

    if not unclassified_alerts:
        return {"action_type": "submit_investigation"}

    target = unclassified_alerts[0]
    alert_id = target["alert_id"]
    inv = investigations.get(alert_id, {})

    indicators = target.get("indicators", {})
    queried = set(inv.get("queried_sources", {}).keys())
    enriched = set(inv.get("enriched_indicators", {}).keys())

    # Enrich IOCs first (only valid indicator types)
    for itype, values in indicators.items():
        if itype not in VALID_INDICATOR_TYPES:
            continue
        for val in values[:2]:  # max 2 per type
            if val not in enriched:
                return {
                    "action_type": "enrich_indicator",
                    "indicator": val,
                    "indicator_type": itype,
                    "query_alert_id": alert_id,
                }

    # Query at least one primary log source before classifying
    primary_sources = ["email_gateway", "endpoint", "auth", "firewall"]
    queried_primary = [s for s in primary_sources if s in queried]
    if not queried_primary:
        return {
            "action_type": "query_logs",
            "log_source": primary_sources[0],
            "query_alert_id": alert_id,
            "time_window_hours": 24,
        }

    # Budget-aware: with many alerts, limit log queries to conserve steps
    steps_per_alert = max(1, budget // max(1, len(unclassified_alerts)))
    max_log_queries = 2 if steps_per_alert <= 4 else 8

    log_priority = ["email_gateway", "endpoint", "auth", "firewall", "dns", "proxy", "ids", "cloud_trail"]
    for source in log_priority[:max_log_queries]:
        if source not in queried:
            return {
                "action_type": "query_logs",
                "log_source": source,
                "query_alert_id": alert_id,
                "time_window_hours": 24,
            }

    # Try to correlate with adjacent alerts only (skip when budget is very tight)
    global _attempted_correlations
    adjacent = [a for a in alerts if a["alert_id"] != alert_id][:2]
    corr_attempts_for_alert = sum(
        1 for pair in _attempted_correlations if alert_id in pair
    )
    if steps_per_alert > 4 and corr_attempts_for_alert < 2:
        for other_alert in adjacent:
            pair = frozenset([alert_id, other_alert["alert_id"]])
            if pair not in _attempted_correlations:
                _attempted_correlations.add(pair)
                return {
                    "action_type": "correlate_alerts",
                    "alert_id_a": alert_id,
                    "alert_id_b": other_alert["alert_id"],
                }

    # Classify based on enrichment results
    enrichment_results = inv.get("enriched_indicators", {})
    malicious_count = sum(
        1 for r in enrichment_results.values()
        if isinstance(r, dict) and r.get("malicious")
    )

    if malicious_count > 0:
        classification = "true_positive"
        technique = "T1566.001"  # Default phishing technique
    else:
        classification = "false_positive"
        technique = None

    # Classify
    if not inv.get("classification"):
        return {
            "action_type": "classify_alert",
            "alert_id": alert_id,
            "classification": classification,
            "confidence": 0.7,
        }

    # Map technique for TPs
    if classification == "true_positive" and technique and not inv.get("mapped_techniques"):
        return {
            "action_type": "map_technique",
            "alert_id": alert_id,
            "technique_id": technique,
        }

    # Recommend action for TPs
    if classification == "true_positive" and not inv.get("recommended_actions"):
        return {
            "action_type": "recommend_action",
            "alert_id": alert_id,
            "response_action": "block_ip",
        }

    # Submit when done or low budget
    if budget <= 3 or not unclassified_alerts:
        return {"action_type": "submit_investigation"}

    return {"action_type": "noop"}


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def main():
    """Run baseline agent against all 3 tasks and print summary scores."""

    print("SOC-Triage-Gym Baseline Inference")
    print(f"Server: {SERVER_URL}")
    print(f"Model: {MODEL_NAME or 'heuristic (no LLM configured)'}")
    print(f"Seed: {SEED}")

    # Verify server is reachable
    try:
        health = httpx.get(f"{SERVER_URL}/health", timeout=10).json()
        print(f"Server health: {health}")
    except Exception as e:
        print(f"[ERROR] Cannot reach server at {SERVER_URL}: {e}")
        print("Start the server with: uvicorn server.app:app --host 0.0.0.0 --port 7860")
        sys.exit(1)

    # Initialize LLM client (optional)
    llm_client = None
    if API_BASE_URL and API_KEY and MODEL_NAME and OpenAI is not None:
        try:
            llm_client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)
            print(f"LLM client initialized: {API_BASE_URL}")
        except Exception as e:
            print(f"[WARNING] Failed to initialize LLM client: {e}. Using heuristic agent.")
    else:
        print("[INFO] No LLM configured (set API_BASE_URL, API_KEY/HF_TOKEN, MODEL_NAME). Using heuristic agent.")

    # Run all 3 tasks
    tasks = ["phishing", "lateral_movement", "queue_management"]
    results = {}
    total_start = time.time()

    with httpx.Client(base_url=SERVER_URL, timeout=60) as server_client:
        for task_id in tasks:
            _attempted_correlations.clear()  # reset per-task
            task_score = run_task(
                task_id=task_id,
                server_client=server_client,
                llm_client=llm_client,
                seed=SEED,
                verbose=True,
            )
            results[task_id] = task_score

    total_elapsed = time.time() - total_start

    # Print summary
    print(f"\n{'='*60}")
    print("FINAL RESULTS")
    print(f"{'='*60}")
    for task_id, score in results.items():
        bar = "#" * max(0, int(score * 20))
        print(f"  {task_id:<25} {score:.4f}  {bar}")
    avg_score = sum(results.values()) / len(results)
    print(f"  {'AVERAGE':<25} {avg_score:.4f}")
    print(f"\nTotal runtime: {total_elapsed:.1f}s")
    print(f"{'='*60}")

    return results


if __name__ == "__main__":
    main()
