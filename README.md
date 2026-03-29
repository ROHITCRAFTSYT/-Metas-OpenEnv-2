---
title: SOC Triage Gym
emoji: 🛡️
colorFrom: red
colorTo: purple
sdk: docker
app_port: 7860
tags:
  - openenv
  - reinforcement-learning
  - cybersecurity
  - soc
  - mitre-attack
  - siem
---

# SOC-Triage-Gym 🛡️

**A production-grade OpenEnv-compliant reinforcement learning environment simulating a Security Operations Center (SOC) analyst workflow.**

SOC-Triage-Gym addresses the #1 cybersecurity workforce challenge: the global shortage of skilled SOC analysts. Modern enterprises generate 10,000+ SIEM alerts daily, and more than 50% go uninvestigated. Billions of dollars have been invested in AI SOC agents (Dropzone, Prophet, 7AI, Torq) — yet **no standardized RL training environment exists** for the investigative reasoning workflow. SOC-Triage-Gym fills this gap.

---

## Overview

An AI agent receives SIEM alerts and must:

1. **Enrich indicators** — Query threat intelligence for IPs, domains, file hashes, emails, URLs
2. **Query log sources** — Search firewall, proxy, DNS, endpoint, auth, email gateway, IDS, and cloud trail logs
3. **Correlate events** — Discover shared indicators across alerts to reconstruct kill chains
4. **Classify alerts** — Determine True Positive / False Positive / Benign True Positive
5. **Map ATT&CK techniques** — Identify MITRE ATT&CK technique IDs for each finding
6. **Recommend containment** — Propose appropriate response actions per alert

The environment simulates realistic SOC conditions:
- **75–95% false positive rates** (just like real enterprise SIEMs)
- **Multi-stage attacks hidden in noise** (requires strategic investigation)
- **Information asymmetry** (agent must actively gather evidence, not passively receive it)
- **Budget constraints** (limited investigation steps force prioritization)

---

## Quick Start

### Docker (Recommended)

```bash
# Build and run
docker build -t soc-triage-gym .
docker run -p 8000:8000 soc-triage-gym

# Test health
curl http://localhost:8000/health

# Start a phishing investigation
curl -X POST http://localhost:8000/reset \
  -H "Content-Type: application/json" \
  -d '{"task_id": "phishing", "seed": 42}'
```

### Local Development

```bash
pip install -e .
uvicorn server.app:app --host 0.0.0.0 --port 8000
```

### Run Baseline Agent

```bash
# With an LLM
export API_BASE_URL="https://router.huggingface.co/v1"
export HF_TOKEN="hf_your_token_here"
export MODEL_NAME="meta-llama/Llama-3.1-8B-Instruct"
export SERVER_URL="http://localhost:8000"
python inference.py

# Without LLM (heuristic agent for testing)
SERVER_URL="http://localhost:8000" python inference.py
```

---

## Environment API

### POST /reset
Start a new episode.

```json
{"task_id": "phishing", "seed": 42}
```

**task_id**: `"phishing"` | `"lateral_movement"` | `"queue_management"`
**seed**: Any integer — same seed always produces the same scenario.

### POST /step
Execute an action.

```json
{"action_type": "enrich_indicator", "indicator": "1.2.3.4", "indicator_type": "ip", "query_alert_id": "PHI-ABC123"}
```

Returns updated `SOCObservation`.

### GET /state
Get current episode metadata (does not consume a step).

### GET /health
Liveness check.

---

## Action Space

All actions use the flat `SOCAction` model with `action_type` as the discriminator.

| action_type | Parameters | Description |
|---|---|---|
| `enrich_indicator` | `indicator`, `indicator_type`, `query_alert_id` | Query threat intel for an IOC |
| `query_logs` | `log_source`, `query_alert_id`, `time_window_hours` | Search a SIEM log source |
| `correlate_alerts` | `alert_id_a`, `alert_id_b` | Check if two alerts share indicators |
| `check_asset` | `hostname` | Look up asset in inventory |
| `check_user` | `username` | Look up user in directory |
| `classify_alert` | `alert_id`, `classification`, `confidence` | Record TP/FP/BTP decision |
| `map_technique` | `alert_id`, `technique_id` | Map MITRE ATT&CK technique |
| `recommend_action` | `alert_id`, `response_action`, `action_target` | Recommend containment |
| `escalate` | `alert_id`, `escalation_severity`, `justification` | Escalate to senior analyst |
| `submit_investigation` | *(none)* | Finalize and grade the episode |
| `noop` | *(none)* | No operation (small penalty) |

**indicator_type**: `ip` | `domain` | `file_hash` | `email` | `url` | `user`
**log_source**: `firewall` | `proxy` | `dns` | `endpoint` | `auth` | `email_gateway` | `ids` | `cloud_trail`
**classification**: `true_positive` | `false_positive` | `benign_true_positive`
**response_action**: `isolate_endpoint` | `disable_account` | `block_ip` | `block_domain` | `quarantine_file` | `reset_password` | `revoke_sessions` | `no_action`

---

## Observation Space

The `SOCObservation` model contains:

| Field | Type | Description |
|---|---|---|
| `alert_queue` | `List[AlertMeta]` | All alerts in current episode (with IOCs, severity, source) |
| `investigations` | `Dict[str, InvestigationState]` | Per-alert investigation tracking |
| `enrichment_results` | `List[EnrichmentResult]` | Results from last `enrich_indicator` |
| `log_results` | `List[LogEntry]` | Results from last `query_logs` |
| `correlated_events` | `List[CorrelatedEvent]` | All correlations found so far |
| `asset_info` | `Optional[AssetInfo]` | Result from last `check_asset` |
| `user_info` | `Optional[UserInfo]` | Result from last `check_user` |
| `investigation_budget` | `int` | Steps remaining before forced termination |
| `step` | `int` | Current step number |
| `done` | `bool` | Episode termination flag |
| `reward` | `float` | Step reward |
| `cumulative_reward` | `float` | Total episode reward so far |
| `message` | `str` | Human-readable status from environment |

---

## Reward Function

| Event | Reward |
|---|---|
| Enrich relevant IOC (malicious) | +0.12 |
| Enrich relevant IOC (clean) | +0.08 |
| Enrich irrelevant IOC | -0.03 |
| Query relevant log source | +0.10 |
| Query irrelevant log source | -0.05 |
| Duplicate log query | -0.03 |
| Correlation found (adjacent kill chain) | +0.30 |
| Correlation found (other) | +0.20 |
| No correlation (no shared indicators) | -0.03 |
| Correct classification | +0.30 |
| Wrong classification | -0.20 |
| Classify without evidence | -0.10 |
| Recommend appropriate response (TP) | +0.08 |
| Recommend no_action for FP | +0.05 |
| Recommend no_action for TP | -0.10 |
| NOOP | -0.01 |
| **Final grader score on submit** | **0.0–1.0 × efficiency multiplier** |
| Missed TP on timeout | -0.5 per missed TP |

**Efficiency multiplier:**
- ≤50% budget used: ×1.2
- ≤75% budget used: ×1.0
- ≤90% budget used: ×0.85
- >90% budget used: ×0.70

---

## Task Definitions

### Task 1: Single-Alert Phishing Triage (Easy)
**Max steps**: 15 | **Typical completion**: 6–10 steps

The agent receives a single phishing alert. It must:
- Enrich sender IP, domain, file hash, and email address
- Query email gateway, endpoint, DNS, and firewall logs
- Classify as TP or FP (seed-dependent, ~60% TP rate)
- For TPs: map T1566.001 and recommend isolate/block actions

**Grader weights**:
- Classification accuracy: 40%
- MITRE ATT&CK technique mapping: 20%
- Evidence completeness (relevant sources queried): 20%
- Response action quality: 20%

**Baseline score** (heuristic agent): ~0.45–0.60

### Task 2: Multi-Alert Lateral Movement Kill Chain (Medium)
**Max steps**: 30 | **Typical completion**: 15–25 steps

5 correlated alerts representing a complete attacker kill chain:
1. Phishing email (T1566.001)
2. LSASS credential dump (T1003.001, T1059.001)
3. RDP lateral movement (T1021.001, T1078)
4. Data staging on file server (T1074.001, T1560.001)
5. Exfiltration to C2 (T1041, T1071.001)

Adjacent alerts share indicators (IP, username, hostname). The agent must correlate all 5 into a connected chain.

**Grader weights**:
- Classification accuracy (all 5 as TP): 30%
- ATT&CK technique mapping per alert: 20%
- Kill chain reconstruction (4 adjacent correlations): 20%
- Response actions per phase: 20%
- Efficiency bonus: 10%

**Baseline score** (heuristic agent): ~0.30–0.45

### Task 3: Alert Queue Management Under Noise (Hard)
**Max steps**: 60 | **Typical completion**: 35–55 steps

20 alerts in shuffled order:
- **5 True Positives**: 2 attack chains (3+2 alerts)
  - Chain A: Credential stuffing → Account takeover → Mass exfiltration
  - Chain B: Spearphishing link → Scheduled task persistence
- **3 Benign True Positives**: Authorized pentest, admin PsExec, IT password reset
- **12 False Positives**: Geoblocking, AV false detections, service account noise, CDN DNS alerts, backup transfers

Agent must prioritize investigation, efficiently dismiss FPs, and surface hidden attacks.

**Grader weights**:
- F1 score on classifications (TP+BTP vs FP): 30%
- Attack chain identification: 20%
- Missed TP penalty (-0.2 per missed TP, -0.1 per missed BTP): 20%
- Efficiency (steps vs. budget): 15%
- Response quality for TPs: 15%

**Baseline score** (heuristic agent): ~0.25–0.40

---

## Architecture

```
soc-triage-gym/
├── inference.py              # Baseline LLM agent script
├── models.py                 # All Pydantic v2 models (Action, Observation, etc.)
├── client.py                 # HTTP client wrapper
├── openenv.yaml              # OpenEnv manifest
├── pyproject.toml            # Package configuration
├── Dockerfile                # Container definition
│
├── server/
│   ├── app.py                # FastAPI application (POST /reset, /step, GET /state, /health)
│   ├── environment.py        # SOCEnvironment state machine
│   └── requirements.txt      # Server dependencies
│
├── scenarios/
│   ├── base.py               # BaseScenario with seeded RNG + data generators
│   ├── phishing.py           # Task 1: single alert (TP/FP variants)
│   ├── lateral_movement.py   # Task 2: 5-alert kill chain
│   └── queue_management.py   # Task 3: 20-alert mixed queue
│
├── graders/
│   ├── base.py               # BaseGrader interface + shared helpers
│   ├── phishing_grader.py    # Task 1 grader (0.0-1.0)
│   ├── lateral_movement_grader.py  # Task 2 grader
│   └── queue_management_grader.py  # Task 3 grader
│
├── tools/                    # Simulated SOC tool implementations
│   ├── enrichment.py         # Threat intel lookup
│   ├── log_query.py          # SIEM log search
│   ├── correlation.py        # Alert correlation engine
│   ├── asset_lookup.py       # Asset inventory lookup
│   └── user_lookup.py        # User directory lookup
│
└── data/
    └── mitre_attack.py       # MITRE ATT&CK v14.0 technique database
```

**Data flow per step:**
```
Agent → POST /step (SOCAction JSON)
      → FastAPI deserializes to SOCAction (Pydantic v2)
      → SOCEnvironment._dispatch(action) under threading.Lock
      → Tool function reads ScenarioConfig, writes InvestigationState
      → Step reward computed
      → SOCObservation built and returned
      → Agent receives JSON observation
```

**Episode termination:**
- Agent calls `submit_investigation` → Grader runs → Final reward = score × efficiency_mult
- Budget exhausted → Auto-grade with missed TP penalties

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `API_BASE_URL` | For LLM | OpenAI-compatible endpoint |
| `HF_TOKEN` or `API_KEY` | For LLM | Bearer token |
| `MODEL_NAME` | For LLM | Model identifier |
| `SERVER_URL` | No | Server URL (default: `http://localhost:8000`) |
| `SEED` | No | Episode seed (default: `42`) |
| `TASK_TIMEOUT_SECONDS` | No | Per-task timeout (default: `360`) |

---

## Example Interaction

```python
# Reset phishing task
POST /reset  {"task_id": "phishing", "seed": 42}
→ Returns: alert_queue with 1 alert, budget=15

# Enrich suspicious IP
POST /step  {"action_type": "enrich_indicator", "indicator": "185.220.101.45", "indicator_type": "ip"}
→ Returns: EnrichmentResult(malicious=True, threat_score=88, threat_type="phishing", tags=["phishing-actor"])
            reward=+0.12, cumulative=0.12

# Query email gateway logs
POST /step  {"action_type": "query_logs", "log_source": "email_gateway", "query_alert_id": "PHI-ABC123"}
→ Returns: 1 LogEntry (email_received, spf=fail, dkim=fail, attachment=Invoice_Q4.exe)
            reward=+0.10, cumulative=0.22

# Query endpoint logs
POST /step  {"action_type": "query_logs", "log_source": "endpoint", "query_alert_id": "PHI-ABC123"}
→ Returns: 2 LogEntries (process_created for Invoice_Q4.exe, powershell encoded command)
            reward=+0.10, cumulative=0.32

# Classify as true positive
POST /step  {"action_type": "classify_alert", "alert_id": "PHI-ABC123", "classification": "true_positive", "confidence": 0.95}
→ reward=+0.30, cumulative=0.62

# Map ATT&CK technique
POST /step  {"action_type": "map_technique", "alert_id": "PHI-ABC123", "technique_id": "T1566.001"}
→ reward=+0.05, cumulative=0.67

# Recommend containment
POST /step  {"action_type": "recommend_action", "alert_id": "PHI-ABC123", "response_action": "isolate_endpoint"}
→ reward=+0.08, cumulative=0.75

# Submit investigation (after 7 steps = 47% budget used → 1.2× efficiency multiplier)
POST /step  {"action_type": "submit_investigation"}
→ Grader score: 0.90 × 1.20 = 1.08
   Final cumulative: 1.83
```

---

## Baseline Performance

Expected scores for the heuristic agent (no LLM):

| Task | Expected Score | Notes |
|---|---|---|
| Phishing (Easy) | 0.45–0.60 | Gets classification right ~70% of the time |
| Lateral Movement (Medium) | 0.30–0.45 | Misses kill chain correlations |
| Queue Management (Hard) | 0.25–0.40 | Struggles with FP dismissal efficiency |

An LLM-based agent using the provided system prompt is expected to score:

| Task | Expected Score |
|---|---|
| Phishing (Easy) | 0.65–0.85 |
| Lateral Movement (Medium) | 0.50–0.70 |
| Queue Management (Hard) | 0.40–0.60 |

---

## Design Principles

1. **Realistic partial observability** — Agent must actively gather evidence; facts are not presented upfront
2. **Information asymmetry** — Same scenario looks different depending on investigation order
3. **Asymmetric risk** — Missing a true positive costs 3–5× more than a false positive escalation
4. **Deterministic reproducibility** — Same seed always produces identical scenario and grader result
5. **Dense reward signal** — Meaningful rewards at every step, not just episode end
6. **No external dependencies** — All data in-memory, no network calls during episodes

---

## Citation

If you use SOC-Triage-Gym in research, please cite:
```
@software{soc_triage_gym_2024,
  title={SOC-Triage-Gym: A Reinforcement Learning Environment for SOC Analyst Training},
  year={2024},
  url={https://huggingface.co/spaces/rohitcraftsyt/openenv2}
}
```

---

## License

MIT License — see LICENSE file for details.
