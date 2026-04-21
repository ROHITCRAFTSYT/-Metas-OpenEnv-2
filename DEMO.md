# SOC-Triage-Gym v3 — Judge Demo Guide

Run these steps in order to see every major feature in under 7 minutes.
For a one-shot theme-coverage manifest, hit `GET /themes/coverage` first.

```bash
curl -s http://localhost:7860/themes/coverage | python -m json.tool
```

## Prerequisites

```bash
pip install -e ".[dev]"
uvicorn server.app:app --host 0.0.0.0 --port 7860
```

Then open `http://localhost:7860` in a browser.

---

## Demo 1 — Solo Triage (Theme baseline, 1 min)

```bash
curl -s -X POST http://localhost:7860/reset \
  -H "Content-Type: application/json" \
  -d '{"task_id":"phishing","seed":42}' | python -m json.tool | head -30
```

Shows: alert queue, IOC indicators, investigation budget.

```bash
python inference.py
```

Watch the agent enrich indicators, classify, map MITRE ATT&CK, and submit.

---

## Demo 2 — Team Mode Episode (Theme #1 + Fleet AI, 2 min)

```bash
curl -s -X POST http://localhost:7860/reset \
  -H "Content-Type: application/json" \
  -d '{"task_id":"team_lateral_team","seed":42,"mode":"team"}' | python -m json.tool | head -20
```

In the landing UI:
1. Select **team_lateral_team** and click Reset
2. Watch Tier-1 triage 8 alerts — escalation tickets appear in the inbox column
3. Phase advances to Tier-2 — see response actions (isolate, block, close)
4. Phase advances to Manager — audit, flag inconsistencies, explain team behavior
5. Episode ends with **team_f1** score shown in the final breakdown

Check the team inbox endpoint:

```bash
curl http://localhost:7860/inbox/tier2
```

---

## Demo 3 — Red-Team Curriculum (Theme #4, 1 min)

```bash
curl -s -X POST http://localhost:7860/generate_scenario \
  -H "Content-Type: application/json" \
  -d '{"difficulty_floor":0.7,"noise_density":0.6,"seed":99}' | python -m json.tool | head -20
```

Shows: adversarially generated scenario with elevated difficulty and noise.

To visualize the full curriculum oscillation, run:

```bash
python scripts/gen_plots.py
# Produces redteam_curriculum.png
```

![Red-Team Curriculum Oscillation](redteam_curriculum.png)

The Red-Team Generator increases difficulty when the blue team wins >75% of rounds
and backs off when it drops below 45% — keeping the agent in the learning zone.

---

## Demo 4 — Per-Step GRPO Training (Reward Pipeline, 1 min)

```bash
# Dry-run: plots oracle reward curve, no GPU needed
python train_grpo.py --role tier1 --dry-run

# Real per-step dataset preview
python - <<'EOF'
import httpx
from train_grpo import build_step_dataset
c = httpx.Client(base_url="http://localhost:7860", timeout=30)
ds = build_step_dataset(c, ["team_phishing_escalation"], [42, 43], "tier1")
print(f"{len(ds)} per-step training rows collected")
print("Sample:", {k: v for k, v in ds[5].items() if k != "prompt"})
EOF
```

Each row is a single (obs, step_index) pair. The reward function replays the
environment to that exact state and scores the model's action with the env's
immediate step reward — real GRPO signal, not oracle theater.

---

## Reward Hack Exploit Tests

Verify the six audit fixes hold:

```bash
# 1. close_case idempotency
python - <<'EOF'
from server.environment import SOCEnvironment
from models import ActionType, AlertClassification, AgentRole, SOCAction
env = SOCEnvironment()
env.reset("team_phishing_escalation", seed=42, mode="team")
aid = env._config.alerts[0].alert_id
ip = list(env._config.alerts[0].indicators.get("ip", ["1.2.3.4"]))[0]
env.step(SOCAction(action_type=ActionType.ENRICH_INDICATOR, indicator=ip, indicator_type="ip", query_alert_id=aid, role=AgentRole.TIER1))
env.step(SOCAction(action_type=ActionType.CLASSIFY_ALERT, alert_id=aid, classification=AlertClassification.TRUE_POSITIVE, role=AgentRole.TIER1))
env.step(SOCAction(action_type=ActionType.ESCALATE_TO_TIER2, alert_id=aid, justification="TP", role=AgentRole.TIER1))
env.step(SOCAction(action_type=ActionType.PHASE_COMPLETE, role=AgentRole.TIER1))
r1 = env.step(SOCAction(action_type=ActionType.CLOSE_CASE, alert_id=aid, justification="Done", role=AgentRole.TIER2))
r2 = env.step(SOCAction(action_type=ActionType.CLOSE_CASE, alert_id=aid, justification="Done again", role=AgentRole.TIER2))
import re
def role_r(obs): m = re.search(r"role=(-?[\d.]+)", obs.message); return float(m.group(1)) if m else None
print(f"First close_case:     role_reward = {role_r(r1):.3f}  (expected +0.05)")
print(f"Duplicate close_case: role_reward = {role_r(r2):.3f}  (expected -0.02)")
EOF

# 2. Run full regression suite
pytest tests/ -q
```

---

## API Reference

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Liveness check |
| `/tasks` | GET | List all 7 tasks |
| `/reset` | POST | Start episode (`task_id`, `seed`, `mode`) |
| `/step` | POST | Submit action, get next observation |
| `/state` | GET | Current state without advancing |
| `/grader` | POST | Score without terminating |
| `/baseline` | POST | Run scripted oracle baseline |
| `/generate_scenario` | POST | Generate adversarial red-team scenario |
| `/inbox/{role}` | GET | Fetch ticket inbox for tier1/tier2/manager |

---

## Demo 7 — v3 Sub-Theme Sweep (3 min)

**Halluminate — external NPC actors:**
```bash
curl -s -X POST http://localhost:7860/reset -H "Content-Type: application/json" \
  -d '{"task_id":"queue_management","seed":7}' > /dev/null
for i in $(seq 1 30); do
  curl -s -X POST http://localhost:7860/step -H "Content-Type: application/json" \
    -d '{"action_type":"noop"}' > /dev/null
done
curl -s http://localhost:7860/actors/messages | python -m json.tool | head -40
```
Expect to see ThreatIntel / Compliance / EndUser messages with a mix of
`ground_truth_relevant: true` (real) and `false` (distractors).

**Patronus — mid-episode schema drift:**
```bash
curl -s http://localhost:7860/policy/history | python -m json.tool
```
Shows 2 PolicyVersion entries with `description` fields like
`"Severity tightening: HIGH now requires CVSS ≥ 8.5"`.

**Mercor — token-scaled reward curve:**
```bash
for n in 5 50 150 400 800; do
  TEXT=$(python -c "print('word '*$n)")
  curl -s -X POST http://localhost:7860/reward/token_bonus \
    -H "Content-Type: application/json" \
    -d "{\"text\":\"$TEXT\",\"content_quality\":1.0}"
  echo
done
```
Bonus climbs from 0.0 → 0.10 as length crosses floor then saturates at cap.

**Snorkel — rotate the expert judge:**
```bash
for r in 0 1 2 3; do
  curl -s -X POST http://localhost:7860/experts/rotate \
    -H "Content-Type: application/json" -d "{\"round_index\":$r}" \
    | python -c "import sys,json; x=json.load(sys.stdin); print(r'round', x['round'], '→', x['expert']['display_name'])"
done
```

**Scaler AI Labs — cross-app rule:**
```bash
curl -s "http://localhost:7860/tickets/can_disable_user?alert_id=ALT-XYZ"   # => allowed:false
curl -s -X POST http://localhost:7860/tickets/open \
  -H "Content-Type: application/json" \
  -d '{"alert_id":"ALT-XYZ","priority":"P1","note":"audit trail"}'
curl -s "http://localhost:7860/tickets/can_disable_user?alert_id=ALT-XYZ"   # => allowed:true
```

**Theme #2 — super-long-horizon APT campaign:**
```bash
curl -s -X POST http://localhost:7860/reset \
  -H "Content-Type: application/json" \
  -d '{"task_id":"apt_campaign","seed":42}' \
  | python -c "import sys,json; o=json.load(sys.stdin); print('alerts:', len(o['alert_queue']), 'budget:', o['investigation_budget'])"
```
Should print `alerts: 60+ budget: 250`.

---

## Demo 8 — Deterministic Replay (30 sec)

```bash
python -m scripts.replay episodes/sample.jsonl --in-process
```
Re-runs a recorded episode byte-for-byte — judges can reproduce any reward
number in the leaderboard themselves.
