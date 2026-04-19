---
title: SOC Triage Gym
emoji: 🛡️
colorFrom: red
colorTo: yellow
sdk: docker
app_port: 7860
tags:
  - openenv
  - reinforcement-learning
  - cybersecurity
  - soc
  - mitre-attack
  - siem
  - multi-agent
  - grpo
---

# SOC-Triage-Gym v2

**OpenEnv Hackathon Apr 2026 — Theme #1 Multi-Agent Interactions + Fleet AI Oversight + Theme #4 Self-Improvement**

The first OpenEnv environment that trains and evaluates AI agents as a coordinated SOC team — not a single analyst.

A real Security Operations Center has three tiers: Tier-1 triages alerts and escalates, Tier-2 contains confirmed threats, and a Manager audits the team's decisions. SOC-Triage-Gym v2 models all three roles with a live ticket bus, a phase state machine, and an LLM-based manager judge. The reward signal is a blend of individual role performance and team F1 — so an agent that maximizes personal score at the expense of team outcome is penalized.

---

## Architecture

```
Alert Queue → [Tier-1 Analyst] → escalate_to_tier2 → [Tier-2 Responder] → [SOC Manager]
               TRIAGE phase          ticket bus          RESPONSE phase      OVERSIGHT phase
               (40 steps)                                (20 steps)          (8 steps)
                                                                    ↑
                                                         [Red-Team Generator]
                                                         (adaptive curriculum)
```

**Reward blend per step:**
```
step_reward = 0.6 × role_specific_reward + 0.4 × Δteam_F1
```

Team F1 uses delta (not sticky value) — NOOP-spamming after a correct classification yields zero team reward.

---

## Tasks

| Task | Mode | Alerts | Difficulty |
|------|------|--------|-----------|
| `phishing` | solo | 1 | easy |
| `lateral_movement` | solo | 5 | medium |
| `queue_management` | solo | 20 | hard |
| `insider_threat` | solo | 30 | expert |
| `team_phishing_escalation` | team | 1 | easy |
| `team_lateral_team` | team | 8 | medium |
| `red_team_generated` | team | dynamic | adaptive |

---

## Team Mode

Team episodes run through three phases. Each phase has a dedicated step budget.

**Tier-1 actions:** `enrich_indicator`, `query_logs`, `correlate_alerts`, `check_asset`, `check_user`, `classify_alert`, `map_technique`, `recommend_action`, `escalate_to_tier2`, `phase_complete`, `noop`

**Tier-2 actions:** `forensic_timeline`, `sandbox_detonate`, `memory_analysis`, `isolate_host`, `disable_user`, `block_ioc`, `close_case`, `phase_complete`, `noop`

**Manager actions:** `review_decision`, `override_classification`, `flag_inconsistency`, `explain_team_behavior`, `phase_complete`, `noop`

Inter-role communication flows through the ticket bus (`POST /step` with `escalate_to_tier2` creates a ticket; `GET /inbox/{role}` retrieves it).

---

## Red-Team Curriculum (Theme #4)

The Red-Team Generator co-evolves with the blue team. After each curriculum round:

- blue win rate > 75% → difficulty_floor increases by 0.1
- blue win rate < 45% → difficulty_floor decreases by 0.1
- otherwise → difficulty holds

This keeps the agent in the learning zone automatically.

![Red-Team Curriculum Oscillation](redteam_curriculum.png)

*Blue-team win rate oscillates around 0.5 as the Red-Team Generator adapts difficulty. The generator converges to an equilibrium that matches blue-team skill level — the hallmark of a self-improving curriculum.*

---

## GRPO Training

Training uses real per-step GRPO — not full-episode oracle rollouts.

```
Dataset row = (observation at step_index, task_id, seed, step_index)
Reward      = env.step(model_action).reward   ← immediate step signal
```

The reward function replays the environment to `step_index` deterministically (same seed → same state), applies the model's single action, and returns the env's immediate blended step reward.

```bash
# Colab/GPU training
python train_grpo.py --role tier1 --model Qwen/Qwen2.5-0.5B --unsloth

# Dry-run (oracle baseline, no GPU)
python train_grpo.py --role tier1 --dry-run
```

See [`soc_triage_gym_v2_training.ipynb`](soc_triage_gym_v2_training.ipynb) for the full Colab walkthrough.

---

## Quick Start

```bash
pip install -e ".[dev]"
uvicorn server.app:app --host 0.0.0.0 --port 7860
```

**Solo episode:**
```bash
curl -X POST http://localhost:7860/reset \
  -H "Content-Type: application/json" \
  -d '{"task_id":"phishing","seed":42}'
```

**Team episode:**
```bash
curl -X POST http://localhost:7860/reset \
  -H "Content-Type: application/json" \
  -d '{"task_id":"team_lateral_team","seed":42,"mode":"team"}'
```

**Scripted oracle baseline:**
```bash
python inference.py
```

See [DEMO.md](DEMO.md) for step-by-step judge demo instructions.

---

## API

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Liveness check |
| `/tasks` | GET | All 7 tasks |
| `/reset` | POST | Start episode |
| `/step` | POST | Submit action |
| `/state` | GET | Current state |
| `/grader` | POST | Score current state |
| `/baseline` | POST | Run oracle baseline |
| `/generate_scenario` | POST | Generate adversarial scenario |
| `/inbox/{role}` | GET | Ticket inbox for tier1/tier2/manager |

---

## Reward Design

Dense step rewards for productive investigation. Final score on submit/phase_complete is the grader score (0–1) × efficiency multiplier.

**Per-action rewards (examples):**

| Action | Reward |
|--------|--------|
| Correct indicator enrichment | +0.08 |
| Correct classification | +0.15 |
| Escalate true positive | +0.10 |
| Escalate false positive | −0.05 |
| Over-escalation (>25% of alerts) | −0.08 |
| Host isolation (TP) | +0.20 |
| Host isolation (FP) | −0.15 |
| Legitimate flag_inconsistency | +0.15 |
| Spurious flag_inconsistency | −0.15 |
| Duplicate close_case | −0.02 |

**Efficiency multiplier:**

| Budget used | Multiplier |
|-------------|------------|
| ≤ 50% | ×1.00 |
| ≤ 75% | ×1.00 |
| ≤ 90% | ×0.85 |
| > 90% | ×0.70 |

---

## Test Coverage

```
86 passed, 1 skipped
```

Coverage includes: solo backward-compat, team phase state machine, ticket bus, containment tools, manager oversight, team grader, red-team generator, reward-hack regression tests (close_case idempotency, team_f1 delta, zero-escalation guard, over-escalation threshold, manager judge fallback).

---

## Repository Layout

```
soc-triage-gym/
  server/           FastAPI app + SOCEnvironment
  scenarios/        Scenario configs + RedTeamGenerator
  graders/          Task graders + ManagerJudge (LLM + heuristic fallback)
  tools/            enrichment, log query, correlation, containment, oversight
  tests/            86 tests
  scripts/          gen_plots.py (pre-generate reward curves)
  models.py         Pydantic v2 types
  train_grpo.py     Per-step GRPO training script
  inference.py      Scripted oracle baseline
  openenv.yaml      OpenEnv metadata
  PITCH.md          3-min pitch script
  DEMO.md           Judge demo walkthrough
```

---

## Theme Coverage

| Theme | How |
|-------|-----|
| **Theme #1 Multi-Agent Interactions** | 3-role team (T1→T2→Manager) with ticket bus, phase state machine, blended team reward |
| **Fleet AI Scalable Oversight** | SOC Manager audits every decision, flags inconsistencies, explains behavior — scored by LLM judge |
| **Theme #4 Self-Improvement** | Red-Team Generator adapts difficulty to keep blue win rate near 0.5; curriculum oscillation shown above |

---

## License

MIT
