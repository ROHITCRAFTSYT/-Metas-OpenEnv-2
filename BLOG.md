# SOC-Triage-Gym v2: Training a Multi-Agent Security Team with GRPO

*OpenEnv Hackathon Apr 2026 submission — Theme #1 Multi-Agent Interactions + Fleet AI Oversight + Theme #4 Self-Improvement*

---

## The Problem with Solo SOC Agents

Every existing SOC agent benchmark trains a single analyst. It sees an alert, gathers evidence, classifies, submits. Done.

Real Security Operations Centers don't work that way. A Tier-1 analyst triages 50–100 alerts per shift and escalates the critical ones. A Tier-2 responder takes those tickets and runs forensic timelines, isolates compromised hosts, blocks C2 infrastructure. A SOC Manager reviews both, catches inconsistencies, and explains team decisions to leadership.

When you train a solo agent, you're training for a job that doesn't exist. When you evaluate it alone, you're missing the failure mode that matters most: an agent that's locally optimal but breaks the team workflow.

SOC-Triage-Gym v2 is built to fix that.

---

## What We Built

A three-tier team environment running as a stateful HTTP server compatible with the OpenEnv spec:

```
Alert Queue → [Tier-1] → escalate_to_tier2 → [Tier-2] → [SOC Manager]
              TRIAGE phase    ticket bus        RESPONSE    OVERSIGHT
              (40 steps)                        (20 steps)  (8 steps)
```

Each role has a dedicated action space, a phase budget, and an inter-agent ticket bus. Escalations from Tier-1 become tickets that Tier-2 picks up via `GET /inbox/tier2`. Manager review uses an LLM-based judge that scores the team's natural-language explanation — with a keyword heuristic fallback so it works without an API key.

The reward signal is a blend:

```
step_reward = 0.6 × role_specific + 0.4 × Δteam_F1
```

The `Δteam_F1` (delta, not cumulative) means an agent that correctly classifies one alert and then NOOPs for the rest of its budget gets no further team reward. The learning signal stays honest.

---

## Real Per-Step GRPO

Previous versions of the training pipeline were "theater" — the model generated one action and the oracle handled the remaining 79 steps. The reward was the full episode score, which was dominated by scripted behavior.

We rewrote it completely. The new pipeline:

1. **Dataset**: Run oracle rollouts, record every `(observation, step_index)` pair where the target role is acting. Each row is a single decision point.
2. **Reward**: At scoring time, reset the environment with the same `(task_id, seed)` and replay oracle actions up to `step_index` — deterministically reconstructing the exact state. Apply the model's action. Return the env's **immediate step reward**.
3. **Training**: TRL's `GRPOTrainer` with group size 8. Each group of completions gets ranked by per-step reward, advantage-normalized, and used for policy gradient.

This means the model is actually learning which actions the environment rewards at each state, not just imitating the oracle's final episode score.

---

## Red-Team Curriculum (Theme #4)

The Red-Team Generator co-evolves with the blue team. After each curriculum round:

- Blue win rate > 75% → difficulty increases by 0.1
- Blue win rate < 45% → difficulty decreases by 0.1
- Otherwise → holds

This keeps the agent in the learning zone automatically — the curriculum tracks skill rather than using a fixed difficulty schedule.

![Red-Team Curriculum](https://huggingface.co/spaces/rohitcraftsyt/openenv2/resolve/main/redteam_curriculum.png)

The oscillation in difficulty is the hallmark of a working self-play curriculum: the red team and blue team reach a dynamic equilibrium rather than one dominating the other.

---

## Reward Integrity

Six reward-hack vulnerabilities were found and fixed before submission:

| Issue | Fix |
|-------|-----|
| `close_case` farmed (+0.05 per call) | Idempotency: duplicate → −0.02 |
| `team_f1` sticky after classification | Reward on delta only |
| `flag_inconsistency` EV-positive at 40% guess rate | Penalty raised to −0.15 (matching reward) |
| Over-escalation threshold off-by-one | Strict >25% on prospective count |
| Zero-escalation triage wastes T2/Manager budget | Short-circuit with −0.10 penalty |
| Manager judge crashes without API key | Heuristic fallback, no exception |

All six are regression-tested. 86 tests pass.

---

## Try It

```bash
pip install -e ".[dev]"
uvicorn server.app:app --port 7860

# Team episode
curl -X POST http://localhost:7860/reset \
  -H "Content-Type: application/json" \
  -d '{"task_id":"team_lateral_team","seed":42,"mode":"team"}'
```

Full training notebook: [`soc_triage_gym_v2_training.ipynb`](https://huggingface.co/spaces/rohitcraftsyt/openenv2/blob/main/soc_triage_gym_v2_training.ipynb)

Source: [github.com/ROHITCRAFTSYT/-Metas-OpenEnv-2](https://github.com/ROHITCRAFTSYT/-Metas-OpenEnv-2)
