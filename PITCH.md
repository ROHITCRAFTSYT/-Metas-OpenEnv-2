# SOC-Triage-Gym v3 — 3-Minute Pitch Script

> **Structure:** Hook (30s) → Problem (30s) → Solution + Demo (90s) → Results (30s)
> **Memorize the first 30 seconds cold — that's what wins or loses the judges' attention.**

---

## HOOK (0:00–0:30)

> "A real Security Operations Center processes 10,000 alerts a day.
> The average analyst has 11 minutes per alert.
> Missing one real attack costs millions.
> Dismissing too much noise burns out your team.
>
> AI agents are being deployed in SOCs right now — but every existing benchmark
> trains and evaluates them **alone**, as a single tier.
> Real SOCs are **teams**."

---

## PROBLEM (0:30–1:00)

> "Current agent benchmarks — including OpenEnv Round 1 — treat SOC triage as
> a one-agent problem: classify, map, submit.
>
> But real analysts don't work that way. Tier-1 triages and escalates.
> Tier-2 contains and closes. A manager reviews, audits inconsistencies,
> and explains team behavior to leadership.
>
> No existing environment rewards the **team outcome** —
> and no existing benchmark has oversight built into the reward signal itself."

---

## SOLUTION + DEMO (1:00–2:30)

> "SOC-Triage-Gym v2 is the first OpenEnv that models all three roles
> as a coordinated team, with a live ticket bus, phase state machine,
> and an LLM-based manager judge."

**[DEMO: open the landing UI — team_lateral_team task]**

> "Watch what happens.
> Tier-1 triages 8 alerts in the queue, escalates the confirmed true positives
> via tickets — those appear here in real time.
> Phase advances to Tier-2, who runs forensic timelines, isolates compromised
> hosts, and closes cases.
> Then the SOC Manager reviews: auditing inconsistencies, flagging missed threats,
> and scoring a natural-language explanation of what the team did.
>
> The reward signal is a blend: 60% role-specific, 40% team F1.
> That means an agent that maximizes its own score at the expense of team
> outcome is penalized."

**[DEMO: scroll to Kill Chain View — show correlated alerts]**

> "And to prevent the environment itself from being gamed, we built four
> specific guardrails: close-case is idempotent, team F1 only rewards
> on improvement deltas, over-escalation triggers penalties past 25%,
> and zero-escalation triage short-circuits the episode."

**[DEMO: click 'Generate Scenario' — show red-team adaptation]**

> "Finally — Theme #4. The Red-Team Generator co-evolves with the blue team.
> As the blue-team win rate climbs above 75%, difficulty ratchets up.
> If it drops below 45%, the generator backs off.
> This produces a curriculum that stays in the learning zone automatically."

---

## RESULTS (2:30–3:00)

> "108 tests green. Six reward-hack vulnerabilities fixed.
> Training pipeline converted from oracle theater to real per-step GRPO —
> each training example is a single observation, the model generates one action,
> and the reward is the environment's immediate step signal.
>
> **Nine themes / sub-themes covered, all machine-verifiable at `GET /themes/coverage`:**
> Theme #1 multi-agent + Fleet AI oversight. Halluminate multi-actor with three external NPCs.
> Theme #2 super-long-horizon via the 250-step `apt_campaign` task.
> Mercor token-length-scaled narrative rewards — floor/cap/quality-gated so you can't farm them.
> Patronus mid-episode schema drift: alert fields rename, severity thresholds tighten, policies update.
> Scaler AI Labs multi-app enterprise with cross-app rules (can't disable a user without an open P2+ ticket).
> Snorkel rotating expert judges — Dr. Accuracy, Speedy Sam, Thorough Thea — whose weights shift the reward function.
> Theme #4 red-team co-evolution keeps the curriculum pinned to the learning zone.
>
> SOC-Triage-Gym v3: the first OpenEnv where the reward knows the team won — under drift, under audit, under a rotating expert."

---

## Q&A PREP

**Q: Is the training actually learning or just a scripted baseline?**
> The reward function is now real per-step GRPO. Each example is one (obs, step_index) pair.
> We replay the environment to that exact state deterministically, apply the model's action,
> and return the env's immediate step reward. No oracle wrap.

**Q: How does the Manager judge work without an API key?**
> It falls back to a keyword heuristic — mentions of alert IDs, escalation signals,
> containment terms, and explanation length. Tested explicitly.

**Q: Can an agent spam close_case to farm reward?**
> No. Idempotency check: duplicate closure returns -0.02 instead of +0.05.
> All six reward hacks from the audit are fixed and regression-tested.

**Q: What's the difficulty range for red-team scenarios?**
> difficulty_floor 0.05–0.95, noise_density 0.0–0.95.
> Fully deterministic: same seed + same config → same scenario.
