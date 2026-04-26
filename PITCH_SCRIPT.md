# 120-second pitch video script

**Format:** screen recording + voice-over. Read verbatim at a relaxed pace.

---

### [0:00 – 0:15] Hook

> "Every OpenEnv submission you've seen today trains one agent. A real SOC has three: a Tier-1 analyst, a Tier-2 responder, and a manager auditing both. SOC-Triage-Gym trains them as a team, with a ticket bus between them and a reward that punishes selfish behavior."

**Show:** architecture diagram from README.

---

### [0:15 – 0:35] The environment

> "Eight tasks, from a single phishing alert up to a 250-step APT campaign. Standard OpenEnv `/reset` and `/step`. What's new is a phase state machine — TRIAGE, RESPONSE, OVERSIGHT — and a blended reward: sixty percent your role, forty percent delta team F1. If you spam NOOP after a correct classification, you get zero."

**Show:** `curl localhost:7860/metadata` then `curl localhost:7860/themes/coverage | jq`.

---

### [0:35 – 0:55] Theme coverage

> "We claim coverage of every hackathon theme and six sub-theme prizes. Every claim is backed by code *and* a regression test. Here's the machine-readable manifest."

**Show:** scroll through `/themes/coverage` JSON output, then `pytest tests/test_themes_coverage.py -v` passing.

---

### [0:55 – 1:25] Training proof

> "We trained Qwen 2.5 1.5B with GRPO on the Tier-1 role for three epochs on a Colab T4. On fifteen held-out seeds across two tasks, the trained policy scores [X percent] versus the untrained baseline at [Y percent] — a [Z] point improvement. The red-team curriculum runs underneath, oscillating scenario difficulty around a fifty-percent blue win rate."

**Show:** `trained_vs_baseline.png` plot, then `redteam_curriculum.png`.

---

### [1:25 – 1:45] Safeguards

> "Six named reward-hacking defenses, each locked in as a test. The manager judge uses an LLM with a heuristic fallback. Mid-episode policy drift forces the agent to re-reason — rules that changed at step thirty don't retroactively score step one. Token-length reward is capped, not linear — you can't ramble your way to a higher score."

**Show:** split screen of test file + reward_hacking_defenses JSON.

---

### [1:45 – 2:00] Close

> "Everything in this submission — the environment, the trained checkpoint, the plots, this video — is in one HuggingFace Space. One-command demo is `python demo.py`. Thanks for judging."

**Show:** HF Space URL + GitHub link.

---

## Recording tips

- **Resolution:** 1920×1080, 30fps. Higher is overkill.
- **Audio:** use a real mic, not laptop built-in. AirPods are acceptable, MacBook mic is not.
- **Font size in terminal:** bump to at least 18pt so text is legible on mobile playback.
- **Speed:** resist the urge to talk fast. 2 minutes sounds long while recording; it's right on-screen.
- **Cut ruthlessly.** Don't show loading spinners. Jump-cut after starting a command to when output appears.
- **One take is fine** if you read from this script. Don't chase perfection.

## Tooling

- **Mac:** built-in Screen Recording (Cmd+Shift+5) + QuickTime for trimming. Free.
- **Cross-platform:** OBS Studio. Free, powerful, five-minute learning curve.
- **Hosted:** Loom. Paid, but one-click.

## Upload

- YouTube (unlisted, shareable link) is safest for judges.
- Add the link at the **top** of README.md — don't bury it.
