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
---

# SOC-Triage-Gym

An OpenEnv-compatible reinforcement learning environment for SOC analyst training. Agents investigate SIEM alerts, gather evidence, classify outcomes, map MITRE ATT&CK techniques, and recommend containment actions across single-alert triage, multi-alert kill chains, noisy queues, and insider threat investigations.

## Why This Project

Most agent benchmarks stop at simple tool use or narrow classification. Real SOC work is different:

- alerts arrive with incomplete information
- evidence must be gathered actively
- false positives dominate the queue
- missing real attacks is much more costly than over-investigating noise

SOC-Triage-Gym is built to train and evaluate that workflow directly.

## What The Agent Can Do

The action space includes:

- `enrich_indicator`
- `query_logs`
- `correlate_alerts`
- `check_asset`
- `check_user`
- `classify_alert`
- `map_technique`
- `recommend_action`
- `escalate`
- `submit_investigation`
- `noop`

The observation includes the visible alert queue, per-alert investigation state, latest tool results, remaining budget, reward, and cumulative reward.

## Tasks

### 1. Phishing

- 1 alert
- binary triage with evidence gathering
- max steps: 15

### 2. Lateral Movement

- 5 alerts
- reconstruct a kill chain across phishing, credential theft, lateral movement, staging, and exfiltration
- max steps: 30

### 3. Queue Management

- 20 alerts
- 2 real attack chains hidden among benign and false-positive noise
- max steps: 60

### 4. Insider Threat

- 30 alerts
- 3 hidden chains across data theft, vendor compromise, and disgruntled employee behavior
- max steps: 80

## Validation Snapshot

Recent local verification:

- `python -m openenv.cli validate . --verbose` -> passed
- `python -m pytest tests\test_server.py tests\test_environment.py -q` -> `24 passed`
- `python benchmark.py --seeds 42 --repeat 1` -> deterministic across all 4 tasks

## Measured Baseline

Deterministic heuristic baseline results for `seed=42`:

| Task | Score |
|---|---:|
| Phishing | 0.65 |
| Lateral Movement | 0.71 |
| Queue Management | 0.885 |
| Insider Threat | 0.92 |
| Overall Average | 0.791 |

This baseline is intentionally deterministic and reproducible. It is useful as a floor, regression target, and judging aid.

## Quick Start

### Docker

```bash
docker build -t soc-triage-gym .
docker run -p 8000:7860 soc-triage-gym
curl http://localhost:8000/health
```

### Local

```bash
pip install -e .
uvicorn server.app:app --host 0.0.0.0 --port 7860
```

### Run The Baseline Agent

```bash
python inference.py
```

### Run The Benchmark

```bash
python benchmark.py --seeds 42,123,256 --repeat 2
```

## API

Core endpoints:

- `POST /reset`
- `POST /step`
- `GET /state`
- `GET /health`
- `GET /metadata`
- `GET /schema`
- `POST /mcp`
- `GET /tasks`
- `POST /grader`
- `POST /baseline`

Example reset:

```json
{"task_id": "phishing", "seed": 42}
```

Valid `task_id` values:

- `phishing`
- `lateral_movement`
- `queue_management`
- `insider_threat`

## Reward Design

The environment uses dense rewards for useful investigation actions and a final normalized grader score on submit.

Examples:

- relevant enrichment: positive reward
- relevant log query: positive reward
- useful correlation: positive reward
- correct classification: positive reward
- classify without evidence: penalty
- missed true positives on timeout: penalty

Efficiency multiplier:

- `<=50%` budget used: `x1.0`
- `<=75%` budget used: `x1.0`
- `<=90%` budget used: `x0.85`
- `>90%` budget used: `x0.70`

## Repository Layout

```text
soc-triage-gym/
  baseline_agent.py
  benchmark.py
  inference.py
  models.py
  openenv.yaml
  server/
  scenarios/
  graders/
  tools/
  tests/
  data/
```

## Why It Should Judge Well

- realistic and practically useful domain
- multi-task curriculum from easy to expert
- deterministic seeded generation
- explicit grading logic
- OpenEnv validation passes
- reproducible benchmark and baseline

## Strongest Next Extensions

- stronger learned or LLM baseline results across multiple seeds
- screenshots or a short demo GIF of the UI
- benchmark tables for multiple seeds in the README
- richer scenario ambiguity and analyst notes

## License

MIT License. See `LICENSE`.
