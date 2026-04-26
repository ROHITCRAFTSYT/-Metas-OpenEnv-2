# SOC-Triage-Gym Pitch

SOC-Triage-Gym is an OpenEnv environment for training agents to operate as a coordinated Security Operations Center team.

Instead of a single agent solving toy alerts, the environment models Tier-1 triage, Tier-2 containment, and Manager oversight with role-specific actions, a ticket bus, phase budgets, and a blended team reward. It also includes external NPC actors, mid-episode policy drift, rotating expert judges, token-scaled narrative rewards, and a 250-step APT campaign for long-horizon planning.

The key differentiator is that agents are scored on operational teamwork, not just isolated classification accuracy. An agent that maximizes its own local reward while hurting team F1 is penalized.

Judges can verify the implementation with:

```bash
curl http://localhost:7860/themes/coverage
python3 -m pytest -q
python3 inference.py
```
