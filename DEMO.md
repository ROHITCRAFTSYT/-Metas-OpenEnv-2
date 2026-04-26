# SOC-Triage-Gym Judge Demo

## 90-second path

```bash
python3 -m pip install -e ".[dev]"
uvicorn server.app:app --host 0.0.0.0 --port 7860
```

Open `http://localhost:7860/` for the dashboard, or verify the API:

```bash
curl http://localhost:7860/health
curl http://localhost:7860/themes/coverage
curl -X POST http://localhost:7860/baseline \
  -H "Content-Type: application/json" \
  -d '{"task_id":"team_phishing_escalation","seed":42,"mode":"team"}'
```

## What to show

1. `GET /themes/coverage` proves the hackathon theme mapping in one request.
2. `POST /reset` with `team_lateral_team` and `mode=team` shows Tier-1/Tier-2/Manager phases.
3. `GET /actors/messages`, `GET /policy/history`, and `GET /experts/current` show the v3 theme hooks.
4. `POST /baseline` demonstrates the environment can run end-to-end without external API keys.

