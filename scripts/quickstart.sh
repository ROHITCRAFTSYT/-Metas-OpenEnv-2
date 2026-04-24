#!/usr/bin/env bash
# Judge-facing 60-second quickstart. Starts the env, proves theme coverage,
# runs the 5-beat demo. Exits cleanly whether or not a trained checkpoint
# is present.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> 1/4 · installing deps (if needed)"
python -m pip install --quiet -r requirements.txt

echo "==> 2/4 · starting env server on :7860"
python -m uvicorn server.app:app --host 0.0.0.0 --port 7860 >/tmp/soc_server.log 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT

# wait for health (max 30s)
for i in $(seq 1 30); do
  if curl -fs http://localhost:7860/health >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fs http://localhost:7860/health >/dev/null || {
  echo "server did not become healthy; see /tmp/soc_server.log"; exit 1;
}

echo "==> 3/4 · theme coverage manifest"
python - <<'PY'
import json, urllib.request
d = json.load(urllib.request.urlopen("http://localhost:7860/themes/coverage"))
covered = [k for k, v in (d.get("coverage") or {}).items() if v]
print(f"  themes covered ({len(covered)}): {', '.join(covered)}")
print(f"  reward-hacking defenses: {len(d.get('reward_hacking_defenses', []))}")
PY

echo "==> 4/4 · 5-beat demo walkthrough"
python demo.py

echo ""
echo "==> done. server PID $SERVER_PID still running for exploration."
echo "    stop it with:  kill $SERVER_PID"
trap - EXIT
