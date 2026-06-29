#!/usr/bin/env bash
# Deploy the A2A privacy dashboard on a server (run this ON the server).
#   bash deploy/serve.sh            # clones/pulls + installs + serves on :8099
# Then open http://<server-ip>:8099  (ensure the port is reachable / tunneled).
set -euo pipefail

REPO="${REPO:-https://github.com/Justin0504/federated-agent-audit.git}"
DIR="${DIR:-$HOME/federated-agent-audit}"
PORT="${PORT:-8099}"

if [ ! -d "$DIR/.git" ]; then
  git clone "$REPO" "$DIR"
fi
cd "$DIR"
git pull --ff-only || true

python3 -m venv .venv-demo 2>/dev/null || true
# shellcheck disable=SC1091
source .venv-demo/bin/activate
pip install -q --upgrade pip
pip install -q -e ".[transport]"

echo "Serving A2A privacy dashboard on 0.0.0.0:$PORT"
# background, survives logout; logs to serve.log
HOST=0.0.0.0 PORT="$PORT" nohup python examples/a2a_serve.py > serve.log 2>&1 &
sleep 4
curl -s "http://127.0.0.1:$PORT/healthz" && echo
echo "→ open http://<server-ip>:$PORT   (logs: $DIR/serve.log)"
echo "  if the port is firewalled, tunnel from your laptop:"
echo "    ssh -L $PORT:localhost:$PORT <user>@<server>   then open http://localhost:$PORT"
