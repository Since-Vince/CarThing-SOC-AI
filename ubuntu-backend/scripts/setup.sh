#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if ! command -v python3 >/dev/null; then
  echo "Python 3 is required" >&2
  exit 1
fi
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
if [[ ! -e .env ]]; then
  cp .env.example .env
  .venv/bin/python - <<'PY'
from pathlib import Path
from secrets import token_urlsafe
p = Path('.env')
p.write_text(p.read_text().replace('CARTHING_API_KEY=CHANGE_ME', 'CARTHING_API_KEY=' + token_urlsafe(32)))
PY
fi
chmod 600 .env
echo
printf 'Setup complete. Your private API key is in .env (keep it secret).\n'
printf 'Start with: .venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8765\n'
