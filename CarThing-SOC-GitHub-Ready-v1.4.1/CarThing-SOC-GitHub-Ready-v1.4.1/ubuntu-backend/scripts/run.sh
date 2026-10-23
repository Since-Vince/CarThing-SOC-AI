#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Reads .env to honor configured local host/port; no shell eval of its contents.
exec .venv/bin/python -m app.run
