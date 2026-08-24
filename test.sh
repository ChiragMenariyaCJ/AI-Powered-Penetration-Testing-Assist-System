#!/bin/sh

set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON=${PTAS_TEST_PYTHON:-"$PROJECT_DIR/.venv/bin/python"}

[ -x "$PYTHON" ] || { echo "Run ./kali-setup.sh first." >&2; exit 1; }
cd "$PROJECT_DIR"
"$PYTHON" generate-tests.py
exec "$PYTHON" -m unittest discover -s tests -p 'test_*.py' -v
