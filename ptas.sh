#!/bin/bash

set -euo pipefail

# Find the project folder when ptas is started from a symlink.
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
PROJECT_DIR="$(cd "$(dirname "$SCRIPT_PATH")"; pwd)"

if [ -x "$PROJECT_DIR/.venv/bin/python" ]; then
    PYTHON="$PROJECT_DIR/.venv/bin/python"
else
    echo "PTAS virtual environment not found at $PROJECT_DIR/.venv" >&2
    echo "Run ./kali-setup.sh first, or create it with: python3 -m venv .venv" >&2
    exit 1
fi

cd "$PROJECT_DIR"
exec "$PYTHON" -m Backend.cli "$@"
