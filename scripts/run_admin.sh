#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! python3 -c 'import tkinter' >/dev/null 2>&1; then
  echo "Tkinter is not installed. On Kali run:"
  echo "  sudo apt update && sudo apt install -y python3-tk python3-venv"
  exit 1
fi

if [ ! -d .admin-venv ]; then
  python3 -m venv .admin-venv
fi

source .admin-venv/bin/activate
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements-admin.txt
exec python scripts/endpointtrust_admin_app.py
