#!/bin/bash
# One-shot setup for a fresh clone (Linux/macOS). Run: bash setup.sh
set -e
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"

echo "Installing Python dependencies..."
"$PYTHON" -m pip install -r requirements.txt

echo "Installing Playwright Chromium sandbox..."
"$PYTHON" -m playwright install chromium

echo "Installing Frontend dependencies..."
(cd frontend && npm ci)

echo "Setup Complete!"
