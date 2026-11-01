#!/bin/bash
# One-shot setup for a fresh clone (Linux/macOS). Run: bash setup.sh
set -e
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"

# The pinned wheels exist for 64-bit CPython 3.12-3.14 (onnxruntime, numpy and
# scikit-learn have none for 3.15 yet); Vite 8 needs Node.js ^20.19 or >=22.12.
"$PYTHON" -c 'import struct, sys; sys.exit(not ((3, 12) <= sys.version_info[:2] <= (3, 14) and struct.calcsize("P") == 8 and getattr(sys, "_is_gil_enabled", lambda: True)()))' || {
    echo "Setup needs 64-bit Python 3.12-3.14 (not free-threaded); $PYTHON is: $("$PYTHON" --version 2>&1)" >&2
    echo "Pick another interpreter, e.g.: PYTHON=python3.13 bash setup.sh" >&2
    exit 1
}
node -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit((a === 20 && b >= 19) || a > 22 || (a === 22 && b >= 12) ? 0 : 1)' || {
    echo "Setup needs Node.js 20.19+ or 22.12+ (Vite 8); found: $(node -v 2>&1)" >&2
    exit 1
}

echo "Installing Python dependencies..."
"$PYTHON" -m pip install -r requirements.txt

echo "Installing Playwright Chromium sandbox..."
"$PYTHON" -m playwright install chromium

echo "Installing Frontend dependencies..."
(cd frontend && npm ci)

echo "Checking that the backend imports..."
"$PYTHON" -c "import app.main"

echo "Setup Complete!"
