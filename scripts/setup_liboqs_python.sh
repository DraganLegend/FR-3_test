#!/usr/bin/env bash
set -euo pipefail

# Setup script to install Open Quantum Safe Python bindings (liboqs-python)
# into a uv-managed virtual environment and verify basic functionality.

VENV_PATH=".venv"

usage() {
  cat <<EOF
Usage: $0 [--venv-path PATH]

Options:
  --venv-path PATH   Path to create/use the uv virtualenv (default: .venv)

This script will:
  - Ensure 'uv' is installed (try pipx or brew if missing)
  - Create a virtualenv with uv
  - Remove conflicting PyPI package 'oqs' if present
  - Install 'liboqs-python' (which provides the 'oqs' module)
  - Verify a Dilithium2 sign/verify round-trip
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --venv-path)
      VENV_PATH="$2"; shift 2;
      ;;
    -h|--help)
      usage; exit 0;
      ;;
    *)
      echo "Unknown argument: $1" >&2; usage; exit 2;
      ;;
  esac
done

echo "[1/5] Checking for uv..."
if ! command -v uv >/dev/null 2>&1; then
  echo "'uv' not found. Attempting to install..."
  if command -v pipx >/dev/null 2>&1; then
    pipx install uv >/dev/null 2>&1 || pipx upgrade uv >/dev/null 2>&1 || true
  elif command -v brew >/dev/null 2>&1; then
    brew install uv
  else
    echo "Please install uv first: https://docs.astral.sh/uv/getting-started/" >&2
    exit 1
  fi
  if ! command -v uv >/dev/null 2>&1; then
    echo "Failed to install 'uv'. Please install it manually." >&2
    exit 1
  fi
fi

echo "[2/5] Creating virtualenv at '$VENV_PATH'..."
uv venv "$VENV_PATH"

PY="$VENV_PATH/bin/python"
if [[ ! -x "$PY" ]]; then
  echo "Python interpreter not found at $PY" >&2
  exit 1
fi

echo "[3/5] Removing conflicting package 'oqs' (if installed)..."
# Non-fatal if not present
uv pip uninstall -p "$PY" oqs >/dev/null 2>&1 || true

echo "[4/5] Installing 'liboqs-python'..."
uv pip install -p "$PY" liboqs-python --upgrade

echo "[5/5] Verifying oqs import and sign/verify..."
"$PY" - <<'PY'
import sys
import oqs

try:
    with oqs.Signature('Dilithium2') as sig:
        pk = sig.generate_keypair()
        msg = b'hello oqs'
        sig_bytes = sig.sign(msg)
        ok = sig.verify(msg, sig_bytes, pk)
        print('oqs verification:', ok)
        sys.exit(0 if ok else 2)
except Exception as e:
    print('oqs verification error:', e)
    sys.exit(3)
PY

echo
echo "Success. Activate with: source $VENV_PATH/bin/activate"
echo "Or run Python with: $VENV_PATH/bin/python"

