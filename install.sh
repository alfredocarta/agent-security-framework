#!/usr/bin/env bash
# Make executable after checkout if needed: chmod +x install.sh

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

if [ -n "$CONDA_PREFIX" ] && [ -x "$CONDA_PREFIX/bin/python" ]; then
  PYTHON_FOR_INSTALL="$CONDA_PREFIX/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_FOR_INSTALL="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_FOR_INSTALL="python"
else
  echo "Error: Python 3 is required. Install it and re-run install.sh."
  exit 1
fi

PYTHON_VERSION=$("$PYTHON_FOR_INSTALL" -c 'import sys; print("%d.%d" % (sys.version_info[0], sys.version_info[1]))')
if ! "$PYTHON_FOR_INSTALL" -c 'import sys; raise SystemExit(not (sys.version_info[0] > 3 or (sys.version_info[0] == 3 and sys.version_info[1] >= 11)))'; then
  echo "ERROR: ASF requires Python 3.11 or later. Found Python $PYTHON_VERSION."
  echo "Please activate a Python 3.11+ environment (e.g. conda activate <env>) and re-run install.sh."
  exit 1
fi

# Source rustup env if cargo is not yet in PATH (common when running as bash on macOS)
if ! command -v cargo >/dev/null 2>&1 && [ -f "$HOME/.cargo/env" ]; then
  # shellcheck source=/dev/null
  source "$HOME/.cargo/env"
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "Rust not found. Installing via rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source "$HOME/.cargo/env"
fi

if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
  echo "Error: Python 3 is required. Install it and re-run install.sh."
  exit 1
fi

if ! (cd "$SCRIPT_DIR/asf_rust_daemon" && cargo build --release); then
  exit 1
fi

if [ -n "$CONDA_PREFIX" ]; then
  PIP="$CONDA_PREFIX/bin/pip"
elif command -v pip3 >/dev/null 2>&1; then
  PIP="pip3"
elif command -v pip >/dev/null 2>&1; then
  PIP="pip"
else
  echo "Error: pip is required. Install it and re-run install.sh."
  exit 1
fi

if ! "$PIP" install -r "$SCRIPT_DIR/requirements.txt"; then
  exit 1
fi

BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"
ln -sf "$SCRIPT_DIR/asf_rust_daemon/target/release/asf-run" "$BIN_DIR/asf-run"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    SHELL_PROFILE=""
    if [ -n "$ZSH_VERSION" ] || [ "$(basename "$SHELL")" = "zsh" ]; then
      SHELL_PROFILE="$HOME/.zshrc"
    else
      SHELL_PROFILE="$HOME/.bashrc"
    fi
    echo "export PATH=\"$HOME/.local/bin:\$PATH\"" >> "$SHELL_PROFILE"
    echo "PATH updated in $SHELL_PROFILE. Run: source $SHELL_PROFILE or open a new terminal before using asf-run."
    ;;
esac

cat <<'EOF'
ASF installato.

Comandi disponibili:
  asf-run claude      — avvia Claude Code con ASF attivo
  asf-run hermes      — avvia Hermes con ASF attivo
  asf-run update      — mostra istruzioni per aggiornare

Gli hook di Claude Code vengono configurati automaticamente al primo avvio.
EOF
