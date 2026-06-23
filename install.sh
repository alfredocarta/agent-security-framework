#!/usr/bin/env bash
# Make executable after checkout if needed: chmod +x install.sh

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

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

ASE_DIR="$(dirname "$SCRIPT_DIR")/agent-security-evaluation"
if [ ! -d "$ASE_DIR/dashboard_v2" ]; then
  echo "Cloning agent-security-evaluation..."
  if ! git clone https://github.com/alfredocarta/agent-security-evaluation.git "$ASE_DIR"; then
    echo "Error: failed to clone agent-security-evaluation."
    exit 1
  fi
else
  echo "agent-security-evaluation already present, skipping clone."
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
    echo "Added ~/.local/bin to $SHELL_PROFILE. Run: source $SHELL_PROFILE"
    ;;
esac

cat <<'EOF'
ASF installato.

Comandi disponibili:
  asf-run claude      — avvia Claude Code con ASF attivo
  asf-run hermes      — avvia Hermes con ASF attivo
  asf-run dashboard   — avvia la dashboard (http://localhost:8080/overview)
  asf-run update      — mostra istruzioni per aggiornare

Gli hook di Claude Code vengono configurati automaticamente al primo avvio.
EOF
