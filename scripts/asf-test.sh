#!/usr/bin/env bash
# Avvia una sessione Claude Code in modalità TEST (ASF_ENV=test).
# Killa i daemon attivi e rimuove i socket, così ripartono puliti ed
# ereditano ASF_ENV=test. Poi sostituisce la shell con `claude` in test.
#
# Uso:  ./scripts/asf-test.sh
# Tutti gli argomenti vengono passati a claude (es. ./scripts/asf-test.sh --help).

set -euo pipefail

CACHE="$HOME/.cache/asf-hook"
STATE_FILE="$CACHE/asf_env"

mkdir -p "$CACHE"
chmod 700 "$CACHE"
printf '%s\n' "test" > "$STATE_FILE"

echo "[asf-test] fermo i daemon ASF attivi..."
pkill -f asf_hook_daemon.py 2>/dev/null || true
pkill -f asf-rust-daemon    2>/dev/null || true

echo "[asf-test] rimuovo socket e pid file..."
rm -f "$CACHE"/asf_hook.sock "$CACHE"/asf_hook.pid \
      "$CACHE"/asf_rust.sock "$CACHE"/asf_rust.pid

echo "[asf-test] avvio Claude Code con ASF_ENV=test"
echo "[asf-test] le scritture andranno su: ${ASF_TEST_DB:-$(cd "$(dirname "$0")/.." && pwd)/asf_test.db}"
echo

exec env ASF_ENV=test claude "$@"
