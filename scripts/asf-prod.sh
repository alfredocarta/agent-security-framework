#!/usr/bin/env bash
# Riporta l'ambiente in PRODUZIONE.
# Killa i daemon (che fossero rimasti in modalità test) e pulisce i socket,
# così la PROSSIMA sessione Claude Code normale li fa ripartire in prod.
#
# Uso:  ./scripts/asf-prod.sh           -> solo pulizia (poi avvia `claude` a mano)
#       ./scripts/asf-prod.sh --launch  -> pulisce e avvia subito `claude` in prod

set -euo pipefail

CACHE="$HOME/.cache/asf-hook"
STATE_FILE="$CACHE/asf_env"

mkdir -p "$CACHE"
chmod 700 "$CACHE"
printf '%s\n' "production" > "$STATE_FILE"

echo "[asf-prod] fermo i daemon ASF attivi..."
pkill -f asf_hook_daemon.py 2>/dev/null || true
pkill -f asf-rust-daemon    2>/dev/null || true

echo "[asf-prod] rimuovo socket e pid file..."
rm -f "$CACHE"/asf_hook.sock "$CACHE"/asf_hook.pid \
      "$CACHE"/asf_rust.sock "$CACHE"/asf_rust.pid

if [[ "${1:-}" == "--launch" ]]; then
  shift
  echo "[asf-prod] avvio Claude Code in produzione"
  echo
  exec env ASF_ENV=production claude "$@"
fi

echo "[asf-prod] pulizia completata. La prossima sessione 'claude' partirà in prod."
