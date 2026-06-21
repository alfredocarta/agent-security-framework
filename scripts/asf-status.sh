#!/usr/bin/env bash
# Mostra lo stato corrente: daemon attivi, conteggi nei DB di prod e test.
# Non scrive nulla, è solo lettura.
#
# Uso:  ./scripts/asf-status.sh

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROD_DB="$ROOT/asf_local.db"
TEST_DB="${ASF_TEST_DB:-$ROOT/asf_test.db}"

echo "=== Daemon ASF attivi ==="
if ps aux | grep -iE "asf_hook_daemon|asf-rust-daemon" | grep -v grep; then :; else
  echo "(nessun daemon attivo)"
fi

count() {
  local db="$1" tbl="$2"
  if [[ -f "$db" ]]; then
    sqlite3 "$db" "SELECT COUNT(*) FROM $tbl;" 2>/dev/null || echo "n/d"
  else
    echo "(file assente)"
  fi
}

echo
echo "=== PROD  ($PROD_DB) ==="
echo "audit_trail:        $(count "$PROD_DB" audit_trail)"
echo "claude_tool_traces: $(count "$PROD_DB" claude_tool_traces)"

echo
echo "=== TEST  ($TEST_DB) ==="
echo "audit_trail:        $(count "$TEST_DB" audit_trail)"
echo "claude_tool_traces: $(count "$TEST_DB" claude_tool_traces)"
if [[ -f "$TEST_DB" ]]; then
  echo "agent_id distinti in test:"
  sqlite3 "$TEST_DB" "SELECT DISTINCT agent_id FROM audit_trail;" 2>/dev/null | sed 's/^/  - /'
fi
