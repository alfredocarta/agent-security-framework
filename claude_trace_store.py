from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from trace_output_preview import output_preview_text as _shared_output_preview_text


DEFAULT_MAX_PREVIEW_BYTES = int(os.environ.get("ASF_HOOK_MAX_PREVIEW_BYTES", "8192"))
AGENT_ID = "claude-code-agent"
DEFAULT_AGENT_MODEL = os.environ.get("ASF_CLAUDE_AGENT_MODEL", "claude-sonnet-4-6 via Claude Code")

SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\s*[=:]\s*[^\s'\"]{8,}"),
    re.compile(r"(?i)\b(bearer|sk-[a-z0-9_-]{12,}|ghp_[a-z0-9_]{20,})"),
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS claude_tool_traces (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'claude-code',
    agent_id TEXT NOT NULL,
    agent_model TEXT,
    session_id TEXT,
    transcript_path TEXT,
    tool_call_id TEXT,
    claude_tool_name TEXT NOT NULL,
    asf_tool_name TEXT NOT NULL,
    args_hash TEXT NOT NULL,
    args_preview TEXT,
    output_hash TEXT,
    output_preview TEXT,
    verdict TEXT,
    outcome TEXT,
    reason TEXT,
    trace_id TEXT,
    audit_hash TEXT,
    created_at TEXT NOT NULL
)
"""

_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_claude_traces_timestamp ON claude_tool_traces(timestamp DESC)",
    "CREATE INDEX IF NOT EXISTS idx_claude_traces_session ON claude_tool_traces(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_claude_traces_tool_call ON claude_tool_traces(tool_call_id)",
    "CREATE INDEX IF NOT EXISTS idx_claude_traces_trace ON claude_tool_traces(trace_id)",
    "CREATE INDEX IF NOT EXISTS idx_claude_traces_audit_hash ON claude_tool_traces(audit_hash)",
)


def _utc_now() -> str:
    return datetime.utcnow().isoformat(timespec="milliseconds")


def _json_default(value: Any) -> str:
    try:
        return str(value)
    except Exception:
        return repr(value)


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=_json_default)


def sha256_text(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8", errors="replace")).hexdigest()


def _redact_text(text: str) -> str:
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED_SECRET]", redacted)
    canary = os.environ.get("ASF_HOOK_CANARY") or os.environ.get("ASF_HERMES_CANARY")
    if canary:
        redacted = redacted.replace(canary, "[REDACTED_CANARY]")
    return redacted


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_value(v) for v in value)
    return value


def preview_value(value: Any, max_bytes: int = DEFAULT_MAX_PREVIEW_BYTES) -> str:
    text = stable_json(redact_value(value))
    raw = text.encode("utf-8", errors="replace")
    if len(raw) <= max_bytes:
        return text
    clipped = raw[:max_bytes].decode("utf-8", errors="ignore")
    return f"{clipped}...[truncated {len(raw) - max_bytes} bytes]"


def output_preview_text(value: Any, max_bytes: int = DEFAULT_MAX_PREVIEW_BYTES) -> str:
    return _shared_output_preview_text(value, max_bytes)


def _sqlite_path_from_url(database_url: str) -> Path | None:
    if not database_url.startswith("sqlite"):
        return None
    parsed = urlparse(database_url)
    if parsed.scheme not in {"sqlite", "sqlite3"}:
        return None
    if parsed.path in {"", "/:memory:"}:
        return None
    return Path(unquote(parsed.path))


def resolve_db_path() -> Path:
    explicit = os.environ.get("ASF_HOOK_DB")
    if explicit:
        return Path(explicit).expanduser()
    database_url = os.environ.get("DATABASE_URL")
    if database_url:
        parsed = _sqlite_path_from_url(database_url)
        if parsed is not None:
            return parsed
    asf_root = Path(os.environ.get("ASF_ROOT", Path(__file__).resolve().parent))
    return asf_root / "asf_local.db"


def make_tool_call_id(payload: dict[str, Any], tool_name: str, tool_input: Any) -> str:
    explicit = (
        payload.get("tool_call_id")
        or payload.get("tool_use_id")
        or payload.get("tool_id")
        or payload.get("id")
    )
    if explicit:
        return str(explicit)
    seed = stable_json(
        {
            "session_id": payload.get("session_id"),
            "transcript_path": payload.get("transcript_path"),
            "tool_name": tool_name,
            "args_hash": sha256_text(tool_input),
        }
    )
    return f"claude-call-{hashlib.sha256(seed.encode()).hexdigest()[:16]}"


def make_trace_id(session_id: str | None, tool_call_id: str | None, tool_name: str, tool_input: Any) -> str:
    seed = stable_json(
        {
            "session_id": session_id,
            "tool_call_id": tool_call_id,
            "tool_name": tool_name,
            "args_hash": sha256_text(tool_input),
        }
    )
    return f"claude-{hashlib.sha256(seed.encode()).hexdigest()[:16]}"


class ClaudeTraceStore:
    def __init__(self, db_path: str | Path | None = None):
        self.db_path = Path(db_path).expanduser() if db_path is not None else resolve_db_path()
        self._lock = threading.Lock()

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def ensure_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(_SCHEMA)
            for index_sql in _INDEXES:
                conn.execute(index_sql)
            conn.commit()

    def start_trace(
        self,
        *,
        session_id: str | None,
        transcript_path: str | None,
        tool_call_id: str,
        claude_tool_name: str,
        asf_tool_name: str,
        args: Any,
        verdict: str | None,
        outcome: str | None,
        reason: str | None,
        audit_hash: str | None = None,
        trace_id: str | None = None,
        agent_model: str | None = None,
    ) -> str:
        self.ensure_schema()
        now = _utc_now()
        trace_id = trace_id or make_trace_id(session_id, tool_call_id, claude_tool_name, args)
        row_id = uuid.uuid4().hex
        redacted_args = redact_value(args)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO claude_tool_traces (
                    id, timestamp, source, agent_id, agent_model, session_id,
                    transcript_path, tool_call_id, claude_tool_name, asf_tool_name,
                    args_hash, args_preview, verdict, outcome, reason, trace_id,
                    audit_hash, created_at
                ) VALUES (?, ?, 'claude-code', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row_id,
                    now,
                    AGENT_ID,
                    agent_model or DEFAULT_AGENT_MODEL,
                    session_id,
                    transcript_path,
                    tool_call_id,
                    claude_tool_name,
                    asf_tool_name,
                    sha256_text(redacted_args),
                    preview_value(redacted_args),
                    verdict,
                    outcome,
                    reason,
                    trace_id,
                    audit_hash,
                    now,
                ),
            )
            conn.commit()
        return trace_id

    def finish_trace(
        self,
        *,
        result: Any,
        tool_call_id: str | None = None,
        session_id: str | None = None,
        trace_id: str | None = None,
    ) -> int:
        self.ensure_schema()
        where, params = self._lookup_clause(tool_call_id, session_id, trace_id)
        if not where:
            return 0
        redacted_result = redact_value(result)
        values: list[Any] = [sha256_text(redacted_result), output_preview_text(redacted_result)]
        values.extend(params)
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                f"UPDATE claude_tool_traces SET output_hash = ?, output_preview = ? WHERE {where}",
                values,
            )
            conn.commit()
            return int(cur.rowcount or 0)

    def fetch_traces(
        self,
        *,
        session_id: str | None = None,
        trace_id: str | None = None,
        tool_call_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        self.ensure_schema()
        clauses: list[str] = []
        params: list[Any] = []
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if trace_id:
            clauses.append("trace_id = ?")
            params.append(trace_id)
        if tool_call_id:
            clauses.append("tool_call_id = ?")
            params.append(tool_call_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM claude_tool_traces {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _lookup_clause(
        tool_call_id: str | None,
        session_id: str | None,
        trace_id: str | None,
    ) -> tuple[str, list[Any]]:
        if tool_call_id:
            if session_id:
                return "tool_call_id = ? AND session_id = ?", [tool_call_id, session_id]
            return "tool_call_id = ?", [tool_call_id]
        if trace_id:
            return "trace_id = ?", [trace_id]
        return "", []


def get_default_store() -> ClaudeTraceStore:
    return ClaudeTraceStore()
