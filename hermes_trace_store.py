from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse


DEFAULT_MAX_PREVIEW_BYTES = int(os.environ.get("ASF_HERMES_MAX_PREVIEW_BYTES", "2048"))


_SCHEMA = """
CREATE TABLE IF NOT EXISTS hermes_tool_traces (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'hermes',
    agent_id TEXT NOT NULL,
    agent_type TEXT,
    agent_model TEXT,
    session_id TEXT,
    task_id TEXT,
    tool_call_id TEXT,
    hermes_tool_name TEXT NOT NULL,
    asf_tool_name TEXT NOT NULL,
    args_hash TEXT NOT NULL,
    args_preview TEXT,
    output_hash TEXT,
    output_preview TEXT,
    verdict TEXT,
    outcome TEXT,
    reason TEXT,
    stage TEXT,
    confidence REAL,
    asf_latency_ms INTEGER,
    tool_duration_ms INTEGER,
    side_effect_verified INTEGER DEFAULT 0,
    side_effect_occurred INTEGER,
    expected_label TEXT,
    human_label TEXT,
    scenario_id TEXT,
    threat_id TEXT,
    trace_id TEXT,
    audit_hash TEXT,
    created_at TEXT NOT NULL
)
"""

_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_hermes_traces_timestamp ON hermes_tool_traces(timestamp DESC)",
    "CREATE INDEX IF NOT EXISTS idx_hermes_traces_session ON hermes_tool_traces(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_hermes_traces_tool_call ON hermes_tool_traces(tool_call_id)",
    "CREATE INDEX IF NOT EXISTS idx_hermes_traces_verdict ON hermes_tool_traces(verdict)",
    "CREATE INDEX IF NOT EXISTS idx_hermes_traces_threat ON hermes_tool_traces(threat_id)",
    "CREATE INDEX IF NOT EXISTS idx_hermes_traces_source ON hermes_tool_traces(source)",
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


def preview_value(value: Any, max_bytes: int = DEFAULT_MAX_PREVIEW_BYTES) -> str:
    text = stable_json(value)
    raw = text.encode("utf-8", errors="replace")
    if len(raw) <= max_bytes:
        return text
    clipped = raw[:max_bytes].decode("utf-8", errors="ignore")
    return f"{clipped}…[truncated {len(raw) - max_bytes} bytes]"


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
    explicit = os.environ.get("ASF_HERMES_DB")
    if explicit:
        return Path(explicit).expanduser()

    database_url = os.environ.get("DATABASE_URL")
    if database_url:
        parsed = _sqlite_path_from_url(database_url)
        if parsed is not None:
            return parsed

    asf_root = Path(os.environ.get("ASF_ROOT", Path(__file__).resolve().parent))
    return asf_root / "asf_local.db"


class HermesTraceStore:
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
        agent_id: str,
        hermes_tool_name: str,
        asf_tool_name: str,
        args: Any,
        verdict: str | None = None,
        outcome: str | None = None,
        reason: str | None = None,
        session_id: str | None = None,
        task_id: str | None = None,
        tool_call_id: str | None = None,
        agent_type: str | None = "hermes-agent",
        agent_model: str | None = None,
        stage: str | None = None,
        confidence: float | None = None,
        asf_latency_ms: int | None = None,
        expected_label: str | None = None,
        human_label: str | None = None,
        scenario_id: str | None = None,
        threat_id: str | None = None,
        trace_id: str | None = None,
        audit_hash: str | None = None,
    ) -> str:
        self.ensure_schema()
        now = _utc_now()
        trace_id = trace_id or _make_trace_id(session_id, task_id, tool_call_id, hermes_tool_name, args)
        row_id = uuid.uuid4().hex
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO hermes_tool_traces (
                    id, timestamp, source, agent_id, agent_type, agent_model,
                    session_id, task_id, tool_call_id, hermes_tool_name, asf_tool_name,
                    args_hash, args_preview, verdict, outcome, reason, stage,
                    confidence, asf_latency_ms, expected_label, human_label,
                    scenario_id, threat_id, trace_id, audit_hash, created_at
                ) VALUES (?, ?, 'hermes', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row_id,
                    now,
                    agent_id,
                    agent_type,
                    agent_model,
                    session_id,
                    task_id,
                    tool_call_id,
                    hermes_tool_name,
                    asf_tool_name,
                    sha256_text(args),
                    preview_value(args),
                    verdict,
                    outcome,
                    reason,
                    stage,
                    confidence,
                    asf_latency_ms,
                    expected_label,
                    human_label,
                    scenario_id,
                    threat_id,
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
        task_id: str | None = None,
        trace_id: str | None = None,
        tool_duration_ms: int | None = None,
        side_effect_verified: bool | None = None,
        side_effect_occurred: bool | None = None,
        output_verdict: str | None = None,
        output_reason: str | None = None,
    ) -> int:
        self.ensure_schema()
        where, params = self._lookup_clause(tool_call_id, session_id, task_id, trace_id)
        if not where:
            return 0
        assignments = [
            "output_hash = ?",
            "output_preview = ?",
            "tool_duration_ms = COALESCE(?, tool_duration_ms)",
        ]
        values: list[Any] = [sha256_text(result), preview_value(result), tool_duration_ms]
        if side_effect_verified is not None:
            assignments.append("side_effect_verified = ?")
            values.append(1 if side_effect_verified else 0)
        if side_effect_occurred is not None:
            assignments.append("side_effect_occurred = ?")
            values.append(1 if side_effect_occurred else 0)
        if output_verdict is not None:
            assignments.append("verdict = ?")
            values.append(output_verdict)
        if output_reason is not None:
            assignments.append("reason = COALESCE(reason, '') || ?")
            values.append(f" | output_guard: {output_reason}")
        values.extend(params)
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                f"UPDATE hermes_tool_traces SET {', '.join(assignments)} WHERE {where}",
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
                f"SELECT * FROM hermes_tool_traces {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _lookup_clause(
        tool_call_id: str | None,
        session_id: str | None,
        task_id: str | None,
        trace_id: str | None,
    ) -> tuple[str, list[Any]]:
        if tool_call_id:
            if session_id:
                return "tool_call_id = ? AND session_id = ?", [tool_call_id, session_id]
            return "tool_call_id = ?", [tool_call_id]
        if trace_id:
            return "trace_id = ?", [trace_id]
        if session_id and task_id:
            return "session_id = ? AND task_id = ?", [session_id, task_id]
        return "", []


def _make_trace_id(session_id: str | None, task_id: str | None, tool_call_id: str | None, tool_name: str, args: Any) -> str:
    seed = stable_json(
        {
            "session_id": session_id,
            "task_id": task_id,
            "tool_call_id": tool_call_id,
            "tool_name": tool_name,
            "args_hash": sha256_text(args),
        }
    )
    return f"hermes-{hashlib.sha256(seed.encode()).hexdigest()[:16]}"


def get_default_store() -> HermesTraceStore:
    return HermesTraceStore()
