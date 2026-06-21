import importlib
import io
import json
import os
import sqlite3
import sys
from pathlib import Path

import pytest


class _Stdin:
    def __init__(self, payload):
        self.buffer = io.BytesIO(json.dumps(payload).encode())


def _load_hook(monkeypatch, monitor_only="true", fail_closed="false"):
    monkeypatch.setenv("ASF_HOOK_MONITOR_ONLY", monitor_only)
    monkeypatch.setenv("ASF_HOOK_FAIL_CLOSED", fail_closed)
    sys.modules.pop("asf_hook", None)
    import asf_hook

    return importlib.reload(asf_hook)


def _run_main(monkeypatch, hook, payload):
    monkeypatch.setattr(hook, "_init_runtime_dir", lambda: None)
    monkeypatch.setattr(sys, "stdin", _Stdin(payload))
    with pytest.raises(SystemExit) as exc:
        hook.main()
    return exc.value.code


def test_claude_hook_pretooluse_defers_enforcement_to_rust_hook(monkeypatch):
    hook = _load_hook(monkeypatch, monitor_only="false")
    ensure_calls = []

    # PreToolUse enforcement moved to asf-rust-hook; Python only warms its daemon.
    monkeypatch.setattr(hook, "ensure_daemon", lambda: ensure_calls.append(True))
    monkeypatch.setattr(
        hook,
        "query_daemon",
        lambda *args, **kwargs: pytest.fail("PreToolUse should not query the Python daemon"),
    )

    code = _run_main(
        monkeypatch,
        hook,
        {"tool_name": "Bash", "tool_input": {"command": "python build.py"}, "session_id": "s1"},
    )

    assert code == 0
    assert ensure_calls == [True]


def test_claude_daemon_persists_pretool_input(tmp_path, monkeypatch):
    db_path = tmp_path / "daemon.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("ASF_HOOK_DB", str(db_path))
    # Reloading registry/audit rebinds their engines to this throwaway DB. Snapshot the
    # original modules and restore sys.modules afterwards; otherwise later tests (and the
    # already-imported interceptor, which keeps the original registry) end up with a
    # split-brain registry pointing at this temp DB and start denying everything.
    reloaded = ("asf_hook_daemon", "registry", "audit")
    saved = {name: sys.modules.get(name) for name in reloaded}
    for module_name in reloaded:
        sys.modules.pop(module_name, None)
    try:
        import asf_hook_daemon

        importlib.reload(asf_hook_daemon)
        monkeypatch.setattr(asf_hook_daemon, "hardened_interceptor", lambda agent_id, tool, text: ("ALLOW", "ok"))

        left, right = __import__("socket").socketpair()
        asf_hook_daemon._client_slots.acquire()
        try:
            payload = {
                "tool": "shell",
                "input": "python work.py --password=SECRET123456",
                "tool_name": "Bash",
                "tool_input": {"command": "python work.py --password=SECRET123456"},
                "tool_call_id": "call-pre-1",
                "session_id": "session-pre",
            }
            right.sendall((json.dumps(payload) + "\n").encode())
            right.shutdown(__import__("socket").SHUT_WR)
            asf_hook_daemon.handle_client(left)
            response = json.loads(right.recv(4096).decode().strip())
        finally:
            right.close()

        assert response["verdict"] == "ALLOW"
        with sqlite3.connect(db_path) as conn:
            row = conn.execute("SELECT args_preview, args_hash FROM claude_tool_traces WHERE tool_call_id = 'call-pre-1'").fetchone()
        assert row is not None
        assert row[1]
        assert "SECRET123456" not in row[0]
        assert "[REDACTED_SECRET]" in row[0]
    finally:
        for name, mod in saved.items():
            if mod is not None:
                sys.modules[name] = mod
            else:
                sys.modules.pop(name, None)


def test_claude_hook_post_tool_use_persists_output(tmp_path, monkeypatch):
    db_path = tmp_path / "claude.db"
    monkeypatch.setenv("ASF_HOOK_DB", str(db_path))
    hook = _load_hook(monkeypatch, monitor_only="true")
    from claude_trace_store import get_default_store, make_tool_call_id

    payload = {
        "session_id": "s-output",
        "tool_name": "Bash",
        "tool_input": {"command": "python work.py --api_key=SECRET123456"},
        "tool_response": "done token=SECRET123456",
    }
    tool_call_id = make_tool_call_id(payload, "Bash", payload["tool_input"])
    get_default_store().start_trace(
        session_id="s-output",
        transcript_path=None,
        tool_call_id=tool_call_id,
        claude_tool_name="Bash",
        asf_tool_name="shell",
        args=payload["tool_input"],
        verdict="ALLOW",
        outcome="ALLOWED",
        reason="ok",
        audit_hash="audit-1",
    )

    code = _run_main(monkeypatch, hook, {**payload, "hook_event_name": "PostToolUse"})

    assert code == 0
    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT args_preview, output_preview, output_hash FROM claude_tool_traces").fetchone()
    assert row is not None
    assert row[2]
    assert "SECRET123456" not in row[0]
    assert "SECRET123456" not in row[1]
    assert "[REDACTED_SECRET]" in row[1]
