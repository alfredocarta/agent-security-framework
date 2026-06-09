import json
import time
from pathlib import Path

import pytest

from wrapper import langgraph_mvp
from hermes_trace_store import HermesTraceStore


def _store_rows(db_path, session_id="lg-session"):
    return HermesTraceStore(db_path).fetch_traces(session_id=session_id, limit=20)


def test_langgraph_malicious_tool_is_blocked_without_execution(monkeypatch, tmp_path):
    db_path = tmp_path / "trace.db"
    side_effect = tmp_path / "should-not-exist.txt"
    monkeypatch.setenv("ASF_HERMES_DB", str(db_path))
    monkeypatch.setenv("ASF_LANGGRAPH_MODE", "enforce")

    wrapper = langgraph_mvp.AsfLangGraphToolWrapper(
        agent="langgraph-test-agent",
        session_id="lg-session",
        task_id="deny-task",
        check_fn=lambda *args: ("DENY", "test deny"),
    )

    with pytest.raises(langgraph_mvp.ToolBlocked):
        wrapper.call_tool("terminal", {"command": f"touch {side_effect}"}, tool_call_id="deny-call")

    assert not side_effect.exists()
    rows = _store_rows(db_path)
    assert len(rows) == 1
    assert rows[0]["agent_type"] == "langgraph-agent"
    assert rows[0]["verdict"] == "DENY"
    assert rows[0]["output_preview"] is None


def test_langgraph_benign_tool_proceeds_and_correlates_output(monkeypatch, tmp_path):
    db_path = tmp_path / "trace.db"
    monkeypatch.setenv("ASF_HERMES_DB", str(db_path))
    monkeypatch.setenv("ASF_LANGGRAPH_MODE", "enforce")

    wrapper = langgraph_mvp.AsfLangGraphToolWrapper(
        agent="langgraph-test-agent",
        session_id="lg-session",
        task_id="allow-task",
        check_fn=lambda *args: ("ALLOW", "test allow"),
    )

    result = wrapper.call_tool("echo", {"text": "hello"}, tool_call_id="allow-call")

    assert result == "echo:hello"
    rows = _store_rows(db_path)
    assert len(rows) == 1
    row = rows[0]
    assert row["tool_call_id"] == "allow-call"
    assert row["hermes_tool_name"] == "echo"
    assert row["verdict"] == "ALLOW"
    assert "hello" in row["args_preview"]
    assert "echo:hello" in row["output_preview"]


def test_langgraph_hitl_waits_and_times_out(monkeypatch, tmp_path):
    db_path = tmp_path / "trace.db"
    monkeypatch.setenv("ASF_HERMES_DB", str(db_path))
    monkeypatch.setenv("ASF_LANGGRAPH_MODE", "enforce")
    monkeypatch.setenv("ASF_HERMES_HITL_TIMEOUT", "0.02")
    monkeypatch.setenv("ASF_HERMES_HITL_POLL_MS", "1")
    monkeypatch.setenv("ASF_HERMES_HITL_ON_TIMEOUT", "block")

    def fake_hitl(agent_id, tool_name, security_text, session_id=None):
        from audit import AUDITOR

        AUDITOR.log_event(agent_id, tool_name, "HITL_REQUESTED", "langgraph HITL", session_id=session_id)
        return "HITL", "langgraph HITL"

    wrapper = langgraph_mvp.AsfLangGraphToolWrapper(
        agent="langgraph-test-agent",
        session_id="lg-session",
        task_id="hitl-task",
        check_fn=fake_hitl,
    )

    start = time.monotonic()
    with pytest.raises(langgraph_mvp.ToolBlocked) as excinfo:
        wrapper.call_tool("echo", {"text": "needs review"}, tool_call_id="hitl-call")

    assert time.monotonic() - start >= 0.015
    assert "timeout" in str(excinfo.value).lower()
    rows = _store_rows(db_path)
    assert len(rows) == 1
    assert rows[0]["verdict"] == "HITL"
    assert rows[0]["audit_hash"]
    assert rows[0]["output_preview"] is None


def test_langgraph_shell_tool_uses_sandbox_when_enabled(monkeypatch, tmp_path):
    db_path = tmp_path / "trace.db"
    side_effect = tmp_path / "outside.txt"
    monkeypatch.setenv("ASF_HERMES_DB", str(db_path))
    monkeypatch.setenv("ASF_LANGGRAPH_MODE", "enforce")
    monkeypatch.setenv("ASF_HERMES_SANDBOX", "true")
    monkeypatch.setenv("ASF_HERMES_SANDBOX_WORKDIR", str(tmp_path / "sandbox"))

    def fake_sandbox(args, *, asf_root):
        assert "touch" in args["command"]
        return json.dumps({"output": "blocked by fake sandbox", "exit_code": 1, "sandboxed": True})

    monkeypatch.setattr(langgraph_mvp.asf_core, "sandbox_terminal", fake_sandbox)
    wrapper = langgraph_mvp.AsfLangGraphToolWrapper(
        agent="langgraph-test-agent",
        session_id="lg-session",
        task_id="sandbox-task",
        check_fn=lambda *args: ("ALLOW", "test allow"),
    )

    result = wrapper.call_tool("terminal", {"command": f"touch {side_effect}"}, tool_call_id="sandbox-call")

    assert result["sandboxed"] is True
    assert result["exit_code"] == 1
    assert not side_effect.exists()
    rows = _store_rows(db_path)
    assert rows[0]["output_preview"]
    assert "sandboxed" in rows[0]["output_preview"]


def test_langgraph_demo_graph_blocks_tool(monkeypatch, tmp_path):
    pytest.importorskip("langgraph")
    db_path = tmp_path / "trace.db"
    side_effect = tmp_path / "graph-denied.txt"
    monkeypatch.setenv("ASF_HERMES_DB", str(db_path))
    monkeypatch.setenv("ASF_LANGGRAPH_MODE", "enforce")
    monkeypatch.setattr(langgraph_mvp, "run_asf_check", lambda *args, **kwargs: ("DENY", "graph deny"))

    app = langgraph_mvp.build_demo_graph()
    result = app.invoke(
        {
            "agent_id": "langgraph-test-agent",
            "tool_name": "terminal",
            "args": {"command": f"touch {side_effect}"},
            "session_id": "lg-session",
            "task_id": "graph-task",
            "tool_call_id": "graph-call",
        }
    )

    assert "error" in result
    assert "BLOCKED" in result["error"]
    assert not side_effect.exists()
