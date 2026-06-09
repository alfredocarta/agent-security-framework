import json
from pathlib import Path



def test_insert_and_update_hermes_tool_trace(tmp_path):
    from hermes_trace_store import HermesTraceStore, sha256_text

    db_path = tmp_path / "asf_test.db"
    store = HermesTraceStore(db_path)

    trace_id = store.start_trace(
        agent_id="hermes-live-agent",
        session_id="session-1",
        task_id="task-1",
        tool_call_id="call-1",
        hermes_tool_name="terminal",
        asf_tool_name="shell",
        args={"command": "pwd"},
        verdict="ALLOW",
        outcome="ALLOWED",
        reason="benign command",
        asf_latency_ms=12,
        stage="Stage 1",
        confidence=0.99,
    )

    rows = store.fetch_traces(session_id="session-1")
    assert len(rows) == 1
    row = rows[0]
    assert row["trace_id"] == trace_id
    assert row["source"] == "hermes"
    assert row["hermes_tool_name"] == "terminal"
    assert row["asf_tool_name"] == "shell"
    assert row["args_hash"]
    assert "pwd" in row["args_preview"]
    assert row["verdict"] == "ALLOW"
    assert row["asf_latency_ms"] == 12

    store.finish_trace(
        tool_call_id="call-1",
        session_id="session-1",
        result={"output": "/Users/alfredo"},
        tool_duration_ms=34,
        side_effect_verified=True,
        side_effect_occurred=False,
    )

    updated = store.fetch_traces(session_id="session-1")[0]
    assert updated["output_hash"]
    assert updated["output_hash"] == sha256_text({"output": "/Users/alfredo"})
    assert updated["output_preview"] == "/Users/alfredo"
    assert updated["tool_duration_ms"] == 34
    assert updated["side_effect_verified"] == 1
    assert updated["side_effect_occurred"] == 0


def test_get_default_store_uses_asf_sqlite_url(monkeypatch, tmp_path):
    from hermes_trace_store import get_default_store

    db_path = tmp_path / "from_env.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    store = get_default_store()
    store.ensure_schema()

    assert db_path.exists()


def test_identical_traces_without_tool_call_id_get_unique_trace_ids(tmp_path):
    from hermes_trace_store import HermesTraceStore

    store = HermesTraceStore(tmp_path / "asf_test.db")
    args = {"command": "printf same"}

    first = store.start_trace(
        agent_id="hermes-live-agent",
        session_id="session-1",
        task_id="task-1",
        tool_call_id=None,
        hermes_tool_name="terminal",
        asf_tool_name="shell",
        args=args,
        verdict="ALLOW",
        outcome="ALLOWED",
        reason="first",
    )
    second = store.start_trace(
        agent_id="hermes-live-agent",
        session_id="session-1",
        task_id="task-1",
        tool_call_id=None,
        hermes_tool_name="terminal",
        asf_tool_name="shell",
        args=args,
        verdict="ALLOW",
        outcome="ALLOWED",
        reason="second",
    )

    assert first != second
    rows = store.fetch_traces(session_id="session-1", limit=10)
    assert {row["trace_id"] for row in rows} == {first, second}


def _stored_output_preview(tmp_path, result):
    from hermes_trace_store import HermesTraceStore

    store = HermesTraceStore(tmp_path / "asf_test.db")
    store.start_trace(
        agent_id="hermes-live-agent",
        session_id="session-output",
        task_id="task-output",
        tool_call_id="call-output",
        hermes_tool_name="terminal",
        asf_tool_name="shell",
        args={"command": "run"},
    )
    store.finish_trace(tool_call_id="call-output", session_id="session-output", result=result)
    return store.fetch_traces(session_id="session-output")[0]


def test_output_preview_unwraps_output_dict_without_json_wrapper(tmp_path):
    from hermes_trace_store import sha256_text

    result = {"output": "plain tool output"}
    row = _stored_output_preview(tmp_path, result)

    assert row["output_preview"] == "plain tool output"
    assert row["output_hash"] == sha256_text(result)


def test_output_preview_unwraps_double_encoded_json_string(tmp_path):
    from hermes_trace_store import sha256_text

    result = json.dumps(json.dumps({"output": "double encoded output"}))
    row = _stored_output_preview(tmp_path, result)

    assert row["output_preview"] == "double encoded output"
    assert row["output_hash"] == sha256_text(result)


def test_output_preview_formats_stdout_stderr_envelope(tmp_path):
    from hermes_trace_store import sha256_text

    result = {"stdout": "normal output", "stderr": "warning output", "exit_code": 2}
    row = _stored_output_preview(tmp_path, result)

    assert row["output_preview"] == "normal output\nstderr: warning output\nexit_code: 2"
    assert row["output_hash"] == sha256_text(result)


def test_output_preview_keeps_plain_string_as_is(tmp_path):
    from hermes_trace_store import sha256_text

    result = "already plain output"
    row = _stored_output_preview(tmp_path, result)

    assert row["output_preview"] == "already plain output"
    assert row["output_hash"] == sha256_text(result)


def test_output_preview_truncates_plain_text_after_unwrapping():
    from hermes_trace_store import output_preview_text

    result = {"output": "abcdef"}

    assert output_preview_text(result, max_bytes=3) == "abc…[truncated 3 bytes]"
