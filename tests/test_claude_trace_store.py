import json


def _stored_claude_output_preview(tmp_path, result):
    from claude_trace_store import ClaudeTraceStore

    store = ClaudeTraceStore(tmp_path / "claude_test.db")
    store.start_trace(
        session_id="session-claude",
        transcript_path=None,
        tool_call_id="call-claude",
        claude_tool_name="Read",
        asf_tool_name="file_read",
        args={"file_path": "sample.txt"},
        verdict="ALLOW",
        outcome="ALLOWED",
        reason="ok",
    )
    store.finish_trace(tool_call_id="call-claude", session_id="session-claude", result=result)
    return store.fetch_traces(session_id="session-claude")[0]


def test_claude_output_preview_extracts_read_file_content(tmp_path):
    from claude_trace_store import redact_value, sha256_text

    result = {"file": {"content": "file body", "filePath": "sample.txt", "numLines": 1}, "type": "text"}
    row = _stored_claude_output_preview(tmp_path, result)

    assert row["output_preview"] == "file body"
    assert row["output_hash"] == sha256_text(redact_value(result))


def test_claude_output_preview_extracts_top_level_content(tmp_path):
    from claude_trace_store import redact_value, sha256_text

    result = {"content": "top-level content", "type": "text"}
    row = _stored_claude_output_preview(tmp_path, result)

    assert row["output_preview"] == "top-level content"
    assert row["output_hash"] == sha256_text(redact_value(result))


def test_claude_output_preview_unwraps_output_dict(tmp_path):
    from claude_trace_store import redact_value, sha256_text

    result = {"output": "plain output"}
    row = _stored_claude_output_preview(tmp_path, result)

    assert row["output_preview"] == "plain output"
    assert row["output_hash"] == sha256_text(redact_value(result))


def test_claude_output_preview_formats_stdout_stderr(tmp_path):
    from claude_trace_store import redact_value, sha256_text

    result = {"stdout": "normal", "stderr": "warn", "exit_code": 3}
    row = _stored_claude_output_preview(tmp_path, result)

    assert row["output_preview"] == "normal\nstderr: warn\nexit_code: 3"
    assert row["output_hash"] == sha256_text(redact_value(result))


def test_claude_output_preview_keeps_plain_string(tmp_path):
    from claude_trace_store import redact_value, sha256_text

    result = "plain string"
    row = _stored_claude_output_preview(tmp_path, result)

    assert row["output_preview"] == "plain string"
    assert row["output_hash"] == sha256_text(redact_value(result))


def test_claude_output_preview_unknown_dict_uses_pretty_json(tmp_path):
    from claude_trace_store import redact_value, sha256_text

    result = {"z": 1, "a": {"b": 2}}
    row = _stored_claude_output_preview(tmp_path, result)

    assert row["output_preview"] == '{\n  "a": {\n    "b": 2\n  },\n  "z": 1\n}'
    assert row["output_hash"] == sha256_text(redact_value(result))


def test_claude_output_preview_unwraps_double_encoded_json_string(tmp_path):
    from claude_trace_store import redact_value, sha256_text

    result = json.dumps(json.dumps({"file": {"content": "double file body"}}))
    row = _stored_claude_output_preview(tmp_path, result)

    assert row["output_preview"] == "double file body"
    assert row["output_hash"] == sha256_text(redact_value(result))


def test_claude_output_preview_truncates_after_extraction():
    from claude_trace_store import output_preview_text

    assert output_preview_text({"file": {"content": "abcdef"}}, max_bytes=3) == "abc…[truncated 3 bytes]"


def test_claude_output_preview_uses_redacted_result_for_hash_and_preview(tmp_path):
    from claude_trace_store import redact_value, sha256_text

    result = {"content": "api_key=supersecretvalue"}
    row = _stored_claude_output_preview(tmp_path, result)
    redacted = redact_value(result)

    assert row["output_preview"] == "[REDACTED_SECRET]"
    assert row["output_hash"] == sha256_text(redacted)
    assert row["output_hash"] != sha256_text(result)
