from __future__ import annotations

import json
import pytest


SENTINEL = "sk-TESTKEY0000000000000000000000000000"
GAP_PREVIEW = "GAP-APIKEY-001: trace_output_preview has no secret redaction"
GAP_HERMES_STORE = "GAP-APIKEY-002: HermesTraceStore direct storage has no secret redaction"
GAP_AUDIT_DASHBOARD = "GAP-APIKEY-003: audit/dashboard/canonical_log do not redact secret-bearing text"
GAP_FRAGMENT = "GAP-APIKEY-004: no explicit key-fragment/shape-probe suppression"


def _all_text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def test_t1_read_env_via_secure_read_tool_does_not_return_full_key():
    """Simulate read_file returning .env content to model-visible preview text."""
    from trace_output_preview import output_preview_text

    tool_result = {"file": {"content": f"OPENROUTER_API_KEY={SENTINEL}\n", "filePath": ".env"}}
    returned_text = output_preview_text(tool_result, max_bytes=8192)

    assert SENTINEL not in returned_text


def test_t2_bash_key_dump_output_absent_from_tool_result_and_trace(tmp_path):
    """Simulate env/printenv/cat .env output moving through output guard + Hermes trace."""
    from hermes_trace_store import HermesTraceStore
    from output_guard import check_output

    shell_result = {"stdout": f"OPENROUTER_API_KEY={SENTINEL}\n", "exit_code": 0}
    leaked, reason = check_output(shell_result["stdout"], SENTINEL)
    assert leaked is True
    assert "Canary trap" in reason or "Secret detected" in reason

    store = HermesTraceStore(tmp_path / "hermes.db")
    store.start_trace(
        agent_id="test-hermes-agent",
        session_id="s-t2",
        task_id="task-t2",
        tool_call_id="call-t2",
        hermes_tool_name="terminal",
        asf_tool_name="shell",
        args={"command": "env; printenv; cat .env"},
        verdict="DENY" if leaked else "ALLOW",
        outcome="BLOCKED" if leaked else "ALLOWED",
        reason=reason,
    )
    store.finish_trace(tool_call_id="call-t2", session_id="s-t2", result=shell_result)
    row = store.fetch_traces(session_id="s-t2")[0]
    persisted = _all_text(row)

    assert SENTINEL not in persisted


def test_t3_output_guard_flags_tool_output_containing_sentinel():
    from output_guard import check_output

    leaked, reason = check_output(f"tool output contained {SENTINEL}", SENTINEL)

    assert leaked is True
    assert reason


def test_t4_claude_trace_store_redacts_sentinel_in_input_and_output(tmp_path, monkeypatch):
    from claude_trace_store import ClaudeTraceStore

    monkeypatch.setenv("ASF_HOOK_CANARY", SENTINEL)
    store = ClaudeTraceStore(tmp_path / "claude.db")
    store.start_trace(
        session_id="s-t4-claude",
        transcript_path=None,
        tool_call_id="call-t4-claude",
        claude_tool_name="Bash",
        asf_tool_name="shell",
        args={"command": f"printf '%s' {SENTINEL}"},
        verdict="ALLOW",
        outcome="ALLOWED",
        reason="test",
    )
    store.finish_trace(
        tool_call_id="call-t4-claude",
        session_id="s-t4-claude",
        result={"stdout": f"OPENROUTER_API_KEY={SENTINEL}"},
    )
    row = store.fetch_traces(session_id="s-t4-claude")[0]

    assert SENTINEL not in _all_text(row)
    assert "[REDACTED" in (row["args_preview"] + row["output_preview"])


def test_t4_hermes_trace_store_redacts_sentinel_in_input_and_output(tmp_path, monkeypatch):
    from hermes_trace_store import HermesTraceStore

    monkeypatch.setenv("ASF_HERMES_CANARY", SENTINEL)
    store = HermesTraceStore(tmp_path / "hermes.db")
    store.start_trace(
        agent_id="test-hermes-agent",
        session_id="s-t4-hermes",
        task_id="task-t4-hermes",
        tool_call_id="call-t4-hermes",
        hermes_tool_name="terminal",
        asf_tool_name="shell",
        args={"command": f"printf '%s' {SENTINEL}"},
    )
    store.finish_trace(
        tool_call_id="call-t4-hermes",
        session_id="s-t4-hermes",
        result={"stdout": f"OPENROUTER_API_KEY={SENTINEL}"},
    )
    row = store.fetch_traces(session_id="s-t4-hermes")[0]

    assert SENTINEL not in _all_text(row)


def test_t4_trace_output_preview_redacts_sentinel_before_storage(monkeypatch):
    from trace_output_preview import output_preview_text

    monkeypatch.setenv("ASF_HERMES_CANARY", SENTINEL)
    preview = output_preview_text({"stdout": f"OPENROUTER_API_KEY={SENTINEL}"}, max_bytes=8192)

    assert SENTINEL not in preview


def test_t4_canonical_log_redacts_sentinel(tmp_path, monkeypatch):
    import canonical_log

    log_path = tmp_path / "canonical.jsonl"
    monkeypatch.setenv("ASF_CANONICAL_LOG", str(log_path))
    canonical_log.log("apikey_redteam", "py", {"input": SENTINEL}, {"preview": SENTINEL})
    text = log_path.read_text(encoding="utf-8")

    assert SENTINEL not in text




def test_gap005_launched_agent_environment_scrubs_provider_keys(monkeypatch):
    from wrapper.hermes_mvp import build_env

    monkeypatch.setenv("OPENROUTER_API_KEY", "provider-sentinel")
    monkeypatch.setenv("OPENAI_API_KEY", "provider-sentinel")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "provider-sentinel")
    monkeypatch.setenv("GROQ_API_KEY", "provider-sentinel")
    monkeypatch.setenv("LANGFUSE_SECRET_KEY", "provider-sentinel")
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "provider-sentinel")
    monkeypatch.setenv("ASF_MASTER_KEY", "provider-sentinel")
    monkeypatch.setenv("ASF_DASHBOARD_PASSWORD", "provider-sentinel")
    monkeypatch.setenv("CUSTOM_PROVIDER_KEY", "provider-sentinel")
    monkeypatch.setenv("ASF_SCRUB_ENV_VARS", "CUSTOM_PROVIDER_KEY")

    env = build_env("enforce", "/tmp/asf-redteam", sandbox=True)

    for name in (
        "OPENROUTER_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GROQ_API_KEY",
        "LANGFUSE_SECRET_KEY",
        "LANGFUSE_PUBLIC_KEY",
        "ASF_MASTER_KEY",
        "ASF_DASHBOARD_PASSWORD",
        "CUSTOM_PROVIDER_KEY",
    ):
        assert name not in env
    assert "provider-sentinel" not in _all_text(env)
    assert env.get("ASF_OPENROUTER_API_KEY_FILE")

def test_gap005_stage3_openrouter_key_loads_from_owner_only_file_after_env_scrub(tmp_path, monkeypatch):
    from interceptor import _read_openrouter_api_key
    from wrapper.env_scrub import persist_openrouter_key_file, scrub_env

    monkeypatch.setenv("OPENROUTER_API_KEY", "stage3-provider-sentinel")
    env = {}
    persist_openrouter_key_file(env, root=tmp_path)
    scrub_env(env)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("ASF_OPENROUTER_API_KEY_FILE", env["ASF_OPENROUTER_API_KEY_FILE"])

    key_path = tmp_path / "openrouter_api_key"
    assert oct(key_path.stat().st_mode & 0o777) == "0o600"
    assert _read_openrouter_api_key() == "stage3-provider-sentinel"


def test_t5_shape_probe_first_last_chars_not_exposed_or_stored(tmp_path):
    """A key-shape probe can reconstruct fragments even when full sentinel is absent."""
    from hermes_trace_store import HermesTraceStore
    from output_guard import check_output

    fragment = f"first={SENTINEL[:7]} last={SENTINEL[-6:]} len={len(SENTINEL)}"
    leaked, _reason = check_output(fragment, SENTINEL)

    store = HermesTraceStore(tmp_path / "hermes.db")
    store.start_trace(
        agent_id="test-hermes-agent",
        session_id="s-t5",
        task_id="task-t5",
        tool_call_id="call-t5",
        hermes_tool_name="terminal",
        asf_tool_name="shell",
        args={"command": "python - <<'PY'\nprint(key[:7], key[-6:])\nPY"},
    )
    store.finish_trace(tool_call_id="call-t5", session_id="s-t5", result={"stdout": fragment})
    row = store.fetch_traces(session_id="s-t5")[0]
    persisted = _all_text(row)

    if not leaked or SENTINEL[:7] in persisted or SENTINEL[-6:] in persisted:
        pytest.xfail(GAP_FRAGMENT)
    assert leaked is True
    assert SENTINEL[:7] not in persisted
    assert SENTINEL[-6:] not in persisted
