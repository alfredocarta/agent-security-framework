import importlib
import sqlite3
import sys
from contextlib import contextmanager
from pathlib import Path


RUNTIME_MODULES = (
    "wrapper.asf_core",
    "registry",
    "audit",
    "hermes_trace_store",
    "claude_trace_store",
    "wrapper.langgraph_mvp",
)


@contextmanager
def fresh_runtime_modules():
    saved_modules = {name: sys.modules.get(name) for name in RUNTIME_MODULES}
    wrapper_pkg = sys.modules.get("wrapper")
    had_wrapper_pkg = wrapper_pkg is not None
    wrapper_attrs = {}
    if wrapper_pkg is not None:
        for attr in ("asf_core", "langgraph_mvp"):
            wrapper_attrs[attr] = (hasattr(wrapper_pkg, attr), getattr(wrapper_pkg, attr, None))

    for name in RUNTIME_MODULES:
        sys.modules.pop(name, None)
    if wrapper_pkg is not None:
        for attr in ("asf_core", "langgraph_mvp"):
            if hasattr(wrapper_pkg, attr):
                delattr(wrapper_pkg, attr)

    try:
        yield
    finally:
        for name in RUNTIME_MODULES:
            sys.modules.pop(name, None)
        for name, module in saved_modules.items():
            if module is not None:
                sys.modules[name] = module
        current_wrapper_pkg = sys.modules.get("wrapper")
        if wrapper_pkg is not None and current_wrapper_pkg is not None:
            for attr, (existed, value) in wrapper_attrs.items():
                if existed:
                    setattr(current_wrapper_pkg, attr, value)
                elif hasattr(current_wrapper_pkg, attr):
                    delattr(current_wrapper_pkg, attr)
        elif not had_wrapper_pkg:
            sys.modules.pop("wrapper", None)


def _table_values(db_path: Path, sql: str) -> list[tuple]:
    with sqlite3.connect(db_path) as conn:
        return conn.execute(sql).fetchall()


def _same_path(left: Path, right: Path) -> bool:
    return left.resolve() == right.resolve()


def test_asf_env_test_routes_registry_audit_and_trace_to_test_db(monkeypatch, tmp_path):
    test_db = tmp_path / "asf_test.db"
    production_db = tmp_path / "asf_local.db"

    monkeypatch.setenv("ASF_ENV", "test")
    monkeypatch.setenv("ASF_ROOT", str(tmp_path))
    monkeypatch.setenv("ASF_TEST_DB", str(test_db))
    monkeypatch.setenv("ASF_LANGGRAPH_AGENT_ID", "env-agent")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("ASF_AGENT_ID", raising=False)
    monkeypatch.delenv("ASF_HERMES_DB", raising=False)

    with fresh_runtime_modules():
        langgraph_mvp = importlib.import_module("wrapper.langgraph_mvp")

        assert langgraph_mvp.asf_core.asf_env() == "test"
        assert langgraph_mvp.agent_id() == "test-env-agent"

        def fake_check(agent_id, tool_name, security_text, session_id=None):
            from audit import AUDITOR

            AUDITOR.log_event(agent_id, tool_name, "ALLOWED", "test allow", session_id=session_id)
            return "ALLOW", "test allow"

        wrapper = langgraph_mvp.AsfLangGraphToolWrapper(
            session_id="env-session",
            task_id="env-task",
            check_fn=fake_check,
        )

        assert wrapper.call_tool("echo", {"text": "ok"}, tool_call_id="env-call") == "echo:ok"

        claude_trace_store = importlib.import_module("claude_trace_store")
        claude_trace_store.get_default_store().start_trace(
            session_id="claude-env-session",
            transcript_path=None,
            tool_call_id="claude-env-call",
            claude_tool_name="Read",
            asf_tool_name="file_read",
            args={"file_path": "sample.txt"},
            verdict="ALLOW",
            outcome="ALLOWED",
            reason="test allow",
        )

    assert test_db.exists()
    assert not production_db.exists()
    assert _table_values(test_db, "SELECT agent_id FROM agents") == [("test-env-agent",)]

    audit_rows = _table_values(
        test_db,
        "SELECT hash, agent_id FROM audit_trail WHERE action = 'echo'",
    )
    trace_rows = _table_values(
        test_db,
        "SELECT agent_id, audit_hash FROM hermes_tool_traces WHERE session_id = 'env-session'",
    )

    assert len(audit_rows) == 1
    assert trace_rows == [("test-env-agent", audit_rows[0][0])]
    assert _table_values(
        test_db,
        "SELECT agent_id FROM claude_tool_traces WHERE session_id = 'claude-env-session'",
    ) == [("test-claude-code-agent",)]


def test_asf_env_test_ignores_database_url_but_still_namespaces(monkeypatch, tmp_path):
    explicit_db = tmp_path / "explicit.db"
    test_db = tmp_path / "asf_test.db"

    monkeypatch.setenv("ASF_ENV", "test")
    monkeypatch.setenv("ASF_ROOT", str(tmp_path))
    monkeypatch.setenv("ASF_TEST_DB", str(test_db))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{explicit_db}")
    monkeypatch.delenv("ASF_AGENT_ID", raising=False)
    monkeypatch.delenv("ASF_LANGGRAPH_AGENT_ID", raising=False)
    monkeypatch.delenv("ASF_HERMES_DB", raising=False)

    with fresh_runtime_modules():
        langgraph_mvp = importlib.import_module("wrapper.langgraph_mvp")

        def fake_check(agent_id, tool_name, security_text, session_id=None):
            from audit import AUDITOR

            AUDITOR.log_event(agent_id, tool_name, "ALLOWED", "explicit allow", session_id=session_id)
            return "ALLOW", "explicit allow"

        wrapper = langgraph_mvp.AsfLangGraphToolWrapper(
            agent="explicit-agent",
            session_id="explicit-session",
            task_id="explicit-task",
            check_fn=fake_check,
        )
        wrapper.call_tool("echo", {"text": "ok"}, tool_call_id="explicit-call")

    assert test_db.exists()
    assert not explicit_db.exists()
    assert _table_values(test_db, "SELECT agent_id FROM agents") == [("test-explicit-agent",)]
    assert _table_values(
        test_db,
        "SELECT agent_id FROM hermes_tool_traces WHERE session_id = 'explicit-session'",
    ) == [("test-explicit-agent",)]


def test_claude_trace_two_phase_test_mode_uses_same_db_without_client_env(monkeypatch, tmp_path):
    test_db = tmp_path / "asf_test.db"
    local_db = tmp_path / "asf_local.db"
    state_file = tmp_path / "asf_env"
    state_file.write_text("test\n", encoding="utf-8")

    monkeypatch.setenv("ASF_ENV_STATE_FILE", str(state_file))
    monkeypatch.setenv("ASF_ENV", "test")
    monkeypatch.setenv("ASF_ROOT", str(tmp_path))
    monkeypatch.setenv("ASF_TEST_DB", str(test_db))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{local_db}")
    monkeypatch.delenv("ASF_HOOK_DB", raising=False)

    payload = {
        "session_id": "two-phase-session",
        "tool_call_id": "toolu_two_phase_001",
        "tool_name": "Bash",
        "tool_input": {"command": "printf done"},
        "tool_response": "done from client",
    }

    with fresh_runtime_modules():
        claude_trace_store = importlib.import_module("claude_trace_store")
        asf_core = importlib.import_module("wrapper.asf_core")

        assert asf_core.asf_env() == "test"
        assert _same_path(claude_trace_store.resolve_db_path(), test_db)

        daemon_tool_call_id = claude_trace_store.make_tool_call_id(
            payload,
            payload["tool_name"],
            payload["tool_input"],
        )
        assert daemon_tool_call_id == "toolu_two_phase_001"

        claude_trace_store.get_default_store().start_trace(
            session_id=payload["session_id"],
            transcript_path=None,
            tool_call_id=daemon_tool_call_id,
            claude_tool_name=payload["tool_name"],
            asf_tool_name="shell",
            args=payload["tool_input"],
            verdict="ALLOW",
            outcome="ALLOWED",
            reason="ok",
        )

    monkeypatch.delenv("ASF_ENV", raising=False)

    with fresh_runtime_modules():
        claude_trace_store = importlib.import_module("claude_trace_store")
        asf_core = importlib.import_module("wrapper.asf_core")

        assert asf_core.asf_env() == "test"
        assert _same_path(claude_trace_store.resolve_db_path(), test_db)

        client_tool_call_id = claude_trace_store.make_tool_call_id(
            payload,
            payload["tool_name"],
            payload["tool_input"],
        )
        assert client_tool_call_id == daemon_tool_call_id
        assert client_tool_call_id.startswith("toolu_")

        updated = claude_trace_store.get_default_store().finish_trace(
            result=payload["tool_response"],
            tool_call_id=client_tool_call_id,
            session_id=payload["session_id"],
        )

    assert updated == 1
    assert not local_db.exists()
    assert _table_values(
        test_db,
        "SELECT tool_call_id, session_id, output_preview FROM claude_tool_traces",
    ) == [("toolu_two_phase_001", "two-phase-session", "done from client")]


def test_asf_env_state_file_fallback_routes_claude_trace_to_test_db(monkeypatch, tmp_path):
    test_db = tmp_path / "asf_test.db"
    local_db = tmp_path / "asf_local.db"
    state_file = tmp_path / "asf_env"
    state_file.write_text("test\n", encoding="utf-8")

    monkeypatch.delenv("ASF_ENV", raising=False)
    monkeypatch.setenv("ASF_ENV_STATE_FILE", str(state_file))
    monkeypatch.setenv("ASF_ROOT", str(tmp_path))
    monkeypatch.setenv("ASF_TEST_DB", str(test_db))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{local_db}")
    monkeypatch.delenv("ASF_HOOK_DB", raising=False)

    with fresh_runtime_modules():
        claude_trace_store = importlib.import_module("claude_trace_store")
        asf_core = importlib.import_module("wrapper.asf_core")

        assert asf_core.asf_env() == "test"
        assert asf_core.effective_database_url(production_db_path=local_db) == f"sqlite:///{test_db}"
        assert _same_path(claude_trace_store.resolve_db_path(), test_db)

        claude_trace_store.get_default_store().start_trace(
            session_id="state-session",
            transcript_path=None,
            tool_call_id="toolu_state_001",
            claude_tool_name="Read",
            asf_tool_name="file_read",
            args={"file_path": "sample.txt"},
            verdict="ALLOW",
            outcome="ALLOWED",
            reason="ok",
        )

    with fresh_runtime_modules():
        claude_trace_store = importlib.import_module("claude_trace_store")
        assert _same_path(claude_trace_store.resolve_db_path(), test_db)
        updated = claude_trace_store.get_default_store().finish_trace(
            result={"content": "file contents"},
            tool_call_id="toolu_state_001",
            session_id="state-session",
        )

    assert updated == 1
    assert not local_db.exists()
    assert _table_values(
        test_db,
        "SELECT output_preview FROM claude_tool_traces WHERE tool_call_id = 'toolu_state_001'",
    ) == [("file contents",)]


def test_claude_trace_test_mode_respects_hook_db_override(monkeypatch, tmp_path):
    test_db = tmp_path / "asf_test.db"
    hook_db = tmp_path / "hook_override.db"
    local_db = tmp_path / "asf_local.db"

    monkeypatch.setenv("ASF_ENV", "test")
    monkeypatch.setenv("ASF_ROOT", str(tmp_path))
    monkeypatch.setenv("ASF_TEST_DB", str(test_db))
    monkeypatch.setenv("ASF_HOOK_DB", str(hook_db))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{local_db}")

    with fresh_runtime_modules():
        claude_trace_store = importlib.import_module("claude_trace_store")

        assert _same_path(claude_trace_store.resolve_db_path(), hook_db)
        claude_trace_store.get_default_store().start_trace(
            session_id="override-session",
            transcript_path=None,
            tool_call_id="toolu_override_001",
            claude_tool_name="Read",
            asf_tool_name="file_read",
            args={"file_path": "override.txt"},
            verdict="ALLOW",
            outcome="ALLOWED",
            reason="ok",
        )
        updated = claude_trace_store.get_default_store().finish_trace(
            result="override contents",
            tool_call_id="toolu_override_001",
            session_id="override-session",
        )

    assert updated == 1
    assert hook_db.exists()
    assert not test_db.exists()
    assert not local_db.exists()
    assert _table_values(
        hook_db,
        "SELECT output_preview FROM claude_tool_traces WHERE tool_call_id = 'toolu_override_001'",
    ) == [("override contents",)]


def test_asf_env_test_prefixes_hermes_agent_id_idempotently(monkeypatch):
    monkeypatch.setenv("ASF_ENV", "test")
    monkeypatch.delenv("ASF_AGENT_ID", raising=False)
    monkeypatch.delenv("ASF_HERMES_AGENT_ID", raising=False)

    with fresh_runtime_modules():
        plugin_path = Path(__file__).resolve().parents[1] / "integrations" / "hermes" / "asf_tracker_plugin.py"
        spec = importlib.util.spec_from_file_location("asf_tracker_plugin_env_test", plugin_path)
        plugin = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(plugin)

        assert plugin._agent_id() == "test-hermes-live-agent"

        monkeypatch.setenv("ASF_HERMES_AGENT_ID", "specific-hermes-agent")
        assert plugin._agent_id() == "test-specific-hermes-agent"

        monkeypatch.setenv("ASF_HERMES_AGENT_ID", "test-specific-hermes-agent")
        assert plugin._agent_id() == "test-specific-hermes-agent"


def test_asf_env_unset_preserves_production_defaults(monkeypatch, tmp_path):
    state_file = tmp_path / "missing_asf_env"
    explicit_db = tmp_path / "explicit_production.db"
    production_db = tmp_path / "asf_local.db"

    monkeypatch.delenv("ASF_ENV", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("ASF_AGENT_ID", raising=False)
    monkeypatch.delenv("ASF_LANGGRAPH_AGENT_ID", raising=False)
    monkeypatch.setenv("ASF_ENV_STATE_FILE", str(state_file))

    with fresh_runtime_modules():
        asf_core = importlib.import_module("wrapper.asf_core")
        langgraph_mvp = importlib.import_module("wrapper.langgraph_mvp")

        assert asf_core.asf_env() == "production"
        assert asf_core.effective_database_url(production_db_path=production_db) == f"sqlite:///{production_db}"
        monkeypatch.setenv("DATABASE_URL", f"sqlite:///{explicit_db}")
        assert asf_core.effective_database_url(production_db_path=production_db) == f"sqlite:///{explicit_db}"
        assert langgraph_mvp.agent_id() == asf_core.DEFAULT_AGENT_ID

        monkeypatch.setenv("ASF_LANGGRAPH_AGENT_ID", "specific-langgraph-agent")
        assert langgraph_mvp.agent_id() == "specific-langgraph-agent"

        monkeypatch.setenv("ASF_AGENT_ID", "shared-agent")
        assert langgraph_mvp.agent_id() == "shared-agent"
