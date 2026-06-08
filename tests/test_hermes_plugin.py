import importlib.util
import json
import shutil
from pathlib import Path

import pytest


# The Hermes plugin is vendored in-repo as the source of truth; the test loads the repo
# copy so CI exercises the version-controlled code (not whatever happens to be installed).
# The deployed copy under the user's Hermes home is what runs in production and must stay
# identical, which test_repo_and_deployed_plugin_in_sync asserts.
REPO_PLUGIN_PATH = Path(__file__).resolve().parents[1] / "integrations" / "hermes" / "asf_tracker_plugin.py"
DEPLOYED_PLUGIN_PATH = Path.home() / ".hermes" / "plugins" / "asf-tracker" / "__init__.py"


def load_plugin_module():
    if not REPO_PLUGIN_PATH.exists():
        pytest.skip(f"Vendored Hermes plugin not present at {REPO_PLUGIN_PATH}")
    spec = importlib.util.spec_from_file_location("asf_tracker_plugin", REPO_PLUGIN_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_repo_and_deployed_plugin_in_sync():
    if not DEPLOYED_PLUGIN_PATH.exists():
        pytest.skip(f"No deployed plugin at {DEPLOYED_PLUGIN_PATH} to compare against")
    assert REPO_PLUGIN_PATH.read_text() == DEPLOYED_PLUGIN_PATH.read_text(), (
        "Vendored plugin and deployed ~/.hermes plugin have drifted; re-sync them "
        "(the in-repo copy is the source of truth)."
    )


def test_normalize_tool_name_and_security_text():
    plugin = load_plugin_module()

    assert plugin.normalize_tool_name("terminal") == "shell"
    assert plugin.normalize_tool_name("browser_navigate") == "browser"
    assert plugin.normalize_tool_name("delegate_task") == "delegation"

    text = plugin.build_security_text("terminal", {"command": "cat ~/.hermes/.env"})
    assert "tool=terminal" in text
    assert "asf_tool=shell" in text
    assert "cat ~/.hermes/.env" in text


def test_pre_hook_monitor_records_allow_without_blocking(monkeypatch, tmp_path):
    plugin = load_plugin_module()

    db_path = tmp_path / "trace.db"
    monkeypatch.setenv("ASF_HERMES_DB", str(db_path))
    monkeypatch.setenv("ASF_HERMES_MODE", "monitor")
    monkeypatch.setenv("ASF_HERMES_AGENT_ID", "hermes-live-agent")

    calls = []

    def fake_check(agent_id, tool_name, security_text, session_id=None):
        calls.append((agent_id, tool_name, security_text, session_id))
        return "ALLOW", "test allow"

    monkeypatch.setattr(plugin, "run_asf_check", fake_check)

    result = plugin.on_pre_tool_call(
        tool_name="terminal",
        args={"command": "pwd"},
        task_id="task-1",
        session_id="session-1",
        tool_call_id="call-1",
    )

    assert result is None
    assert calls[0][0] == "hermes-live-agent"
    assert calls[0][1] == "shell"

    from hermes_trace_store import HermesTraceStore
    rows = HermesTraceStore(db_path).fetch_traces(session_id="session-1")
    assert len(rows) == 1
    assert rows[0]["tool_call_id"] == "call-1"
    assert rows[0]["verdict"] == "ALLOW"


def test_post_hook_persists_redacted_output_preview(monkeypatch, tmp_path):
    plugin = load_plugin_module()

    db_path = tmp_path / "trace.db"
    monkeypatch.setenv("ASF_HERMES_DB", str(db_path))
    monkeypatch.setenv("ASF_HERMES_MODE", "monitor")
    monkeypatch.setenv("ASF_HERMES_AGENT_ID", "hermes-live-agent")
    monkeypatch.setenv("ASF_HERMES_MAX_PREVIEW_BYTES", "120")

    monkeypatch.setattr(plugin, "run_asf_check", lambda *args, **kwargs: ("ALLOW", "test allow"))
    plugin.on_pre_tool_call(
        tool_name="terminal",
        args={"command": "printf ok", "token": "secret=supersecretvalue"},
        task_id="task-1",
        session_id="session-1",
        tool_call_id="call-output",
    )
    plugin.on_post_tool_call(
        tool_name="terminal",
        output={"stdout": "ok", "token": "api_key=abcdef1234567890"},
        task_id="task-1",
        session_id="session-1",
        tool_call_id="call-output",
        duration_ms=12,
    )

    from hermes_trace_store import HermesTraceStore
    rows = HermesTraceStore(db_path).fetch_traces(session_id="session-1")
    assert len(rows) == 1
    assert rows[0]["output_preview"]
    assert rows[0]["output_hash"]
    assert rows[0]["tool_duration_ms"] == 12
    assert "[REDACTED_SECRET]" in rows[0]["output_preview"]
    assert "abcdef1234567890" not in rows[0]["output_preview"]
    assert "supersecretvalue" not in rows[0]["args_preview"]


def test_post_hook_correlates_output_without_tool_call_id(monkeypatch, tmp_path):
    plugin = load_plugin_module()

    db_path = tmp_path / "trace.db"
    monkeypatch.setenv("ASF_HERMES_DB", str(db_path))
    monkeypatch.setenv("ASF_HERMES_MODE", "monitor")
    monkeypatch.setenv("ASF_HERMES_AGENT_ID", "hermes-live-agent")

    monkeypatch.setattr(plugin, "run_asf_check", lambda *args, **kwargs: ("ALLOW", "test allow"))
    args_one = {"command": "printf one"}
    args_two = {"command": "printf two"}
    plugin.on_pre_tool_call(tool_name="terminal", args=args_one, task_id="task-shared")
    plugin.on_pre_tool_call(tool_name="terminal", args=args_two, task_id="task-shared")

    plugin.on_post_tool_call(
        tool_name="terminal",
        args=args_one,
        result={"stdout": "one"},
        task_id="task-shared",
        duration_ms=7,
    )

    from hermes_trace_store import HermesTraceStore
    rows = HermesTraceStore(db_path).fetch_traces(limit=10)
    one = next(row for row in rows if "printf one" in row["args_preview"])
    two = next(row for row in rows if "printf two" in row["args_preview"])
    assert one["output_preview"]
    assert "one" in one["output_preview"]
    assert one["tool_duration_ms"] == 7
    assert two["output_preview"] is None


def test_pre_hook_enforce_blocks_deny(monkeypatch, tmp_path):
    plugin = load_plugin_module()

    monkeypatch.setenv("ASF_HERMES_DB", str(tmp_path / "trace.db"))
    monkeypatch.setenv("ASF_HERMES_MODE", "enforce")

    monkeypatch.setattr(
        plugin,
        "run_asf_check",
        lambda *args, **kwargs: ("DENY", "test deny"),
    )

    result = plugin.on_pre_tool_call(
        tool_name="terminal",
        args={"command": "cat ~/.hermes/.env"},
        task_id="task-1",
        session_id="session-1",
        tool_call_id="call-2",
    )

    assert result == {"action": "block", "message": "[ASF BLOCKED] test deny"}


def test_pre_hook_enforce_real_asf_blocks_without_side_effect(monkeypatch, tmp_path):
    plugin = load_plugin_module()
    plugin._AGENT_REGISTERED = False

    side_effect = tmp_path / "hermes-deny-side-effect.txt"
    monkeypatch.setenv("ASF_HERMES_DB", str(tmp_path / "trace.db"))
    monkeypatch.setenv("ASF_HERMES_MODE", "enforce")
    monkeypatch.setenv("ASF_HERMES_AGENT_ID", "hermes-live-agent")
    monkeypatch.setenv("ASF_HERMES_REGISTRY_RESET", "true")
    monkeypatch.setenv("ASF_SKIP_LLM", "true")

    result = plugin.on_pre_tool_call(
        tool_name="terminal",
        args={"command": f"DROP TABLE users; touch {side_effect}"},
        task_id="task-deny",
    )

    assert result is not None
    assert result["action"] == "block"
    assert not side_effect.exists()

    from registry import AuditModel, SessionLocal
    db = SessionLocal()
    try:
        rows = db.query(AuditModel).filter(AuditModel.agent_id == "hermes-live-agent").all()
    finally:
        db.close()
    assert rows


def test_pre_hook_monitor_real_asf_does_not_block(monkeypatch, tmp_path):
    plugin = load_plugin_module()
    plugin._AGENT_REGISTERED = False

    side_effect = tmp_path / "monitor-side-effect.txt"
    monkeypatch.setenv("ASF_HERMES_DB", str(tmp_path / "trace.db"))
    monkeypatch.setenv("ASF_HERMES_MODE", "monitor")
    monkeypatch.setenv("ASF_HERMES_AGENT_ID", "hermes-live-agent")
    monkeypatch.setenv("ASF_HERMES_REGISTRY_RESET", "true")
    monkeypatch.setenv("ASF_SKIP_LLM", "true")

    result = plugin.on_pre_tool_call(
        tool_name="terminal",
        args={"command": f"DROP TABLE users; touch {side_effect}"},
        task_id="task-monitor",
    )

    assert result is None
    side_effect.write_text("monitor proceeded")
    assert side_effect.exists()


def test_sandbox_terminal_confines_writes(monkeypatch, tmp_path):
    if not shutil.which("sandbox-exec"):
        pytest.skip("sandbox-exec is not available on this platform")
    plugin = load_plugin_module()
    sandbox_root = tmp_path / "sandbox"
    outside = tmp_path / "outside.txt"
    monkeypatch.setenv("ASF_HERMES_SANDBOX", "true")
    monkeypatch.setenv("ASF_HERMES_SANDBOX_WORKDIR", str(sandbox_root))

    raw = plugin._sandbox_terminal({"command": f"echo nope > {outside}"})
    result = json.loads(raw)

    assert result["sandboxed"] is True
    assert result["exit_code"] != 0
    assert not outside.exists()


def test_sandbox_execute_code_blocks_network(monkeypatch, tmp_path):
    if not shutil.which("sandbox-exec"):
        pytest.skip("sandbox-exec is not available on this platform")
    plugin = load_plugin_module()
    monkeypatch.setenv("ASF_HERMES_SANDBOX", "true")
    monkeypatch.setenv("ASF_HERMES_SANDBOX_WORKDIR", str(tmp_path / "sandbox"))

    raw = plugin._sandbox_execute_code(
        {"code": "import socket; socket.create_connection(('127.0.0.1', 9), 0.2)"}
    )
    result = json.loads(raw)

    assert result["sandboxed"] is True
    assert result["exit_code"] != 0


class _FakeRegistry:
    """Stand-in for the framework registry module, injected via sys.modules so
    register_hermes_agent's lazy `import registry` resolves to it."""

    def __init__(self, exists):
        self._exists = exists
        self.added = 0
        self.reinstated = 0

    def agent_exists(self, agent_id):
        return self._exists

    def add_or_update_agent(self, agent_id, risk_level, permissions):
        self.added += 1

    def reinstate_agent(self, agent_id):
        self.reinstated += 1


def test_enforcement_does_not_reinstate_existing_agent(monkeypatch):
    import sys

    plugin = load_plugin_module()
    plugin._AGENT_REGISTERED = False
    fake = _FakeRegistry(exists=True)
    monkeypatch.setitem(sys.modules, "registry", fake)
    monkeypatch.delenv("ASF_HERMES_REGISTRY_RESET", raising=False)

    plugin.register_hermes_agent()

    # A row already exists: enforcement must not touch its status, so a kill-switch
    # suspension persists until a human reinstates it.
    assert fake.added == 0
    assert fake.reinstated == 0


def test_enforcement_registers_missing_agent_once(monkeypatch):
    import sys

    plugin = load_plugin_module()
    plugin._AGENT_REGISTERED = False
    fake = _FakeRegistry(exists=False)
    monkeypatch.setitem(sys.modules, "registry", fake)
    monkeypatch.delenv("ASF_HERMES_REGISTRY_RESET", raising=False)

    plugin.register_hermes_agent()
    plugin.register_hermes_agent()

    # First-time registration only, and just once (process-level guard).
    assert fake.added == 1
    assert fake.reinstated == 0


def test_reset_mode_reinstates_on_every_check(monkeypatch):
    import sys

    plugin = load_plugin_module()
    plugin._AGENT_REGISTERED = False
    fake = _FakeRegistry(exists=True)
    monkeypatch.setitem(sys.modules, "registry", fake)
    monkeypatch.setenv("ASF_HERMES_REGISTRY_RESET", "true")

    plugin.register_hermes_agent()

    # Opt-in reset mode (smoke tests / scenario resets) clears suspension explicitly.
    assert fake.added == 1
    assert fake.reinstated == 1
