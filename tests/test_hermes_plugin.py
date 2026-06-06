import importlib.util
from pathlib import Path

import pytest


# The Hermes plugin is deployed under the user's Hermes home, not vendored in this
# repo. Skip (rather than error) when it is absent so a clean checkout / CI does not
# report false failures for code that is not present in the tree.
PLUGIN_PATH = Path.home() / ".hermes" / "plugins" / "asf-tracker" / "__init__.py"


def load_plugin_module():
    if not PLUGIN_PATH.exists():
        pytest.skip(f"Hermes asf-tracker plugin not present at {PLUGIN_PATH}")
    spec = importlib.util.spec_from_file_location("asf_tracker_plugin", PLUGIN_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


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
