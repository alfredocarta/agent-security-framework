import importlib.util
import json
import shutil
import threading
import time
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




def test_agent_model_uses_runtime_env_before_static_config(monkeypatch, tmp_path):
    plugin = load_plugin_module()
    cfg = tmp_path / "config.yaml"
    cfg.write_text("model:\n  default: gpt-5.5\n  provider: openai-codex\n")

    monkeypatch.delenv("ASF_HERMES_AGENT_MODEL", raising=False)
    monkeypatch.setenv("HERMES_CONFIG", str(cfg))
    monkeypatch.setenv("HERMES_MODEL", "qwen 3.5")
    monkeypatch.setenv("HERMES_TUI_PROVIDER", "openrouter")

    assert plugin._agent_model() == "qwen 3.5 via openrouter"


def test_agent_model_explicit_asf_override_wins(monkeypatch):
    plugin = load_plugin_module()
    monkeypatch.setenv("ASF_HERMES_AGENT_MODEL", "override-model")
    monkeypatch.setenv("HERMES_MODEL", "qwen 3.5")
    monkeypatch.setenv("HERMES_TUI_PROVIDER", "openrouter")

    assert plugin._agent_model() == "override-model"



def test_agent_model_resolution_order_override_runtime_config(monkeypatch, tmp_path):
    plugin = load_plugin_module()
    cfg = tmp_path / "config.yaml"
    cfg.write_text("model:\n  default: stale-config-model\n  provider: stale-provider\n")

    class Agent:
        model = "runtime-qwen-3.5"
        provider = "qwen-oauth"

    class Cli:
        agent = Agent()
        model = "cli-startup-model"
        requested_provider = "cli-provider"

    class Manager:
        _cli_ref = Cli()

    class Ctx:
        _manager = Manager()

    monkeypatch.setattr(plugin, "_PLUGIN_CONTEXT", Ctx())
    monkeypatch.setenv("HERMES_CONFIG", str(cfg))
    monkeypatch.setenv("HERMES_MODEL", "env-model")
    monkeypatch.setenv("HERMES_TUI_PROVIDER", "env-provider")
    monkeypatch.delenv("ASF_HERMES_AGENT_MODEL", raising=False)

    assert plugin._agent_model() == "runtime-qwen-3.5 via qwen-oauth"

    monkeypatch.setenv("ASF_HERMES_AGENT_MODEL", "explicit-override")
    assert plugin._agent_model() == "explicit-override"

    monkeypatch.delenv("ASF_HERMES_AGENT_MODEL", raising=False)
    monkeypatch.setattr(plugin, "_PLUGIN_CONTEXT", None)
    assert plugin._agent_model() == "env-model via env-provider"

    monkeypatch.delenv("HERMES_MODEL", raising=False)
    monkeypatch.delenv("HERMES_TUI_PROVIDER", raising=False)
    assert plugin._agent_model() == "stale-config-model via stale-provider"


def test_pre_hook_records_config_fallback_agent_model(monkeypatch, tmp_path):
    plugin = load_plugin_module()
    cfg = tmp_path / "config.yaml"
    cfg.write_text("model:\n  default: config-default-model\n  provider: openrouter\n")
    db_path = tmp_path / "trace.db"

    monkeypatch.setenv("ASF_HERMES_DB", str(db_path))
    monkeypatch.setenv("ASF_HERMES_MODE", "monitor")
    monkeypatch.setenv("HERMES_CONFIG", str(cfg))
    monkeypatch.delenv("ASF_HERMES_AGENT_MODEL", raising=False)
    monkeypatch.delenv("HERMES_MODEL", raising=False)
    monkeypatch.delenv("HERMES_INFERENCE_MODEL", raising=False)
    monkeypatch.delenv("HERMES_TUI_MODEL", raising=False)
    monkeypatch.setattr(plugin, "_PLUGIN_CONTEXT", None)
    monkeypatch.setattr(plugin, "run_asf_check", lambda *a, **k: ("ALLOW", "ok"))

    plugin.on_pre_tool_call(
        tool_name="terminal",
        args={"command": "pwd"},
        task_id="task-model",
        session_id="session-model",
        tool_call_id="call-model",
    )

    from hermes_trace_store import HermesTraceStore

    row = HermesTraceStore(db_path).fetch_traces(session_id="session-model")[0]
    assert row["agent_model"] == "config-default-model via openrouter"

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
    assert rows[0]["output_preview"] == "ok"
    assert rows[0]["output_hash"]
    assert rows[0]["tool_duration_ms"] == 12
    assert "stdout" not in rows[0]["output_preview"]
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


def _install_fake_tool_registry(monkeypatch, dispatch_fn):
    """Inject a fake `tools.registry` module so the plugin's lazy
    `from tools.registry import registry` resolves to a stand-in whose `dispatch`
    we control, reproducing the Hermes live runtime that executes tools via dispatch."""
    import sys
    import types

    tools_mod = types.ModuleType("tools")
    registry_mod = types.ModuleType("tools.registry")

    class _Reg:
        pass

    reg = _Reg()
    reg.dispatch = dispatch_fn
    registry_mod.registry = reg
    tools_mod.registry = registry_mod
    monkeypatch.setitem(sys.modules, "tools", tools_mod)
    monkeypatch.setitem(sys.modules, "tools.registry", registry_mod)
    return reg


def test_live_dispatch_captures_output_without_post_hook(monkeypatch, tmp_path):
    # Reproduces the Hermes agentic runtime: only pre_tool_call fires, the tool runs through
    # tools.registry.dispatch, and post_tool_call is never invoked. Output and tool_duration_ms
    # must still land on the same row the pre-hook opened (correlated by task_id, no tool_call_id).
    plugin = load_plugin_module()
    plugin._DISPATCH_WRAPPED = False

    db_path = tmp_path / "trace.db"
    monkeypatch.setenv("ASF_HERMES_DB", str(db_path))
    monkeypatch.setenv("ASF_HERMES_MODE", "monitor")
    monkeypatch.setenv("ASF_HERMES_AGENT_ID", "hermes-live-agent")
    monkeypatch.delenv("ASF_HERMES_SANDBOX", raising=False)
    monkeypatch.setattr(plugin, "run_asf_check", lambda *a, **k: ("ALLOW", "test allow"))

    def fake_dispatch(name, args=None, **kwargs):
        time.sleep(0.005)
        return {"stdout": "live-output-123"}

    reg = _install_fake_tool_registry(monkeypatch, fake_dispatch)

    args = {"command": "printf live"}
    # Pre-hook opens the row and installs the dispatch wrapper (no tool_call_id in the live path).
    plugin.on_pre_tool_call(tool_name="terminal", args=args, task_id="task-live", session_id="sess-live")
    assert reg.dispatch is not fake_dispatch

    # Runtime executes the tool: task_id arrives in kwargs, tool_call_id does not.
    result = reg.dispatch("terminal", args, task_id="task-live", session_id="sess-live")
    assert result == {"stdout": "live-output-123"}

    from hermes_trace_store import HermesTraceStore
    rows = HermesTraceStore(db_path).fetch_traces(session_id="sess-live")
    assert len(rows) == 1
    row = rows[0]
    assert row["task_id"] == "task-live"
    assert row["tool_call_id"] is None
    assert "live-output-123" in row["output_preview"]
    assert row["output_hash"]
    assert row["tool_duration_ms"] is not None
    assert row["tool_duration_ms"] >= 0



def test_identical_sequential_live_calls_get_distinct_trace_ids_and_outputs(monkeypatch, tmp_path):
    plugin = load_plugin_module()
    plugin._DISPATCH_WRAPPED = False

    db_path = tmp_path / "trace.db"
    monkeypatch.setenv("ASF_HERMES_DB", str(db_path))
    monkeypatch.setenv("ASF_HERMES_MODE", "monitor")
    monkeypatch.setenv("ASF_HERMES_AGENT_ID", "hermes-live-agent")
    monkeypatch.delenv("ASF_HERMES_SANDBOX", raising=False)
    monkeypatch.setattr(plugin, "run_asf_check", lambda *a, **k: ("ALLOW", "test allow"))

    outputs = iter([{"stdout": "first-output"}, {"stdout": "second-output"}])

    def fake_dispatch(name, args=None, **kwargs):
        return next(outputs)

    reg = _install_fake_tool_registry(monkeypatch, fake_dispatch)

    args = {"command": "printf same"}
    plugin.on_pre_tool_call(tool_name="terminal", args=args, task_id="task-same", session_id="sess-same")
    reg.dispatch("terminal", args, task_id="task-same", session_id="sess-same")
    plugin.on_pre_tool_call(tool_name="terminal", args=args, task_id="task-same", session_id="sess-same")
    reg.dispatch("terminal", args, task_id="task-same", session_id="sess-same")

    from hermes_trace_store import HermesTraceStore
    rows = sorted(
        HermesTraceStore(db_path).fetch_traces(session_id="sess-same", limit=10),
        key=lambda row: row["timestamp"],
    )
    assert len(rows) == 2
    assert rows[0]["trace_id"] != rows[1]["trace_id"]
    assert "first-output" in rows[0]["output_preview"]
    assert "second-output" in rows[1]["output_preview"]
    assert rows[0]["output_hash"] != rows[1]["output_hash"]

def test_live_dispatch_captures_output_with_sandbox(monkeypatch, tmp_path):
    plugin = load_plugin_module()
    plugin._DISPATCH_WRAPPED = False

    db_path = tmp_path / "trace.db"
    monkeypatch.setenv("ASF_HERMES_DB", str(db_path))
    monkeypatch.setenv("ASF_HERMES_MODE", "monitor")
    monkeypatch.setenv("ASF_HERMES_AGENT_ID", "hermes-live-agent")
    monkeypatch.setenv("ASF_HERMES_SANDBOX", "true")
    monkeypatch.setattr(plugin, "run_asf_check", lambda *a, **k: ("ALLOW", "ok"))
    # Stub the sandbox executor so the test is independent of sandbox-exec / a real shell.
    monkeypatch.setattr(plugin, "_sandbox_terminal", lambda a: '{"output": "sandboxed-out", "exit_code": 0}')

    calls = {"original": 0}

    def fake_dispatch(name, args=None, **kwargs):
        calls["original"] += 1
        return "should-not-run"

    reg = _install_fake_tool_registry(monkeypatch, fake_dispatch)

    args = {"command": "echo hi"}
    plugin.on_pre_tool_call(tool_name="terminal", args=args, task_id="task-sbx", session_id="sess-sbx")
    out = reg.dispatch("terminal", args, task_id="task-sbx", session_id="sess-sbx")

    # Sandbox path runs instead of the original dispatch, and its output is still captured.
    assert "sandboxed-out" in out
    assert calls["original"] == 0

    from hermes_trace_store import HermesTraceStore
    row = HermesTraceStore(db_path).fetch_traces(session_id="sess-sbx")[0]
    assert "sandboxed-out" in row["output_preview"]
    assert row["tool_duration_ms"] is not None


def test_dispatch_and_post_hook_do_not_double_write(monkeypatch, tmp_path):
    plugin = load_plugin_module()
    plugin._DISPATCH_WRAPPED = False

    db_path = tmp_path / "trace.db"
    monkeypatch.setenv("ASF_HERMES_DB", str(db_path))
    monkeypatch.setenv("ASF_HERMES_MODE", "monitor")
    monkeypatch.setenv("ASF_HERMES_AGENT_ID", "hermes-live-agent")
    monkeypatch.delenv("ASF_HERMES_SANDBOX", raising=False)
    monkeypatch.setattr(plugin, "run_asf_check", lambda *a, **k: ("ALLOW", "ok"))

    def fake_dispatch(name, args=None, **kwargs):
        return {"stdout": "first-output"}

    reg = _install_fake_tool_registry(monkeypatch, fake_dispatch)

    args = {"command": "printf once"}
    plugin.on_pre_tool_call(tool_name="terminal", args=args, task_id="task-dup", session_id="sess-dup")
    reg.dispatch("terminal", args, task_id="task-dup", session_id="sess-dup")

    # post_tool_call also fires (environments where it does): it must not overwrite the row
    # already finished by the dispatch wrapper.
    plugin.on_post_tool_call(
        tool_name="terminal",
        args=args,
        result={"stdout": "second-output"},
        task_id="task-dup",
        session_id="sess-dup",
        duration_ms=999,
    )

    from hermes_trace_store import HermesTraceStore
    rows = HermesTraceStore(db_path).fetch_traces(session_id="sess-dup")
    assert len(rows) == 1
    row = rows[0]
    assert "first-output" in row["output_preview"]
    assert "second-output" not in row["output_preview"]
    assert row["tool_duration_ms"] != 999


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


def _hitl_fake_check_with_audit(plugin, event_hash_box):
    def fake_check(agent_id, tool_name, security_text, session_id=None):
        from audit import AUDITOR

        AUDITOR.log_event(
            agent_id,
            tool_name,
            "HITL_REQUESTED",
            "test HITL request",
            session_id=session_id,
        )
        event_hash_box["hash"] = AUDITOR.last_hash_for(agent_id)
        return "HITL", "test HITL"

    return fake_check


def _decide_when_event_hash_exists(event_hash_box, outcome):
    from audit import AUDITOR

    for _ in range(200):
        event_hash = event_hash_box.get("hash")
        if event_hash:
            AUDITOR.log_event("human-reviewer", "hitl", outcome, f"event:{event_hash} test decision")
            return
        time.sleep(0.005)


def test_pre_hook_enforce_hitl_approve_waits_then_allows(monkeypatch, tmp_path):
    plugin = load_plugin_module()
    event_hash_box = {}

    monkeypatch.setenv("ASF_HERMES_DB", str(tmp_path / "trace.db"))
    monkeypatch.setenv("ASF_HERMES_MODE", "enforce")
    monkeypatch.setenv("ASF_HERMES_AGENT_ID", "hermes-live-agent")
    monkeypatch.setenv("ASF_HERMES_HITL_TIMEOUT", "2")
    monkeypatch.setenv("ASF_HERMES_HITL_POLL_MS", "10")
    monkeypatch.setattr(plugin, "run_asf_check", _hitl_fake_check_with_audit(plugin, event_hash_box))

    reviewer = threading.Thread(
        target=_decide_when_event_hash_exists,
        args=(event_hash_box, "HITL_APPROVED"),
    )
    reviewer.start()
    result = plugin.on_pre_tool_call(tool_name="terminal", args={"command": "echo ok"}, task_id="hitl-approve")
    reviewer.join(timeout=2)

    assert result is None
    assert event_hash_box.get("hash")


def test_pre_hook_enforce_hitl_reject_waits_then_blocks(monkeypatch, tmp_path):
    plugin = load_plugin_module()
    event_hash_box = {}

    monkeypatch.setenv("ASF_HERMES_DB", str(tmp_path / "trace.db"))
    monkeypatch.setenv("ASF_HERMES_MODE", "enforce")
    monkeypatch.setenv("ASF_HERMES_AGENT_ID", "hermes-live-agent")
    monkeypatch.setenv("ASF_HERMES_HITL_TIMEOUT", "2")
    monkeypatch.setenv("ASF_HERMES_HITL_POLL_MS", "10")
    monkeypatch.setattr(plugin, "run_asf_check", _hitl_fake_check_with_audit(plugin, event_hash_box))

    reviewer = threading.Thread(
        target=_decide_when_event_hash_exists,
        args=(event_hash_box, "HITL_REJECTED"),
    )
    reviewer.start()
    result = plugin.on_pre_tool_call(tool_name="terminal", args={"command": "echo no"}, task_id="hitl-reject")
    reviewer.join(timeout=2)

    assert result is not None
    assert result["action"] == "block"
    assert "HITL rejected" in result["message"]


def test_pre_hook_enforce_hitl_timeout_policy(monkeypatch, tmp_path):
    plugin = load_plugin_module()
    event_hash_box = {}

    monkeypatch.setenv("ASF_HERMES_DB", str(tmp_path / "trace.db"))
    monkeypatch.setenv("ASF_HERMES_MODE", "enforce")
    monkeypatch.setenv("ASF_HERMES_AGENT_ID", "hermes-live-agent")
    monkeypatch.setenv("ASF_HERMES_HITL_TIMEOUT", "0.01")
    monkeypatch.setenv("ASF_HERMES_HITL_POLL_MS", "1")
    monkeypatch.setenv("ASF_HERMES_HITL_ON_TIMEOUT", "block")
    monkeypatch.setattr(plugin, "run_asf_check", _hitl_fake_check_with_audit(plugin, event_hash_box))

    result = plugin.on_pre_tool_call(tool_name="terminal", args={"command": "echo timeout"}, task_id="hitl-timeout")
    assert result is not None
    assert result["action"] == "block"
    assert "timeout" in result["message"].lower()

    monkeypatch.setenv("ASF_HERMES_HITL_ON_TIMEOUT", "allow")
    result = plugin.on_pre_tool_call(tool_name="terminal", args={"command": "echo timeout"}, task_id="hitl-timeout-allow")
    assert result is None


def test_pre_hook_monitor_hitl_does_not_wait(monkeypatch, tmp_path):
    plugin = load_plugin_module()

    monkeypatch.setenv("ASF_HERMES_DB", str(tmp_path / "trace.db"))
    monkeypatch.setenv("ASF_HERMES_MODE", "monitor")
    monkeypatch.setattr(plugin, "run_asf_check", lambda *args, **kwargs: ("HITL", "test HITL"))

    start = time.monotonic()
    result = plugin.on_pre_tool_call(tool_name="terminal", args={"command": "echo monitor"})

    assert result is None
    assert time.monotonic() - start < 0.5


def test_allowlist_blocks_command_path_and_network(monkeypatch, tmp_path):
    plugin = load_plugin_module()

    sandbox_root = tmp_path / "sandbox"
    allowed_read = tmp_path / "allowed"
    allowed_read.mkdir()
    monkeypatch.setenv("ASF_HERMES_DB", str(tmp_path / "trace.db"))
    monkeypatch.setenv("ASF_HERMES_MODE", "enforce")
    monkeypatch.setenv("ASF_HERMES_SANDBOX_WORKDIR", str(sandbox_root))
    monkeypatch.setenv("ASF_HERMES_CMD_ALLOW", "echo,python")
    monkeypatch.setenv("ASF_HERMES_PATH_ALLOW", str(allowed_read))
    monkeypatch.setenv("ASF_HERMES_NET_ALLOW", "example.com")
    monkeypatch.setattr(plugin, "run_asf_check", lambda *args, **kwargs: ("ALLOW", "test allow"))

    assert plugin.on_pre_tool_call(tool_name="terminal", args={"command": "echo ok"}) is None

    blocked_cmd = plugin.on_pre_tool_call(tool_name="terminal", args={"command": "curl https://example.com"})
    assert blocked_cmd is not None
    assert "command" in blocked_cmd["message"]

    blocked_path = plugin.on_pre_tool_call(tool_name="read_file", args={"path": str(tmp_path / "secret.txt")})
    assert blocked_path is not None
    assert "path" in blocked_path["message"]

    assert plugin.on_pre_tool_call(tool_name="read_file", args={"path": str(allowed_read / "ok.txt")}) is None


def test_allowlist_blocks_unapproved_network_destination(monkeypatch, tmp_path):
    plugin = load_plugin_module()

    monkeypatch.setenv("ASF_HERMES_DB", str(tmp_path / "trace.db"))
    monkeypatch.setenv("ASF_HERMES_MODE", "enforce")
    monkeypatch.setenv("ASF_HERMES_CMD_ALLOW", "curl")
    monkeypatch.setenv("ASF_HERMES_NET_ALLOW", "example.com")
    monkeypatch.setattr(plugin, "run_asf_check", lambda *args, **kwargs: ("ALLOW", "test allow"))

    result = plugin.on_pre_tool_call(tool_name="terminal", args={"command": "curl https://evil.test/path"})
    assert result is not None
    assert result["action"] == "block"
    assert "network destination" in result["message"]

    assert plugin.on_pre_tool_call(tool_name="terminal", args={"command": "curl https://sub.example.com"}) is None


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
