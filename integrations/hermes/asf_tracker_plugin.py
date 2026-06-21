from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import shlex
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def _resolve_asf_root() -> Path:
    # 1. Explicit override always wins.
    env_root = os.environ.get("ASF_ROOT")
    if env_root:
        return Path(env_root)
    # 2. Vendored copy lives at <repo>/integrations/hermes/asf_tracker_plugin.py: walk up
    #    to the framework root that actually contains the modules, so the in-repo copy is
    #    portable to any checkout location without ASF_ROOT being set (no hardcoded path).
    for ancestor in Path(__file__).resolve().parents:
        if (ancestor / "interceptor.py").exists() and (ancestor / "registry.py").exists():
            return ancestor
    # 3. Deployed copy lives outside the repo (e.g. ~/.hermes/plugins): fall back to the
    #    conventional checkout location.
    return Path.home() / "Projects" / "agent-security-framework"


DEFAULT_ASF_ROOT = _resolve_asf_root()
# Hermes should use the production Stage 3 backend: ONNX Prompt Guard.
# Keep setdefault so an explicit user override still wins.
os.environ.setdefault("ASF_STAGE3_BACKEND", "onnx")
if str(DEFAULT_ASF_ROOT) not in sys.path:
    sys.path.insert(0, str(DEFAULT_ASF_ROOT))
if not (DEFAULT_ASF_ROOT / "interceptor.py").exists():
    # Make misconfiguration loud instead of silently fail-opening: without the framework
    # modules the ASF check raises and on_pre_tool_call falls back to ALLOW (unless
    # ASF_HERMES_FAIL_CLOSED=true).
    print(
        f"[ASF WARNING] ASF framework modules not found under {DEFAULT_ASF_ROOT}. "
        "Set ASF_ROOT to the agent-security-framework checkout, otherwise the Hermes ASF "
        "check will fail-open (set ASF_HERMES_FAIL_CLOSED=true to fail closed).",
        file=sys.stderr,
    )

from wrapper import asf_core

_REGISTERED_AGENT_IDS: set[str] = set()
_TRACE_BY_CALL_KEY: dict[tuple[str, str, str], str] = {}
_TRACE_LOCK = threading.Lock()
_DISPATCH_WRAPPED = False
_ORIGINAL_DISPATCH = None
_PLUGIN_CONTEXT = None

TOOL_MAP = {
    "terminal": "shell",
    "execute_code": "code_execution",
    "read_file": "file_read",
    "write_file": "file_write",
    "patch": "code_edit",
    "search_files": "file_search",
    "send_message": "communication",
    "memory": "memory_write",
    "cronjob": "scheduler",
    "delegate_task": "delegation",
    "skill_manage": "security_sensitive_write",
    "skill_view": "skill_read",
    "skills_list": "skill_read",
    "session_search": "memory_read",
    "todo": "task_state",
    "image_generate": "media_generation",
    "text_to_speech": "media_generation",
}

PREFIX_MAP = {
    "browser_": "browser",
}

SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\s*[=:]\s*[^\s'\"]{8,}"),
    re.compile(r"(?i)\b(bearer|sk-[a-z0-9_-]{12,}|ghp_[a-z0-9_]{20,})"),
)


def _env_bool(name: str, default: bool = False) -> bool:
    return asf_core.env_bool(name, default)


def _env_list(name: str) -> list[str]:
    return asf_core.env_list(name)


def _mode() -> str:
    return os.environ.get("ASF_HERMES_MODE", "monitor").strip().lower()


def _enabled() -> bool:
    return _env_bool("ASF_HERMES_ENABLED", True)


def _agent_id() -> str:
    return os.environ.get("ASF_AGENT_ID") or os.environ.get("ASF_HERMES_AGENT_ID") or asf_core.DEFAULT_AGENT_ID


def _clean_str(value: Any) -> str | None:
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return None


def _runtime_model_from_env() -> tuple[str | None, str | None]:
    # Hermes sets these for explicit TUI/CLI launches and TUI runtime model
    # switches. They are process-local and fresher than ~/.hermes/config.yaml,
    # but not present for the normal wrapper path when the model only comes
    # from config.yaml.
    model = (
        os.environ.get("HERMES_MODEL")
        or os.environ.get("HERMES_INFERENCE_MODEL")
        or os.environ.get("HERMES_TUI_MODEL")
    )
    provider = (
        os.environ.get("HERMES_TUI_PROVIDER")
        or os.environ.get("HERMES_INFERENCE_PROVIDER")
        or os.environ.get("HERMES_PROVIDER")
    )
    return _clean_str(model), _clean_str(provider)


def _runtime_model_from_plugin_context() -> tuple[str | None, str | None]:
    # Authoritative live CLI source: PluginContext -> PluginManager._cli_ref ->
    # active AIAgent. The status bar uses the same agent.model because it changes
    # after fallback and /model switches, while cli.model is only the startup
    # value. register(ctx) runs before ChatCLI stores _cli_ref, so resolve this
    # lazily at tool-call time from the retained context.
    ctx = _PLUGIN_CONTEXT
    manager = getattr(ctx, "_manager", None) if ctx is not None else None
    cli = getattr(manager, "_cli_ref", None) if manager is not None else None
    agent = getattr(cli, "agent", None) if cli is not None else None

    model = _clean_str(getattr(agent, "model", None)) if agent is not None else None
    provider = _clean_str(getattr(agent, "provider", None)) if agent is not None else None
    if model:
        return model, provider

    # Early startup fallback before cli.agent is attached. This is runtime state
    # (constructor-resolved config/CLI arg), but it will be superseded by
    # agent.model as soon as the agent exists.
    if cli is not None:
        model = _clean_str(getattr(cli, "model", None))
        provider = (
            _clean_str(getattr(cli, "provider", None))
            or _clean_str(getattr(cli, "requested_provider", None))
        )
        if model:
            return model, provider

    return None, None


def _hermes_config_path() -> Path:
    explicit = _clean_str(os.environ.get("HERMES_CONFIG"))
    if explicit:
        return Path(explicit).expanduser()
    home = _clean_str(os.environ.get("HERMES_HOME"))
    return (Path(home).expanduser() if home else Path.home() / ".hermes") / "config.yaml"


def _config_model_fallback() -> tuple[str | None, str | None]:
    path = _hermes_config_path()
    if not path.exists():
        return None, None
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return None, None

    data: Any = None
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(text)
    except Exception:
        data = None

    if isinstance(data, dict):
        model_cfg = data.get("model")
        if isinstance(model_cfg, dict):
            return _clean_str(model_cfg.get("default") or model_cfg.get("model")), _clean_str(model_cfg.get("provider"))
        return _clean_str(model_cfg), None

    # Tiny fallback parser for tests/minimal installs where PyYAML is not
    # available. It intentionally handles only the model block we need.
    in_model = False
    model: str | None = None
    provider: str | None = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        if indent == 0:
            if stripped.startswith("model:"):
                in_model = True
                rest = stripped.split(":", 1)[1].strip()
                if rest:
                    model = rest.strip('"\'')
            else:
                in_model = False
            continue
        if in_model and indent > 0 and ":" in stripped:
            key, value = stripped.split(":", 1)
            value = value.strip().strip('"\'')
            if key.strip() in {"default", "model"} and value and model is None:
                model = value
            elif key.strip() == "provider" and value:
                provider = value
    return _clean_str(model), _clean_str(provider)


def _format_agent_model(model: str | None, provider: str | None = None) -> str | None:
    if not model:
        return None
    if provider and f" via {provider}" not in model:
        return f"{model} via {provider}"
    return model


def _agent_model() -> str | None:
    explicit = os.environ.get("ASF_HERMES_AGENT_MODEL")
    if explicit:
        return explicit.strip() or None

    for resolver in (
        _runtime_model_from_plugin_context,
        _runtime_model_from_env,
        _config_model_fallback,
    ):
        model, provider = resolver()
        formatted = _format_agent_model(model, provider)
        if formatted:
            return formatted
    return None


def normalize_tool_name(tool_name: str) -> str:
    return asf_core.normalize_tool_name(tool_name, TOOL_MAP, PREFIX_MAP)


def _redact_text(text: str) -> str:
    return asf_core.redact_text(text)


def _redact_value(value: Any) -> Any:
    return asf_core.redact_value(value)


def _safe_preview(value: Any, max_chars: int | None = None) -> str:
    return asf_core.safe_preview(value, max_chars)

def _stable_json(value: Any) -> str:
    return asf_core.stable_json(value)


def _args_hash(args: Any) -> str:
    return asf_core.args_hash(args)


def _call_key(task_id: str, tool_name: str, args: dict[str, Any] | None) -> tuple[str, str, str]:
    return asf_core.call_key(task_id, tool_name, args)


def build_security_text(tool_name: str, args: dict[str, Any] | None) -> str:

    args = args or {}
    asf_tool = normalize_tool_name(tool_name)
    parts = [f"source=hermes", f"tool={tool_name}", f"asf_tool={asf_tool}"]

    if tool_name == "terminal":
        parts.append(f"command={_safe_preview(args.get('command', ''))}")
    elif tool_name == "execute_code":
        parts.append(f"code={_safe_preview(args.get('code', ''))}")
    elif tool_name in {"read_file", "write_file"}:
        parts.append(f"path={args.get('path', '')}")
        if "content" in args:
            parts.append(f"content={_safe_preview(args.get('content', ''))}")
    elif tool_name == "patch":
        parts.append(f"path={args.get('path', '')}")
        parts.append(f"old={_safe_preview(args.get('old_string', ''))}")
        parts.append(f"new={_safe_preview(args.get('new_string', ''))}")
    elif tool_name == "send_message":
        parts.append(f"target={args.get('target', '')}")
        parts.append(f"message={_safe_preview(args.get('message', ''))}")
    else:
        parts.append(f"args={_safe_preview(args)}")

    return "\n".join(parts)


def _all_permissions() -> list[str]:
    return sorted(set(TOOL_MAP.values()) | set(PREFIX_MAP.values()) | {"terminal", "web"})


def register_hermes_agent() -> None:
    try:
        import registry
        resolved_agent_id = _agent_id()

        # Reset mode (ASF_HERMES_REGISTRY_RESET=true) is an explicit opt-in for smoke
        # tests / scenario resets: it re-asserts permissions and clears any suspension
        # on every check. In normal (enforcement) operation a kill-switch suspension
        # MUST persist until a human reinstates the agent, so we register the agent only
        # once (when missing) and never auto-clear status here. Re-running
        # add_or_update_agent unconditionally would flip status back to "active" and
        # silently defeat the kill-switch.
        if _env_bool("ASF_HERMES_REGISTRY_RESET", False):
            registry.add_or_update_agent(
                resolved_agent_id,
                risk_level=os.environ.get("ASF_HERMES_RISK_LEVEL", "high"),
                permissions=_all_permissions(),
            )
            if hasattr(registry, "reinstate_agent"):
                registry.reinstate_agent(resolved_agent_id)
            _REGISTERED_AGENT_IDS.add(resolved_agent_id)
            return

        if resolved_agent_id in _REGISTERED_AGENT_IDS:
            return
        already_registered = (
            registry.agent_exists(resolved_agent_id) if hasattr(registry, "agent_exists") else False
        )
        if not already_registered:
            registry.add_or_update_agent(
                resolved_agent_id,
                risk_level=os.environ.get("ASF_HERMES_RISK_LEVEL", "high"),
                permissions=_all_permissions(),
            )
        _REGISTERED_AGENT_IDS.add(resolved_agent_id)
    except Exception:
        if _env_bool("ASF_HERMES_FAIL_CLOSED", False):
            raise


def run_asf_check(agent_id: str, tool_name: str, security_text: str, session_id: str | None = None) -> tuple[str, str]:
    register_hermes_agent()
    return asf_core.run_asf_check(agent_id, tool_name, security_text, session_id=session_id)


def _store():
    return asf_core.store_from_env("ASF_HERMES_DB")


def _outcome_from_verdict(verdict: str) -> str:
    return asf_core.outcome_from_verdict(verdict)


def _block_directive(verdict: str, reason: str) -> dict[str, str]:
    return asf_core.block_directive(verdict, reason)




def _find_hitl_decision(event_hash: str) -> tuple[str, str] | None:
    return asf_core.find_hitl_decision(event_hash)


def _wait_for_hitl_decision(event_hash: str, reason: str) -> tuple[bool, str]:
    return asf_core.wait_for_hitl_decision(event_hash, reason)


def _sandbox_enabled() -> bool:
    return asf_core.sandbox_enabled()


def _sandbox_workdir() -> str:
    return asf_core.sandbox_workdir()


def _sandbox_cwd(requested: str | None, root: str) -> str:
    return asf_core.sandbox_cwd(requested, root)


def _sandbox_argv(command: list[str]) -> tuple[list[str], str | None]:
    return asf_core.sandbox_argv(command, asf_root=DEFAULT_ASF_ROOT)


def _sandbox_env() -> dict[str, str]:
    return asf_core.sandbox_env()


def _run_sandboxed_process(command: list[str], *, cwd: str, timeout: int | None = None) -> dict[str, Any]:
    return asf_core.run_sandboxed_process(command, cwd=cwd, asf_root=DEFAULT_ASF_ROOT, timeout=timeout)


def _sandbox_terminal(args: dict[str, Any]) -> str:
    return asf_core.sandbox_terminal(args, asf_root=DEFAULT_ASF_ROOT)


def _sandbox_execute_code(args: dict[str, Any]) -> str:
    return asf_core.sandbox_execute_code(args, asf_root=DEFAULT_ASF_ROOT)


def _sandbox_file_tools_enabled() -> bool:
    return _env_bool("ASF_HERMES_SANDBOX_FILE_TOOLS", True)


def _sandbox_file_tool(name: str, args: dict[str, Any], kwargs: dict[str, Any] | None = None) -> str:
    payload = {
        "tool": name,
        "args": args,
        "kwargs": {k: v for k, v in (kwargs or {}).items() if k in {"task_id"}},
    }
    worker = DEFAULT_ASF_ROOT / "wrapper" / "asf_file_worker.py"
    result = _run_sandboxed_process(
        [sys.executable, str(worker), json.dumps(payload, ensure_ascii=False)],
        cwd=_sandbox_workdir(),
    )
    if result.get("blocked"):
        return json.dumps(result, ensure_ascii=False)
    output = str(result.get("output", "")).strip()
    if result.get("exit_code") not in (0, None):
        return json.dumps({"error": output or f"sandboxed file worker failed with exit_code {result.get('exit_code')}"}, ensure_ascii=False)
    if not output:
        return json.dumps({"error": "sandboxed file worker produced no output"}, ensure_ascii=False)
    try:
        # Validate that the worker emitted the native Hermes payload. Some native
        # tools (notably truncated search_files) append a human hint after the JSON
        # object, so accept a JSON object prefix and return the original string.
        json.JSONDecoder().raw_decode(output)
        return output
    except Exception:
        return json.dumps({"error": f"sandboxed file worker produced invalid JSON: {output[:500]}"}, ensure_ascii=False)


def _persist_dispatch_output(
    *,
    tool_name: str,
    args: dict[str, Any],
    result: Any,
    task_id: str,
    session_id: str,
    tool_call_id: str,
    duration_ms: int | None,
) -> None:
    # Correlates the tool output with the row opened by on_pre_tool_call (same
    # call_key(task_id, tool_name, args)) and persists output_preview + tool_duration_ms.
    # finish_call_trace / the store are idempotent, so a duplicate from on_post_tool_call
    # (in environments where it fires) does not overwrite this row.
    output_risky, output_reason = _detect_output_risk(result)
    output_verdict = "DENY" if output_risky else None
    asf_core.finish_call_trace(
        tool_call_id=tool_call_id or None,
        session_id=session_id or None,
        task_id=task_id or None,
        source_tool_name=tool_name,
        args=args,
        result=result,
        duration_ms=duration_ms,
        side_effect_verified=False,
        side_effect_occurred=None,
        output_verdict=output_verdict,
        output_reason=output_reason if output_risky else None,
    )


def install_dispatch_wrapper() -> None:
    # The Hermes agentic runtime executes tools through tools.registry.dispatch and only ever
    # invokes the pre_tool_call hook (post_tool_call/transform_tool_result live on an unused
    # path), so output and tool_duration_ms can only be captured here. We wrap dispatch once,
    # whenever the plugin is enabled (not just when the sandbox is on), run the tool (sandboxed
    # when ASF_HERMES_SANDBOX is set, otherwise the original), then persist its output.
    global _DISPATCH_WRAPPED, _ORIGINAL_DISPATCH
    if _DISPATCH_WRAPPED or not _enabled():
        return
    try:
        from tools.registry import registry as tool_registry
    except Exception:
        return

    original = tool_registry.dispatch

    def asf_dispatch(name: str, args: dict | None = None, **kwargs: Any) -> Any:
        call_args = args if isinstance(args, dict) else {}
        task_id = str(kwargs.get("task_id", "") or "")
        session_id = str(kwargs.get("session_id", "") or "")
        tool_call_id = str(kwargs.get("tool_call_id", "") or "")
        sandboxed = _sandbox_enabled()
        file_tool_sandboxed = sandboxed and _sandbox_file_tools_enabled() and name in {"read_file", "write_file", "patch", "search_files"}
        start = time.monotonic()
        result: Any = None
        try:
            if sandboxed and name == "terminal":
                result = _sandbox_terminal(call_args)
            elif sandboxed and name == "execute_code":
                result = _sandbox_execute_code(call_args)
            elif file_tool_sandboxed:
                result = _sandbox_file_tool(name, call_args, kwargs)
            else:
                result = original(name, args, **kwargs)
            return result
        finally:
            duration_ms = int((time.monotonic() - start) * 1000)
            try:
                _persist_dispatch_output(
                    tool_name=name,
                    args=call_args,
                    result=result,
                    task_id=task_id,
                    session_id=session_id,
                    tool_call_id=tool_call_id,
                    duration_ms=duration_ms,
                )
            except Exception:
                pass

    tool_registry.dispatch = asf_dispatch
    _ORIGINAL_DISPATCH = original
    _DISPATCH_WRAPPED = True


def on_pre_tool_call(
    *,
    tool_name: str = "",
    args: dict[str, Any] | None = None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    **_: Any,
) -> dict[str, str] | None:
    if not _enabled() or not tool_name:
        return None
    install_dispatch_wrapper()

    args = args if isinstance(args, dict) else {}

    asf_tool_name = normalize_tool_name(tool_name)
    security_text = build_security_text(tool_name, args)

    decision = asf_core.asf_decision(
        agent_id=_agent_id(),
        asf_tool=asf_tool_name,
        security_text=security_text,
        action_id=tool_call_id or task_id or None,
        session_id=session_id or None,
        check_fn=lambda agent_id, asf_tool, text, sid: run_asf_check(agent_id, asf_tool, text, session_id=sid),
    )
    verdict = decision.verdict
    reason = decision.reason
    audit_hash = decision.audit_hash

    try:
        asf_core.start_call_trace(
            agent_id=_agent_id(),
            session_id=session_id or None,
            task_id=task_id or None,
            tool_call_id=tool_call_id or None,
            source_tool_name=tool_name,
            asf_tool_name=asf_tool_name,
            args=args,
            agent_model=_agent_model(),
            verdict=verdict,
            outcome=_outcome_from_verdict(verdict),
            reason=reason,
            latency_ms=decision.latency_ms,
            audit_hash=audit_hash,
        )
    except Exception:
        if _env_bool("ASF_HERMES_FAIL_CLOSED", False):
            return {"action": "block", "message": "[ASF BLOCKED] failed to persist Hermes trace"}

    if _mode() == "enforce":
        if verdict.upper() == "DENY":
            return _block_directive(verdict, reason)
        if verdict.upper() == "HITL":
            if not audit_hash:
                return _block_directive("HITL", f"No HITL event hash available: {reason}")
            approved, decision_reason = _wait_for_hitl_decision(audit_hash, reason)
            if approved:
                return None
            return _block_directive("HITL", decision_reason)
    if verdict.upper() == "DENY" and _env_bool("ASF_HERMES_FAIL_CLOSED", False):
        return _block_directive(verdict, reason)
    return None


def _detect_output_risk(result: Any) -> tuple[bool, str]:
    return asf_core.detect_output_risk(result)


def on_post_tool_call(
    *,
    tool_name: str = "",
    args: dict[str, Any] | None = None,
    result: Any = None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    duration_ms: int | None = None,
    **kwargs: Any,
) -> None:
    if not _enabled() or not tool_name:
        return

    if result is None:
        for key in ("result", "output", "response", "tool_output"):
            if key in kwargs:
                result = kwargs.get(key)
                break

    if duration_ms is None:
        for key in ("tool_duration_ms", "elapsed_ms", "latency_ms"):
            value = kwargs.get(key)
            if isinstance(value, (int, float)):
                duration_ms = int(value)
                break

    # Harmless fallback: the live runtime captures output via the dispatch wrapper, but if
    # post_tool_call does fire we still persist here. The store is idempotent, so this never
    # double-writes a row already finished by the dispatch wrapper.
    try:
        _persist_dispatch_output(
            tool_name=tool_name,
            args=args if isinstance(args, dict) else {},
            result=result,
            task_id=task_id,
            session_id=session_id,
            tool_call_id=tool_call_id,
            duration_ms=duration_ms,
        )
    except Exception:
        return


def register(ctx) -> None:
    global _PLUGIN_CONTEXT
    _PLUGIN_CONTEXT = ctx
    install_dispatch_wrapper()
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
