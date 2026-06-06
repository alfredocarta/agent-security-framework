from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path
from typing import Any


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

_AGENT_REGISTERED = False

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
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _mode() -> str:
    return os.environ.get("ASF_HERMES_MODE", "monitor").strip().lower()


def _enabled() -> bool:
    return _env_bool("ASF_HERMES_ENABLED", True)


def _agent_id() -> str:
    return os.environ.get("ASF_HERMES_AGENT_ID", "hermes-live-agent")


def _agent_model() -> str | None:
    explicit = os.environ.get("ASF_HERMES_AGENT_MODEL")
    if explicit:
        return explicit
    try:
        import yaml

        config_path = Path(os.environ.get("HERMES_CONFIG", str(Path.home() / ".hermes" / "config.yaml")))
        config = yaml.safe_load(config_path.read_text()) or {}
        model_cfg = config.get("model", {}) if isinstance(config, dict) else {}
        model = model_cfg.get("default") or model_cfg.get("model")
        provider = model_cfg.get("provider")
        if model and provider:
            return f"{model} via {provider}"
        return model
    except Exception:
        return None


def normalize_tool_name(tool_name: str) -> str:
    if tool_name in TOOL_MAP:
        return TOOL_MAP[tool_name]
    for prefix, mapped in PREFIX_MAP.items():
        if tool_name.startswith(prefix):
            return mapped
    return tool_name


def _safe_preview(value: Any, max_chars: int | None = None) -> str:
    max_chars = max_chars or int(os.environ.get("ASF_HERMES_MAX_ARG_BYTES", "8192"))
    text = str(value)
    if len(text) <= max_chars:
        return text
    return f"{text[:max_chars]}…[truncated {len(text) - max_chars} chars]"


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
    global _AGENT_REGISTERED
    try:
        import registry

        # Reset mode (ASF_HERMES_REGISTRY_RESET=true) is an explicit opt-in for smoke
        # tests / scenario resets: it re-asserts permissions and clears any suspension
        # on every check. In normal (enforcement) operation a kill-switch suspension
        # MUST persist until a human reinstates the agent, so we register the agent only
        # once (when missing) and never auto-clear status here. Re-running
        # add_or_update_agent unconditionally would flip status back to "active" and
        # silently defeat the kill-switch.
        if _env_bool("ASF_HERMES_REGISTRY_RESET", False):
            registry.add_or_update_agent(
                _agent_id(),
                risk_level=os.environ.get("ASF_HERMES_RISK_LEVEL", "high"),
                permissions=_all_permissions(),
            )
            if hasattr(registry, "reinstate_agent"):
                registry.reinstate_agent(_agent_id())
            return

        if _AGENT_REGISTERED:
            return
        already_registered = (
            registry.agent_exists(_agent_id()) if hasattr(registry, "agent_exists") else False
        )
        if not already_registered:
            registry.add_or_update_agent(
                _agent_id(),
                risk_level=os.environ.get("ASF_HERMES_RISK_LEVEL", "high"),
                permissions=_all_permissions(),
            )
        _AGENT_REGISTERED = True
    except Exception:
        if _env_bool("ASF_HERMES_FAIL_CLOSED", False):
            raise


def run_asf_check(agent_id: str, tool_name: str, security_text: str, session_id: str | None = None) -> tuple[str, str]:
    register_hermes_agent()
    from interceptor import hardened_interceptor

    result = hardened_interceptor(agent_id, tool_name, security_text, session_id=session_id)
    verdict = result[0] if len(result) > 0 else "DENY"
    reason = result[1] if len(result) > 1 else "No reason returned"
    return str(verdict), str(reason)


def _store():
    from hermes_trace_store import get_default_store, HermesTraceStore

    explicit = os.environ.get("ASF_HERMES_DB")
    if explicit:
        return HermesTraceStore(explicit)
    return get_default_store()


def _outcome_from_verdict(verdict: str) -> str:
    verdict = verdict.upper()
    if verdict == "ALLOW":
        return "ALLOWED"
    if verdict == "HITL":
        return "HITL_REQUESTED"
    if verdict == "DENY":
        return "BLOCKED"
    return verdict


def _block_directive(verdict: str, reason: str) -> dict[str, str]:
    if verdict.upper() == "HITL":
        return {"action": "block", "message": f"[ASF HITL] Human approval required: {reason}"}
    return {"action": "block", "message": f"[ASF BLOCKED] {reason}"}


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

    args = args if isinstance(args, dict) else {}
    asf_tool_name = normalize_tool_name(tool_name)
    security_text = build_security_text(tool_name, args)
    t0 = time.monotonic()
    verdict = "ALLOW"
    reason = "ASF monitor disabled"

    try:
        verdict, reason = run_asf_check(_agent_id(), asf_tool_name, security_text, session_id=session_id or None)
    except Exception as exc:
        verdict = "DENY" if _env_bool("ASF_HERMES_FAIL_CLOSED", False) else "ALLOW"
        reason = f"ASF check failed: {exc}"

    asf_latency_ms = int((time.monotonic() - t0) * 1000)
    try:
        _store().start_trace(
            agent_id=_agent_id(),
            session_id=session_id or None,
            task_id=task_id or None,
            tool_call_id=tool_call_id or None,
            hermes_tool_name=tool_name,
            asf_tool_name=asf_tool_name,
            args=args,
            agent_model=_agent_model(),
            verdict=verdict,
            outcome=_outcome_from_verdict(verdict),
            reason=reason,
            asf_latency_ms=asf_latency_ms,
        )
    except Exception:
        if _env_bool("ASF_HERMES_FAIL_CLOSED", False):
            return {"action": "block", "message": "[ASF BLOCKED] failed to persist Hermes trace"}

    if _mode() == "enforce" and verdict.upper() in {"DENY", "HITL"}:
        return _block_directive(verdict, reason)
    if verdict.upper() == "DENY" and _env_bool("ASF_HERMES_FAIL_CLOSED", False):
        return _block_directive(verdict, reason)
    return None


def _detect_output_risk(result: Any) -> tuple[bool, str]:
    text = str(result)
    for pattern in SECRET_PATTERNS:
        if pattern.search(text):
            return True, f"Sensitive output matched pattern {pattern.pattern[:40]}"
    canary = os.environ.get("ASF_HERMES_CANARY")
    if canary and canary in text:
        return True, "Canary value appeared in tool output"
    return False, ""


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

    if duration_ms is None:
        for key in ("tool_duration_ms", "elapsed_ms", "latency_ms"):
            value = kwargs.get(key)
            if isinstance(value, (int, float)):
                duration_ms = int(value)
                break

    output_risky, output_reason = _detect_output_risk(result)
    output_verdict = "DENY" if output_risky else None
    try:
        _store().finish_trace(
            tool_call_id=tool_call_id or None,
            session_id=session_id or None,
            task_id=task_id or None,
            result=result,
            tool_duration_ms=duration_ms,
            side_effect_verified=False,
            side_effect_occurred=None,
            output_verdict=output_verdict,
            output_reason=output_reason if output_risky else None,
        )
    except Exception:
        return


def register(ctx) -> None:
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
