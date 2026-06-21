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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import unquote, urlparse


@dataclass(frozen=True)
class AsfDecision:
    verdict: str
    reason: str
    audit_hash: str | None
    latency_ms: int


DEFAULT_TOOL_MAP = {
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
    "shell": "shell",
    "python": "code_execution",
}

DEFAULT_PREFIX_MAP = {"browser_": "browser"}

SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\s*[=:]\s*[^\s'\"]{8,}"),
    re.compile(r"(?i)\b(bearer|sk-[a-z0-9_-]{12,}|ghp_[a-z0-9_]{20,})"),
)

_TRACE_BY_CALL_KEY: dict[tuple[str, str, str], str] = {}
_TRACE_LOCK = threading.Lock()
DEFAULT_AGENT_ID = "hermes-live-agent"
_ENV_PRODUCTION = "production"
_ENV_TEST = "test"
_ENV_STATE_FILE_ENV = "ASF_ENV_STATE_FILE"
_ENV_STATE_FILE_NAME = "asf_env"


def asf_env_state_file() -> Path:
    explicit = os.environ.get(_ENV_STATE_FILE_ENV)
    if explicit:
        return Path(explicit).expanduser()
    return Path.home() / ".cache" / "asf-hook" / _ENV_STATE_FILE_NAME


def _normalize_asf_env(raw_value: str | None, source: str, *, invalid_default: str | None) -> str | None:
    value = (raw_value or "").strip().lower()
    if not value:
        return None
    if value in {_ENV_TEST, _ENV_PRODUCTION}:
        return value
    if invalid_default:
        message = f"[ASF WARN] Unknown {source}={value!r}; using {invalid_default!r}."
    else:
        message = f"[ASF WARN] Unknown {source}={value!r}; ignoring."
    print(message, file=sys.stderr)
    return invalid_default


def _read_asf_env_state() -> str | None:
    state_file = asf_env_state_file()
    try:
        raw_value = state_file.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        print(f"[ASF WARN] Could not read {state_file}: {exc}; using 'production'.", file=sys.stderr)
        return None
    return _normalize_asf_env(raw_value, str(state_file), invalid_default=None)


def _resolve_asf_env() -> str:
    raw_env = os.environ.get("ASF_ENV")
    if raw_env is not None:
        return _normalize_asf_env(raw_env, "ASF_ENV", invalid_default=_ENV_PRODUCTION) or _ENV_PRODUCTION
    return _read_asf_env_state() or _ENV_PRODUCTION


_ASF_ENV = _resolve_asf_env()


def asf_env() -> str:
    return _ASF_ENV


def is_test_env() -> bool:
    return _ASF_ENV == _ENV_TEST


def asf_root() -> Path:
    env_root = os.environ.get("ASF_ROOT")
    if env_root:
        return Path(env_root).expanduser()
    return Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def asf_test_db_path() -> Path:
    explicit = os.environ.get("ASF_TEST_DB")
    if explicit:
        return Path(explicit).expanduser()
    return asf_root() / "asf_test.db"


def sqlite_url_for_path(path: str | Path) -> str:
    return f"sqlite:///{Path(path)}"


def sqlite_path_from_url(database_url: str) -> Path | None:
    if not database_url.startswith("sqlite"):
        return None
    parsed = urlparse(database_url)
    if parsed.scheme not in {"sqlite", "sqlite3"}:
        return None
    if parsed.path in {"", "/:memory:"}:
        return None
    return Path(unquote(parsed.path))


def effective_database_url(*, production_db_path: str | Path | None = None) -> str:
    if is_test_env():
        return sqlite_url_for_path(asf_test_db_path())
    explicit = os.environ.get("DATABASE_URL")
    if explicit:
        return explicit
    return sqlite_url_for_path(production_db_path or (asf_root() / "asf_local.db"))


def effective_sqlite_db_path(
    *,
    explicit_path_env: str | None = None,
    production_db_path: str | Path | None = None,
) -> Path:
    if explicit_path_env:
        explicit = os.environ.get(explicit_path_env)
        if explicit:
            return Path(explicit).expanduser()

    parsed = sqlite_path_from_url(effective_database_url(production_db_path=production_db_path))
    if parsed is not None:
        return parsed

    if is_test_env():
        return asf_test_db_path()
    return Path(production_db_path or (asf_root() / "asf_local.db"))


def namespace_agent_id(agent_id: str) -> str:
    if not is_test_env():
        return agent_id
    return agent_id if agent_id.startswith("test-") else f"test-{agent_id}"


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_list(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return []
    values: list[str] = []
    for part in re.split(r"[,\n]", raw):
        value = part.strip()
        if value:
            values.append(value)
    return values


def normalize_tool_name(tool_name: str, tool_map: dict[str, str] | None = None, prefix_map: dict[str, str] | None = None) -> str:
    tool_map = tool_map or DEFAULT_TOOL_MAP
    prefix_map = prefix_map or DEFAULT_PREFIX_MAP
    if tool_name in tool_map:
        return tool_map[tool_name]
    for prefix, mapped in prefix_map.items():
        if tool_name.startswith(prefix):
            return mapped
    return tool_name


def redact_text(text: str, *, canary_env: str = "ASF_HERMES_CANARY") -> str:
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED_SECRET]", redacted)
    canary = os.environ.get(canary_env)
    if canary:
        redacted = redacted.replace(canary, "[REDACTED_CANARY]")
    return redacted


def redact_value(value: Any, *, canary_env: str = "ASF_HERMES_CANARY") -> Any:
    if isinstance(value, str):
        return redact_text(value, canary_env=canary_env)
    if isinstance(value, dict):
        return {k: redact_value(v, canary_env=canary_env) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v, canary_env=canary_env) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_value(v, canary_env=canary_env) for v in value)
    return value


def safe_preview(value: Any, max_chars: int | None = None, *, max_arg_env: str = "ASF_HERMES_MAX_ARG_BYTES") -> str:
    max_chars = max_chars or int(os.environ.get(max_arg_env, "8192"))
    text = redact_text(str(value))
    if len(text) <= max_chars:
        return text
    return f"{text[:max_chars]}...[truncated {len(text) - max_chars} chars]"


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def args_hash(args: Any) -> str:
    return hashlib.sha256(stable_json(args).encode("utf-8", errors="replace")).hexdigest()


def call_key(task_id: str, tool_name: str, args: dict[str, Any] | None) -> tuple[str, str, str]:
    return (task_id or "", tool_name or "", args_hash(redact_value(args or {})))


def outcome_from_verdict(verdict: str) -> str:
    verdict = verdict.upper()
    if verdict == "ALLOW":
        return "ALLOWED"
    if verdict == "HITL":
        return "HITL_REQUESTED"
    if verdict == "DENY":
        return "BLOCKED"
    return verdict


def block_directive(verdict: str, reason: str) -> dict[str, str]:
    if verdict.upper() == "HITL":
        return {"action": "block", "message": f"[ASF HITL] Human approval required: {reason}"}
    return {"action": "block", "message": f"[ASF BLOCKED] {reason}"}


def run_asf_check(agent_id: str, asf_tool: str, security_text: str, session_id: str | None = None) -> tuple[str, str]:
    from interceptor import hardened_interceptor

    result = hardened_interceptor(agent_id, asf_tool, security_text, session_id=session_id)
    verdict = result[0] if len(result) > 0 else "DENY"
    reason = result[1] if len(result) > 1 else "No reason returned"
    return str(verdict), str(reason)


def asf_decision(
    *,
    agent_id: str,
    asf_tool: str,
    security_text: str,
    action_id: str | None = None,
    session_id: str | None = None,
    fail_closed_env: str = "ASF_HERMES_FAIL_CLOSED",
    check_fn: Callable[[str, str, str, str | None], tuple[str, str]] | None = None,
    register_fn: Callable[[], None] | None = None,
) -> AsfDecision:
    if register_fn is not None:
        register_fn()
    auditor = None
    audit_hash_before = None
    try:
        from audit import AUDITOR as auditor

        audit_hash_before = auditor.last_hash_for(agent_id)
    except Exception:
        auditor = None

    t0 = time.monotonic()
    try:
        verdict, reason = (check_fn or run_asf_check)(agent_id, asf_tool, security_text, session_id)
    except Exception as exc:
        verdict = "DENY" if env_bool(fail_closed_env, False) else "ALLOW"
        reason = f"ASF check failed: {exc}"
    latency_ms = int((time.monotonic() - t0) * 1000)

    audit_hash = None
    if auditor is not None:
        try:
            audit_hash_after = auditor.last_hash_for(agent_id)
            if audit_hash_after and audit_hash_after != audit_hash_before:
                audit_hash = audit_hash_after
        except Exception:
            audit_hash = None
    return AsfDecision(str(verdict), str(reason), audit_hash, latency_ms)


def store_from_env(db_env: str = "ASF_HERMES_DB"):
    from hermes_trace_store import HermesTraceStore, get_default_store

    explicit = os.environ.get(db_env)
    if explicit:
        return HermesTraceStore(explicit)
    return get_default_store()


def start_call_trace(
    *,
    agent_id: str,
    source_tool_name: str,
    asf_tool_name: str,
    args: dict[str, Any],
    verdict: str,
    outcome: str,
    reason: str,
    latency_ms: int,
    audit_hash: str | None,
    session_id: str | None = None,
    task_id: str | None = None,
    tool_call_id: str | None = None,
    agent_type: str | None = "hermes-agent",
    agent_model: str | None = None,
    db_env: str = "ASF_HERMES_DB",
) -> str:
    trace_id = store_from_env(db_env).start_trace(
        agent_id=agent_id,
        session_id=session_id or None,
        task_id=task_id or None,
        tool_call_id=tool_call_id or None,
        hermes_tool_name=source_tool_name,
        asf_tool_name=asf_tool_name,
        args=redact_value(args),
        agent_type=agent_type,
        agent_model=agent_model,
        verdict=verdict,
        outcome=outcome,
        reason=reason,
        asf_latency_ms=latency_ms,
        audit_hash=audit_hash,
    )
    with _TRACE_LOCK:
        _TRACE_BY_CALL_KEY[call_key(task_id or "", source_tool_name, args)] = trace_id
    return trace_id


def finish_call_trace(
    *,
    source_tool_name: str,
    args: dict[str, Any] | None,
    result: Any,
    session_id: str | None = None,
    task_id: str | None = None,
    tool_call_id: str | None = None,
    duration_ms: int | None = None,
    side_effect_verified: bool | None = False,
    side_effect_occurred: bool | None = None,
    output_verdict: str | None = None,
    output_reason: str | None = None,
    db_env: str = "ASF_HERMES_DB",
) -> int:
    with _TRACE_LOCK:
        trace_id = _TRACE_BY_CALL_KEY.pop(call_key(task_id or "", source_tool_name, args), None)
    return store_from_env(db_env).finish_trace(
        tool_call_id=tool_call_id or None,
        session_id=session_id or None,
        task_id=task_id or None,
        trace_id=trace_id,
        result=redact_value(result),
        tool_duration_ms=duration_ms,
        side_effect_verified=side_effect_verified,
        side_effect_occurred=side_effect_occurred,
        output_verdict=output_verdict,
        output_reason=output_reason,
    )


def allow_directive_reason(kind: str, value: str) -> str:
    return f"{kind} is outside ASF Hermes allowlist: {value}"


def command_from_shell(command: str) -> str:
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        parts = command.strip().split()
    if not parts:
        return ""
    first = parts[0]
    if first in {"env", "command", "time", "timeout"} and len(parts) > 1:
        first = parts[1]
    return first


def is_command_allowed(command: str, *, cmd_allow_env: str = "ASF_HERMES_CMD_ALLOW") -> bool:
    allowed = env_list(cmd_allow_env)
    if not allowed:
        return True
    executable = command_from_shell(command)
    if not executable:
        return True
    executable_name = Path(executable).name
    return executable in allowed or executable_name in allowed


def sandbox_workdir(*, workdir_env: str = "ASF_HERMES_SANDBOX_WORKDIR", session_env: str = "ASF_HERMES_SESSION") -> str:
    configured = os.environ.get(workdir_env)
    if configured:
        path = Path(configured).expanduser().resolve()
    else:
        path = Path(tempfile.gettempdir()) / "asf-hermes-sandbox" / (os.environ.get(session_env, "default"))
    path.mkdir(parents=True, exist_ok=True)
    return str(path)


def path_allowed(path_value: str | None, *, write: bool = False, path_allow_env: str = "ASF_HERMES_PATH_ALLOW", workdir_env: str = "ASF_HERMES_SANDBOX_WORKDIR") -> bool:
    if not path_value:
        return True
    root = Path(sandbox_workdir(workdir_env=workdir_env)).resolve()
    candidate = Path(path_value).expanduser().resolve()
    if write:
        try:
            candidate.relative_to(root)
            return True
        except Exception:
            return False
    allowed = [root]
    allowed.extend(Path(p).expanduser().resolve() for p in env_list(path_allow_env))
    for base in allowed:
        try:
            candidate.relative_to(base)
            return True
        except Exception:
            continue
    return False


def hosts_in_text(text: str) -> set[str]:
    hosts: set[str] = set()
    for match in re.finditer(r"https?://[^\s'\"]+", text):
        parsed = urlparse(match.group(0))
        if parsed.hostname:
            hosts.add(parsed.hostname.lower())
    for flag in ("--connect-to", "--resolve"):
        if flag in text:
            hosts.add("dynamic-network-target")
    return hosts


def host_allowed(host: str, allowed: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for item in allowed:
        value = item.lower().rstrip(".")
        if host == value or host.endswith(f".{value}"):
            return True
    return False


def network_allowed_for_text(text: str, *, net_allow_env: str = "ASF_HERMES_NET_ALLOW") -> tuple[bool, str | None]:
    allowed = env_list(net_allow_env)
    if not allowed:
        return True, None
    for host in hosts_in_text(text):
        if not host_allowed(host, allowed):
            return False, host
    return True, None


def allowlist_block_reason(tool_name: str, args: dict[str, Any]) -> str | None:
    if tool_name in {"terminal", "shell"}:
        command = str(args.get("command", ""))
        if not is_command_allowed(command):
            return allow_directive_reason("command", command_from_shell(command))
        ok, host = network_allowed_for_text(command)
        if not ok and host:
            return allow_directive_reason("network destination", host)
    elif tool_name in {"execute_code", "python"}:
        ok, host = network_allowed_for_text(str(args.get("code", "")))
        if not ok and host:
            return allow_directive_reason("network destination", host)

    if tool_name in {"read_file", "write_file", "patch", "search_files"}:
        path = args.get("path")
        if isinstance(path, str) and not path_allowed(path, write=tool_name in {"write_file", "patch"}):
            return allow_directive_reason("path", path)
    return None


def find_hitl_decision(event_hash: str) -> tuple[str, str] | None:
    from registry import AuditModel, SessionLocal

    marker = f"event:{event_hash}"
    db = SessionLocal()
    try:
        row = (
            db.query(AuditModel)
            .filter(AuditModel.outcome.in_(["HITL_APPROVED", "HITL_REJECTED"]))
            .filter(AuditModel.reason.contains(marker))
            .order_by(AuditModel.timestamp.desc())
            .first()
        )
        if row is None:
            return None
        return str(row.outcome), str(row.reason)
    finally:
        db.close()


def wait_for_hitl_decision(event_hash: str, reason: str, *, timeout_env: str = "ASF_HERMES_HITL_TIMEOUT", poll_env: str = "ASF_HERMES_HITL_POLL_MS", on_timeout_env: str = "ASF_HERMES_HITL_ON_TIMEOUT") -> tuple[bool, str]:
    timeout_s = float(os.environ.get(timeout_env, "300"))
    poll_ms = int(os.environ.get(poll_env, "1000"))
    on_timeout = os.environ.get(on_timeout_env, "block").strip().lower()
    deadline = time.monotonic() + max(timeout_s, 0.0)
    print(f"[ASF HITL] Waiting for dashboard decision event:{event_hash}", file=sys.stderr)
    while True:
        decision = find_hitl_decision(event_hash)
        if decision is not None:
            outcome, decision_reason = decision
            if outcome == "HITL_APPROVED":
                return True, f"HITL approved for event:{event_hash}: {decision_reason}"
            return False, f"HITL rejected for event:{event_hash}: {decision_reason}"
        if time.monotonic() >= deadline:
            if on_timeout == "allow":
                return True, f"HITL timeout allowed by {on_timeout_env}=allow for event:{event_hash}"
            return False, f"HITL timeout blocked for event:{event_hash}: {reason}"
        time.sleep(max(poll_ms, 1) / 1000.0)


def sandbox_enabled(*, sandbox_env: str = "ASF_HERMES_SANDBOX") -> bool:
    return env_bool(sandbox_env, False)


def sandbox_cwd(requested: str | None, root: str) -> str:
    root_path = Path(root).resolve()
    if requested:
        candidate = Path(requested).expanduser().resolve()
        try:
            candidate.relative_to(root_path)
            candidate.mkdir(parents=True, exist_ok=True)
            return str(candidate)
        except Exception:
            pass
    return str(root_path)


def sandbox_argv(command: list[str], *, asf_root: Path, profile_path: Path | None = None) -> tuple[list[str], str | None]:
    sandbox_exec = shutil.which("sandbox-exec")
    if not sandbox_exec:
        warning = "sandbox unavailable: sandbox-exec not available; refusing to execute unconfined"
        if env_bool("ASF_HERMES_SANDBOX_ALLOW_UNCONFINED", False) and not env_bool("ASF_HERMES_SANDBOX_FAIL_CLOSED", False):
            return command, "sandbox-exec not available, executing without OS sandbox because ASF_HERMES_SANDBOX_ALLOW_UNCONFINED=true"
        if env_bool("ASF_HERMES_SANDBOX_FAIL_CLOSED", True):
            raise RuntimeError(warning)
        raise RuntimeError(warning)
    profile = profile_path or asf_root / "wrapper" / "asf_sandbox.sb"
    return [
        sandbox_exec,
        "-D",
        f"WORKDIR={sandbox_workdir()}",
        "-D",
        f"PROXY_PORT={os.environ.get('ASF_EGRESS_PROXY_PORT', '9')}",
        "-f",
        str(profile),
        *command,
    ], None


def sandbox_env() -> dict[str, str]:
    env = os.environ.copy()
    proxy_port = os.environ.get("ASF_EGRESS_PROXY_PORT")
    if proxy_port:
        proxy_url = f"http://127.0.0.1:{proxy_port}"
        env["HTTP_PROXY"] = proxy_url
        env["HTTPS_PROXY"] = proxy_url
        env["http_proxy"] = proxy_url
        env["https_proxy"] = proxy_url
        env["NO_PROXY"] = ""
        env["no_proxy"] = ""
    return env


def run_sandboxed_process(command: list[str], *, cwd: str, asf_root: Path, timeout: int | None = None, profile_path: Path | None = None) -> dict[str, Any]:
    try:
        argv, warning = sandbox_argv(command, asf_root=asf_root, profile_path=profile_path)
    except RuntimeError as exc:
        return {
            "error": str(exc),
            "exit_code": 126,
            "sandboxed": False,
            "blocked": True,
        }
    completed = subprocess.run(
        argv,
        cwd=cwd,
        text=True,
        capture_output=True,
        env=sandbox_env(),
        timeout=timeout or int(os.environ.get("ASF_HERMES_SANDBOX_TIMEOUT", "30")),
        check=False,
    )
    output = completed.stdout
    if completed.stderr:
        output = f"{output}\n[stderr]\n{completed.stderr}" if output else f"[stderr]\n{completed.stderr}"
    result: dict[str, Any] = {"output": output, "exit_code": completed.returncode, "sandboxed": warning is None}
    if warning:
        result["sandbox_warning"] = warning
    return result


def sandbox_terminal(args: dict[str, Any], *, asf_root: Path) -> str:
    if args.get("background") or args.get("pty"):
        return json.dumps({"error": "ASF sandbox MVP supports only foreground non-PTY terminal calls"})
    root = sandbox_workdir()
    cwd = sandbox_cwd(args.get("workdir"), root)
    result = run_sandboxed_process(
        ["/bin/sh", "-c", str(args.get("command", ""))],
        cwd=cwd,
        asf_root=asf_root,
        timeout=args.get("timeout"),
    )
    return json.dumps(result, ensure_ascii=False)


def sandbox_execute_code(args: dict[str, Any], *, asf_root: Path) -> str:
    root = sandbox_workdir()
    cwd = sandbox_cwd(args.get("workdir"), root)
    code = str(args.get("code", ""))
    result = run_sandboxed_process([sys.executable, "-c", code], cwd=cwd, asf_root=asf_root)
    return json.dumps(result, ensure_ascii=False)


def detect_output_risk(result: Any, *, canary_env: str = "ASF_HERMES_CANARY") -> tuple[bool, str]:
    text = str(result)
    for pattern in SECRET_PATTERNS:
        if pattern.search(text):
            return True, f"Sensitive output matched pattern {pattern.pattern[:40]}"
    canary = os.environ.get(canary_env)
    if canary and canary in text:
        return True, "Canary value appeared in tool output"
    return False, ""
