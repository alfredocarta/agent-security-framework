from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import uuid
from pathlib import Path
from typing import Any

AGENT_ID = "wrapper-agent"
MAX_OUTPUT_CHARS = 4000
DEFAULT_TIMEOUT_SECONDS = 15

_registered_db_url: str | None = None
_register_lock = threading.Lock()


def _register_agent_once() -> None:
    global _registered_db_url
    with _register_lock:
        import registry

        database_url = getattr(registry, "DATABASE_URL", "")
        if _registered_db_url == database_url and registry.agent_exists(AGENT_ID):
            return
        registry.add_or_update_agent(AGENT_ID, risk_level="medium", permissions=["shell"])
        _registered_db_url = database_url


def _preview(stdout: str, stderr: str) -> str:
    combined = stdout
    if stderr:
        combined = f"{combined}\n[stderr]\n{stderr}" if combined else f"[stderr]\n{stderr}"
    if len(combined) > MAX_OUTPUT_CHARS:
        return combined[:MAX_OUTPUT_CHARS] + "\n[truncated]"
    return combined


def _sandbox_command(command: str, workdir: str) -> tuple[list[str], str | None]:
    sandbox_exec = shutil.which("sandbox-exec")
    if not sandbox_exec:
        return ["/bin/sh", "-c", command], (
            "sandbox-exec not available. Running without OS sandbox; "
            "ASF pre-execution DENY/HITL blocking is still enforced."
        )

    profile = Path(__file__).with_name("asf_sandbox.sb")
    return [
        sandbox_exec,
        "-D",
        f"WORKDIR={workdir}",
        "-D",
        f"READ_ALLOW={workdir}",
        "-D",
        f"PROXY_PORT={os.environ.get('ASF_EGRESS_PROXY_PORT', '9')}",
        "-f",
        str(profile),
        "/bin/sh",
        "-c",
        command,
    ], None


def _audit_supervisor_action(action_id: str, command: str, outcome: str, reason: str) -> None:
    try:
        from audit import AUDITOR

        AUDITOR.log_event(
            AGENT_ID,
            f"shell:{action_id}",
            outcome,
            f"action_id={action_id}; command={command!r}; {reason}",
            session_id=action_id,
        )
    except Exception as exc:
        print(f"[ASF wrapper] supervisor audit write failed: {exc}", file=sys.stderr)


def run_action(command: str, *, workdir: str) -> dict[str, Any]:
    """Ask ASF for a verdict, execute only on ALLOW, and return a structured result.

    This is an opt-in feasibility spike for synthetic commands on macOS. It must not be
    used as a wrapper for a real interactive user shell.
    """
    action_id = str(uuid.uuid4())
    workdir_path = Path(workdir).expanduser().resolve()
    workdir_path.mkdir(parents=True, exist_ok=True)
    workdir_abs = str(workdir_path)

    _register_agent_once()

    from interceptor import hardened_interceptor

    interceptor_result = hardened_interceptor(AGENT_ID, "shell", command, session_id=action_id)
    verdict = interceptor_result[0]
    reason = interceptor_result[1] if len(interceptor_result) > 1 else ""
    if verdict in {"DENY", "HITL"}:
        _audit_supervisor_action(action_id, command, "SUPERVISOR_BLOCKED", reason)
        return {
            "verdict": verdict,
            "reason": reason,
            "executed": False,
            "action_id": action_id,
        }

    if verdict != "ALLOW":
        reason = f"invalid interceptor verdict: {verdict!r}"
        _audit_supervisor_action(action_id, command, "SUPERVISOR_BLOCKED", reason)
        return {
            "verdict": "DENY",
            "reason": reason,
            "executed": False,
            "action_id": action_id,
        }

    argv, sandbox_warning = _sandbox_command(command, workdir_abs)
    try:
        completed = subprocess.run(
            argv,
            cwd=workdir_abs,
            text=True,
            capture_output=True,
            timeout=DEFAULT_TIMEOUT_SECONDS,
            check=False,
        )
        exit_code = completed.returncode
        output_preview = _preview(completed.stdout, completed.stderr)
    except subprocess.TimeoutExpired as exc:
        exit_code = 124
        timeout_stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        timeout_stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        output_preview = _preview(timeout_stdout, timeout_stderr)
        if output_preview:
            output_preview = f"{output_preview}\n[timeout after {DEFAULT_TIMEOUT_SECONDS}s]"
        else:
            output_preview = f"[timeout after {DEFAULT_TIMEOUT_SECONDS}s]"

    result: dict[str, Any] = {
        "verdict": verdict,
        "reason": reason,
        "executed": True,
        "action_id": action_id,
        "exit_code": exit_code,
        "output_preview": output_preview,
    }
    if sandbox_warning:
        result["sandbox_warning"] = sandbox_warning

    audit_reason = f"exit_code={exit_code}"
    if sandbox_warning:
        audit_reason = f"{audit_reason}; {sandbox_warning}"
    _audit_supervisor_action(action_id, command, "SUPERVISOR_EXECUTED", audit_reason)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ASF wrapper supervisor spike")
    parser.add_argument("command", help="Synthetic command to run only if ASF returns ALLOW")
    parser.add_argument(
        "--workdir",
        default=os.getcwd(),
        help="Directory where allowed commands run and where sandbox writes are permitted",
    )
    args = parser.parse_args(argv)

    result = run_action(args.command, workdir=args.workdir)
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result.get("executed"):
        return 126
    return int(result.get("exit_code") or 0)


if __name__ == "__main__":
    raise SystemExit(main())
