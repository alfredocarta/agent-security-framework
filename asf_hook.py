#!/usr/bin/env python3
"""
ASF PreToolUse hook for Claude Code.

Registered in ~/.claude/settings.json under hooks.PreToolUse.
Claude Code calls this script before every matched Bash execution.

Connects to asf_hook_daemon on SOCKET_PATH. If the daemon is not
running, starts it automatically (first call pays startup cost).

Exit 0 = allow, exit 2 = block (stdout shown to Claude Code as reason).

Env:
  ASF_HOOK_MONITOR_ONLY=true       kill-switch: monitor only, never block (default)
  ASF_HOOK_MONITOR_ONLY=false      enforce ASF DENY/HITL decisions
  ASF_HOOK_FAIL_CLOSED=true        block on daemon errors instead of allow
  ASF_HOOK_RETRIES=2               connection retry count (default 2, 0-10)
  ASF_HOOK_STARTUP_TIMEOUT=10      seconds to wait for daemon to start (1-60)
"""

import sys
import json
import os
import re
import shlex
import socket
import stat as _stat
import struct
import subprocess
import time
import fcntl

from claude_trace_store import get_default_store, make_tool_call_id

RUNTIME_DIR     = os.path.expanduser("~/.cache/asf-hook")
SOCKET_PATH     = os.path.join(RUNTIME_DIR, "asf_hook.sock")
PID_FILE        = os.path.join(RUNTIME_DIR, "asf_hook.pid")
LOCK_FILE       = os.path.join(RUNTIME_DIR, "asf_hook.lock")
DAEMON_SCRIPT   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "asf_hook_daemon.py")
WATCHED_FILES   = [
    DAEMON_SCRIPT,
    os.path.join(os.path.dirname(DAEMON_SCRIPT), "hardening.py"),
    os.path.join(os.path.dirname(DAEMON_SCRIPT), "interceptor.py"),
    os.path.join(os.path.dirname(DAEMON_SCRIPT), "claude_trace_store.py"),
]
PYTHON          = "/Users/alfredo/miniconda3/envs/eval-framework/bin/python"
TIMEOUT         = 1.0
MAX_STDIN_BYTES = 256 * 1024

# macOS LOCAL_PEERPID constants (SOL_LOCAL=0, LOCAL_PEERPID=2).
_SOL_LOCAL      = 0
_LOCAL_PEERPID  = 2

def _edit_extractor(i):
    parts = [f"path={i.get('file_path', '')}"]
    if i.get("new_string") is not None:
        parts.append(f"new={i.get('new_string', '')}")
    for edit in i.get("edits", []) or []:
        parts.append(f"new={edit.get('new_string', '')}")
    return "\n".join(parts)


# Native Claude Code tools routed through ASF. Map tool name -> (ASF tool category,
# extractor that builds the text ASF inspects). Tools not listed are passed through
# untouched. In monitor mode (default) every match is logged but never blocked.
TOOL_MAP = {
    "Bash":         ("shell",       lambda i: i.get("command", "")),
    "Read":         ("file_read",   lambda i: f"path={i.get('file_path', '')}"),
    "Write":        ("file_write",  lambda i: f"path={i.get('file_path', '')}\ncontent={i.get('content', '')}"),
    "Edit":         ("code_edit",   _edit_extractor),
    "MultiEdit":    ("code_edit",   _edit_extractor),
    "NotebookEdit": ("code_edit",   lambda i: f"path={i.get('notebook_path', '')}\nnew={i.get('new_source', '')}"),
    "Glob":         ("file_search", lambda i: f"pattern={i.get('pattern', '')} path={i.get('path', '')}"),
    "Grep":         ("file_search", lambda i: f"pattern={i.get('pattern', '')} path={i.get('path', '')}"),
    "WebFetch":     ("web",         lambda i: f"url={i.get('url', '')} prompt={i.get('prompt', '')}"),
}

# Parsed passthrough: single command, no shell metacharacters, no substitution.
# ps/pgrep excluded: wide flag variants expose env vars with tokens.
_SAFE_PASSTHROUGH_CMDS = {
    "ls", "cd", "pwd",
    "which", "type", "df",
}
_SHELL_META = re.compile(r"[;&|`$<>\n\r()]")


def _int_env(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return min(max(int(os.environ.get(name, str(default))), lo), hi)
    except ValueError:
        # A typo'd env var must not block every tool call; warn and use the default.
        print(f"[ASF WARN] invalid env {name}, using default {default}", file=sys.stderr, flush=True)
        return default


def _float_env(name: str, default: float, lo: float, hi: float) -> float:
    try:
        return min(max(float(os.environ.get(name, str(default))), lo), hi)
    except ValueError:
        print(f"[ASF WARN] invalid env {name}, using default {default}", file=sys.stderr, flush=True)
        return default


RETRIES         = _int_env("ASF_HOOK_RETRIES", 2, 0, 10)
STARTUP_TIMEOUT = _float_env("ASF_HOOK_STARTUP_TIMEOUT", 10.0, 1.0, 60.0)
FAIL_CLOSED     = os.environ.get("ASF_HOOK_FAIL_CLOSED", "false").lower() == "true"
# Monitor mode (default): ASF logs every matched tool call to the audit trail but never
# blocks. Set ASF_HOOK_MONITOR_ONLY=false to let DENY verdicts block the tool.
MONITOR_ONLY    = os.environ.get("ASF_HOOK_MONITOR_ONLY", "true").lower() == "true"


def _fail_open(reason: str) -> None:
    """Exit safely on a malformed payload or broken runtime.

    Default posture is fail-open: a bad/unexpected hook payload or a runtime problem must
    never lock the user out of their own tools. Only block (exit 2) when the operator has
    explicitly opted into ASF_HOOK_FAIL_CLOSED=true.
    """
    if FAIL_CLOSED:
        print(f"[ASF DENY] {reason}", flush=True)
        sys.exit(2)
    print(f"[ASF WARN] fail-open: {reason}", file=sys.stderr, flush=True)
    sys.exit(0)


def is_bash_passthrough(command: str) -> bool:
    if _SHELL_META.search(command):
        return False
    try:
        parts = shlex.split(command)
    except ValueError:
        return False
    return bool(parts) and parts[0] in _SAFE_PASSTHROUGH_CMDS


def _open_runtime_file(path, mode=0o600):
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, mode)
    try:
        st = os.fstat(fd)
        if not _stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1:
            raise RuntimeError(f"unsafe runtime file: {path}")
        os.ftruncate(fd, 0)
    except Exception:
        os.close(fd)
        raise
    return os.fdopen(fd, "w")


def _read_runtime_pid() -> int:
    fd = os.open(PID_FILE, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not _stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_size > 16:
            raise RuntimeError(f"unsafe pid file: {PID_FILE}")
        return int(os.read(fd, 16).decode().strip())
    finally:
        os.close(fd)


def _get_unix_peer_pid(sock) -> int:
    try:
        data = sock.getsockopt(_SOL_LOCAL, _LOCAL_PEERPID, 4)
        return struct.unpack("I", data)[0]
    except OSError:
        return -1


def _pid_belongs_to_daemon(pid: int) -> bool:
    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            capture_output=True, text=True, timeout=2,
        )
        cmd = result.stdout.strip()
        parts = shlex.split(cmd)
        return (
            len(parts) >= 2
            and os.path.realpath(parts[0]) == os.path.realpath(PYTHON)
            and os.path.realpath(parts[1]) == os.path.realpath(DAEMON_SCRIPT)
        )
    except Exception:
        return False


def _daemon_trusted(pid: int) -> bool:
    """Connect to SOCKET_PATH and verify the peer is the expected daemon process."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(0.2)
        s.connect(SOCKET_PATH)
        peer_pid = _get_unix_peer_pid(s)
        if peer_pid == -1:
            return False
        return peer_pid == pid and _pid_belongs_to_daemon(pid)
    except OSError:
        return False
    finally:
        s.close()


def _socket_alive() -> bool:
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(0.2)
        s.connect(SOCKET_PATH)
        s.close()
        return True
    except OSError:
        return False


def _stop_daemon():
    try:
        pid = _read_runtime_pid()
        if not _pid_belongs_to_daemon(pid):
            return
        import signal as _sig
        os.kill(pid, _sig.SIGTERM)
        time.sleep(0.3)
    except Exception:
        pass


def _ensure_daemon_locked():
    if os.path.exists(SOCKET_PATH):
        trusted = False
        if os.path.exists(PID_FILE):
            try:
                pid = _read_runtime_pid()
                trusted = _daemon_trusted(pid)
            except Exception:
                trusted = False

        if not trusted:
            try:
                os.unlink(SOCKET_PATH)
            except FileNotFoundError:
                pass
        else:
            sock_mtime = os.path.getmtime(SOCKET_PATH)
            if any(
                os.path.exists(p) and os.path.getmtime(p) > sock_mtime
                for p in WATCHED_FILES
            ):
                _stop_daemon()
                deadline = time.monotonic() + 2.0
                while time.monotonic() < deadline and _socket_alive():
                    time.sleep(0.1)
                try:
                    os.unlink(SOCKET_PATH)
                except FileNotFoundError:
                    pass

    # A daemon may already be starting (PID written but socket not bound yet).
    if not os.path.exists(SOCKET_PATH) and os.path.exists(PID_FILE):
        try:
            pid = _read_runtime_pid()
            if _pid_belongs_to_daemon(pid):
                deadline = time.monotonic() + STARTUP_TIMEOUT
                while time.monotonic() < deadline:
                    time.sleep(0.15)
                    if os.path.exists(SOCKET_PATH):
                        return
        except Exception:
            pass

    if not os.path.exists(SOCKET_PATH):
        proc = subprocess.Popen(
            [PYTHON, DAEMON_SCRIPT],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        with _open_runtime_file(PID_FILE) as f:
            f.write(str(proc.pid))
        deadline = time.monotonic() + STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            time.sleep(0.15)
            if os.path.exists(SOCKET_PATH):
                return


def ensure_daemon():
    with _open_runtime_file(LOCK_FILE) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _ensure_daemon_locked()


def query_daemon(asf_tool, text, metadata=None):
    ensure_daemon()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    resp = b""
    try:
        sock.settimeout(TIMEOUT)
        sock.connect(SOCKET_PATH)
        peer_pid = _get_unix_peer_pid(sock)
        if peer_pid == -1:
            raise RuntimeError("socket peer PID unavailable")
        try:
            expected_pid = _read_runtime_pid()
        except Exception as e:
            raise RuntimeError(f"pid read failed after connect: {e}")
        if peer_pid != expected_pid:
            raise RuntimeError(f"socket peer PID mismatch: {peer_pid} != {expected_pid}")
        if not _pid_belongs_to_daemon(expected_pid):
            raise RuntimeError(f"socket peer is not trusted daemon: {expected_pid}")
        req_payload = {"tool": asf_tool, "input": text}
        if metadata:
            req_payload.update(metadata)
        req = json.dumps(req_payload) + "\n"
        sock.sendall(req.encode())
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
            if b"\n" in resp:
                break
    finally:
        sock.close()
    return json.loads(resp.decode().strip())


def _init_runtime_dir():
    try:
        os.makedirs(RUNTIME_DIR, mode=0o700, exist_ok=True)
        fd = os.open(RUNTIME_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW)
        try:
            st = os.fstat(fd)
            if not _stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
                raise RuntimeError("unsafe runtime dir")
            os.fchmod(fd, 0o700)
        finally:
            os.close(fd)
    except Exception:
        _fail_open(f"unsafe ASF hook runtime dir: {RUNTIME_DIR}")


def _extract_tool_output(payload):
    for key in ("tool_response", "tool_output", "output", "response", "result"):
        if key in payload:
            return payload.get(key)
    return None


def _block_message(tool_name: str, reason: str) -> str:
    return (
        f"[ASF SECURITY BLOCK]\n"
        f"Tool blocked: {tool_name}\n"
        f"Reason: {reason}\n"
        f"\n"
        f"The tool call was NOT executed. Next steps:\n"
        f"1. Ask the user to explicitly review and approve this specific action.\n"
        f"2. Reformulate the request to avoid the flagged pattern.\n"
        f"3. If this is a false positive, the user can disable enforcement:\n"
        f"     export ASF_HOOK_MONITOR_ONLY=true\n"
    )


def _handle_post_tool_use(payload: dict) -> None:
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {})
    if not isinstance(tool_input, dict):
        tool_input = {}
    tool_call_id = make_tool_call_id(payload, tool_name, tool_input)
    result = _extract_tool_output(payload)
    if result is None:
        return
    try:
        get_default_store().finish_trace(
            result=result,
            tool_call_id=tool_call_id,
            session_id=payload.get("session_id"),
        )
    except Exception:
        if FAIL_CLOSED:
            print("[ASF DENY] failed to persist PostToolUse output", flush=True)
            sys.exit(2)


def main():
    _init_runtime_dir()

    raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
    if len(raw) > MAX_STDIN_BYTES:
        _fail_open("hook request too large")
    raw = raw.decode("utf-8", errors="replace")

    try:
        payload = json.loads(raw)
    except Exception:
        _fail_open("invalid hook request")

    if not isinstance(payload, dict):
        _fail_open("invalid hook request")

    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {})
    hook_event = str(payload.get("hook_event_name") or payload.get("event") or "PreToolUse")

    if hook_event == "PostToolUse":
        _handle_post_tool_use(payload)
        sys.exit(0)

    if not isinstance(tool_input, dict):
        _fail_open("invalid hook request")

    if tool_name not in TOOL_MAP:
        sys.exit(2 if FAIL_CLOSED else 0)

    asf_tool, extractor = TOOL_MAP[tool_name]
    text = extractor(tool_input)
    if not isinstance(text, str):
        _fail_open("invalid tool command payload")
    if not text or not text.strip():
        sys.exit(0)

    if tool_name == "Bash" and is_bash_passthrough(text):
        sys.exit(0)

    last_error = None
    for _ in range(RETRIES + 1):
        try:
            metadata = {
                "tool_name": tool_name,
                "tool_input": tool_input,
                "tool_call_id": make_tool_call_id(payload, tool_name, tool_input),
                "session_id": payload.get("session_id"),
                "transcript_path": payload.get("transcript_path"),
            }
            data = query_daemon(asf_tool, text, metadata)
            verdict = data.get("verdict")
            if verdict not in {"ALLOW", "DENY"}:
                raise ValueError(f"invalid daemon verdict: {verdict!r}")
            reason = data.get("reason", "")
            if MONITOR_ONLY:
                # Observability only: the daemon already recorded this call in the audit
                # trail. Never block, whatever the verdict.
                if verdict == "DENY":
                    print(f"[ASF monitor] would block {tool_name}: {reason}", file=sys.stderr, flush=True)
                sys.exit(0)
            if verdict == "ALLOW":
                sys.exit(0)
            print(_block_message(tool_name, reason), flush=True)
            sys.exit(2)
        except Exception as exc:
            last_error = exc
            time.sleep(0.1)

    if FAIL_CLOSED:
        print(f"[ASF DENY] hook error: {last_error}", flush=True)
        sys.exit(2)
    print(f"[ASF WARN] fail-open: {last_error}", file=sys.stderr, flush=True)
    sys.exit(0)


if __name__ == "__main__":
    main()
