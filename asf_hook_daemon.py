#!/usr/bin/env python3
"""
ASF Hook Daemon - Unix socket server for the Claude Code PreToolUse hook.

Holds the full ASF pipeline in memory (interceptor, models, registry).
The lightweight asf_hook.py client connects per tool call - no Python
startup cost, no model reload.

Start:   python asf_hook_daemon.py &
Socket:  ~/.cache/asf-hook/asf_hook.sock
Stop:    kill $(cat ~/.cache/asf-hook/asf_hook.pid)

Env:
  ASF_HOOK_FAIL_CLOSED=true   DENY on daemon errors instead of ALLOW
"""

import sys
import os
import json
import socket
import stat as _stat
import struct
import threading
import signal
import re as _re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wrapper import asf_core

RUNTIME_DIR = os.path.expanduser("~/.cache/asf-hook")
try:
    os.makedirs(RUNTIME_DIR, mode=0o700, exist_ok=True)
    _fd = os.open(RUNTIME_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW)
    try:
        _st = os.fstat(_fd)
        if not _stat.S_ISDIR(_st.st_mode) or _st.st_uid != os.getuid():
            raise RuntimeError(f"unsafe ASF hook runtime dir: {RUNTIME_DIR}")
        os.fchmod(_fd, 0o700)
    finally:
        os.close(_fd)
except Exception as _e:
    print(f"[ASF daemon] unsafe runtime dir: {_e}", file=sys.stderr, flush=True)
    sys.exit(1)
SOCKET_PATH = os.path.join(RUNTIME_DIR, "asf_hook.sock")
PID_FILE    = os.path.join(RUNTIME_DIR, "asf_hook.pid")
AGENT_ID    = asf_core.namespace_agent_id("claude-code-agent")

MAX_REQUEST_BYTES  = 64 * 1024
MAX_CLIENT_THREADS = 32
FAIL_CLOSED = os.environ.get("ASF_HOOK_FAIL_CLOSED", "false").lower() == "true"

_client_slots = threading.BoundedSemaphore(MAX_CLIENT_THREADS)
_shutdown = threading.Event()
_server = None


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

import registry
from interceptor import hardened_interceptor, make_session_id
from claude_trace_store import get_default_store

_TSID = _re.compile(r'^\d{8}_\d{6}_[0-9a-f]{6}$')

try:
    registry.add_or_update_agent(
        AGENT_ID,
        risk_level="medium",
        permissions=["shell", "file_read", "file_write", "file_search", "code_edit", "read_db", "web"]
    )
    print(f"[ASF daemon] agent {AGENT_ID!r} registered", file=sys.stderr, flush=True)
except Exception as e:
    print(f"[ASF daemon] registry error: {e}", file=sys.stderr, flush=True)


def handle_client(conn):
    try:
        conn.settimeout(2.0)
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > MAX_REQUEST_BYTES:
                try:
                    conn.sendall(
                        (json.dumps({"verdict": "DENY", "reason": "hook request too large"}) + "\n").encode()
                    )
                except OSError:
                    pass
                return
            if b"\n" in data:
                break

        try:
            req = json.loads(data.decode().strip())
        except Exception as e:
            resp = json.dumps({"verdict": "DENY", "reason": f"invalid hook request: {e}"}) + "\n"
            conn.sendall(resp.encode())
            return

        asf_tool = req.get("tool", "shell")
        text = req.get("input", "")
        tool_name = req.get("tool_name", asf_tool)
        tool_input = req.get("tool_input", text)
        session_id = req.get("session_id")
        if not session_id or not _TSID.match(session_id):
            session_id = make_session_id()
        transcript_path = req.get("transcript_path")
        tool_call_id = req.get("tool_call_id")

        audit_hash_before = None
        try:
            from audit import AUDITOR
            audit_hash_before = AUDITOR.last_hash_for(AGENT_ID)
        except Exception:
            AUDITOR = None

        result = hardened_interceptor(AGENT_ID, asf_tool, text)
        raw_verdict = result[0]
        verdict = raw_verdict
        reason = result[1] if len(result) > 1 else ""
        if verdict == "HITL":
            verdict = "DENY"
            reason = reason or "Human approval required"
        elif verdict not in {"ALLOW", "DENY"}:
            invalid_verdict = verdict
            verdict = "DENY"
            reason = f"invalid interceptor verdict: {invalid_verdict!r}"

        audit_hash = None
        try:
            audit_hash_after = AUDITOR.last_hash_for(AGENT_ID) if AUDITOR is not None else None
            if audit_hash_after and audit_hash_after != audit_hash_before:
                audit_hash = audit_hash_after
        except Exception:
            audit_hash = None

        trace_id = None
        try:
            trace_id = get_default_store().start_trace(
                session_id=session_id,
                transcript_path=transcript_path,
                tool_call_id=tool_call_id,
                claude_tool_name=tool_name,
                asf_tool_name=asf_tool,
                args=tool_input,
                verdict=raw_verdict,
                outcome="ALLOWED" if verdict == "ALLOW" else "BLOCKED",
                reason=reason,
                audit_hash=audit_hash,
            )
        except Exception as exc:
            print(f"[ASF daemon] claude trace persist error: {exc}", file=sys.stderr, flush=True)

        resp = json.dumps({"verdict": verdict, "reason": reason, "trace_id": trace_id, "audit_hash": audit_hash}) + "\n"
        conn.sendall(resp.encode())
    except Exception as e:
        resp = json.dumps({"verdict": "DENY", "reason": f"daemon error: {e}"}) + "\n"
        try:
            conn.sendall(resp.encode())
        except Exception:
            pass
    finally:
        conn.close()
        _client_slots.release()


def cleanup(signum=None, frame=None):
    _shutdown.set()
    if _server:
        try:
            _server.close()
        except OSError:
            pass
    try:
        owns_pid = _read_runtime_pid() == os.getpid()
    except Exception:
        owns_pid = False
    if owns_pid:
        for path in (SOCKET_PATH, PID_FILE):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass


def main():
    global _server

    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    with _open_runtime_file(PID_FILE) as f:
        f.write(str(os.getpid()))

    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    _server = server
    server.bind(SOCKET_PATH)
    server.listen(16)
    os.chmod(SOCKET_PATH, 0o600)

    print(f"[ASF daemon] pid={os.getpid()} listening on {SOCKET_PATH}", file=sys.stderr, flush=True)

    while not _shutdown.is_set():
        try:
            conn, _ = server.accept()
            if not _client_slots.acquire(blocking=False):
                try:
                    conn.sendall(
                        (json.dumps({"verdict": "DENY", "reason": "daemon overloaded"}) + "\n").encode()
                    )
                except OSError:
                    pass
                conn.close()
                continue
            t = threading.Thread(target=handle_client, args=(conn,), daemon=True)
            t.start()
        except Exception:
            pass


if __name__ == "__main__":
    main()
