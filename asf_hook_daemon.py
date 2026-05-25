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
import threading
import signal

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

RUNTIME_DIR = os.path.expanduser("~/.cache/asf-hook")
os.makedirs(RUNTIME_DIR, mode=0o700, exist_ok=True)
_lst = os.lstat(RUNTIME_DIR)
_st = os.stat(RUNTIME_DIR)
if _stat.S_ISLNK(_lst.st_mode) or not _stat.S_ISDIR(_st.st_mode) or _st.st_uid != os.getuid():
    raise RuntimeError(f"unsafe ASF hook runtime dir: {RUNTIME_DIR}")
os.chmod(RUNTIME_DIR, 0o700)
SOCKET_PATH = os.path.join(RUNTIME_DIR, "asf_hook.sock")
PID_FILE    = os.path.join(RUNTIME_DIR, "asf_hook.pid")
AGENT_ID    = "claude-code-agent"

MAX_REQUEST_BYTES  = 64 * 1024
MAX_CLIENT_THREADS = 32
FAIL_CLOSED = os.environ.get("ASF_HOOK_FAIL_CLOSED", "false").lower() == "true"

_client_slots = threading.BoundedSemaphore(MAX_CLIENT_THREADS)
_shutdown = threading.Event()
_server = None

import registry
from interceptor import hardened_interceptor

try:
    registry.add_or_update_agent(
        AGENT_ID,
        risk_level="medium",
        permissions=["shell", "file_read", "file_write", "file_search", "code_edit", "read_db"]
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

        result = hardened_interceptor(AGENT_ID, asf_tool, text)
        verdict = result[0]
        reason = result[1] if len(result) > 1 else ""

        resp = json.dumps({"verdict": verdict, "reason": reason}) + "\n"
        conn.sendall(resp.encode())
    except Exception as e:
        verdict = "DENY" if FAIL_CLOSED else "ALLOW"
        resp = json.dumps({"verdict": verdict, "reason": f"daemon error: {e}"}) + "\n"
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
        owns_pid = int(open(PID_FILE).read().strip()) == os.getpid()
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

    fd = os.open(PID_FILE, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
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
                verdict = "DENY" if FAIL_CLOSED else "ALLOW"
                try:
                    conn.sendall(
                        (json.dumps({"verdict": verdict, "reason": "daemon overloaded"}) + "\n").encode()
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
