#!/usr/bin/env python3
"""
ASF PreToolUse hook for Claude Code.

Registered in ~/.claude/settings.json under hooks.PreToolUse.
Claude Code calls this script before every matched Bash execution.

Connects to asf_hook_daemon on /tmp/asf_hook.sock. If the daemon is not
running, starts it automatically (first call pays startup cost).

Exit 0 = allow, exit 2 = block (stdout shown to Claude Code as reason).

Env:
  ASF_HOOK_FAIL_CLOSED=true        block on daemon errors instead of allow
  ASF_HOOK_RETRIES=2               connection retry count (default 2)
  ASF_HOOK_STARTUP_TIMEOUT=10      seconds to wait for daemon to start
"""

import sys
import json
import os
import re
import socket
import subprocess
import time

SOCKET_PATH     = "/tmp/asf_hook.sock"
PID_FILE        = "/tmp/asf_hook.pid"
DAEMON_SCRIPT   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "asf_hook_daemon.py")
WATCHED_FILES   = [
    DAEMON_SCRIPT,
    os.path.join(os.path.dirname(DAEMON_SCRIPT), "hardening.py"),
    os.path.join(os.path.dirname(DAEMON_SCRIPT), "interceptor.py"),
]
PYTHON          = "/Users/alfredo/miniconda3/envs/eval-framework/bin/python"
TIMEOUT         = 1.0
RETRIES         = int(os.environ.get("ASF_HOOK_RETRIES", "2"))
STARTUP_TIMEOUT = float(os.environ.get("ASF_HOOK_STARTUP_TIMEOUT", "10"))
FAIL_CLOSED     = os.environ.get("ASF_HOOK_FAIL_CLOSED", "false").lower() == "true"
MAX_STDIN_BYTES = 256 * 1024

TOOL_MAP = {
    "Bash": ("shell", lambda i: i.get("command", "")),
}

# Narrow passthrough: only unambiguously read-only or process-inspection ops.
# Execution tools (python, conda, pip, git, rm, curl, chmod, etc.) go through ASF.
_BASH_PASSTHROUGH = re.compile(
    r"^\s*(ls|cd|pwd|wc|head|tail|ps|pgrep|which|type|stat|df|du)\b"
)


def _stop_daemon():
    try:
        pid = int(open(PID_FILE).read().strip())
        import signal as _sig
        os.kill(pid, _sig.SIGTERM)
        time.sleep(0.3)
    except Exception:
        pass


def ensure_daemon():
    if os.path.exists(SOCKET_PATH) and os.path.exists(PID_FILE):
        sock_mtime = os.path.getmtime(SOCKET_PATH)
        if any(
            os.path.exists(p) and os.path.getmtime(p) > sock_mtime
            for p in WATCHED_FILES
        ):
            _stop_daemon()

    if not os.path.exists(SOCKET_PATH):
        subprocess.Popen(
            [PYTHON, DAEMON_SCRIPT],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        deadline = time.monotonic() + STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            time.sleep(0.15)
            if os.path.exists(SOCKET_PATH):
                return


def query_daemon(asf_tool, text):
    ensure_daemon()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    sock.connect(SOCKET_PATH)
    req = json.dumps({"tool": asf_tool, "input": text}) + "\n"
    sock.sendall(req.encode())
    resp = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp += chunk
        if b"\n" in resp:
            break
    sock.close()
    return json.loads(resp.decode().strip())


def main():
    raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
    if len(raw) > MAX_STDIN_BYTES:
        sys.exit(2 if FAIL_CLOSED else 0)
    raw = raw.decode("utf-8", errors="replace")

    try:
        payload = json.loads(raw)
    except Exception:
        sys.exit(0)

    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {})

    if tool_name not in TOOL_MAP:
        sys.exit(0)

    asf_tool, extractor = TOOL_MAP[tool_name]
    text = extractor(tool_input)
    if not text or not text.strip():
        sys.exit(0)

    if tool_name == "Bash" and _BASH_PASSTHROUGH.match(text):
        sys.exit(0)

    last_error = None
    for _ in range(RETRIES + 1):
        try:
            data = query_daemon(asf_tool, text)
            verdict = data.get("verdict", "ALLOW")
            reason = data.get("reason", "")
            if verdict == "ALLOW":
                sys.exit(0)
            print(f"[ASF {verdict}] {reason}", flush=True)
            sys.exit(2)
        except Exception as exc:
            last_error = exc
            time.sleep(0.1)

    if FAIL_CLOSED:
        print(f"[ASF DENY] hook error: {last_error}", flush=True)
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
