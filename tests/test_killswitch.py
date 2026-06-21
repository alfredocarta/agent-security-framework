import os
os.environ["ASF_SKIP_LLM"] = "true"

import json
import shutil
import signal
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest
from interceptor import security_interceptor
from registry import get_agent_permissions
from tests.conftest import is_blocked, is_allowed


def _rust_hook_bin_or_skip():
    repo_root = Path(__file__).resolve().parents[1]
    hook_bin = repo_root / "asf_rust_daemon" / "target" / "release" / "asf-rust-hook"
    if not hook_bin.exists():
        pytest.skip("release Rust hook binary is not built")
    return hook_bin


def _run_rust_hook(hook_bin, home, payload, monitor_only="false", fail_closed="false", extra_env=None):
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home),
            "ASF_HOOK_MONITOR_ONLY": monitor_only,
            "ASF_HOOK_FAIL_CLOSED": fail_closed,
            "ASF_HOOK_STARTUP_TIMEOUT": "1",
        }
    )
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [str(hook_bin)],
        input=json.dumps(payload).encode(),
        capture_output=True,
        env=env,
        timeout=5,
    )


def _start_fake_rust_daemon(socket_path, response):
    socket_path.parent.mkdir(parents=True)
    stop = threading.Event()
    seen = []
    errors = []
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    server.listen(8)

    def serve():
        server.settimeout(0.1)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if not stop.is_set():
                    errors.append(exc)
                break
            with conn:
                data = b""
                while b"\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                if not data.strip():
                    continue
                seen.append(json.loads(data.decode().strip()))
                conn.sendall((json.dumps(response) + "\n").encode())

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    def cleanup():
        stop.set()
        server.close()
        thread.join(timeout=1)

    return seen, errors, cleanup


class TestKillSwitch:
    def test_kill_switch_triggers_on_sql_injection(self):
        result = security_interceptor("billing_agent", "write_db", "DROP TABLE users")
        assert is_blocked(result), f"Expected BLOCKED, got: {result}"

    def test_suspended_agent_blocked_on_any_subsequent_request(self):
        security_interceptor("billing_agent", "write_db", "DROP TABLE users")
        result = security_interceptor("billing_agent", "read_db", "SELECT * FROM users")
        assert is_blocked(result), f"Suspended agent should be blocked on all requests"

    def test_suspended_agent_blocked_on_safe_input(self):
        security_interceptor("billing_agent", "write_db", "DROP TABLE users")
        result = security_interceptor("billing_agent", "read_db", "quarterly_report.pdf")
        assert is_blocked(result), f"Suspended agent should be blocked even on safe input"

    def test_suspension_persists_in_db(self):
        security_interceptor("billing_agent", "write_db", "DROP TABLE users")
        permissions = get_agent_permissions("billing_agent")
        assert permissions == [], "Suspended agent should return empty permissions"

    def test_clean_agent_not_suspended(self):
        result = security_interceptor("billing_agent", "read_db", "quarterly_report.pdf")
        assert is_allowed(result), f"Clean agent should not be suspended"
        permissions = get_agent_permissions("billing_agent")
        assert permissions != [], "Clean agent should still have permissions"

    def test_rust_hook_enforce_denies_with_asf_suggestion(self):
        hook_bin = _rust_hook_bin_or_skip()
        home = Path(tempfile.mkdtemp(prefix="asf-rh-", dir="/tmp"))
        socket_path = home / ".cache" / "asf-hook" / "asf_rust.sock"
        cleanup = None
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "grep token secrets.txt"},
            "session_id": "20260621_120000_abc123",
            "tool_use_id": "call-rust-deny",
        }

        try:
            seen, errors, cleanup = _start_fake_rust_daemon(
                socket_path,
                {"verdict": "DENY", "reason": "policy denied"},
            )
            result = _run_rust_hook(hook_bin, home, payload, monitor_only="false")
        finally:
            if cleanup is not None:
                cleanup()
            shutil.rmtree(home, ignore_errors=True)

        out = result.stdout.decode(errors="replace")
        assert result.returncode == 2
        assert "[ASF SECURITY BLOCK]" in out
        assert "Tool blocked: Bash" in out
        assert "ASF_HOOK_MONITOR_ONLY=true" in out
        assert [req["tool_name"] for req in seen] == ["Bash"]
        assert not errors

    def test_rust_hook_monitor_only_does_not_block(self):
        hook_bin = _rust_hook_bin_or_skip()
        home = Path(tempfile.mkdtemp(prefix="asf-rh-", dir="/tmp"))
        socket_path = home / ".cache" / "asf-hook" / "asf_rust.sock"
        cleanup = None
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "python build.py"},
            "session_id": "20260621_120000_abc123",
            "tool_use_id": "call-rust-monitor",
        }

        try:
            seen, errors, cleanup = _start_fake_rust_daemon(
                socket_path,
                {"verdict": "DENY", "reason": "policy denied"},
            )
            result = _run_rust_hook(hook_bin, home, payload, monitor_only="true")
        finally:
            if cleanup is not None:
                cleanup()
            shutil.rmtree(home, ignore_errors=True)

        assert result.returncode == 0
        assert "would block Bash: policy denied" in result.stderr.decode(errors="replace")
        assert result.stdout == b""
        assert [req["tool_name"] for req in seen] == ["Bash"]
        assert not errors

    def test_rust_hook_fail_open_when_rust_daemon_unavailable(self, tmp_path):
        source_hook = _rust_hook_bin_or_skip()
        isolated_bin_dir = tmp_path / "isolated-bin"
        isolated_bin_dir.mkdir()
        isolated_hook = isolated_bin_dir / "asf-rust-hook"
        shutil.copy2(source_hook, isolated_hook)
        isolated_hook.chmod(0o755)
        home = Path(tempfile.mkdtemp(prefix="asf-rh-", dir="/tmp"))
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "python build.py"},
            "session_id": "20260621_120000_abc123",
            "tool_use_id": "call-rust-fail-open",
        }

        try:
            result = _run_rust_hook(
                isolated_hook,
                home,
                payload,
                monitor_only="false",
                fail_closed="false",
                extra_env={"PATH": str(isolated_bin_dir)},
            )
        finally:
            shutil.rmtree(home, ignore_errors=True)

        assert result.returncode == 0
        assert "fail-open" in result.stderr.decode(errors="replace")
        assert result.stdout == b""

    def test_rust_stage25_deny_blocks_one_call_and_daemon_survives(self):
        repo_root = Path(__file__).resolve().parents[1]
        hook_bin = repo_root / "asf_rust_daemon" / "target" / "release" / "asf-rust-hook"
        daemon_bin = repo_root / "asf_rust_daemon" / "target" / "release" / "asf-rust-daemon"
        if not hook_bin.exists() or not daemon_bin.exists():
            pytest.skip("release Rust hook/daemon binaries are not built")

        home = Path(tempfile.mkdtemp(prefix="asf-rust-kill-", dir="/tmp"))
        runtime_dir = home / ".cache" / "asf-hook"
        runtime_dir.mkdir(parents=True)
        python_socket = runtime_dir / "asf_hook.sock"
        rust_pid_file = runtime_dir / "asf_rust.pid"
        rust_log = runtime_dir / "asf_rust.log"
        db_path = home / "asf.db"
        session_id = "20260621_120000_abcdef"
        transcript_path = str(home / "transcript.jsonl")
        stop = threading.Event()
        seen = []
        server_errors = []
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        def fake_python_daemon():
            server.settimeout(0.1)
            while not stop.is_set():
                try:
                    conn, _ = server.accept()
                except socket.timeout:
                    continue
                except OSError as exc:
                    if not stop.is_set():
                        server_errors.append(exc)
                    break
                with conn:
                    data = b""
                    while b"\n" not in data:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    if not data.strip():
                        continue
                    req = json.loads(data.decode().strip())
                    seen.append(req)
                    if req.get("tool_call_id") == "call-deny":
                        response = {
                            "verdict": "DENY",
                            "reason": "KILL SWITCH ACTIVATED (Stage 2.5 DeBERTa: DANGEROUS p=1.00).",
                        }
                    else:
                        response = {"verdict": "ALLOW", "reason": "Authorized (Stage 2.5 DeBERTa cleared)."}
                    conn.sendall((json.dumps(response) + "\n").encode())

        def run_hook(tool_use_id, command):
            payload = {
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "tool_use_id": tool_use_id,
                "session_id": session_id,
                "transcript_path": transcript_path,
            }
            env = os.environ.copy()
            env.update(
                {
                    "HOME": str(home),
                    "ASF_HOOK_MONITOR_ONLY": "false",
                    "ASF_HOOK_FAIL_CLOSED": "false",
                    "ASF_HOOK_STARTUP_TIMEOUT": "5",
                    "ASF_HOOK_DB": str(db_path),
                }
            )
            return subprocess.run(
                [str(hook_bin)],
                input=json.dumps(payload).encode(),
                capture_output=True,
                env=env,
                timeout=10,
            )

        def stop_rust_daemon():
            try:
                pid = int(rust_pid_file.read_text().strip())
            except Exception:
                return
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                return
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                try:
                    os.kill(pid, 0)
                except OSError:
                    return
                time.sleep(0.05)
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass

        try:
            server.bind(str(python_socket))
            server.listen(8)
            thread = threading.Thread(target=fake_python_daemon, daemon=True)
            thread.start()

            blocked = run_hook("call-deny", "printf stage25-deny-fixture")
            allowed = run_hook("call-allow", "printf benign-fixture")

            assert blocked.returncode == 2, blocked.stderr.decode(errors="replace")
            assert b"Stage 2.5 DeBERTa" in blocked.stdout
            assert allowed.returncode == 0, allowed.stderr.decode(errors="replace")

            forwarded_ids = [req.get("tool_call_id") for req in seen]
            assert forwarded_ids == ["call-deny", "call-allow"]
            assert not server_errors

            log_text = rust_log.read_text()
            assert 'tool=Bash verdict=DENY reason="KILL SWITCH ACTIVATED (Stage 2.5 DeBERTa: DANGEROUS p=1.00)."' in log_text
            assert 'tool=Bash verdict=ALLOW reason="Authorized (Stage 2.5 DeBERTa cleared)."' in log_text

            with sqlite3.connect(db_path) as conn:
                row = conn.execute(
                    """
                    SELECT verdict, outcome, reason
                    FROM claude_tool_traces
                    WHERE tool_call_id = 'call-deny'
                    """
                ).fetchone()
            assert row == (
                "DENY",
                "BLOCKED",
                "KILL SWITCH ACTIVATED (Stage 2.5 DeBERTa: DANGEROUS p=1.00).",
            )
        finally:
            stop.set()
            server.close()
            stop_rust_daemon()
            shutil.rmtree(home, ignore_errors=True)
