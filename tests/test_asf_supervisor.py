import os
import shlex
import shutil
from pathlib import Path

import pytest

from wrapper.asf_supervisor import run_action


def _audit_rows_for_action(action_id):
    from registry import AuditModel, SessionLocal

    db = SessionLocal()
    try:
        return (
            db.query(AuditModel)
            .filter(AuditModel.agent_id == "wrapper-agent")
            .filter(AuditModel.action == f"shell:{action_id}")
            .all()
        )
    finally:
        db.close()


def test_benign_command_is_allowed_executed_and_audited(tmp_path):
    result = run_action("echo hello", workdir=str(tmp_path))

    assert result["verdict"] == "ALLOW"
    assert result["executed"] is True
    assert result["exit_code"] == 0
    assert "hello" in result["output_preview"]

    rows = _audit_rows_for_action(result["action_id"])
    assert rows
    assert any(row.outcome == "SUPERVISOR_EXECUTED" for row in rows)


def test_deny_command_is_not_executed_and_side_effect_does_not_happen(tmp_path):
    side_effect = tmp_path / "deny-side-effect.txt"
    command = f"DROP TABLE users; touch {shlex.quote(str(side_effect))}"

    result = run_action(command, workdir=str(tmp_path))

    assert result["verdict"] in {"DENY", "HITL"}
    assert result["executed"] is False
    assert not side_effect.exists()

    rows = _audit_rows_for_action(result["action_id"])
    assert rows
    assert any(row.outcome == "SUPERVISOR_BLOCKED" for row in rows)

    from registry import AuditModel, SessionLocal

    db = SessionLocal()
    try:
        interceptor_rows = (
            db.query(AuditModel)
            .filter(AuditModel.agent_id == "wrapper-agent")
            .filter(AuditModel.action == "shell")
            .all()
        )
    finally:
        db.close()
    assert interceptor_rows


def test_sandbox_blocks_write_outside_workdir_when_available(tmp_path):
    if not shutil.which("sandbox-exec"):
        pytest.skip("sandbox-exec is not available on this platform")

    outside = Path(os.environ.get("TMPDIR", "/tmp")) / "asf-wrapper-outside-write.txt"
    try:
        outside.unlink()
    except FileNotFoundError:
        pass

    command = f"echo outside > {shlex.quote(str(outside))}"
    result = run_action(command, workdir=str(tmp_path))

    assert result["verdict"] == "ALLOW"
    assert result["executed"] is True
    assert result["exit_code"] != 0
    assert not outside.exists()


def test_sandbox_blocks_network_when_available(tmp_path):
    if not shutil.which("sandbox-exec"):
        pytest.skip("sandbox-exec is not available on this platform")

    result = run_action(
        "python3 -c 'import socket; socket.create_connection((\"127.0.0.1\", 9), 0.2)'",
        workdir=str(tmp_path),
    )

    assert result["verdict"] == "ALLOW"
    assert result["executed"] is True
    assert result["exit_code"] != 0
