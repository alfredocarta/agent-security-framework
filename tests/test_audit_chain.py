import os
os.environ["ASF_SKIP_LLM"] = "true"

import pytest
from interceptor import security_interceptor
from registry import SessionLocal, AuditModel
from datetime import datetime

def get_recent_events(agent_id, action, limit=10):
    db = SessionLocal()
    events = (
        db.query(AuditModel)
        .filter(AuditModel.agent_id == agent_id, AuditModel.action == action)
        .order_by(AuditModel.timestamp.desc())
        .limit(limit)
        .all()
    )
    outcomes = [e.outcome for e in events]
    db.close()
    return outcomes

def get_last_n_events(n=20):
    db = SessionLocal()
    events = (
        db.query(AuditModel)
        .order_by(AuditModel.timestamp.desc())
        .limit(n)
        .all()
    )
    db.close()
    return list(reversed(events))

class TestIntermediateLogging:
    def test_allowed_request_logs_all_stages(self):
        before = datetime.utcnow()
        security_interceptor("billing_agent", "read_db", "quarterly_report.pdf")

        db = SessionLocal()
        events = (
            db.query(AuditModel)
            .filter(AuditModel.agent_id == "billing_agent", AuditModel.timestamp >= before)
            .order_by(AuditModel.timestamp.asc())
            .all()
        )
        db.close()
        outcomes = [e.outcome for e in events]

        assert "INTERCEPTOR_START" in outcomes, "INTERCEPTOR_START must be logged"
        assert "STAGE_1_START" in outcomes, "STAGE_1_START must be logged"
        assert "STAGE_1_PASS" in outcomes, "STAGE_1_PASS must be logged"
        assert "STAGE_2_START" in outcomes, "STAGE_2_START must be logged"
        assert "ALLOWED" in outcomes, "Final ALLOWED must be logged"

    def test_stage1_block_does_not_reach_stage2(self):
        before = datetime.utcnow()
        security_interceptor("billing_agent", "write_db", "DROP TABLE users")

        db = SessionLocal()
        events = (
            db.query(AuditModel)
            .filter(AuditModel.agent_id == "billing_agent", AuditModel.timestamp >= before)
            .order_by(AuditModel.timestamp.asc())
            .all()
        )
        db.close()
        outcomes = [e.outcome for e in events]

        assert "KILL_SWITCH" in outcomes, "KILL_SWITCH must be logged when Stage 1 blocks"
        assert "STAGE_2_START" not in outcomes, "Stage 2 must not start if Stage 1 blocks"
        assert "ALLOWED" not in outcomes, "ALLOWED must not appear after kill switch"

    def test_hash_chain_is_unbroken(self):
        security_interceptor("billing_agent", "read_db", "invoice 101")
        security_interceptor("analytics_agent", "read_db", "monthly report")

        db = SessionLocal()
        events = (
            db.query(AuditModel)
            .order_by(AuditModel.timestamp.asc())
            .all()
        )
        db.close()

        for i in range(1, len(events)):
            assert events[i].prev_hash == events[i - 1].hash, \
                f"Hash chain broken between event {i-1} and {i}"

    def test_hash_chain_genesis_block(self):
        db = SessionLocal()
        first = (
            db.query(AuditModel)
            .order_by(AuditModel.timestamp.asc())
            .first()
        )
        db.close()
        assert first is not None
        assert first.prev_hash == "0" * 64, "Genesis block must have prev_hash of 64 zeros"

    def test_suspended_agent_blocked_event_logged(self):
        before = datetime.utcnow()
        security_interceptor("billing_agent", "write_db", "DROP TABLE users")
        security_interceptor("billing_agent", "read_db", "safe input")

        db = SessionLocal()
        events = (
            db.query(AuditModel)
            .filter(AuditModel.agent_id == "billing_agent", AuditModel.timestamp >= before)
            .order_by(AuditModel.timestamp.asc())
            .all()
        )
        db.close()
        outcomes = [e.outcome for e in events]

        assert outcomes.count("BLOCKED") >= 1, \
            "At least one BLOCKED event must be logged for suspended agent"
