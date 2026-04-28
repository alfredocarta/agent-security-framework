import os
import hashlib
import threading
from registry import SessionLocal, AuditModel

_audit_lock = threading.Lock()

class AuditTrail:
    def log_event(self, agent_id, action, outcome, reason):
        with _audit_lock:
            db = SessionLocal()
            try:
                last_event = (
                    db.query(AuditModel)
                    .order_by(AuditModel.timestamp.desc())
                    .with_for_update()
                    .first()
                )
                prev_hash = last_event.hash if last_event else "0" * 64

                data = f"{agent_id}{action}{outcome}{reason}{prev_hash}"
                new_hash = hashlib.sha256(data.encode()).hexdigest()

                event = AuditModel(
                    hash=new_hash,
                    agent_id=agent_id,
                    action=action,
                    outcome=outcome,
                    reason=reason,
                    prev_hash=prev_hash
                )

                db.add(event)
                db.commit()
                print(f"[AUDIT] Event stored: {new_hash[:12]}")
            except Exception as e:
                db.rollback()
                print(f"[AUDIT] Write error: {e}")
            finally:
                db.close()

AUDITOR = AuditTrail()
