import os
import hashlib
import threading
from registry import SessionLocal, AuditModel

_audit_lock = threading.Lock()
_langfuse = None


def _compliance_metadata(outcome: str) -> dict:
    mapping = {
        "KILL_SWITCH": ("Art. 9", "risk management"),
        "ALLOWED": ("Art. 15", "accuracy"),
        "HITL_REQUESTED": ("Art. 14", "human oversight"),
        "OUTPUT_BLOCK": ("Art. 12", "record keeping"),
    }
    if outcome not in mapping:
        return {}
    article, control = mapping[outcome]
    return {"eu_ai_act_article": article, "eu_ai_act_control": control}


def _get_langfuse():
    global _langfuse
    if _langfuse is not None:
        return _langfuse
    pk = os.environ.get("LANGFUSE_PUBLIC_KEY")
    sk = os.environ.get("LANGFUSE_SECRET_KEY")
    if not pk or not sk:
        return None
    try:
        from langfuse import Langfuse
        host = os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com")
        _langfuse = Langfuse(public_key=pk, secret_key=sk, host=host)
        return _langfuse
    except Exception:
        return None


class AuditTrail:
    def log_event(self, agent_id, action, outcome, reason,
                  *, trace_id=None, latency_ms=None, confidence=None,
                  metadata=None, session_id=None):
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
                print(f"[AUDIT] Event stored: {new_hash[:12]}", file=__import__("sys").stderr)
            except Exception as e:
                db.rollback()
                print(f"[AUDIT] Write error: {e}", file=__import__("sys").stderr)
            finally:
                db.close()

        # Langfuse emission — non-blocking, never raises into the security pipeline
        try:
            lf = _get_langfuse()
            if lf and trace_id:
                trace = lf.trace(
                    id=trace_id,
                    name="security_interceptor",
                    user_id=agent_id,
                    session_id=session_id,
                    input={"agent_id": agent_id, "tool_name": action},
                    output=f"{outcome} - {reason}",
                )
                event_metadata = {"action": action}
                if latency_ms is not None:
                    event_metadata["latency_ms"] = latency_ms
                if confidence is not None:
                    event_metadata["confidence"] = confidence
                event_metadata.update(_compliance_metadata(outcome))
                if metadata:
                    event_metadata.update(metadata)
                trace.event(
                    name=outcome,
                    input=reason,
                    output=outcome,
                    metadata=event_metadata,
                )
        except Exception:
            pass


AUDITOR = AuditTrail()

def flush_langfuse():
    try:
        lf = _get_langfuse()
        if lf:
            lf.flush()
    except Exception:
        pass
