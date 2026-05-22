"""Bridge ASF audit events into Microsoft AGT's Merkle audit chain."""

from __future__ import annotations

import json
import sys
import types
import hashlib
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from importlib import util
from pathlib import Path
from typing import Any


AGT_SRC_PATH = "/tmp/agt/agent-governance-python/agent-mesh/src"

AuditEntry, MerkleAuditChain = None, None


class _CompatField:
    def __init__(self, default=None, default_factory=None, **_kwargs):
        self.default = default
        self.default_factory = default_factory

    def value(self):
        if self.default_factory is not None:
            return self.default_factory()
        return self.default


class _CompatBaseModel:
    """Small fallback for AGT audit.py when pydantic is unavailable."""

    def __init__(self, **kwargs):
        fields = {}
        for base in reversed(self.__class__.__mro__):
            for name in getattr(base, "__annotations__", {}):
                if not name.startswith("_"):
                    fields[name] = getattr(self.__class__, name, ...)

        for name, default in fields.items():
            if name in kwargs:
                value = kwargs.pop(name)
            elif isinstance(default, _CompatField):
                value = default.value()
            elif default is not ...:
                value = default
            else:
                raise TypeError(f"Missing required field: {name}")
            setattr(self, name, value)

        for name, value in kwargs.items():
            setattr(self, name, value)

        post_init = getattr(self, "model_post_init", None)
        if callable(post_init):
            post_init(None)

    def model_dump(self):
        return {
            key: value
            for key, value in self.__dict__.items()
            if not key.startswith("_")
        }


def _compat_field(default=None, default_factory=None, **kwargs):
    return _CompatField(default=default, default_factory=default_factory, **kwargs)


def _load_agt_classes():
    if AGT_SRC_PATH not in sys.path:
        sys.path.insert(0, AGT_SRC_PATH)

    try:
        from agentmesh.governance.audit import AuditEntry as AGTAuditEntry
        from agentmesh.governance.audit import MerkleAuditChain as AGTMerkleAuditChain

        return AGTAuditEntry, AGTMerkleAuditChain
    except ModuleNotFoundError as exc:
        if exc.name != "pydantic":
            raise

    pydantic_module = types.ModuleType("pydantic")
    pydantic_module.BaseModel = _CompatBaseModel
    pydantic_module.Field = _compat_field
    sys.modules.setdefault("pydantic", pydantic_module)

    audit_path = Path(AGT_SRC_PATH) / "agentmesh" / "governance" / "audit.py"
    spec = util.spec_from_file_location("_agt_governance_audit", audit_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load AGT audit module from {audit_path}")

    module = util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.AuditEntry, module.MerkleAuditChain


class _FallbackAuditEntry:
    """Deterministic local substitute when AGT audit classes are unavailable."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def model_dump(self):
        return dict(self.__dict__)


class _FallbackMerkleAuditChain:
    """Minimal Merkle-like chain compatible with the bridge's append/export API."""

    def __init__(self):
        self._entries = []
        self._hashes = []

    def add_entry(self, entry):
        previous_hash = self._hashes[-1] if self._hashes else "0" * 64
        payload = {
            "previous_hash": previous_hash,
            "entry": AGTAuditBridge._readable(entry),
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        self._entries.append(entry)
        self._hashes.append(digest)
        return digest

    def verify_chain(self):
        previous_hash = "0" * 64
        for entry, expected_hash in zip(self._entries, self._hashes):
            payload = {
                "previous_hash": previous_hash,
                "entry": AGTAuditBridge._readable(entry),
            }
            actual_hash = hashlib.sha256(
                json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest()
            if actual_hash != expected_hash:
                return False
            previous_hash = expected_hash
        return True

    def export(self):
        return {
            "entries": [
                {
                    "entry": AGTAuditBridge._readable(entry),
                    "hash": entry_hash,
                }
                for entry, entry_hash in zip(self._entries, self._hashes)
            ]
        }

    def __len__(self):
        return len(self._entries)


class AGTAuditBridge:
    """Adapt ASF audit events to AGT's MerkleAuditChain implementation."""

    def __init__(self, db_path: str | None = None, mirror_asf: bool = True):
        self.db_path = db_path
        self.mirror_asf = mirror_asf
        self.agt_available = False
        self.agt_error: str | None = None
        try:
            self._audit_entry_cls, chain_cls = _load_agt_classes()
            self.agt_available = True
        except Exception as exc:
            self._audit_entry_cls, chain_cls = _FallbackAuditEntry, _FallbackMerkleAuditChain
            self.agt_error = f"{type(exc).__name__}: {exc}"
        self.chain = chain_cls()
        self._count = 0
        self._asf_logger = self._init_asf_logger(db_path) if mirror_asf else None

    def log_event(
        self,
        agent_id,
        tool_name,
        action=None,
        reason=None,
        trace_id=None,
        session_id=None,
        latency_ms=None,
        confidence=None,
        outcome=None,
        metadata=None,
        **kwargs,
    ):
        tool_name, action, outcome, reason = self._normalize_log_args(
            tool_name, action, outcome, reason
        )
        metadata = {
            "outcome": outcome,
            "trace_id": trace_id,
            "session_id": session_id,
            "latency_ms": latency_ms,
            "confidence": confidence,
            "metadata": self._json_safe(metadata or {}),
            "kwargs": self._json_safe(kwargs),
        }

        entry = self._build_entry(
            agent_id=agent_id,
            tool_name=tool_name,
            action=action,
            reason=reason,
            outcome=outcome,
            trace_id=trace_id,
            session_id=session_id,
            metadata=metadata,
        )

        self._append_agt_entry(entry)
        self._log_to_asf(agent_id, tool_name, action, reason, trace_id, session_id,
                         latency_ms, confidence, outcome, metadata)
        return entry

    def verify_integrity(self) -> bool:
        verifier = getattr(self.chain, "verify_chain", None) or getattr(self.chain, "verify", None)
        if verifier is None:
            return False

        result = verifier()
        if isinstance(result, tuple):
            return bool(result[0])
        return bool(result)

    def get_chain_length(self) -> int:
        try:
            return len(self.chain)
        except TypeError:
            pass

        entries = getattr(self.chain, "_entries", None)
        if entries is not None:
            return len(entries)
        return self._count

    def export_chain(self) -> list:
        exporter = getattr(self.chain, "export", None)
        if callable(exporter):
            exported = exporter()
            if isinstance(exported, dict) and isinstance(exported.get("entries"), list):
                return [self._readable(item) for item in exported["entries"]]
            if isinstance(exported, list):
                return [self._readable(item) for item in exported]

        entries = getattr(self.chain, "_entries", None)
        if entries is not None:
            return [self._readable(entry) for entry in entries]

        return []

    def _build_entry(
        self,
        *,
        agent_id: Any,
        tool_name: Any,
        action: Any,
        reason: Any,
        outcome: Any,
        trace_id: Any,
        session_id: Any,
        metadata: dict[str, Any],
    ):
        normalized_action = str(action)
        return self._audit_entry_cls(
            event_type=self._event_type(normalized_action, outcome),
            agent_did=str(agent_id),
            action=normalized_action,
            resource=str(tool_name),
            data={
                "agent_id": str(agent_id),
                "tool_name": str(tool_name),
                "tool": str(tool_name),
                "action": normalized_action,
                "reason": str(reason),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metadata": self._json_safe(metadata),
            },
            outcome=self._agt_outcome(normalized_action, outcome),
            policy_decision=normalized_action,
            trace_id=str(trace_id) if trace_id is not None else None,
            session_id=str(session_id) if session_id is not None else None,
        )

    def _append_agt_entry(self, entry: AuditEntry) -> None:
        for method_name in ("add_entry", "append", "add", "log"):
            method = getattr(self.chain, method_name, None)
            if callable(method):
                method(entry)
                self._count += 1
                return
        raise AttributeError("MerkleAuditChain has no supported append/add method")

    def _log_to_asf(
        self,
        agent_id,
        tool_name,
        action,
        reason,
        trace_id,
        session_id,
        latency_ms,
        confidence,
        outcome,
        metadata,
    ) -> None:
        if self._asf_logger is None:
            return

        try:
            self._asf_logger.log_event(
                agent_id,
                tool_name,
                outcome if outcome is not None else action,
                reason,
                trace_id=trace_id,
                latency_ms=latency_ms,
                confidence=confidence,
                metadata={**metadata, "tool_name": tool_name},
                session_id=session_id,
            )
        except Exception:
            pass

    @staticmethod
    def _init_asf_logger(db_path: str | None):
        try:
            from audit import AuditLogger

            if db_path is None:
                return AuditLogger()
            return AuditLogger(db_path)
        except Exception:
            pass

        try:
            from audit import AUDITOR

            return AUDITOR
        except Exception:
            return None

    @staticmethod
    def _normalize_log_args(tool_name, action, outcome, reason):
        if action is None or reason is None:
            raise TypeError("log_event requires agent_id, tool/action, outcome/action, and reason")

        if outcome is not None:
            return tool_name, action, outcome, reason

        # Existing ASF calls are log_event(agent_id, tool_name, outcome, reason).
        # Preserve that mapping when no explicit outcome keyword is supplied.
        return tool_name, action, action, reason

    @staticmethod
    def _event_type(action: str, outcome: Any) -> str:
        marker = f"{action} {outcome or ''}".upper()
        if any(token in marker for token in ("DENY", "BLOCK", "KILL_SWITCH", "KILL SWITCH")):
            return "tool_blocked"
        return "tool_invocation"

    @staticmethod
    def _agt_outcome(action: str, outcome: Any) -> str:
        marker = str(outcome if outcome is not None else action).upper()
        if any(token in marker for token in ("DENY", "BLOCK", "KILL_SWITCH", "KILL SWITCH")):
            return "denied"
        if any(token in marker for token in ("ERROR", "EXCEPTION")):
            return "error"
        if any(token in marker for token in ("FAIL", "FAILED")):
            return "failure"
        return "success"

    @classmethod
    def _json_safe(cls, value: Any) -> Any:
        try:
            json.dumps(value)
            return value
        except TypeError:
            pass

        if isinstance(value, dict):
            return {str(k): cls._json_safe(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [cls._json_safe(item) for item in value]
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, Path):
            return str(value)
        return repr(value)

    @classmethod
    def _readable(cls, value: Any) -> Any:
        if hasattr(value, "model_dump"):
            return cls._json_safe(value.model_dump())
        if is_dataclass(value):
            return cls._json_safe(asdict(value))
        if isinstance(value, dict):
            return cls._json_safe(value)
        return repr(value)
