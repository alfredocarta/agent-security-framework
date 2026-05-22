"""Optional Microsoft AGT human-in-the-loop approval bridge for ASF."""

from __future__ import annotations

import hashlib
import sys
import time
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


AGT_SRC_PATH = "/tmp/agt/agent-governance-python/agent-mesh/src"
VALID_STATUSES = {"PENDING", "APPROVED", "REJECTED", "EXPIRED", "UNKNOWN"}

if AGT_SRC_PATH not in sys.path:
    sys.path.insert(0, AGT_SRC_PATH)


class AGTHITLBridge:
    """Submit ASF HITL pauses to AGT approval types when available.

    AGT currently exposes synchronous approval handlers and request/decision
    models, but no durable quorum queue. This bridge therefore records pending
    requests in memory while preserving AGT's ApprovalRequest shape when the
    package can be imported.
    """

    def __init__(self, required_approvals: int = 1, timeout_seconds: int = 300):
        self.required_approvals = max(1, int(required_approvals))
        self.timeout_seconds = max(1, int(timeout_seconds))
        self._requests: dict[str, dict[str, Any]] = {}
        self.agt_available = False
        self.agt_error: str | None = None
        self._ApprovalRequest = None
        self._trace_approval = None
        self._load_agt_api()

    def request_approval(
        self,
        trace_id: str,
        agent_id: str,
        tool_name: str,
        reason: str,
    ) -> str:
        request_id = self._request_id(trace_id, agent_id, tool_name, reason)
        if request_id in self._requests:
            return request_id

        now = time.time()
        record = {
            "request_id": request_id,
            "status": "PENDING",
            "trace_id": str(trace_id),
            "agent_id": str(agent_id),
            "tool_name": str(tool_name),
            "reason": str(reason),
            "required_approvals": self.required_approvals,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at_monotonic": now + self.timeout_seconds,
            "agt_available": self.agt_available,
            "agt_request": None,
        }

        agt_request = self._build_agt_request(trace_id, agent_id, tool_name, reason)
        if agt_request is not None:
            record["agt_request"] = self._json_safe(agt_request)

        self._requests[request_id] = record
        return request_id

    def check_approval(self, request_id: str) -> str:
        record = self._requests.get(str(request_id))
        if record is None:
            return "UNKNOWN"

        status = str(record.get("status", "UNKNOWN")).upper()
        if status == "PENDING" and time.time() >= float(record["expires_at_monotonic"]):
            record["status"] = "EXPIRED"
            return "EXPIRED"
        if status in VALID_STATUSES:
            return status
        return "UNKNOWN"

    def _load_agt_api(self) -> None:
        if not Path(AGT_SRC_PATH).exists():
            self.agt_error = f"AGT source path not found: {AGT_SRC_PATH}"
            return

        try:
            from agentmesh.governance import ApprovalRequest, trace_approval

            self._ApprovalRequest = ApprovalRequest
            self._trace_approval = trace_approval
            self.agt_available = True
        except Exception as exc:  # pragma: no cover - optional dependency path
            self.agt_error = f"{type(exc).__name__}: {exc}"

    def _build_agt_request(
        self,
        trace_id: str,
        agent_id: str,
        tool_name: str,
        reason: str,
    ) -> Any:
        if self._ApprovalRequest is None:
            return None

        context = {
            "trace_id": str(trace_id),
            "tool_name": str(tool_name),
            "reason": str(reason),
            "required_approvals": self.required_approvals,
            "timeout_seconds": self.timeout_seconds,
            "source": "agent-security-framework",
        }
        try:
            return self._ApprovalRequest(
                action=str(tool_name),
                rule_name="asf_hitl_quorum",
                policy_name="asf_security_interceptor",
                agent_id=str(agent_id),
                context=context,
                approvers=[],
            )
        except Exception as exc:  # pragma: no cover - optional AGT API drift
            self.agt_error = f"{type(exc).__name__}: {exc}"
            return None

    @staticmethod
    def _request_id(trace_id: str, agent_id: str, tool_name: str, reason: str) -> str:
        payload = "\x1f".join([str(trace_id), str(agent_id), str(tool_name), str(reason)])
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]
        return f"agt-hitl-{digest}"

    @classmethod
    def _json_safe(cls, value: Any) -> Any:
        if is_dataclass(value):
            return cls._json_safe(asdict(value))
        if hasattr(value, "model_dump"):
            return cls._json_safe(value.model_dump())
        if isinstance(value, dict):
            return {str(key): cls._json_safe(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [cls._json_safe(item) for item in value]
        if isinstance(value, datetime):
            return value.isoformat()
        try:
            import json

            json.dumps(value)
            return value
        except TypeError:
            return repr(value)
