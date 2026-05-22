"""
Minimal ASF + AGT audit-chain integration probe.

AGT is a monorepo. In the local checkout inspected on 2026-05-22,
MerkleAuditChain lives in agentmesh.governance.audit rather than
agent_governance.audit.
"""

from __future__ import annotations

import sys
from pathlib import Path


AGT_ROOT = Path("/tmp/agt")
ASF_ROOT = Path("/Users/alfredo/Projects/agent-security-framework")

for path in (
    AGT_ROOT / "agent-governance-python" / "agent-mesh" / "src",
    ASF_ROOT,
):
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)


try:
    from agentmesh.governance.audit import AuditEntry, MerkleAuditChain

    AGT_AVAILABLE = True
    print("[AGT] MerkleAuditChain loaded from agentmesh.governance.audit")
except Exception as exc:
    AuditEntry = None
    MerkleAuditChain = None
    AGT_AVAILABLE = False
    print(f"[AGT] Not available: {exc}")

from audit import AuditTrail


def asf_event_to_agt_entry(
    *,
    agent_id: str,
    action: str,
    outcome: str,
    reason: str,
) -> "AuditEntry":
    return AuditEntry(
        event_type="asf_security_decision",
        agent_did=agent_id,
        action=action,
        resource=action,
        outcome=outcome.lower(),
        policy_decision=outcome,
        data={
            "reason": reason,
            "source": "agent-security-framework",
        },
    )


def main() -> int:
    asf_auditor = AuditTrail()

    event = {
        "agent_id": "test-agent",
        "action": "read_db",
        "outcome": "ALLOWED",
        "reason": "Authorized (Stage 2.5 DeBERTa cleared)",
    }

    asf_auditor.log_event(**event)
    print("[ASF] Event stored through AuditTrail")

    if not AGT_AVAILABLE:
        return 1

    agt_chain = MerkleAuditChain()
    agt_entry = asf_event_to_agt_entry(**event)
    agt_chain.add_entry(agt_entry)

    valid, error = agt_chain.verify_chain()
    print(f"[AGT] Chain length: {len(agt_chain._entries)}")
    print(f"[AGT] Root hash: {agt_chain.get_root_hash()}")
    print(f"[AGT] Chain valid: {valid}")
    if error:
        print(f"[AGT] Verification error: {error}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
