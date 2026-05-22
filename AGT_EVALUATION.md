# AGT Evaluation: Microsoft Agent Governance Toolkit vs ASF

## 1. What AGT provides

The Microsoft Agent Governance Toolkit (AGT) is a governance layer for AI agents, focused on deterministic policy enforcement, auditability, identity/trust, and compliance.

### Modules/Components
- **`agent-mesh`**: Multi-agent governance, audit chain, compliance engine, EU AI Act classifier, identity/trust services.
- **`agent-compliance`**: Unified installer/CLI package and compliance-oriented tooling.
- **`agent-hypervisor`**: Runtime supervision features including kill-switch support.
- **`MerkleAuditChain`**: Tamper-evident append-only audit chain with Merkle root/proof support.
- **`ComplianceEngine` / `EUAIActRiskClassifier`**: Formal compliance controls and risk classification support.

### Key Features
- **Kill Switch**: AGT has a standalone hypervisor kill-switch module.
- **Audit Merkle-chain**: AGT's `MerkleAuditChain` and `AuditLog` provide reusable tamper-evident audit primitives.
- **Regulatory Mapping**: AGT includes SOC 2, HIPAA, GDPR, and EU AI Act-oriented compliance code.
- **Framework Agnostic**: AGT provides integrations across multiple agent frameworks.

### License and Dependencies
- **License**: MIT.
- **Observed version**: `3.7.0` from `/tmp/agt/VERSION`.
- **Observed commit**: `a0e9943` from the shallow Git clone.
- **Python packaging**: The repo root is not directly installable; Python packages live under `agent-governance-python/*`.

---

## 2. Overlap with ASF

| Capability | AGT | ASF | Gap |
|---|---|---|---|
| **Kill switch** | `hypervisor.security.kill_switch` module | Stage outcomes such as `KILL_SWITCH` in interceptor/audit flow | AGT can provide lifecycle mechanics; ASF currently blocks/logs decisions. |
| **HITL approval** | AgentMesh approval/governance workflows | `HITL_REQUESTED` pipeline outcome | AGT appears better suited for formal quorum workflows. |
| **Audit tamper-evidence** | `MerkleAuditChain` and `AuditLog` | SHA-256 hash chain in `audit.py` | Functional overlap; AGT gives reusable Merkle proof/export semantics. |
| **EU AI Act mapping** | Compliance engine and EU AI Act risk classifier | Lightweight metadata mapping in Langfuse emission | AGT is stronger for formal compliance reporting. |
| **Prompt injection detection** | Governance/policy-oriented controls | Multi-stage detection pipeline with regex, ML, DeBERTa, and LLM/ONNX fallbacks | ASF remains stronger for detection and should stay authoritative. |

---

## Integration Attempt - 2026-05-22

### Clone and installability

- Clone succeeded from `https://github.com/microsoft/agent-governance-toolkit.git` into `/tmp/agt`.
- Root install failed: `/tmp/agt` has no root-level `setup.py` or `pyproject.toml`.
- Standalone package install succeeded for `agent-governance-python/agent-mesh` using:
  `conda run -n eval-framework pip install -e agent-governance-python/agent-mesh --break-system-packages`
- `agent-mesh` installed as `agentmesh_platform==3.7.0`.

### Modules successfully imported

The requested `agent_governance.*` module names did not exist in this checkout. These modules were successfully imported instead:

- `agentmesh.governance.audit`
- `agentmesh.governance.compliance`
- `agentmesh.governance.eu_ai_act`
- `agent_compliance`
- `hypervisor.security.kill_switch`

### Modules that failed

These task-provided candidates failed when only `/tmp/agt` was inserted on `sys.path`:

- `agent_governance`
- `agent_governance.audit`
- `agent_governance.compliance`
- `agent_governance.kill_switch`
- `agt`
- `agt.audit`

### Relevant standalone APIs found

- `agentmesh.governance.audit.MerkleAuditChain`
- `agentmesh.governance.audit.AuditEntry`
- `agentmesh.governance.audit.AuditLog`
- `agentmesh.governance.compliance.ComplianceEngine`
- `agentmesh.governance.compliance.ComplianceFramework`
- `agentmesh.governance.eu_ai_act.EUAIActRiskClassifier`
- `agentmesh.governance.eu_ai_act.AgentRiskProfile`
- `hypervisor.security.kill_switch`

### Proof-of-concept

Created `agt_integration.py`.

The PoC:
- Imports AGT `MerkleAuditChain` from `agentmesh.governance.audit`.
- Wraps one ASF audit decision into an AGT `AuditEntry`.
- Logs the event through ASF `AuditTrail`.
- Adds the same event to AGT `MerkleAuditChain`.
- Verifies AGT chain integrity with `verify_chain()`.

### Feasibility assessment

MerkleAuditChain integration is feasible as a thin adapter around ASF audit events. The main adjustment is API naming: AGT exposes this through `agentmesh.governance.audit`, not `agent_governance.audit`. ASF can retain its existing database-backed `AuditTrail` while mirroring security decisions into an AGT chain for Merkle roots, inclusion proofs, and exportable evidence.

Compliance integration is also feasible, but it should be added as metadata enrichment/reporting rather than as a detection stage. AGT's compliance modules can map ASF outcomes to formal controls and risk classifications while ASF remains the source of truth for prompt-injection/tool-abuse detection.

### Revised effort estimate

Original estimate: **4-5 days**.

Revised estimate: **3-4 days** for a focused integration:
- **0.5 day**: Stabilize import/install path and dependency strategy.
- **1 day**: Build ASF-to-AGT audit adapter and tests.
- **1 day**: Add compliance metadata mapping/report generation.
- **0.5-1 day**: Wire docs, CI verification, and failure-mode handling.

Keep **4-5 days** if the scope includes HITL quorum workflows or kill-switch lifecycle integration beyond audit/compliance mirroring.

---

## 4. Recommendation

Integrate AGT audit and compliance modules, but keep ASF's detection pipeline authoritative.

Immediate next steps:
1. Add a production adapter that mirrors `AuditTrail.log_event(...)` into AGT `AuditEntry`.
2. Add tests for AGT chain validity, tamper detection, and ASF behavior when AGT is unavailable.
3. Map ASF outcomes (`ALLOWED`, `KILL_SWITCH`, `HITL_REQUESTED`, `OUTPUT_BLOCK`) into AGT compliance controls.
4. Defer AGT HITL quorum and kill-switch lifecycle changes until the audit/compliance path is stable.
