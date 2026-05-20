# AGT Evaluation: Microsoft Agent Governance Toolkit vs ASF

## 1. What AGT provides

The Microsoft Agent Governance Toolkit (AGT) is a comprehensive governance layer for AI agents, focusing on deterministic policy enforcement, auditability, and compliance.

### Modules/Components:
- **`agent-runtime`**: Execution rings, resource limits, and **Kill Switch** (graceful/immediate termination).
- **`agent-mesh`**: Governance for multi-agent coordination, including **HITL (Human-in-the-loop) approval** workflows.
- **`agent-compliance`**: Explicit mapping to regulatory frameworks (**EU AI Act**, **OWASP Agentic Top 10**, SOC2, etc.).
- **`MerkleAuditChain`**: Cryptographically signed, tamper-evident audit logs using SHA-256 hash chains.
- **`PolicyEvaluator`**: Sub-millisecond policy engine for evaluating tool calls and messages against defined rules.

### Key Features:
- **Kill Switch**: Formal API for pausing, resuming, or terminating agents.
- **HITL Quorum**: Support for multi-signature approvals for high-risk actions.
- **Audit Merkle-chain**: Append-only logs where each entry hashes the previous, ensuring tamper-evidence.
- **Regulatory Mapping**: Built-in support for verifying compliance against the EU AI Act (specifically Article 12) and OWASP Agentic Top 10 (2026).
- **Framework Agnostic**: Supports LangChain, CrewAI, AutoGen, OpenAI Agents, and more.

### License and Dependencies:
- **License**: MIT
- **Dependencies**: Python (3.10+), TypeScript, .NET, Rust, Go. Minimal core dependencies for the policy engine.

---

## 2. Overlap with ASF

| Capability | AGT | ASF | Gap |
|---|---|---|---|
| **Kill switch** | `KillSwitch` API (terminate/pause/resume) | Stage 1 regex (logs `KILL_SWITCH` outcome) | AGT provides an active termination mechanism; ASF is currently reactive/blocking. |
| **HITL approval** | `AgentMesh` multi-sig quorum | `HITL verdict` integration in pipeline | AGT's quorum-based approach is more robust for enterprise workflows. |
| **Audit tamper-evidence** | `MerkleAuditChain` (SHA-256) | SHA-256 hash chain (built-in) | Functional parity. AGT's implementation is slightly more modular. |
| **EU AI Act mapping** | Built-in (Articles 12, 14, etc.) | Langfuse metadata | AGT has superior formal mapping and documentation for EU compliance. |
| **Prompt injection** | Basic detection (.NET/Python) | L1.5 + Stage 2 (TF-IDF) + Stage 2.5 (DeBERTa) | **ASF is significantly stronger** in multi-stage heuristic and ML-based detection. |
| **OWASP Agentic Top 10** | 10/10 coverage mapping | Partially covered via stages | AGT provides a formal "compliance gate" (`agt verify`) for OWASP ASI. |

---

## 3. Integration Feasibility

- **Portability**: AGT Python modules (`agent-governance-toolkit`) are available on PyPI and can be imported alongside ASF without major conflicts.
- **Framework Support**: ASF's interceptor-based approach is compatible with AGT's policy evaluator. AGT can act as an additional "Stage" in the ASF pipeline.
- **Requirements**: AGT requires Python 3.10+, which aligns with ASF.
- **Estimated Effort**:
    - **Audit Log Migration**: 1 day (standardizing on `MerkleAuditChain`).
    - **Policy Engine Integration**: 2 days (mapping ASF "Stages" to AGT policies).
    - **EU AI Act Metadata**: 1 day (enriching Langfuse exports with AGT's compliance tags).
    - **Total**: ~4-5 days for a deep integration.

---

## 4. Recommendation

**"Integrate AGT modules for Audit and Compliance as they add formal capabilities ASF lacks."**

Specifically:
1. **Adopt `MerkleAuditChain`**: Standardize ASF's hash chain on AGT's implementation for better interoperability and external verification tools.
2. **Import EU AI Act Mapping**: Use AGT's compliance metadata to tag ASF's Langfuse logs, providing "out-of-the-box" regulatory reporting.
3. **Keep ASF's Detection Pipeline**: Do NOT replace ASF's Stage 2/2.5 detection with AGT's native filters, as ASF's ensemble approach is significantly more sophisticated for red-team resistance.
4. **Monitor Kill Switch**: Consider wrapping ASF's Stage 1 blocking logic in a `KillSwitch` abstraction for cleaner lifecycle management.
