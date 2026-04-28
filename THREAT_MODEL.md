# Threat Model - Agent Security Framework

## System Overview

A Zero Trust security middleware for multi-agent LangGraph architectures.
Each agent call is intercepted and evaluated before execution.

## Assets

- Agent private keys (Ed25519, encrypted at rest with AES-256-GCM)
- Agent registry and permission table (SQLite)
- Audit trail (hash-chained, tamper-evident)
- Tool execution capability (write_db, issue_refund, etc.)

## Adversary Model

We assume an adversary that:
- Controls one or more compromised agents (insider threat or prompt injection)
- Can craft arbitrary tool_input strings
- May attempt to impersonate other agents
- May attempt inter-agent delegation to bypass permissions
- Does NOT have direct access to the filesystem or database

## Threat Scenarios and Controls

| Threat | Attack Vector | Control | Layer |
|---|---|---|---|
| Unauthorized tool use | Agent calls tool outside its permissions | Permission check against registry | Registry |
| Identity spoofing | Agent forges another agent's request | Ed25519 signature verification | Key Authority |
| SQL injection | Malicious tool_input to write_db | Stage 1 regex + Stage 2 classifier | Interceptor |
| Prompt injection | Instruction override in tool_input | Stage 1 regex + Stage 3 LLM | Interceptor |
| Privilege escalation | Agent requests admin-level action | Stage 2 classifier + kill switch | Interceptor |
| Delegation attack | Agent A instructs Agent B to run restricted tool | Validator delegation pattern detection | Validator |
| Persistence after detection | Suspended agent re-registers key | Key Authority blocks re-registration for suspended agents | Key Authority |
| Audit tampering | Attacker modifies past log entries | SHA-256 hash chaining on audit records | Audit Trail |
| LLM unavailability | Stage 3 unreachable | Fail closed - block by default | Interceptor |

## Security Assumptions

- The master key (AES-256-GCM) is kept secret and loaded from environment variable only
- The SQLite database is not directly accessible to agents
- LangGraph orchestration runs in a trusted process
- Human operators are trusted for unsuspend operations (EU AI Act Art. 14)

## Out of Scope

- OS-level or container-level isolation (application-layer only)
- Network egress filtering
- Adversaries with direct filesystem or database access

## Compliance Note

The kill switch and unsuspend_agent.py satisfy EU AI Act Art. 14 (human oversight)
by ensuring a human operator must explicitly reinstate any suspended agent.
