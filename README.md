# Agent Security Framework

> A Zero Trust security middleware for multi-agent LangGraph architectures.
> Every tool call is intercepted and validated through a 3-stage pipeline before execution.

---

## How it works

```
      +----------------+       +-----------------+
      | Agent Registry |       |  Key Authority  |
      |   (SQLite)     |       | (Crypto Signing)|
      +-------+--------+       +--------+--------+
              |                         |
              +-----------+-------------+
                          |
                 +--------v----------+
                 |  LangGraph Agent  |  <-- Signs the request
                 +--------+----------+
                          |
               signed tool call request
                          |
                 +--------v----------+          +-------------------+
                 | Message Validator | <------- |   Policy Engine   |
                 | (Check Signature) |          |  (SQLite, hashed) |
                 +--------+----------+          +-------------------+
                          |
                          +-- INVALID SIGNATURE --> REJECT / LOG
                          |
                       VALID
                          |
                 +--------v----------+
                 |    Interceptor    | <-- entry point for security stages
                 +--------+----------+
                          |
               +----------+------------------+
               |                             |
    +----------v-----------+      +----------v-----------+
    | Stage 1 - Regex      |BLOCK |      DENY / LOG      |
    | Kill-switch patterns |----> +----------------------+
    +----------+-----------+
               | PASS
    +----------v-----------+      +----------------------+
    | Stage 2 - ML         |BLOCK |      DENY / LOG      |
    | TF-IDF + RandomForest|----> +----------------------+
    +----------+-----------+
               |
               +-- dangerous_proba <= 0.25 (SAFE) ----------+
               |                                             |
               +-- dangerous_proba >= 0.85 --> DENY / LOG   |
               |                                             |
               +-- 0.25 < p < 0.85 (UNCERTAIN)              |
               |                                             |
    +----------v-----------+      +----------------------+  |
    | Stage 3 - Semantic   |BLOCK |      DENY / LOG      |  |
    | Local LLM (Gemma 3)  |----> +----------------------+  |
    +----------+-----------+                                 |
               | PASS                                        |
               +<--------------------------------------------+
               |         (SAFE bypass from Stage 2)
    +----------v-----------+
    |  Sandbox Executor    |  isolated Docker container, no network
    +----------+-----------+
               |
          tool output
               |
    +----------v-----------+
    |   SQLite Audit Trail |  persistent hash-chained log of every decision
    +----------------------+
```

---

## Architecture

### Stage 1 - Regex kill-switches
Deterministic pattern matching against known bad inputs. Fast, zero-overhead, no model inference. Blocks obvious injection attempts, prompt leaks, and forbidden command patterns before anything else runs. On match: agent is immediately suspended and the event is logged.

### Stage 2 - ML classifier
TF-IDF + Random Forest trained on real-world jailbreaks, injection payloads, Base64/Hex obfuscations, and prompt leaking attacks. Three explicit outcomes based on dangerous_proba:

- >= 0.85 (DANGEROUS): block immediately, suspend agent
- <= 0.25 (SAFE): allow directly, skip Stage 3
- 0.25 < p < 0.85 (UNCERTAIN): escalate to Stage 3

### Stage 3 - Semantic LLM
Local Gemma 3 instance performs zero-shot semantic validation for unknown or zero-day attack patterns that evade stages 1 and 2. Only invoked when Stage 2 is uncertain. Last line of automated defense before execution. Can be bypassed via ASF_SKIP_LLM=true (fails closed).

### Sandbox executor
Risky tools run inside ephemeral Docker containers with no network access, no shared filesystem, strict resource limits, cap_drop=ALL, no-new-privileges, and a seccomp whitelist. The container is destroyed after each execution.

### Audit trail (SQLite)
Every interceptor decision is persisted in a SHA-256 hash-chained SQLite table. Each event references the hash of the previous event, making the log tamper-evident. Intermediate stage events are logged before final outcome, so a crash mid-pipeline still leaves a partial trace.

### Policy engine (SQLite)
Detection patterns are stored in a dedicated SQLite policies table with a content_hash for integrity verification. policies.yaml is used only as an import source via migrate_policies.py. At runtime, the interceptor reads exclusively from the database.

---

## Security posture

- Zero Trust: no tool call is trusted by default
- EU AI Act Art. 14 compliant: human oversight via HITL when classifier is uncertain
- Defense-in-depth: three independent validation layers before execution
- Tamper-evident audit trail: SHA-256 hash chain across all events
- Policy integrity: detection patterns stored in DB with content hash, not in editable flat files

---

## Compliance (EU AI Act)

| Article | Requirement | Implementation |
|---|---|---|
| Art. 9 - Risk Management | Risk classification and lifecycle control | Agent Registry with per-agent risk level and operational state |
| Art. 12 - Logging | Tamper-proof, reconstructable logs | Audit Trail with HMAC signing and hash chaining |
| Art. 14 - Human Oversight | Human intervention capability | HITL via LangGraph MemorySaver + manual kill switch |
| Art. 15 - Robustness | Resilience against adversarial inputs | Deterministic policy enforcement, 3-stage detection pipeline, fail-closed behavior |

---

## Competitive landscape

| Feature | AgentGuard | MS Agent Governance Toolkit | Asqav | This Framework |
|---|---|---|---|---|
| Agent → Tool security | Yes | Yes | Yes | Yes |
| Inter-agent permission isolation | No | No | No | Yes |
| Context poisoning detection | Partial | No | No | Yes |
| Agent impersonation prevention | No | No | No | Yes |
| Human-triggered kill switch | No | Partial | No | Yes |
| Audit trail with hash chaining | No | Yes | No | Yes |

> Competitor feature assessment based on publicly available documentation as of April 2026. Independent verification recommended.

---

## Quick start

```bash
# Run migration (populates DB from policies.yaml - first time only)
python migrate_policies.py

# Run the standard demo
python demo.py

# Run the Human-in-the-Loop demo
python demo_hitl.py

# Run the full test suite
python -m pytest tests/ -v
```

---

## Environment variables

| Variable | Required | Description |
|---|---|---|
| ASF_MASTER_KEY | Yes | Base64-encoded AES-256 key for encrypting agent private keys |
| ASF_SKIP_LLM | No | Set to true to skip Stage 3 LLM (fails closed) |
| DATABASE_URL | No | SQLite connection string (default: sqlite:///./asf_local.db) |

---

## Stack

| Component | Technology |
|---|---|
| Agent framework | LangGraph + LangChain |
| Stage 1 | Regex (deterministic) |
| Stage 2 | scikit-learn - TF-IDF + Random Forest |
| Stage 3 | Gemma 3 (local inference via LM Studio) |
| HITL | LangGraph MemorySaver + interrupt |
| Sandbox | Docker (ephemeral, no-network, seccomp hardened) |
| Registry | SQLite via SQLAlchemy |
| Audit | SQLite - SHA-256 hash-chained |
| Policy engine | SQLite with content hash verification |
| Crypto | Ed25519 signing + AES-256-GCM key encryption |

---

## Project structure

```
agent-security-framework/
- interceptor.py        # 3-stage pipeline entry point
- validator.py          # Inter-agent message validation (A2A)
- audit.py              # Hash-chained audit trail writer
- registry.py           # Agent registry + policy storage (SQLite)
- key_authority.py      # Ed25519 identity, signing, AES-256 key encryption
- sandbox.py            # Docker sandbox executor (seccomp hardened)
- graph_framework.py    # LangGraph graph definition and routing
- migrate_policies.py   # One-time import of policies.yaml into DB
- train_classifier.py   # Stage 2 model training
- dataset_builder.py    # Training data construction and augmentation
- demo.py               # Standard end-to-end demo
- demo_hitl.py          # HITL demo with human approval flow
- policies.yaml         # Import source for agents and detection patterns
- tests/                # Full test suite (45 tests)
```
