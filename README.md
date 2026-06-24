# Agent Security Framework

> A Zero Trust security middleware for multi-agent LangGraph architectures.
> Every tool call is intercepted and validated through a 3-stage pipeline before execution.

---

## How it works

```
                    +------------------+
                    | LangGraph Agent  |
                    +--------+---------+
                             |
                 signed tool call request
                             |
                    +--------v---------+
                    |   Interceptor    |
                    +--------+---------+
                             |
                    +--------v---------+       match       +----------------------+
                    | Stage 1 - Rust   |------------------>|      DENY / LOG      |
                    | regex kill-      |                   |    suspend agent     |
                    | switches         |                   +----------------------+
                    +--------+---------+
                             | PASS
                    +--------v---------+       match       +----------------------+
                    | L1.5 - Rust      |------------------>|      DENY / LOG      |
                    | hardening layer  |                   |    suspend agent     |
                    +--------+---------+                   +----------------------+
                             | PASS
                    +--------v---------+ dangerous_proba >= 0.85 +----------------+
                    | Stage 2 - ML     |------------------------>|   DENY / LOG   |
                    | TF-IDF + Random  |                         +----------------+
                    | Forest           |
                    +--------+---------+
                             |
          +------------------+------------------+
          |                                     |
          | dangerous_proba <= 0.25             | 0.25 < p < 0.85
          |                                     | UNCERTAIN
          |                            +--------v---------+       BLOCK      +----------------+
          |                            | Stage 3 -        |----------------->|   DENY / LOG   |
          |                            | Semantic LLM     |                  +----------------+
          |                            | Gemma 3 / Ollama |
          |                            +--------+---------+
          |                                     | UNCERTAIN
          |                                     v
          |                            +------------------+
          |                            |    HITL queue    |
          |                            +--------+---------+
          |                                     | APPROVE
          |                            +--------v---------+
          |                            | Stage 3 ALLOW    |
          |                            +--------+---------+
          |                                     |
          +-------------------------------------+
                                                |
                                      +---------v--------+
                                      | Tool execution   |
                                      +---------+--------+
                                                |
                                           tool output
                                                |
                                      +---------v--------+       violation  +----------------+
                                      |  Output guard    |----------------->|   DENY / LOG   |
                                      | before return    |                  +----------------+
                                      +---------+--------+
                                                |
                                      +---------v--------+
                                      | return to agent  |
                                      +------------------+

       events from Interceptor, Stage 1, L1.5, Stage 2, Stage 3, Output guard
                                                |
                                      +---------v--------+
                                      | SQLite Audit     |
                                      | Trail            |
                                      +------------------+
```

---

## Security Guarantees and Limitations

ASF enforces the following controls on a local machine:

- All agent tool calls pass through Stage 1 (Rust) and L1.5 (Rust) analysis before execution.
- The pipeline applies Stage 2.5 anomaly detection, Stage 3 output inspection, and an output
  guard.
- Every call is logged to a local SQLite audit database with session and agent identifiers.
- Hook enforcement prevents Claude Code and Hermes from operating without the daemon running.

ASF does not guarantee the following:

- ASF cannot protect itself from a user or attacker with physical or administrative access
  to the machine. Hooks, binaries, and configuration can be bypassed by the local user.
- ASF does not prevent a compromised LLM provider or network-level attacker from injecting
  content before it reaches the pipeline.
- ASF does not provide multi-tenant isolation, fleet-level enforcement, or remote policy
  management.
    All enforcement is local to the machine where the daemon runs.
- ASF is a research prototype. It has not undergone independent security audit.

These limitations are intentional design boundaries for the current version, not defects.
Server-side enforcement, remote policy management, and fleet management are future work.

---

## Architecture

### Stage 1 — Regex kill-switches (Rust)
Deterministic pattern matching against known bad inputs. Fast, zero-overhead, no model inference. Implemented as a Rust binary (`asf_rust_daemon`). Blocks obvious injection attempts, prompt leaks, and forbidden command patterns before anything else runs. On match: agent is immediately suspended and the event is logged.

### L1.5 — Hardening layer (Rust)
Second deterministic Rust stage. Applies structural hardening rules: strips known obfuscation patterns (Base64/Hex encoding of payloads, Unicode homoglyphs, null-byte injection), normalises whitespace and encoding, and blocks inputs that pass Stage 1 but carry evasion markers. Output is a cleaned, normalised representation passed to Stage 2.

### Stage 2 - ML classifier
TF-IDF + Random Forest trained on real-world jailbreaks, injection payloads, Base64/Hex obfuscations, and prompt leaking attacks. Three explicit outcomes based on dangerous_proba:

- >= 0.85 (DANGEROUS): block immediately, suspend agent
- <= 0.25 (SAFE): allow directly, skip Stage 3
- 0.25 < p < 0.85 (UNCERTAIN): escalate to Stage 3

### Stage 2.5 — Anomaly detection
Statistical anomaly detector that flags inputs deviating significantly from the distribution of benign calls seen during training. Acts as a safety net between Stage 2 and Stage 3: anomalous inputs that Stage 2 rated as SAFE are escalated to Stage 3 anyway. Reduces false negatives for zero-day evasion patterns.

### Stage 3 - Semantic LLM
Local LLM (Gemma 3 via Ollama or any OpenAI-compatible endpoint, including Fleet Gateway) performs zero-shot semantic validation for unknown or zero-day attack patterns that evade stages 1 and 2. Only invoked when Stage 2 is uncertain. Last line of automated defense before execution. Can be bypassed via ASF_SKIP_LLM=true (fails closed).

### Sandbox executor
Risky tools run inside ephemeral Docker containers with no network access, no shared filesystem, strict resource limits, cap_drop=ALL, no-new-privileges, and a seccomp whitelist. The container is destroyed after each execution.

### Audit trail (SQLite)
Every interceptor decision is persisted in a SHA-256 hash-chained SQLite table. Each event references the hash of the previous event, making the log tamper-evident. Intermediate stage events are logged before final outcome, so a crash mid-pipeline still leaves a partial trace.

### Output guard
Inspects tool output before it is returned to the agent. Detects data exfiltration patterns, credential leakage, and unexpected content types in the response. Complements Stage 3 by catching threats that materialise in the output rather than the input. On violation: DENY with full audit log entry.

---

## Security posture

- Zero Trust: no tool call is trusted by default
- EU AI Act alignment (Art. 9, 12, 14, 15, 19, 26): technical controls for risk management, tamper-evident logging, human oversight, robustness, and deployer monitoring — see Compliance section
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
| Art. 19 - Log Preservation | Automatically generated logs retained in local SQLite | Audit Trail — events persist across sessions with hash-chain integrity |
| Art. 26 - Deployer Monitoring | Deployer can monitor operation and access logs | Metrics and compliance views available via ASE dashboard pointed at the local audit DB |

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

## Getting Started

**Prerequisites:** Python 3 and pip.

```bash
git clone https://github.com/alfredocarta/agent-security-framework.git
cd agent-security-framework
./install.sh
```

`install.sh` auto-installs Rust via rustup if not present, builds the Rust daemon, installs Python dependencies, creates an `asf-run` symlink in `~/.local/bin`, and appends `~/.local/bin` to your shell profile if needed. It is idempotent and does not require sudo.

Once installed:

```bash
asf-run claude        # launch Claude Code with ASF active
asf-run hermes        # launch Hermes with ASF active
asf-run update        # show version and update instructions
```

**Development commands** (no wrapper required):

```bash
python migrate_policies.py   # populate DB from policies.yaml (first time only)
python demo.py               # standard end-to-end demo
python demo_hitl.py          # HITL demo with human approval flow
python -m pytest tests/ -v   # full test suite
```

---

## Environment variables

| Variable | Required | Description |
|---|---|---|
| ASF_MASTER_KEY | Yes | Base64-encoded AES-256 key for encrypting agent private keys |
| ASF_SKIP_LLM | No | Set to true to skip Stage 3 LLM (fails closed) |
| DATABASE_URL | No | SQLite connection string (default: sqlite:///./asf_local.db) |
| ASF_ENV | No | Set to `test` to use a separate `asf_test.db` database and prefix agent IDs with `test-`. Defaults to production mode. |
| ASF_DASHBOARD_PASSWORD | No | Password for the audit dashboard basic-auth. Default: `asf-secret-2024`. (Note: only relevant if running the ASE dashboard pointed at this framework's audit DB.) |

---

## Stack

| Component | Technology |
|---|---|
| Agent framework | LangGraph + LangChain |
| Stage 1 | Regex (deterministic) — Rust |
| Stage L1.5 | Rust — structural hardening and obfuscation stripping |
| Stage 2 | scikit-learn - TF-IDF + Random Forest |
| Stage 3 | Gemma 3 (local inference via Ollama or any OpenAI-compatible endpoint) |
| Fleet Gateway | Multi-model router (localhost:4000) — selectable provider for Stage 3 |
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
- install.sh            # Plug-and-play installer (installs Rust, builds daemon, creates asf-run symlink)
- interceptor.py        # 3-stage pipeline entry point
- validator.py          # Inter-agent message validation (A2A)
- audit.py              # Hash-chained audit trail writer
- registry.py           # Agent registry + policy storage (SQLite)
- key_authority.py      # Ed25519 identity, signing, AES-256 key encryption
- sandbox.py            # Docker sandbox executor (seccomp hardened)
- hardening.py          # L1.5 Python-side hardening utilities
- hermes_trace_store.py # Hermes trace storage with input/output hashing
- asf_supervisor.py     # HITL supervisor and DENY/resume logic
- graph_framework.py    # LangGraph graph definition and routing
- migrate_policies.py   # One-time import of policies.yaml into DB
- train_classifier.py   # Stage 2 model training
- dataset_builder.py    # Training data construction and augmentation
- demo.py               # Standard end-to-end demo
- demo_hitl.py          # HITL demo with human approval flow
- policies.yaml         # Import source for agents and detection patterns
- wrapper/              # Rust wrapper binary source (`asf-run` entry point)
- asf_rust_daemon/      # Stage 1 and L1.5 Rust daemon source
- tests/                # Full test suite (42+ tests)
```
