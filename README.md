# Agent Security Framework

> A Zero Trust security middleware for multi-agent LangGraph architectures.
> Every tool call is intercepted and validated through a 3-stage pipeline before execution.

---

## How it works

```
      +----------------+       +-----------------+
      | Agent Registry |       |  Key Authority  |
      | (PostgreSQL)   |       | (Crypto Signing)|
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
                 | (Check Signature) |          |  (policies.yaml)  |
                 +--------+----------+          +-------------------+
                          | 
                          +-- INVALID SIGNATURE --> REJECT / DROP
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
               | UNCERTAIN --> HITL pause (LangGraph MemorySaver)
               | PASS
    +----------v-----------+      +----------------------+
    | Stage 3 - Semantic   |BLOCK |      DENY / LOG      |
    | Local LLM (Gemma 3)  |----> +----------------------+
    +----------+-----------+
               | PASS
    +----------v-----------+
    |  Sandbox Executor    |  isolated Docker container, no network
    +----------+-----------+
               |
          tool output
               |
    +----------v-----------+
    |   PostgreSQL Audit   |  persistent log of every decision
    +----------------------+

```

---

## Architecture

### Stage 1 - Regex kill-switches
Deterministic pattern matching against known bad inputs. Fast, zero-overhead, no model inference. Blocks obvious injection attempts, prompt leaks, and forbidden command patterns before anything else runs.

### Stage 2 - ML classifier
TF-IDF + Random Forest model trained on real-world jailbreaks, injection payloads, Base64/Hex obfuscations, and prompt leaking attacks. When confidence is below threshold, execution is paused and routed to a human reviewer via LangGraph MemorySaver (HITL).

### Stage 3 - Semantic LLM
Local Gemma 3 instance performs zero-shot semantic validation for unknown or zero-day attack patterns that evade stages 1 and 2. Last line of automated defense before execution.

### Sandbox executor
Risky tools run inside ephemeral Docker containers with no network access, no shared filesystem, and strict resource limits. The container is destroyed after each execution.

### Audit log (PostgreSQL)
Every interceptor decision - ALLOW, DENY, HITL - is persisted in PostgreSQL with timestamp, agent ID, tool name, input, and the stage that triggered the decision.

---

## Security posture

- Compliant with Zero Trust principles: no tool call is trusted by default
- Aligned with EU AI Act Art. 14 on Human Oversight
- Defense-in-depth: three independent validation layers before execution
- Full audit trail: every decision is logged and queryable

---

## Quick start

```bash
# Start the environment (PostgreSQL + services)
docker-compose up -d --build

# Run the standard demo
python3 demo.py

# Run the Human-in-the-Loop demo
python3 demo_hitl.py
```

---

## Stack

| Component | Technology |
|---|---|
| Agent framework | LangGraph + LangChain |
| Stage 1 | Regex (deterministic) |
| Stage 2 | scikit-learn - TF-IDF + Random Forest |
| Stage 3 | Gemma 3 (local inference) |
| HITL | LangGraph MemorySaver + interrupt |
| Sandbox | Docker (ephemeral, no-network) |
| Registry | PostgreSQL via docker-compose |
| Audit | PostgreSQL async writes |

---

## Project structure

```
agent-security-framework/
- interceptor.py        # 3-stage pipeline entry point
- graph_framework.py    # LangGraph graph definition and routing
- demo_hitl.py          # HITL demo with human approval flow
- demo.py               # Standard end-to-end demo
- train_classifier.py   # Stage 2 model training
- dataset_builder.py    # Training data construction and augmentation
- audit.py              # Audit log writer
- registry.py           # Agent registry (PostgreSQL)
- sandbox.py            # Docker sandbox executor
- key_authority.py      # Cryptographic identity and signing
- validator.py          # Input schema validation
- policies.yaml         # Security policy configuration
- docker-compose.yml    # Full environment definition
```
