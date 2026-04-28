# Agent Security Framework

A Zero Trust security middleware for multi-agent LangGraph architectures.
The system intercepts and blocks malicious actions at runtime before execution.

![Python](https://img.shields.io/badge/python-3.11-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![LangGraph](https://img.shields.io/badge/langgraph-1.1.10-orange)

## Architecture

The framework implements a 3-node LangGraph pipeline:

    Agent Node -> Security Node -> Execution Node

Every tool call is signed by the originating agent, verified cryptographically,
checked against a permission registry, and evaluated through a 3-stage detection
pipeline before execution is allowed.

```mermaid
flowchart TD
    A([Agent Node]) -->|signed request| B([Security Node])
    B --> C{Signature valid?}
    C -->|no| D[BLOCK: invalid identity]
    C -->|yes| E{Permission check}
    E -->|tool not allowed| F[BLOCK: unauthorized tool]
    E -->|allowed| G{Stage 1 - Regex}
    G -->|pattern matched| H[KILL SWITCH]
    G -->|clean| I{Stage 2 - TF-IDF Classifier}
    I -->|DANGEROUS| H
    I -->|SAFE| J([Execution Node])
    I -->|UNCERTAIN| K{Stage 3 - LLM}
    K -->|DANGEROUS| H
    K -->|SAFE| J
    H --> L[(DB: agent suspended)]
    J --> M[Tool executed]
```
## Core Modules

- key_authority.py - Cryptographic identity management. Each agent has a persistent
  Ed25519 key pair encrypted at rest with AES-256-GCM. The master key is loaded from
  the ASF_MASTER_KEY environment variable. Suspended agents cannot re-register.
- registry.py - SQLAlchemy/SQLite persistent store for agent ID, risk level,
  granular permissions, and status (active/suspended).
- interceptor.py - 3-stage detection pipeline evaluated on every tool call.
- audit.py - Immutable hash-chained audit trail. Each record includes the SHA-256
  hash of the previous record, guaranteeing forensic integrity.
- graph_framework.py - LangGraph orchestration of the 3-node pipeline.
- validator.py - Inter-agent message validation with delegation attack detection.
- server.py - FastAPI audit dashboard with HTTP Basic Auth and pagination.

## Detection Pipeline

Stage 1 - Regex: immediate block on known patterns (SQL injection, prompt injection,
privilege escalation). Patterns are loaded from policies.yaml - no code changes needed.

Stage 2 - TF-IDF Classifier: a logistic regression classifier trained on 207 labeled
examples across 5 attack categories (SQL injection, prompt injection, privilege
escalation, data exfiltration, system manipulation). Evaluated with 5-fold
cross-validation.

    accuracy             0.9417 (+/- 0.0367)
    precision_macro      0.9454 (+/- 0.0405)
    recall_macro         0.9347 (+/- 0.0370)
    f1_macro             0.9384 (+/- 0.0384)

If confidence >= 0.60 the verdict is final and Stage 3 is not called.
Only uncertain inputs are escalated.

Stage 3 - LLM: a local model via LM Studio performs semantic intent analysis
using few-shot prompting. Configured in policies.yaml (provider, model, base_url).
If the LLM is unavailable the system fails closed (blocks by default).

## Kill Switch

If an attack is detected at any stage the agent is permanently suspended in the
database. A suspended agent cannot re-register a new key. Human operators can
reinstate an agent via unsuspend_agent.py, satisfying EU AI Act Art. 14 human
oversight requirements. See THREAT_MODEL.md for the full adversary model.

## Policy DSL

Agents, permissions, and detection patterns are fully defined in policies.yaml.

    agents:
      triage_agent:
        risk_level: medium
        permissions: [communication]
      billing_agent:
        risk_level: high
        permissions: [read_db, write_db, issue_refund]

    detection:
      patterns:
        - "(?i)\\bDROP\\s+TABLE\\b"
        - "(?i)ignore\\s+(all\\s+)?previous\\s+instructions"

    llm:
      provider: lm_studio
      base_url: "http://localhost:1234/v1"
      model: "google/gemma-3-4b"
      timeout: 10

## Delegation Attack Detection

The validator detects illegal delegation attempts - scenarios where an agent
without a permission tries to instruct another agent to execute a restricted
action on its behalf. Detection covers explicit delegation patterns, tool
reference bypass, and identity impersonation.

## Environment Variables

    ASF_MASTER_KEY        AES-256-GCM master key (generated on first run if unset)
    ASF_DASHBOARD_USER    Audit dashboard username (default: admin)
    ASF_DASHBOARD_PASSWORD  Audit dashboard password (default: asf-secret-2024)

## Setup

Install dependencies:

    pip install -r requirements.txt

Train the classifier:

    python train_classifier.py

Set environment variables and start LM Studio locally with the configured model on port 1234.

Run the full demo (resets DB, configures agents, runs all scenarios):

    python demo.py

Start the audit dashboard in a separate terminal:

    python server.py

Open http://localhost:8000/audit in your browser.

## Docker

    docker compose up

## Test Scenarios

    python test_security.py       # permission and semantic attack tests
    python test_security_v2.py    # identity and intent validation
    python test_killswitch.py     # kill switch persistence
    python test_delegation.py     # delegation attack detection

## Human Oversight

    python unsuspend_agent.py <agent_id>

## Threat Model

See THREAT_MODEL.md for the full adversary model, threat scenarios, controls, and compliance notes.

## Project Structure

- audit.py - immutable hash-chained audit trail
- demo.py - one-command demo setup and execution
- graph_framework.py - LangGraph orchestration
- interceptor.py - 3-stage detection pipeline
- key_authority.py - Ed25519 key management with AES-256-GCM encryption
- policies.yaml - policy DSL for agents, detection patterns, and LLM config
- registry.py - agent registry and permissions
- server.py - FastAPI audit dashboard
- train_classifier.py - classifier training with cross-validation metrics
- training_data.py - labeled dataset (207 examples across 5 attack categories)
- unsuspend_agent.py - human oversight reinstatement tool
- validator.py - inter-agent message validation and delegation attack detection
- THREAT_MODEL.md - formal threat model and compliance notes
- Dockerfile / docker-compose.yml - containerized deployment
