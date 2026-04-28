# Agent Security Framework

A Zero Trust security middleware for multi-agent LangGraph architectures. Every tool call is intercepted and evaluated through a 3-stage pipeline before execution.

## 🚀 Architecture
- **Stage 1 (Regex):** Deterministic kill-switches for known bad patterns.
- **Stage 2 (ML Classifier):** TF-IDF + Random Forest model trained on real-world jailbreaks and injection payloads.
- **Stage 3 (Semantic LLM):** Local LLM (Gemma 3) validation for unknown zero-day semantics.

## ✨ New Features
- **Human-in-the-Loop (HITL):** Automatic execution pause and human approval routing via LangGraph MemorySaver when the classifier is uncertain.
- **Docker Sandbox Execution:** Isolated, ephemeral containers without network access for executing risky tools.
- **Production Grade Database:** Switched agent registry from SQLite to PostgreSQL via asynchronous docker-compose deployment.
- **Dataset Augmentation:** The TF-IDF model is now trained on real-world obfuscations (Base64, Hex) and prompt leaking attacks.

## 🛠️ Usage
Run the environment:
`docker-compose up -d --build`

Run the HITL demo:
`python3 demo_hitl.py`

## 🔒 Security Posture
Complies with basic Zero Trust principles and EU AI Act Art. 14 guidelines for Human Oversight.
