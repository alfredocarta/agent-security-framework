import os
os.environ["ASF_SKIP_LLM"] = "true"

import pytest
from registry import SessionLocal, AgentModel, add_or_update_agent
from key_authority import KA

AGENTS = {
    "triage_agent":    ("medium", ["communication"]),
    "billing_agent":   ("high",   ["read_db", "write_db", "issue_refund"]),
    "analytics_agent": ("low",    ["read_db", "communication", "read_docs"]),
    "researcher_agent":("low",    ["communication"]),
    "db_agent":        ("medium", ["read_db", "write_db", "communication"]),
}

def reset_all_agents():
    db = SessionLocal()
    for agent in db.query(AgentModel).all():
        agent.status = "active"
    db.commit()
    db.close()
    for agent_id, (risk, perms) in AGENTS.items():
        add_or_update_agent(agent_id, risk, perms)

@pytest.fixture(autouse=True)
def clean_state():
    reset_all_agents()
    yield
    reset_all_agents()

@pytest.fixture(scope="session", autouse=True)
def register_keys():
    for agent_id in AGENTS:
        KA.register_agent(agent_id)

def is_blocked(result):
    verdict, _ = result
    return verdict in ("DENY", "HITL")

def is_allowed(result):
    verdict, _ = result
    return verdict == "ALLOW"

def is_hitl(result):
    verdict, _ = result
    return verdict == "HITL"
