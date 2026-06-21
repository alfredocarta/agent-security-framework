import os
import tempfile

os.environ["ASF_SKIP_LLM"] = "true"

os.environ.setdefault("ASF_HOOK_RUNTIME_DIR", tempfile.mkdtemp(prefix="asf_hook_test_runtime_"))

if "ASF_ENV_STATE_FILE" not in os.environ:
    _ENV_STATE_FILE = os.path.join(tempfile.gettempdir(), "asf_test_suite_env")
    try:
        os.remove(_ENV_STATE_FILE)
    except FileNotFoundError:
        pass
    os.environ["ASF_ENV_STATE_FILE"] = _ENV_STATE_FILE

# Isolate the test suite from the production audit DB (asf_local.db). registry binds its
# engine to DATABASE_URL at import time, so this MUST run before `import registry` below;
# otherwise the suite writes scenario agents and audit events into the real DB and pollutes
# the dashboard (per-agent charts, sessions, KPIs). An externally provided DATABASE_URL is
# honored so targeted runs can point elsewhere.
if "DATABASE_URL" not in os.environ:
    _TEST_DB = os.path.join(tempfile.gettempdir(), "asf_test_suite.db")
    try:
        os.remove(_TEST_DB)
    except FileNotFoundError:
        pass
    os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB}"

import pytest
from registry import SessionLocal, AgentModel, add_or_update_agent
from key_authority import KA
import migrate_policies

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

@pytest.fixture(scope="session", autouse=True)
def seed_isolated_db():
    # The isolated (temp) DB starts empty: load detection patterns and policy agents so
    # the Stage 1/2 and permission tests have the security-critical data they expect.
    migrate_policies.migrate()
    yield


@pytest.fixture(autouse=True)
def clean_state():
    reset_all_agents()
    yield
    reset_all_agents()

@pytest.fixture(scope="session", autouse=True)
def register_keys():
    for agent_id in AGENTS:
        try:
            KA.register_agent(agent_id)
        except Exception:
            # Existing encrypted test keys may have been created with a different
            # temporary ASF_MASTER_KEY. Reset only the test agents so a local
            # developer machine can run the suite deterministically.
            from key_authority import KeyModel, KeySession

            db = KeySession()
            db.query(KeyModel).filter(KeyModel.agent_id == agent_id).delete()
            db.commit()
            db.close()
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
