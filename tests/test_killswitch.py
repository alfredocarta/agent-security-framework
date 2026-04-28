import os
os.environ["ASF_SKIP_LLM"] = "true"

from interceptor import security_interceptor

def test_kill_switch_suspends_agent():
    ok1, msg1 = security_interceptor("billing_agent", "write_db", "DROP TABLE users")
    assert not ok1

def test_suspended_agent_blocked_on_safe_request():
    security_interceptor("billing_agent", "write_db", "DROP TABLE users")
    ok2, msg2 = security_interceptor("billing_agent", "read_db", "SELECT * FROM users")
    assert not ok2, f"Suspended agent should be blocked, got: {msg2}"
