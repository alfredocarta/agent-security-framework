import os
os.environ["ASF_SKIP_LLM"] = "true"

import pytest
from interceptor import security_interceptor
from registry import get_agent_permissions
from tests.conftest import is_blocked, is_allowed

class TestKillSwitch:
    def test_kill_switch_triggers_on_sql_injection(self):
        result = security_interceptor("billing_agent", "write_db", "DROP TABLE users")
        assert is_blocked(result), f"Expected BLOCKED, got: {result}"

    def test_suspended_agent_blocked_on_any_subsequent_request(self):
        security_interceptor("billing_agent", "write_db", "DROP TABLE users")
        result = security_interceptor("billing_agent", "read_db", "SELECT * FROM users")
        assert is_blocked(result), f"Suspended agent should be blocked on all requests"

    def test_suspended_agent_blocked_on_safe_input(self):
        security_interceptor("billing_agent", "write_db", "DROP TABLE users")
        result = security_interceptor("billing_agent", "read_db", "quarterly_report.pdf")
        assert is_blocked(result), f"Suspended agent should be blocked even on safe input"

    def test_suspension_persists_in_db(self):
        security_interceptor("billing_agent", "write_db", "DROP TABLE users")
        permissions = get_agent_permissions("billing_agent")
        assert permissions == [], "Suspended agent should return empty permissions"

    def test_clean_agent_not_suspended(self):
        result = security_interceptor("billing_agent", "read_db", "quarterly_report.pdf")
        assert is_allowed(result), f"Clean agent should not be suspended"
        permissions = get_agent_permissions("billing_agent")
        assert permissions != [], "Clean agent should still have permissions"
