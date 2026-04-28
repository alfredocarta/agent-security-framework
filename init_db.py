from registry import add_or_update_agent

def setup_demo():
    print("--- DEMO SETUP ---")
    add_or_update_agent("analytics_agent", "low", ["read_db", "communication", "read_docs"])
    add_or_update_agent("billing_agent", "high", ["read_db", "write_db", "issue_refund"])
    add_or_update_agent("triage_agent", "medium", ["communication"])
    print("[OK] 3 agents configured with distinct permissions.")

if __name__ == "__main__":
    setup_demo()
