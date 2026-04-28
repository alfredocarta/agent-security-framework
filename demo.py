import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def reset_db():
    for db_file in ["agents_registry.db", "keys_registry.db"]:
        path = os.path.join(BASE_DIR, db_file)
        if os.path.exists(path):
            os.remove(path)
            print(f"[SETUP] Removed {db_file}")

def setup_agents():
    from registry import add_or_update_agent
    add_or_update_agent("analytics_agent", "low", ["read_db", "communication", "read_docs"])
    add_or_update_agent("billing_agent", "high", ["read_db", "write_db", "issue_refund"])
    add_or_update_agent("triage_agent", "medium", ["communication"])
    print("[SETUP] 3 agents configured with distinct permissions.")

def run_demo():
    from graph_framework import app, KA
    import time

    KA.register_agent("triage_agent")
    KA.register_agent("analytics_agent")
    KA.register_agent("billing_agent")

    def run_step(title, agent_id, tool, tool_input, request):
        print(f"\n--- STEP: {title} ---")
        inputs = {
            "agent_id": agent_id,
            "request": request,
            "tool": tool,
            "tool_input": tool_input,
            "log": []
        }
        try:
            for output in app.stream(inputs):
                for key, value in output.items():
                    if "log" in value:
                        print(f"[{key.upper()}] {value['log'][-1]}")
        except Exception as e:
            print(f"[ERROR] {e}")
            sys.exit(1)
        time.sleep(1)

    print("\n=== AGENT SECURITY FRAMEWORK - DEMO ===\n")

    run_step("SAFE OPERATION", "triage_agent", "communication", "Case #45 approved", "Customer update")
    run_step("PRIVILEGE ESCALATION ATTEMPT", "analytics_agent", "issue_refund", "amount=1000", "Urgent refund")
    run_step("SEMANTIC ATTACK", "billing_agent", "write_db", "DROP TABLE users;", "DB maintenance")
    run_step("POST-SUSPENSION PERSISTENCE", "billing_agent", "read_db", "*", "Read data")

    print("\n=== END OF DEMO ===")
    print("[INFO] Audit trail available at http://localhost:8000/audit (credentials: admin / asf-secret-2024)")

if __name__ == "__main__":
    print("=== SETUP ===")
    reset_db()
    setup_agents()
    print("[SETUP] Done. Starting demo...\n")
    run_demo()
