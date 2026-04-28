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
    for output in app.stream(inputs):
        for key, value in output.items():
            if "log" in value:
                print(f"[{key.upper()}] {value['log'][-1]}")
    time.sleep(1)

run_step("SAFE OPERATION", "triage_agent", "communication", "Case #45 approved", "Customer update")
run_step("PRIVILEGE ESCALATION ATTEMPT", "analytics_agent", "issue_refund", "amount=1000", "Urgent refund")
run_step("SEMANTIC ATTACK", "billing_agent", "write_db", "DROP TABLE users;", "DB maintenance")
run_step("POST-SUSPENSION PERSISTENCE", "billing_agent", "read_db", "*", "Read data")

print("\n--- END OF DEMO SEQUENCE ---")
