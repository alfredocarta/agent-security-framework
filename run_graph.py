from graph_framework import app, KA

KA.register_agent("db_agent")

inputs = {
    "agent_id": "db_agent",
    "request": "Reset the system",
    "tool": "write_db",
    "tool_input": "DELETE FROM users; --",
    "log": []
}

print("\n>>> STARTING LANGGRAPH SECURITY FLOW <<<")
for output in app.stream(inputs):
    for key, value in output.items():
        if "log" in value:
            print(f"[LOG] {value['log'][-1]}")
