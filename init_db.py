import yaml
import os
from registry import add_or_update_agent

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
POLICIES_PATH = os.path.join(BASE_DIR, "policies.yaml")

def setup_demo():
    print("--- DEMO SETUP ---")
    with open(POLICIES_PATH, "r") as f:
        policies = yaml.safe_load(f)

    for agent_id, config in policies["agents"].items():
        add_or_update_agent(agent_id, config["risk_level"], config["permissions"])
        print(f"[OK] {agent_id} configured (risk: {config['risk_level']}, permissions: {config['permissions']})")

    print("[OK] All agents configured from policies.yaml.")

if __name__ == "__main__":
    setup_demo()
