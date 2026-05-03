import yaml
import os
from registry import store_detection_patterns, add_or_update_agent

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
POLICIES_PATH = os.path.join(BASE_DIR, "policies.yaml")

def migrate():
    with open(POLICIES_PATH, "r") as f:
        policies = yaml.safe_load(f)

    patterns = policies["detection"]["patterns"]
    h = store_detection_patterns(patterns)
    print(f"[MIGRATE] Detection patterns stored in DB. Hash: {h[:16]}...")

    for agent_id, config in policies["agents"].items():
        add_or_update_agent(agent_id, config["risk_level"], config["permissions"])
        print(f"[MIGRATE] Agent '{agent_id}' configured.")

    print("[MIGRATE] Done. Runtime no longer depends on policies.yaml for security-critical data.")

if __name__ == "__main__":
    migrate()
