from registry import SessionLocal, AgentModel
import sys

def unsuspend(agent_id):
    db = SessionLocal()
    agent = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
    if agent:
        agent.status = "active"
        db.commit()
        print(f"[HUMAN OVERSIGHT] Agent '{agent_id}' successfully reinstated.")
    else:
        print(f"[ERROR] Agent '{agent_id}' not found.")
    db.close()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        unsuspend(sys.argv[1])
    else:
        print("Usage: python unsuspend_agent.py <agent_id>")
