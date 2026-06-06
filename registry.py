import os
import json
import hashlib
from sqlalchemy import create_engine, Column, String, JSON, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'asf_local.db')}")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class AgentModel(Base):
    __tablename__ = "agents"
    agent_id = Column(String, primary_key=True, index=True)
    risk_level = Column(String)
    permissions = Column(JSON)
    status = Column(String, default="active")

class AuditModel(Base):
    __tablename__ = "audit_trail"
    hash = Column(String, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    agent_id = Column(String)
    action = Column(String)
    outcome = Column(String)
    reason = Column(String)
    prev_hash = Column(String)

class PoliciesModel(Base):
    __tablename__ = "policies"
    key = Column(String, primary_key=True)
    value = Column(JSON)
    content_hash = Column(Text)

Base.metadata.create_all(bind=engine)

def get_agent_permissions(agent_id):
    db = SessionLocal()
    agent = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
    db.close()
    if not agent or agent.status == "suspended":
        return []
    return agent.permissions

def suspend_agent(agent_id):
    db = SessionLocal()
    agent = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
    if agent:
        agent.status = "suspended"
        db.commit()
    db.close()

def add_or_update_agent(agent_id, risk_level, permissions):
    db = SessionLocal()
    agent = AgentModel(agent_id=agent_id, risk_level=risk_level, permissions=permissions, status="active")
    db.merge(agent)
    db.commit()
    db.close()

def store_detection_patterns(patterns):
    h = hashlib.sha256(json.dumps(patterns, sort_keys=True).encode()).hexdigest()
    db = SessionLocal()
    record = PoliciesModel(key="detection_patterns", value=patterns, content_hash=h)
    db.merge(record)
    db.commit()
    db.close()
    return h

def get_detection_patterns():
    db = SessionLocal()
    record = db.query(PoliciesModel).filter(PoliciesModel.key == "detection_patterns").first()
    db.close()
    if record is None:
        return None
    return record.value


def reinstate_agent(agent_id: str) -> None:
    """Reinstate a suspended agent to active status. Used by evaluation framework to reset state between scenarios."""
    with SessionLocal() as session:
        agent = session.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
        if agent and agent.status == "suspended":
            agent.status = "active"
            session.commit()


def agent_exists(agent_id: str) -> bool:
    """Return True if the agent is already registered, regardless of status.

    Lets callers register an agent once without resetting an existing row's status
    (e.g. clearing a kill-switch suspension via add_or_update_agent's status='active').
    """
    with SessionLocal() as session:
        return session.query(AgentModel).filter(AgentModel.agent_id == agent_id).first() is not None
