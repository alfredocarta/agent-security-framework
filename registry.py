import os
from sqlalchemy import create_engine, Column, String, JSON, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = f"sqlite:///{os.path.join(BASE_DIR, 'agents_registry.db')}"

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
