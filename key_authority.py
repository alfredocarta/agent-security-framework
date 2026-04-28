from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
    load_pem_private_key, load_pem_public_key
)
from sqlalchemy import create_engine, Column, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_DB_URL = f"sqlite:///{os.path.join(BASE_DIR, 'keys_registry.db')}"

key_engine = create_engine(KEY_DB_URL)
KeySession = sessionmaker(autocommit=False, autoflush=False, bind=key_engine)
KeyBase = declarative_base()

class KeyModel(KeyBase):
    __tablename__ = "agent_keys"
    agent_id = Column(String, primary_key=True, index=True)
    private_key_pem = Column(Text, nullable=False)
    public_key_pem = Column(Text, nullable=False)

KeyBase.metadata.create_all(bind=key_engine)

class KeyAuthority:
    def _get_agent_status(self, agent_id):
        from registry import SessionLocal, AgentModel
        db = SessionLocal()
        agent = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
        db.close()
        if agent is None:
            return None
        return agent.status

    def register_agent(self, agent_id):
        status = self._get_agent_status(agent_id)
        if status == "suspended":
            raise PermissionError(f"REGISTRATION DENIED: agent '{agent_id}' is suspended and cannot re-register.")

        db = KeySession()
        existing = db.query(KeyModel).filter(KeyModel.agent_id == agent_id).first()
        if existing:
            private_key = load_pem_private_key(existing.private_key_pem.encode(), password=None)
            db.close()
            return private_key.public_key()

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
        public_pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()

        db.add(KeyModel(agent_id=agent_id, private_key_pem=private_pem, public_key_pem=public_pem))
        db.commit()
        db.close()
        return public_key

    def sign_message(self, agent_id, message):
        db = KeySession()
        record = db.query(KeyModel).filter(KeyModel.agent_id == agent_id).first()
        db.close()
        if not record:
            raise ValueError(f"Agent '{agent_id}' not registered in KeyAuthority.")
        private_key = load_pem_private_key(record.private_key_pem.encode(), password=None)
        return private_key.sign(message.encode())

    def verify_signature(self, agent_id, message, signature):
        db = KeySession()
        record = db.query(KeyModel).filter(KeyModel.agent_id == agent_id).first()
        db.close()
        if not record:
            return False
        public_key = load_pem_public_key(record.public_key_pem.encode())
        try:
            public_key.verify(signature, message.encode())
            return True
        except Exception:
            return False

KA = KeyAuthority()
