from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
    load_pem_private_key, load_pem_public_key
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import create_engine, Column, String, Text, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
import base64

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_DB_URL = f"sqlite:///{os.path.join(BASE_DIR, chr(39)keys_registry.db{chr(39)})}"

key_engine = create_engine(KEY_DB_URL)
KeySession = sessionmaker(autocommit=False, autoflush=False, bind=key_engine)
KeyBase = declarative_base()

def _get_master_key() -> bytes:
    raw = os.environ.get("ASF_MASTER_KEY")
    if raw:
        return base64.b64decode(raw)
    key = AESGCM.generate_key(bit_length=256)
    encoded = base64.b64encode(key).decode()
    print(f"[KEY AUTHORITY] WARNING: ASF_MASTER_KEY not set. Generated a temporary key.")
    print(f"[KEY AUTHORITY] Set this environment variable to persist across restarts:")
    print(f"  export ASF_MASTER_KEY={encoded}")
    return key

MASTER_KEY = _get_master_key()

def _encrypt(data: bytes) -> bytes:
    aesgcm = AESGCM(MASTER_KEY)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, data, None)

def _decrypt(data: bytes) -> bytes:
    aesgcm = AESGCM(MASTER_KEY)
    nonce, ciphertext = data[:12], data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)

class KeyModel(KeyBase):
    __tablename__ = "agent_keys"
    agent_id = Column(String, primary_key=True, index=True)
    private_key_enc = Column(LargeBinary, nullable=False)
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
            raise PermissionError(f"REGISTRATION DENIED: agent {agent_idrm agents_registry.db audit_log.json} is suspended and cannot re-register.")

        db = KeySession()
        existing = db.query(KeyModel).filter(KeyModel.agent_id == agent_id).first()
        if existing:
            private_key_pem = _decrypt(existing.private_key_enc)
            private_key = load_pem_private_key(private_key_pem, password=None)
            db.close()
            return private_key.public_key()

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        public_pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()

        db.add(KeyModel(
            agent_id=agent_id,
            private_key_enc=_encrypt(private_pem),
            public_key_pem=public_pem
        ))
        db.commit()
        db.close()
        return public_key

    def sign_message(self, agent_id, message):
        db = KeySession()
        record = db.query(KeyModel).filter(KeyModel.agent_id == agent_id).first()
        db.close()
        if not record:
            raise ValueError(f"Agent {agent_idrm agents_registry.db audit_log.json} not registered in KeyAuthority.")
        private_key_pem = _decrypt(record.private_key_enc)
        private_key = load_pem_private_key(private_key_pem, password=None)
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
