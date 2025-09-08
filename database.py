import os
import hashlib
import datetime as dt
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///atix.db")
ALLOWED_EMAIL_DOMAIN = os.getenv("ALLOWED_EMAIL_DOMAIN", "advantec-usa.com")

# Database setup
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = scoped_session(sessionmaker(bind=engine, autocommit=False, autoflush=False))
Base = declarative_base()

def utcnow():
    return dt.datetime.utcnow()

def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 120000)
    return salt.hex() + ":" + digest.hex()

def valid_org_email(email: str) -> bool:
    try:
        domain = email.split("@", 1)[1].lower()
    except Exception:
        return False
    return domain == ALLOWED_EMAIL_DOMAIN.lower()