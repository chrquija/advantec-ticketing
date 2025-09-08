import os
import random
import hashlib
import datetime as dt
from typing import Optional, Tuple
import smtplib
from email.message import EmailMessage

from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy.orm import sessionmaker

# Import shared database setup (CHANGED: was "from main import...")
from database import Base, engine, utcnow, valid_org_email, hash_password

# ... rest of your existing code stays exactly the same ...

# ---------------------------
# 2FA CONFIGURATION
# ---------------------------

# Email settings (reuse from main.py or set here)
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USERNAME or "no-reply@advantec-usa.com")
SMTP_STARTTLS = os.getenv("SMTP_STARTTLS", "1") == "1"
ALLOWED_EMAIL_DOMAIN = os.getenv("ALLOWED_EMAIL_DOMAIN", "advantec-usa.com")

# Verification code settings
CODE_LENGTH = 5
CODE_EXPIRY_MINUTES = 15  # How long codes are valid


# ---------------------------
# DATABASE MODEL
# ---------------------------

class EmailVerification(Base):
    """Stores pending email verifications with codes"""
    __tablename__ = "email_verifications"

    id = Column(Integer, primary_key=True)
    email = Column(String(255), nullable=False, index=True)
    name = Column(String(255), nullable=False)  # Full name for account creation
    password_hash = Column(String(255), nullable=False)  # Hashed password ready to use
    verification_code = Column(String(10), nullable=False)  # The 5-digit code
    created_at = Column(DateTime, default=utcnow)
    expires_at = Column(DateTime, nullable=False)
    is_verified = Column(Boolean, default=False)
    attempts = Column(Integer, default=0)  # Track failed verification attempts


# ---------------------------
# HELPER FUNCTIONS
# ---------------------------

def generate_verification_code() -> str:
    """Generate a random 5-digit verification code"""
    return ''.join([str(random.randint(0, 9)) for _ in range(CODE_LENGTH)])


def send_verification_email(email: str, code: str, name: str) -> Tuple[bool, str]:
    """Send verification code via email"""
    if not SMTP_HOST:
        return False, "Email not configured"

    subject = "ATIX Account Verification Code"

    text_body = f"""Hi {name},

Welcome to ATIX! To complete your account creation, please use this verification code:

Verification Code: {code}

This code will expire in {CODE_EXPIRY_MINUTES} minutes.

If you didn't request this account, please ignore this email.

Best regards,
ATIX Team
ADVANTEC
"""

    html_body = f"""
    <html>
    <body>
        <h2>Welcome to ATIX!</h2>
        <p>Hi <strong>{name}</strong>,</p>

        <p>To complete your account creation, please use this verification code:</p>

        <div style="background-color: #f0f0f0; padding: 20px; text-align: center; margin: 20px 0;">
            <h1 style="color: #2E86AB; font-size: 32px; margin: 0; letter-spacing: 5px;">{code}</h1>
        </div>

        <p>This code will expire in <strong>{CODE_EXPIRY_MINUTES} minutes</strong>.</p>

        <p>If you didn't request this account, please ignore this email.</p>

        <p>Best regards,<br>
        <strong>ATIX Team</strong><br>
        ADVANTEC</p>
    </body>
    </html>
    """

    try:
        msg = EmailMessage()
        msg["From"] = SMTP_FROM
        msg["To"] = email
        msg["Subject"] = subject
        msg.set_content(text_body)
        msg.add_alternative(html_body, subtype="html")

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            if SMTP_STARTTLS:
                server.starttls()
            if SMTP_USERNAME and SMTP_PASSWORD:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)

        return True, "Verification email sent"
    except Exception as e:
        return False, f"Email failed: {str(e)}"


def create_verification_request(email: str, name: str, password: str) -> Tuple[bool, str, str]:
    """Create a new verification request"""

    # Validate inputs
    if not name or not email or not password:
        return False, "All fields are required", ""

    if not valid_org_email(email):
        return False, f"Email must be @{ALLOWED_EMAIL_DOMAIN}", ""

    # Generate code and expiry
    code = generate_verification_code()
    expires_at = dt.datetime.utcnow() + dt.timedelta(minutes=CODE_EXPIRY_MINUTES)

    # Create database session
    Session = sessionmaker(bind=engine)
    session = Session()

    try:
        # Check if user already exists
        from main import User
        existing_user = session.query(User).filter(User.email.ilike(email)).first()
        if existing_user:
            return False, "Account with this email already exists", ""

        # Clean up any old verification requests for this email
        session.query(EmailVerification).filter(EmailVerification.email.ilike(email)).delete()

        # Create new verification record
        verification = EmailVerification(
            email=email.lower(),
            name=name.strip(),
            password_hash=hash_password(password),
            verification_code=code,
            expires_at=expires_at,
            attempts=0
        )

        session.add(verification)
        session.commit()

        # Send email
        email_success, email_msg = send_verification_email(email, code, name)
        if not email_success:
            return False, f"Failed to send verification email: {email_msg}", ""

        return True, f"Verification code sent to {email}", code  # Return code for testing

    except Exception as e:
        session.rollback()
        return False, f"Database error: {str(e)}", ""
    finally:
        session.close()


def verify_code_and_create_account(email: str, entered_code: str) -> Tuple[bool, str]:
    """Verify the code and create the user account if valid"""

    Session = sessionmaker(bind=engine)
    session = Session()

    try:
        # Find the verification request
        verification = session.query(EmailVerification).filter(
            EmailVerification.email.ilike(email),
            EmailVerification.is_verified == False
        ).first()

        if not verification:
            return False, "No verification request found for this email"

        # Check if expired
        if dt.datetime.utcnow() > verification.expires_at:
            session.delete(verification)
            session.commit()
            return False, "Verification code has expired. Please request a new one."

        # Check attempt limits (prevent brute force)
        if verification.attempts >= 5:
            session.delete(verification)
            session.commit()
            return False, "Too many failed attempts. Please request a new verification code."

        # Check if code matches
        if verification.verification_code != entered_code.strip():
            verification.attempts += 1
            session.commit()
            remaining = 5 - verification.attempts
            return False, f"Invalid code. {remaining} attempts remaining."

        # Code is correct! Create the user account
        from main import User
        new_user = User(
            email=verification.email,
            name=verification.name,
            password_hash=verification.password_hash,
            role="user",  # New users always start as regular users
            is_active=True
        )

        session.add(new_user)

        # Mark verification as complete
        verification.is_verified = True

        session.commit()

        # Clean up - delete the verification record
        session.delete(verification)
        session.commit()

        return True, f"Account created successfully! Welcome {new_user.name}!"

    except Exception as e:
        session.rollback()
        return False, f"Error creating account: {str(e)}"
    finally:
        session.close()


def cleanup_expired_verifications():
    """Clean up expired verification requests (run periodically)"""
    Session = sessionmaker(bind=engine)
    session = Session()

    try:
        expired_count = session.query(EmailVerification).filter(
            EmailVerification.expires_at < dt.datetime.utcnow()
        ).delete()
        session.commit()
        return expired_count
    except Exception as e:
        session.rollback()
        return 0
    finally:
        session.close()


def get_verification_status(email: str) -> Optional[dict]:
    """Get status of verification request for debugging"""
    Session = sessionmaker(bind=engine)
    session = Session()

    try:
        verification = session.query(EmailVerification).filter(
            EmailVerification.email.ilike(email)
        ).first()

        if not verification:
            return None

        return {
            "email": verification.email,
            "name": verification.name,
            "created_at": verification.created_at,
            "expires_at": verification.expires_at,
            "attempts": verification.attempts,
            "is_verified": verification.is_verified,
            "is_expired": dt.datetime.utcnow() > verification.expires_at
        }
    finally:
        session.close()


# ---------------------------
# DATABASE INITIALIZATION
# ---------------------------

def init_2fa_db():
    """Initialize the 2FA database tables"""
    Base.metadata.create_all(bind=engine)
    # Clean up any expired verifications on startup
    cleanup_expired_verifications()


# Initialize when imported
init_2fa_db()