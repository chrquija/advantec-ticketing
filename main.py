import os
import streamlit as st  # import Streamlit first

# Must be the first Streamlit call:
st.set_page_config(page_title="ATIX", page_icon="🎫", layout="wide")

# (Optional) Map Streamlit Cloud secrets into env; safe locally too
try:
    if hasattr(st, "secrets") and len(getattr(st, "secrets", {})) > 0:
        os.environ.update({k: str(v) for k, v in st.secrets.items()})
except Exception:
    pass

from dotenv import load_dotenv
load_dotenv()

# --- standard libs ---
import io
import re
import hashlib
import requests
import datetime as dt
from typing import Optional, Tuple, List

# email
import smtplib
from email.message import EmailMessage

import pandas as pd
from sqlalchemy import (
    create_engine, Column, Integer, String, Text, DateTime, Boolean,
    ForeignKey, func, or_, text, inspect, event
)
from sqlalchemy.orm import (
    declarative_base, relationship, sessionmaker, scoped_session, joinedload
)

# ---------------------------
# 0) ENV + GLOBALS
# ---------------------------
APP_NAME = "ATIX"
ORG_NAME = "ADVANTEC"

ALLOWED_EMAIL_DOMAIN = os.getenv("ALLOWED_EMAIL_DOMAIN", "advantec-usa.com")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///atix.db")
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL", "")  # optional (channel Incoming Webhook)
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", f"admin@{ALLOWED_EMAIL_DOMAIN}")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "ChangeMe123!")
# Enable self-signup by default so coworkers can create accounts immediately
ALLOW_SELF_SIGNUP = os.getenv("ALLOW_SELF_SIGNUP", "1") == "1"
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")

# Email (SMTP) config
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USERNAME or f"no-reply@{ALLOWED_EMAIL_DOMAIN}")
SMTP_STARTTLS = os.getenv("SMTP_STARTTLS", "1") == "1"
APP_BASE_URL = os.getenv("APP_BASE_URL", "")

def email_configured() -> bool:
    return bool(SMTP_HOST and SMTP_FROM)

# statuses + priorities
STATUSES = ["New", "In Progress", "Awaiting Approval", "Approved", "Rejected", "On Hold", "Resolved", "Closed"]

# Your P1/P2/P3 wording
PRIORITIES = [
    "P1 - Productivity Impacted (SLA: Same Day)",
    "P2 - Productivity Not Immediately Impacted (SLA: 2-5 Business Days)",
    "P3 - Priority (SLA: 5+ Business Days)",
]

CATEGORIES = ["Civil Engineering", "Data Engineering", "Operations", "Admin/HR", "Other"]

# ---------------------------
# 1) DB SETUP (SQLAlchemy)
# ---------------------------
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = scoped_session(sessionmaker(bind=engine, autocommit=False, autoflush=False))
Base = declarative_base()

# Enforce SQLite foreign keys so deletes/updates can't orphan rows
if DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        try:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON;")
            cursor.close()
        except Exception:
            pass

def utcnow():
    return dt.datetime.utcnow()

# ---------------------------
# 2) MODELS
# ---------------------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=False)
    role = Column(String(50), default="user")  # user / manager / admin
    password_hash = Column(String(255), nullable=True)
    teams_webhook = Column(String(500), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)

class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False)
    code = Column(String(50), unique=True, nullable=True)
    description = Column(Text, nullable=True)
    manager_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    manager = relationship("User")

class Ticket(Base):
    __tablename__ = "tickets"
    id = Column(Integer, primary_key=True)
    short_id = Column(String(24), unique=True, index=True)  # e.g., ATX-2025-0001
    title = Column(String(300), nullable=False)
    description = Column(Text, nullable=False)

    status = Column(String(50), default="New")
    priority = Column(String(80), default="P3 - Priority (SLA: 5+ Business Days)")
    category = Column(String(100), default="Other")

    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    assigned_to_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True)

    request_project_charge = Column(Boolean, default=False)
    approval_status = Column(String(30), default="Not Requested")  # Not Requested / Pending / Approved / Rejected
    approved_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    approval_note = Column(Text, nullable=True)

    due_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow)
    last_activity_at = Column(DateTime, default=utcnow)

    teams_thread_url = Column(String(500), nullable=True)
    attachments_count = Column(Integer, default=0)

    # Archive flag
    is_archived = Column(Boolean, default=False, index=True)

    created_by = relationship("User", foreign_keys=[created_by_id])
    assigned_to = relationship("User", foreign_keys=[assigned_to_id])
    approved_by = relationship("User", foreign_keys=[approved_by_id])
    project = relationship("Project")

class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True)
    ticket_id = Column(Integer, ForeignKey("tickets.id"), index=True)
    author_id = Column(Integer, ForeignKey("users.id"))
    body = Column(Text, nullable=False)
    is_internal = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)

    ticket = relationship("Ticket")
    author = relationship("User")

class Attachment(Base):
    __tablename__ = "attachments"
    id = Column(Integer, primary_key=True)
    ticket_id = Column(Integer, ForeignKey("tickets.id"), index=True)
    uploader_id = Column(Integer, ForeignKey("users.id"))
    file_name = Column(String(300))
    file_path = Column(String(500))
    content_type = Column(String(120))
    file_size = Column(Integer)
    uploaded_at = Column(DateTime, default=utcnow)
    ticket = relationship("Ticket")
    uploader = relationship("User")

class History(Base):
    __tablename__ = "history"
    id = Column(Integer, primary_key=True)
    ticket_id = Column(Integer, ForeignKey("tickets.id"), index=True)
    actor_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String(200))       # e.g., "status_change", "assignment", "created", "comment", "approval", "archive"
    from_status = Column(String(50), nullable=True)
    to_status = Column(String(50), nullable=True)
    note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    ticket = relationship("Ticket")
    actor = relationship("User")

# ---------------------------
# 3) UTIL: SECURITY, TEAMS, EMAIL, IDs
# ---------------------------
def ensure_dirs():
    if not os.path.exists(UPLOAD_DIR):
        os.makedirs(UPLOAD_DIR, exist_ok=True)

def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 120000)
    return salt.hex() + ":" + digest.hex()

def verify_password(pw: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        digest = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 120000)
        return digest.hex() == hash_hex
    except Exception:
        return False

def valid_org_email(email: str) -> bool:
    try:
        domain = email.split("@", 1)[1].lower()
    except Exception:
        return False
    return domain == ALLOWED_EMAIL_DOMAIN.lower()

def generate_short_id(db) -> str:
    year = dt.datetime.utcnow().year
    start = dt.datetime(year, 1, 1)
    end = dt.datetime(year + 1, 1, 1)
    count = db.query(func.count(Ticket.id)).filter(Ticket.created_at >= start, Ticket.created_at < end).scalar() or 0
    return f"ATX-{year}-{count + 1:04d}"

def send_teams_notification(title: str, text: str, webhook: Optional[str] = None) -> Tuple[bool, str]:
    url = webhook or TEAMS_WEBHOOK_URL
    if not url:
        return False, "No webhook configured"
    payload = {"title": title, "text": text}
    try:
        r = requests.post(url, json=payload, timeout=6)
        if r.ok:
            return True, f"Sent ({r.status_code})"
        return False, f"HTTP {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return False, str(e)

def send_email(to_addr: str, subject: str, text_body: str, html_body: Optional[str] = None) -> Tuple[bool, str]:
    if not email_configured():
        return False, "Email not configured"
    try:
        msg = EmailMessage()
        msg["From"] = SMTP_FROM
        msg["To"] = to_addr
        msg["Subject"] = subject
        msg.set_content(text_body)
        if html_body:
            msg.add_alternative(html_body, subtype="html")

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
            if SMTP_STARTTLS:
                s.starttls()
            if SMTP_USERNAME and SMTP_PASSWORD:
                s.login(SMTP_USERNAME, SMTP_PASSWORD)
            s.send_message(msg)
        return True, "sent"
    except Exception as e:
        return False, str(e)

def notify_assignment_email(ticket: Ticket, assigned_to: User, assigned_by: User):
    """Email the assignee when a ticket is assigned to them."""
    if not assigned_to or not assigned_to.email:
        return False, "No recipient"
    url_hint = APP_BASE_URL or ""
    subject = f"[ATIX] {ticket.short_id} assigned to you"
    due_line = f"\nDue: {ticket.due_at.strftime('%Y-%m-%d %H:%M UTC')}" if ticket.due_at else ""
    text_body = (
        f"Hi {assigned_to.name},\n\n"
        f"The following ticket has been assigned to you by {assigned_by.name}:\n"
        f"Ticket: {ticket.short_id}\n"
        f"Title: {ticket.title}\n"
        f"Priority: {ticket.priority}\n"
        f"Status: {ticket.status}{due_line}\n"
        f"Project: {ticket.project.name if ticket.project else '—'}\n\n"
        f"Description:\n{ticket.description[:1000]}\n\n"
        f"Open ATIX: {url_hint}\n"
        f"- ATIX"
    )
    html = f"""
    <p>Hi {assigned_to.name},</p>
    <p>The following ticket has been assigned to you by <b>{assigned_by.name}</b>:</p>
    <ul>
      <li><b>Ticket:</b> {ticket.short_id}</li>
      <li><b>Title:</b> {ticket.title}</li>
      <li><b>Priority:</b> {ticket.priority}</li>
      <li><b>Status:</b> {ticket.status}</li>
      <li><b>Due:</b> {ticket.due_at.strftime('%Y-%m-%d %H:%M UTC') if ticket.due_at else '—'}</li>
      <li><b>Project:</b> {ticket.project.name if ticket.project else '—'}</li>
    </ul>
    <p><b>Description</b>:<br>{ticket.description[:2000].replace('\n','<br>')}</p>
    <p>Open ATIX: <a href="{APP_BASE_URL}">{APP_BASE_URL or '(set APP_BASE_URL to include a link)'}</a></p>
    <p>— ATIX</p>
    """
    ok, msg = send_email(assigned_to.email, subject, text_body, html)
    if not ok and assigned_by and assigned_by.role == "admin":
        st.toast(f"Email not sent: {msg}", icon="⚠️")
    return ok, msg

def send_pm_approval_request_email(db, ticket: Ticket, requested_by: User):
    """Email the Project Manager that an approval was requested."""
    # Guardrails
    if not (ticket and ticket.request_project_charge and ticket.project and ticket.project.manager_id):
        return False, "No PM or approval not requested"
    pm = db.query(User).get(ticket.project.manager_id)
    if not (pm and pm.email):
        return False, "PM has no email"
    url_hint = APP_BASE_URL or ""
    subject = f"[ATIX] Approval requested for {ticket.short_id}"
    text = (
        f"Hi {pm.name},\n\n"
        f"{requested_by.name} requested project charge approval on:\n"
        f"Ticket: {ticket.short_id}\nTitle: {ticket.title}\nProject: {ticket.project.name}\n"
        f"Priority: {ticket.priority}\nStatus: {ticket.status}\n\n"
        f"Open ticket: {url_hint}\n\n"
        f"- ATIX"
    )
    html = f"""
    <p>Hi {pm.name},</p>
    <p><b>{requested_by.name}</b> requested project charge approval on:</p>
    <ul>
      <li><b>Ticket:</b> {ticket.short_id}</li>
      <li><b>Title:</b> {ticket.title}</li>
      <li><b>Project:</b> {ticket.project.name}</li>
      <li><b>Priority:</b> {ticket.priority}</li>
      <li><b>Status:</b> {ticket.status}</li>
    </ul>
    <p>Open ticket: <a href="{APP_BASE_URL}">{APP_BASE_URL or '(set APP_BASE_URL to include a link)'}</a></p>
    <p>— ATIX</p>
    """
    ok, msg = send_email(pm.email, subject, text, html)
    return ok, msg

def add_history(db, ticket_id: int, actor_id: int, action: str, from_status: Optional[str] = None,
                to_status: Optional[str] = None, note: Optional[str] = None):
    h = History(ticket_id=ticket_id, actor_id=actor_id, action=action,
                from_status=from_status, to_status=to_status, note=note)
    db.add(h)
    db.commit()

# ---------------------------
# 4) DB INIT + MIGRATIONS
# ---------------------------
def migrate_priorities(db):
    """Map any legacy priorities to the new P1/P2/P3 scheme."""
    legacy_to_new = {
        "Urgent": PRIORITIES[0],
        "High": PRIORITIES[1],
        "Medium": PRIORITIES[2],
        "Low": PRIORITIES[2],
        "P1 - Urgent": PRIORITIES[0],
        "P2 - High": PRIORITIES[1],
        "P3 - Normal": PRIORITIES[2],
    }
    updated = 0
    for legacy, newv in legacy_to_new.items():
        updated += db.query(Ticket).filter(Ticket.priority == legacy).update(
            {Ticket.priority: newv},
            synchronize_session=False
        )
    if updated:
        db.commit()

def ensure_column(engine, table_name: str, column_name: str, ddl_by_dialect: dict):
    """Add a column if missing (simple migration)."""
    inspector = inspect(engine)
    cols = [c["name"].lower() for c in inspector.get_columns(table_name)]
    if column_name.lower() in cols:
        return
    dialect = engine.dialect.name
    ddl = ddl_by_dialect.get(dialect, ddl_by_dialect.get("default"))
    if not ddl:
        return
    with engine.begin() as conn:
        conn.execute(text(ddl))

def init_db():
    Base.metadata.create_all(bind=engine)
    ensure_dirs()

    # One-time: ensure 'is_archived' exists
    ensure_column(
        engine,
        "tickets",
        "is_archived",
        {
            "sqlite": "ALTER TABLE tickets ADD COLUMN is_archived BOOLEAN DEFAULT 0",
            "postgresql": "ALTER TABLE tickets ADD COLUMN IF NOT EXISTS is_archived BOOLEAN DEFAULT FALSE",
            "mysql": "ALTER TABLE tickets ADD COLUMN is_archived TINYINT(1) DEFAULT 0",
            "mssql": "ALTER TABLE tickets ADD is_archived BIT DEFAULT 0",
            "default": "ALTER TABLE tickets ADD COLUMN is_archived BOOLEAN DEFAULT FALSE",
        },
    )

    db = SessionLocal()
    try:
        # One-time migration
        migrate_priorities(db)

        admin = db.query(User).filter_by(email=ADMIN_EMAIL).first()
        if not admin:
            admin = User(
                email=ADMIN_EMAIL,
                name="ATIX Admin",
                role="admin",
                password_hash=hash_password(ADMIN_PASSWORD),
                is_active=True
            )
            db.add(admin)
            db.commit()
        # Create a default project if none exist
        if db.query(Project).count() == 0:
            p = Project(name="General", code="GEN", description="Default project", manager_id=admin.id)
            db.add(p); db.commit()
    finally:
        db.close()

init_db()

# ---------------------------
# 5) INTRO
# ---------------------------
st.title("ATIX")
st.subheader("Enterprise Ticketing Solution from ADVANTEC")

with st.expander("Learn More About ATIX"):
    st.write("""
    Need something done? Just drop a ticket! 

    **What you can do:**
    - Create, assign, and track **support tickets** within the ENTIRE ADVANTEC network.
    - Attach files, screenshots, and other information to each ticket.
    - Submit work requests and charge them to a project **upon approval from Project Manager.**
    - Receive notifications in Microsoft Teams and email for key events.

    **Why choose ATIX?:**
    - Secure and Reliable: Restricted access to only ADVANTEC employees.
    - Professional Engineering on demand:
        - AI/Data Engineering
        - KPI Dashboards & Visualization
        - Forecasting / Predictive Analytics
        - Dataset discovery & preparation
        - Corridor Analysis for Transportation Studies 
    """)
st.markdown("---")

# ---------------------------
# 6) AUTH HELPERS + VIEW-AS
# ---------------------------
def get_db():
    return SessionLocal()

def current_user() -> Optional[User]:
    return st.session_state.get("user_obj")

def set_current_user(u: Optional[User]):
    st.session_state["user_obj"] = u

def effective_role() -> str:
    u = current_user()
    if not u:
        return ""
    # Admin can toggle view-as-user
    if u.role == "admin" and st.session_state.get("view_as_user", False):
        return "user"
    return u.role

def require_login():
    if not current_user():
        st.warning("Please log in to continue.")
        st.stop()

def require_role(*roles):
    role = effective_role()
    if not role or role not in roles:
        st.error("You do not have access to this section.")
        st.stop()

# ---------------------------
# 7) AUTH UI
# ---------------------------
def login_view():
    st.sidebar.header("Sign in")
    with st.sidebar.form("login_form", clear_on_submit=False):
        email = st.text_input("Email", placeholder=f"user@{ALLOWED_EMAIL_DOMAIN}")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Sign in")
        if submit:
            with get_db() as db:
                u = db.query(User).filter(func.lower(User.email) == email.lower()).first()
                if not u or not u.is_active:
                    st.sidebar.error("Invalid credentials.")
                elif not valid_org_email(u.email):
                    st.sidebar.error("Email domain not permitted.")
                elif not u.password_hash or not verify_password(password, u.password_hash):
                    st.sidebar.error("Invalid credentials.")
                else:
                    set_current_user(u)
                    st.rerun()
                    return

    if ALLOW_SELF_SIGNUP:
        st.sidebar.caption("No account?")
        if st.sidebar.button("Create an account"):
            st.session_state["show_signup"] = True
            st.rerun()
            return

    if st.session_state.get("show_signup", False):
        signup_view()

def signup_view():
    st.sidebar.header("Create an account")
    with st.sidebar.form("signup_form"):
        name = st.text_input("Full name")
        email = st.text_input("Work email", placeholder=f"you@{ALLOWED_EMAIL_DOMAIN}")
        pw1 = st.text_input("Password", type="password")
        pw2 = st.text_input("Confirm password", type="password")
        submit = st.form_submit_button("Create account")
        if submit:
            if not name or not email or not pw1 or not pw2:
                st.sidebar.error("All fields are required.")
            elif pw1 != pw2:
                st.sidebar.error("Passwords do not match.")
            elif not valid_org_email(email):
                st.sidebar.error(f"Must be @{ALLOWED_EMAIL_DOMAIN}.")
            else:
                with get_db() as db:
                    if db.query(User).filter(func.lower(User.email) == email.lower()).first():
                        st.sidebar.error("Account already exists.")
                    else:
                        u = User(email=email, name=name, role="user", password_hash=hash_password(pw1))
                        db.add(u); db.commit()
                        st.sidebar.success("Account created. Please sign in.")
                        st.session_state["show_signup"] = False
                        st.rerun()
                        return

def logout_button():
    user = current_user()
    if user:
        if st.sidebar.button("Sign out"):
            set_current_user(None)
            st.rerun()
            return

# ---------------------------
# 8) SIDEBAR NAV
# ---------------------------
def sidebar_nav():
    user = current_user()
    st.sidebar.title("Navigation")
    if user:
        # View-as-user toggle for admins
        if user.role == "admin":
            st.sidebar.toggle("👁 View as user", key="view_as_user", value=st.session_state.get("view_as_user", False))
        role_label = effective_role()
        suffix = " (viewing as user)" if (user.role == "admin" and role_label == "user") else ""
        st.sidebar.markdown(f"**Signed in as:** {user.name}  \n*Role:* `{role_label}`{suffix}")
        st.sidebar.markdown("---")
        options = [
            "Create Ticket",
            "My Tickets",
            "Team Tickets",
            "Approvals",
            "Dashboard",
            "Projects",
            "Admin",
            "Settings / Profile",
            "Help"
        ]
        # role-gate some items
        visible = []
        role = role_label
        for o in options:
            if o in ["Team Tickets", "Projects", "Approvals"] and role not in ["manager", "admin"]:
                if o == "Approvals":
                    visible.append(o)  # keep visible; actual gate inside
                continue
            if o == "Admin" and role != "admin":
                continue
            visible.append(o)
        page = st.sidebar.radio("Go to", visible, index=0, label_visibility="collapsed")
        st.sidebar.markdown("---")
        logout_button()
        return page
    else:
        login_view()
        st.stop()

# ---------------------------
# 9) HELPERS: USERS/PROJECTS
# ---------------------------
def list_active_users(db) -> List[User]:
    return db.query(User).filter(User.is_active == True).order_by(User.name.asc()).all()

def list_projects(db, active_only=True) -> List[Project]:
    qs = db.query(Project)
    if active_only:
        qs = qs.filter(Project.is_active == True)
    return qs.order_by(Project.name.asc()).all()

def user_display(u: Optional[User]) -> str:
    return f"{u.name} <{u.email}>" if u else "—"

# ---------------------------
# 10) TICKETS — CREATE
# ---------------------------
def create_ticket_view():
    require_login()
    user = current_user()
    st.header("Create Ticket")

    with get_db() as db:
        proj_options = ["(None)"] + [f"{p.name} [{p.code or '—'}]" for p in list_projects(db)]
        projects = list_projects(db)
        users = list_active_users(db)

    with st.form("create_ticket_form", clear_on_submit=True):
        title = st.text_input("Title", max_chars=250)
        desc = st.text_area("Description", height=200, placeholder="Describe the request or issue in detail…")

        col1, col2, col3 = st.columns(3)
        with col1:
            priority = st.selectbox("Priority", PRIORITIES, index=1)  # default P2
        with col2:
            category = st.selectbox("Category", CATEGORIES, index=CATEGORIES.index("Other"))
        with col3:
            set_due = st.checkbox("Set due date")
            if set_due:
                due_date = st.date_input("Due Date", value=dt.date.today(), key="create_due_date")
                due_time = st.time_input("Due Time", value=dt.time(17, 0), key="create_due_time")
            else:
                due_date, due_time = None, None

        col4, col5 = st.columns(2)
        with col4:
            project_choice = st.selectbox("Project (optional)", proj_options, index=0)
        with col5:
            request_charge = st.checkbox("Request project charge approval", value=False)

        # Assignee (new)
        assignee_names = ["(Unassigned)", f"Me - {user.name}"] + [u.name for u in users if u.id != user.id]
        assignee_choice = st.selectbox("Assign To", assignee_names, index=1)

        files = st.file_uploader("Attach files (optional)", type=None, accept_multiple_files=True)

        submit = st.form_submit_button("Submit Ticket", use_container_width=True)

        if submit:
            if not title or not desc:
                st.error("Title and Description are required.")
                return

            with get_db() as db:
                # map project
                project_id = None
                if project_choice != "(None)":
                    idx = proj_options.index(project_choice) - 1
                    if 0 <= idx < len(projects):
                        project_id = projects[idx].id

                # resolve assignee
                assigned_to_id = None
                if assignee_choice.startswith("Me"):
                    assigned_to_id = user.id
                elif assignee_choice != "(Unassigned)":
                    chosen = next((u for u in users if u.name == assignee_choice), None)
                    assigned_to_id = chosen.id if chosen else None

                due_at = dt.datetime.combine(due_date, due_time) if (due_date and due_time) else None

                t = Ticket(
                    short_id=generate_short_id(db),
                    title=title.strip(), description=desc.strip(),
                    status="Awaiting Approval" if request_charge else "New",
                    priority=priority, category=category,
                    created_by_id=user.id,
                    assigned_to_id=assigned_to_id,
                    project_id=project_id,
                    request_project_charge=bool(request_charge),
                    approval_status="Pending" if request_charge else "Not Requested",
                    due_at=due_at,
                    is_archived=False
                )
                db.add(t); db.commit()

                # Save attachments
                if files:
                    ensure_dirs()
                    ticket_dir = os.path.join(UPLOAD_DIR, t.short_id)
                    os.makedirs(ticket_dir, exist_ok=True)
                    count = 0
                    for f in files:
                        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", f.name)
                        path = os.path.join(ticket_dir, safe_name)
                        with open(path, "wb") as out:
                            out.write(f.getbuffer())
                        a = Attachment(
                            ticket_id=t.id,
                            uploader_id=user.id,
                            file_name=safe_name,
                            file_path=path,
                            content_type=f.type or "",
                            file_size=len(f.getbuffer())
                        )
                        db.add(a); count += 1
                    t.attachments_count = count
                    db.commit()
                    add_history(db, t.id, user.id, "attachments", note=f"{count} attachment(s) added")

                add_history(db, t.id, user.id, "created", to_status=t.status)

                # Notify Teams
                title_msg = f"New Ticket {t.short_id}: {t.title}"
                text_msg = f"Priority: {t.priority}\nStatus: {t.status}\nCreated by: {user.name}\nProject: {project_choice}"
                ok, msg = send_teams_notification(title_msg, text_msg)
                if ok:
                    st.toast("Teams notification sent.", icon="✅")

                # Email assignee (if any and not the creator)
                if assigned_to_id and assigned_to_id != user.id:
                    assigned_to = next((u for u in users if u.id == assigned_to_id), None)
                    notify_assignment_email(t, assigned_to, user)

                # >>> NEW: Email the Project Manager immediately when approval is requested
                if t.request_project_charge and t.project and t.project.manager_id:
                    send_pm_approval_request_email(db, t, user)

                st.success(f"Ticket **{t.short_id}** created.")
                st.session_state["last_created_ticket"] = t.short_id

# ---------------------------
# 11) TICKETS — LIST + DETAIL
# ---------------------------
def tickets_table(df: pd.DataFrame, key: str):
    if df.empty:
        st.info("No tickets found.")
    else:
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "short_id": "Ticket",
                "title": "Title",
                "status": st.column_config.SelectboxColumn("Status", options=STATUSES, disabled=True),
                "priority": "Priority",
                "category": "Category",
                "created_at": st.column_config.DatetimeColumn("Created"),
                "updated_at": st.column_config.DatetimeColumn("Updated"),
                "due_at": st.column_config.DatetimeColumn("Due"),
                "created_by": "Created By",
                "assigned_to": "Assigned To",
                "project": "Project",
            },
            height=min(600, 120 + 35 * max(3, len(df)))
        )

def my_tickets_view():
    require_login()
    user = current_user()
    st.header("My Tickets")

    # Simpler filters
    colf1, colf2, colf3, colf4 = st.columns([1.2, 1, 1, 2])
    with colf1:
        view = st.radio("View", ["Created by me", "Assigned to me", "All my tickets"], horizontal=True, index=0)
    with colf2:
        status_group = st.radio("Status", ["Open", "All", "Closed"], horizontal=True, index=0)
    with colf3:
        prio_choice = st.selectbox("Priority", ["Any"] + PRIORITIES, index=0)
    with colf4:
        q = st.text_input("Search (ID / title / description)", placeholder="e.g., ATX-2025-0001 or 'VPN'")

    open_statuses = ["New", "In Progress", "Awaiting Approval", "Approved", "On Hold"]
    closed_statuses = ["Resolved", "Closed"]

    with get_db() as db:
        qs = (
            db.query(Ticket)
              .options(joinedload(Ticket.created_by), joinedload(Ticket.assigned_to), joinedload(Ticket.project))
        )

        # exclude archived by default
        qs = qs.filter(Ticket.is_archived == False)

        if view == "Created by me":
            qs = qs.filter(Ticket.created_by_id == user.id)
        elif view == "Assigned to me":
            qs = qs.filter(Ticket.assigned_to_id == user.id)
        else:
            qs = qs.filter(or_(Ticket.created_by_id == user.id, Ticket.assigned_to_id == user.id))

        if status_group == "Open":
            qs = qs.filter(Ticket.status.in_(open_statuses))
        elif status_group == "Closed":
            qs = qs.filter(Ticket.status.in_(closed_statuses))

        if prio_choice != "Any":
            qs = qs.filter(Ticket.priority == prio_choice)

        if q:
            like = f"%{q.strip()}%"
            qs = qs.filter(or_(Ticket.short_id.ilike(like), Ticket.title.ilike(like), Ticket.description.ilike(like)))

        qs = qs.order_by(Ticket.updated_at.desc())

        rows = []
        for t in qs.all():
            rows.append({
                "short_id": t.short_id,
                "title": t.title,
                "status": t.status,
                "priority": t.priority,
                "category": t.category,
                "created_at": t.created_at,
                "updated_at": t.updated_at,
                "due_at": t.due_at,
                "created_by": user_display(t.created_by),
                "assigned_to": user_display(t.assigned_to),
                "project": t.project.name if t.project else "",
                "id": t.id
            })
        df = pd.DataFrame(rows)
        tickets_table(df, key="mytickets")

        # navigate to a specific ticket
        if not df.empty:
            selected = st.selectbox("Open ticket", ["—"] + df["short_id"].tolist(), index=0)
            if selected != "—":
                ticket_detail_view_by_short_id(selected)

def team_tickets_view():
    require_login()
    user = current_user()
    role = effective_role()
    if role not in ("manager", "admin"):
        st.info("Team view is available for managers and admins.")
        return

    st.header("Team Tickets")
    with get_db() as db:
        colf1, colf2, colf3, colf4 = st.columns(4)
        with colf1:
            status = st.multiselect("Status", STATUSES, default=["New", "In Progress", "Awaiting Approval", "On Hold"])
        with colf2:
            prio = st.multiselect("Priority", PRIORITIES, default=PRIORITIES)
        with colf3:
            assignees = ["(Anyone)"] + [u.name for u in list_active_users(db)]
            assignee = st.selectbox("Assigned To", assignees, index=0)
        with colf4:
            projects = ["(Any)"] + [p.name for p in list_projects(db, active_only=False)]
            proj = st.selectbox("Project", projects, index=0)

        # Admin-only toggle to see archived tickets
        show_archived = False
        if role == "admin":
            show_archived = st.checkbox("Show archived (admin)", value=False)

        qs = (
            db.query(Ticket)
              .options(joinedload(Ticket.created_by), joinedload(Ticket.assigned_to), joinedload(Ticket.project))
              .order_by(Ticket.updated_at.desc())
        )
        qs = qs.filter(Ticket.status.in_(status), Ticket.priority.in_(prio))
        if not show_archived:
            qs = qs.filter(Ticket.is_archived == False)

        if assignee != "(Anyone)":
            u = db.query(User).filter(User.name == assignee).first()
            if u:
                qs = qs.filter(Ticket.assigned_to_id == u.id)
        if proj != "(Any)":
            p = db.query(Project).filter(Project.name == proj).first()
            if p:
                qs = qs.filter(Ticket.project_id == p.id)

        rows = []
        for t in qs.all():
            rows.append({
                "short_id": t.short_id,
                "title": t.title,
                "status": t.status,
                "priority": t.priority,
                "category": t.category,
                "created_at": t.created_at,
                "updated_at": t.updated_at,
                "due_at": t.due_at,
                "created_by": user_display(t.created_by),
                "assigned_to": user_display(t.assigned_to),
                "project": t.project.name if t.project else "",
                "id": t.id
            })
        df = pd.DataFrame(rows)
        tickets_table(df, key="teamtickets")

        if not df.empty:
            selected = st.selectbox("Open ticket", ["—"] + df["short_id"].tolist(), index=0)
            if selected != "—":
                ticket_detail_view_by_short_id(selected)

def ticket_detail_view_by_short_id(short_id: str):
    with get_db() as db:
        t = db.query(Ticket).filter(Ticket.short_id == short_id).first()
        if not t:
            st.error("Ticket not found.")
            return
    ticket_detail_view(t.id)

def ticket_detail_view(ticket_id: int):
    require_login()
    user = current_user()
    role = effective_role()
    with get_db() as db:
        t = (
            db.query(Ticket)
              .options(
                  joinedload(Ticket.created_by),
                  joinedload(Ticket.assigned_to),
                  joinedload(Ticket.project),
              )
              .filter(Ticket.id == ticket_id)
              .first()
        )
        if not t:
            st.error("Ticket not found.")
            return

        # If archived, non-admins can view but not edit; show notice
        if t.is_archived:
            st.info("🗄️ This ticket is archived and read-only. Admins can unarchive to modify.")

        # Compact header
        st.subheader(f"🎫 {t.short_id} — {t.title}")

        # Quick status overview
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Status", t.status)
        col2.metric("Priority", t.priority.split(' - ')[0] if ' - ' in t.priority else t.priority)
        col3.metric("Assigned", t.assigned_to.name if t.assigned_to else "Unassigned")
        col4.metric("Attachments", t.attachments_count)

        # Null-safe caption (fixes crash if creator was removed)
        creator_name = t.created_by.name if t.created_by else "Unknown (user removed)"
        st.caption(f"Created by {creator_name} • {t.created_at.strftime('%Y-%m-%d %H:%M UTC')}")
        st.markdown("---")

        # Admin-only Archive/Unarchive controls
        if role == "admin":
            ac1, ac2 = st.columns([1, 8])
            with ac1:
                if not t.is_archived:
                    if st.button("🗄️ Archive", key=f"arch_{t.id}"):
                        t.is_archived = True
                        t.updated_at = utcnow()
                        t.last_activity_at = utcnow()
                        db.commit()
                        add_history(db, t.id, user.id, "archive", note="archived")
                        st.success("Ticket archived.")
                        st.rerun()
                else:
                    if st.button("♻️ Unarchive", key=f"unarch_{t.id}"):
                        t.is_archived = False
                        t.updated_at = utcnow()
                        t.last_activity_at = utcnow()
                        db.commit()
                        add_history(db, t.id, user.id, "archive", note="unarchived")
                        st.success("Ticket unarchived.")
                        st.rerun()

        st.markdown("---")

        # Tabs
        tabs = ["Details", "Update Ticket", "Files", "Comments"]
        if t.request_project_charge and t.project and t.project.manager_id:
            tabs.insert(2, "Approval")

        if len(tabs) == 4:
            tab1, tab2, tab3, tab4 = st.tabs(tabs)
        else:
            tab1, tab2, tab3, tab4, tab5 = st.tabs(tabs)

        # Details Tab
        with tab1:
            st.markdown("**Description:**")
            st.write(t.description)
            st.markdown("**Ticket Information:**")
            info_col1, info_col2 = st.columns(2)
            with info_col1:
                st.write(f"**Project:** {t.project.name if t.project else 'None'}")
                st.write(f"**Category:** {t.category}")
                st.write(f"**Created:** {t.created_at.strftime('%Y-%m-%d %H:%M UTC')}")
            with info_col2:
                st.write(f"**Updated:** {t.updated_at.strftime('%Y-%m-%d %H:%M UTC')}")
                if t.due_at:
                    st.write(f"**Due:** {t.due_at.strftime('%Y-%m-%d %H:%M UTC')}")
                st.write(f"**Request Charge:** {'Yes' if t.request_project_charge else 'No'}")

        # Update Tab
        with tab2:
            if t.is_archived:
                st.info("This ticket is archived. Unarchive to edit.")
            else:
                with st.form(f"update_ticket_{t.id}", clear_on_submit=False):
                    colu1, colu2 = st.columns(2)
                    with colu1:
                        status = st.selectbox("Status", STATUSES, index=STATUSES.index(t.status))
                        priority = st.selectbox("Priority", PRIORITIES, index=PRIORITIES.index(t.priority) if t.priority in PRIORITIES else 2)
                    with colu2:
                        # assignee selection
                        assignee_options = ["(Unassigned)"]
                        users = list_active_users(db)
                        default_idx = 0
                        for i, u in enumerate(users):
                            assignee_options.append(u.name)
                            if t.assigned_to and t.assigned_to.id == u.id:
                                default_idx = i + 1
                        assignee_choice = st.selectbox("Assign To", assignee_options, index=default_idx)

                        proj_options = ["(None)"] + [p.name for p in list_projects(db)]
                        proj_default = 0
                        projects = list_projects(db)
                        if t.project:
                            for i, p in enumerate(projects):
                                if p.id == t.project.id:
                                    proj_default = i + 1
                                    break
                        project_choice = st.selectbox("Project", proj_options, index=proj_default)

                    colu3, colu4 = st.columns(2)
                    with colu3:
                        due = st.date_input("Due Date", value=t.due_at.date() if t.due_at else dt.date.today())
                    with colu4:
                        due_time = st.time_input("Due Time", value=t.due_at.time() if t.due_at else dt.time(17, 0))

                    note = st.text_input("Update note (optional)")
                    do_update = st.form_submit_button("💾 Save Changes", use_container_width=True)

                    if do_update:
                        # Permissions: creator/assignee can update; managers/admin can update any
                        can_edit = (effective_role() in ["manager", "admin"]) or (user.id in [t.created_by_id, t.assigned_to_id or -1])
                        if not can_edit:
                            st.error("You cannot update this ticket.")
                        else:
                            prev_status = t.status
                            prev_assigned_id = t.assigned_to_id
                            prev_project_id = t.project_id

                            t.status = status
                            t.priority = priority
                            # assignee
                            if assignee_choice == "(Unassigned)":
                                t.assigned_to_id = None
                            else:
                                chosen = next((u for u in users if u.name == assignee_choice), None)
                                t.assigned_to_id = chosen.id if chosen else t.assigned_to_id
                            # project
                            if project_choice == "(None)":
                                t.project_id = None
                            else:
                                chosen = next((p for p in projects if p.name == project_choice), None)
                                t.project_id = chosen.id if chosen else t.project_id
                            # due
                            t.due_at = dt.datetime.combine(due, due_time) if isinstance(due, dt.date) else None
                            t.updated_at = utcnow()
                            t.last_activity_at = utcnow()
                            db.commit()

                            add_history(db, t.id, user.id, "update", from_status=prev_status, to_status=t.status, note=note or "")

                            # If assignment changed -> email assignee
                            if t.assigned_to_id and t.assigned_to_id != prev_assigned_id:
                                new_assignee = db.query(User).get(t.assigned_to_id)
                                notify_assignment_email(t, new_assignee, user)

                            # >>> NEW triggers to PM:
                            # 1) Status moved to Awaiting Approval
                            if t.request_project_charge and t.status == "Awaiting Approval" and t.project and t.project.manager_id:
                                send_pm_approval_request_email(db, t, user)
                            # 2) Project changed and now has a PM (and the request is pending)
                            elif (t.request_project_charge and t.approval_status == "Pending" and
                                  prev_project_id != t.project_id and t.project and t.project.manager_id):
                                send_pm_approval_request_email(db, t, user)

                            send_teams_notification(
                                f"Ticket {t.short_id} updated",
                                f"Status: {t.status}\nPriority: {t.priority}\nAssignee: {t.assigned_to.name if t.assigned_to else '—'}\nBy: {user.name}"
                            )
                            st.success("Changes saved.")
                            st.rerun()

        # Approval Tab (conditional)
        approval_tab = tab3 if t.request_project_charge and t.project and t.project.manager_id else None
        if approval_tab:
            with approval_tab:
                is_pm = (user.id == t.project.manager_id) or (effective_role() in ["manager", "admin"])
                st.write(f"**Approval status:** {t.approval_status}")
                if t.approved_by:
                    st.write(f"**Approved by:** {t.approved_by.name}")
                if t.approval_note:
                    st.write(f"**Note:** {t.approval_note}")

                # >>> NEW: Resend approval email (when pending, not archived)
                can_resend = (t.approval_status == "Pending") and (not t.is_archived)
                can_click = is_pm or (user.id in [t.created_by_id]) or (effective_role() == "admin")
                if can_resend and can_click:
                    if st.button("📧 Resend approval email to PM"):
                        ok, msg = send_pm_approval_request_email(db, t, user)
                        if ok:
                            st.success("Email sent to Project Manager.")
                        else:
                            st.warning(f"Email not sent: {msg}")

                if not t.is_archived and is_pm and t.approval_status in ["Pending", "Rejected"]:
                    colap1, colap2 = st.columns(2)
                    with colap1:
                        note = st.text_input("Approval note (optional)", key=f"ap_note_{t.id}")
                    with colap2:
                        ap = st.radio("Decision", ["Approve", "Reject"], horizontal=True)
                    if st.button("Submit decision", type="primary"):
                        t.approval_status = "Approved" if ap == "Approve" else "Rejected"
                        t.approved_by_id = user.id
                        t.approval_note = note
                        if ap == "Approve" and t.status == "Awaiting Approval":
                            t.status = "Approved"
                        t.updated_at = utcnow()
                        db.commit()
                        add_history(db, t.id, user.id, "approval", from_status="Awaiting Approval", to_status=t.status, note=f"{ap}: {note}")
                        send_teams_notification(
                            f"Ticket {t.short_id} {ap} by {user.name}",
                            f"Approval note: {note or '(none)'}"
                        )
                        st.success(f"Ticket {ap}.")
                        st.rerun()
                elif t.is_archived:
                    st.caption("This ticket is archived. Unarchive to submit a decision.")

        # Files Tab
        files_tab = tab4 if approval_tab else tab3
        with files_tab:
            st.markdown("#### Current Attachments")
            with get_db() as db2:
                atts = db2.query(Attachment).filter(Attachment.ticket_id == t.id).order_by(Attachment.uploaded_at.asc()).all()
            if atts:
                for a in atts:
                    colA1, colA2, colA3, colA4 = st.columns([5, 2, 2, 2])
                    colA1.write(a.file_name)
                    colA2.write(f"{a.file_size / 1024:.1f} KB")
                    colA3.write(a.uploaded_at.strftime("%Y-%m-%d"))
                    try:
                        with open(a.file_path, "rb") as f:
                            colA4.download_button("Download", data=f.read(), file_name=a.file_name, key=f"dl_{a.id}")
                    except FileNotFoundError:
                        colA4.write("❌ Missing")
            else:
                st.info("No attachments yet.")

            if t.is_archived:
                st.caption("This ticket is archived. Unarchive to add files.")
            else:
                st.markdown("#### Add New Attachments")
                upfiles = st.file_uploader("Choose files", accept_multiple_files=True, key=f"att_up_{t.id}")
                if upfiles:
                    ensure_dirs()
                    ticket_dir = os.path.join(UPLOAD_DIR, t.short_id)
                    os.makedirs(ticket_dir, exist_ok=True)
                    for f in upfiles:
                        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", f.name)
                        path = os.path.join(ticket_dir, safe_name)
                        with open(path, "wb") as out:
                            out.write(f.getbuffer())
                        with get_db() as db3:
                            a = Attachment(
                                ticket_id=t.id, uploader_id=user.id, file_name=safe_name,
                                file_path=path, content_type=f.type or "", file_size=len(f.getbuffer())
                            )
                            db3.add(a)
                            tt = db3.query(Ticket).get(t.id)
                            tt.attachments_count = (tt.attachments_count or 0) + 1
                            db3.commit()
                    add_history(db, t.id, user.id, "attachments", note=f"{len(upfiles)} new attachment(s)")
                    st.success("Attachment(s) saved.")
                    st.rerun()

        # Comments Tab
        comments_tab = tab5 if approval_tab else tab4
        with comments_tab:
            st.markdown("#### Discussion History")
            with get_db() as db4:
                comments = (
                    db4.query(Comment)
                       .options(joinedload(Comment.author))
                       .filter(Comment.ticket_id == t.id)
                       .order_by(Comment.created_at.asc())
                       .all()
                )
            if comments:
                for c in comments:
                    with st.container():
                        st.markdown(f"**{c.author.name if c.author else 'Unknown'}** — *{c.created_at.strftime('%Y-%m-%d %H:%M UTC')}*")
                        if c.is_internal:
                            st.markdown("🔒 *Internal Note*")
                        st.write(c.body)
                        st.markdown("---")
            else:
                st.info("No comments yet.")

            if t.is_archived:
                st.caption("This ticket is archived. Unarchive to add comments.")
            else:
                st.markdown("#### Add Comment")
                with st.form(f"comment_{t.id}"):
                    body = st.text_area("Your comment", height=120,
                                        placeholder="Add your thoughts, updates, or questions...")
                    internal = st.checkbox("🔒 Internal note (visible to staff only)")
                    if st.form_submit_button("💬 Post Comment", use_container_width=True):
                        if not body.strip():
                            st.error("Comment cannot be empty.")
                        else:
                            with get_db() as db5:
                                c = Comment(ticket_id=t.id, author_id=user.id, body=body.strip(), is_internal=internal)
                                db5.add(c); db5.commit()
                            add_history(db, t.id, user.id, "comment", note="internal" if internal else "comment")
                            send_teams_notification(f"New comment on {t.short_id}", f"By: {user.name}\n{body[:400]}")
                            st.success("Comment posted.")
                            st.rerun()

# ---------------------------
# 12) APPROVALS PAGE
# ---------------------------
def approvals_view():
    require_login()
    user = current_user()
    st.header("Approvals")

    with get_db() as db:
        # tickets pending approval where current user is project manager
        my_projects = db.query(Project).filter(Project.manager_id == user.id).all()
        my_project_ids = [p.id for p in my_projects]
        qs = (
            db.query(Ticket)
              .options(joinedload(Ticket.created_by), joinedload(Ticket.project))
              .filter(
                  Ticket.approval_status == "Pending",
                  Ticket.project_id.in_(my_project_ids),
                  Ticket.is_archived == False
              )
              .order_by(Ticket.created_at.asc())
        )

        rows = []
        for t in qs.all():
            rows.append({
                "short_id": t.short_id,
                "title": t.title,
                "priority": t.priority,
                "created_by": user_display(t.created_by),
                "project": t.project.name if t.project else "",
                "created_at": t.created_at,
                "id": t.id
            })

        if not rows:
            st.info("No pending approvals right now.")
            return

        df = pd.DataFrame(rows)
        st.dataframe(df[["short_id", "title", "priority", "project", "created_by", "created_at"]], use_container_width=True, hide_index=True)

        selected = st.selectbox("Open ticket to approve", ["—"] + df["short_id"].tolist(), index=0)
        if selected != "—":
            ticket_detail_view_by_short_id(selected)

# ---------------------------
# 13) PROJECTS PAGE
# ---------------------------
def projects_view():
    require_login()
    role = effective_role()
    if role not in ["manager", "admin"]:
        st.info("Projects can be managed by managers or admins.")
        return
    st.header("Projects")

    with get_db() as db:
        colp1, colp2 = st.columns([2, 1])
        with colp1:
            prows = []
            for p in db.query(Project).order_by(Project.is_active.desc(), Project.name.asc()).all():
                prows.append({
                    "name": p.name,
                    "code": p.code or "",
                    "manager": p.manager.name if p.manager else "",
                    "active": "Yes" if p.is_active else "No",
                    "id": p.id
                })
            st.dataframe(pd.DataFrame(prows)[["name", "code", "manager", "active"]], use_container_width=True, hide_index=True)

        with colp2:
            st.subheader("New Project")
            with st.form("new_project"):
                name = st.text_input("Name")
                code = st.text_input("Code (unique)")
                desc = st.text_area("Description", height=100)
                managers = ["(None)"] + [u.name for u in list_active_users(db)]
                msel = st.selectbox("Project Manager", managers, index=0)
                submit = st.form_submit_button("Create Project", use_container_width=True)
                if submit:
                    if not name:
                        st.error("Name is required.")
                    elif db.query(Project).filter(func.lower(Project.name) == name.lower()).first():
                        st.error("A project with this name already exists.")
                    elif code and db.query(Project).filter(func.lower(Project.code) == code.lower()).first():
                        st.error("Code must be unique.")
                    else:
                        pm = None
                        if msel != "(None)":
                            pm = db.query(User).filter(User.name == msel).first()
                        p = Project(name=name, code=code or None, description=desc or None, manager_id=pm.id if pm else None)
                        db.add(p); db.commit()
                        st.success("Project created.")
                        st.rerun()
                        return

# ---------------------------
# 14) DASHBOARD
# ---------------------------
def dashboard_view():
    require_login()
    st.header("KPI Dashboard")

    with get_db() as db:
        total = db.query(func.count(Ticket.id)).filter(Ticket.is_archived == False).scalar() or 0
        open_cnt = db.query(func.count(Ticket.id)).filter(Ticket.status.notin_(["Resolved", "Closed"]), Ticket.is_archived == False).scalar() or 0
        closed_cnt = db.query(func.count(Ticket.id)).filter(Ticket.status.in_(["Resolved", "Closed"]), Ticket.is_archived == False).scalar() or 0
        awaiting = db.query(func.count(Ticket.id)).filter(Ticket.status == "Awaiting Approval", Ticket.is_archived == False).scalar() or 0

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Tickets", total)
        c2.metric("Open", open_cnt)
        c3.metric("Resolved/Closed", closed_cnt)
        c4.metric("Awaiting Approval", awaiting)

        # By status
        st.markdown("#### Tickets by Status (excluding archived)")
        data_status = []
        for s in STATUSES:
            cnt = db.query(func.count(Ticket.id)).filter(Ticket.status == s, Ticket.is_archived == False).scalar() or 0
            data_status.append({"Status": s, "Count": cnt})
        st.bar_chart(pd.DataFrame(data_status).set_index("Status"))

        # By priority
        st.markdown("#### Tickets by Priority (excluding archived)")
        data_prio = []
        for p in PRIORITIES:
            cnt = db.query(func.count(Ticket.id)).filter(Ticket.priority == p, Ticket.is_archived == False).scalar() or 0
            data_prio.append({"Priority": p, "Count": cnt})
        st.bar_chart(pd.DataFrame(data_prio).set_index("Priority"))

        # Trend (last 30 days)
        st.markdown("#### Opened per Day (last 30 days, excluding archived)")
        today = dt.datetime.utcnow().date()
        daily = []
        for i in range(29, -1, -1):
            day = today - dt.timedelta(days=i)
            next_day = day + dt.timedelta(days=1)
            cnt = db.query(func.count(Ticket.id)).filter(
                Ticket.created_at >= dt.datetime.combine(day, dt.time.min),
                Ticket.created_at < dt.datetime.combine(next_day, dt.time.min),
                Ticket.is_archived == False
            ).scalar() or 0
            daily.append({"Date": str(day), "Opened": cnt})
        st.line_chart(pd.DataFrame(daily).set_index("Date"))

        st.markdown("#### Export")
        include_archived = st.checkbox("Include archived tickets in CSV", value=False)
        if st.button("Export all tickets to CSV"):
            rows = []
            qexp = db.query(Ticket).order_by(Ticket.created_at.asc())
            if not include_archived:
                qexp = qexp.filter(Ticket.is_archived == False)
            for t in qexp.all():
                rows.append({
                    "short_id": t.short_id, "title": t.title, "status": t.status, "priority": t.priority,
                    "category": t.category, "project": t.project.name if t.project else "",
                    "created_by": t.created_by.name if t.created_by else "",
                    "assigned_to": t.assigned_to.name if t.assigned_to else "",
                    "created_at": t.created_at.isoformat(), "updated_at": t.updated_at.isoformat(),
                    "due_at": t.due_at.isoformat() if t.due_at else "",
                    "is_archived": bool(t.is_archived),
                })
            buf = io.StringIO()
            pd.DataFrame(rows).to_csv(buf, index=False)
            st.download_button("Download CSV", data=buf.getvalue().encode("utf-8"), file_name="atix_tickets.csv", mime="text/csv")

# ---------------------------
# 15) ADMIN PAGE
# ---------------------------
def admin_view():
    require_login()
    require_role("admin")
    st.header("Admin")

    tab1, tab2 = st.tabs(["Users", "System"])
    with tab1:
        st.subheader("Users")
        with get_db() as db:
            users = db.query(User).order_by(User.is_active.desc(), User.name.asc()).all()

            # Display users with action buttons
            for u in users:
                col1, col2, col3, col4, col5, col6 = st.columns([3, 2, 1, 1, 1, 1])
                col1.write(f"**{u.name}**")
                col2.write(u.email)
                col3.write(u.role)
                col4.write("✅" if u.is_active else "❌")
                col5.write(u.created_at.strftime("%m/%d/%y"))

                # Deactivate / Reactivate (no hard delete)
                current_user_obj = current_user()
                if u.id == current_user_obj.id:
                    col6.write("(You)")
                else:
                    if u.is_active:
                        if col6.button("Deactivate", key=f"deact_{u.id}", help="Set user inactive"):
                            with get_db() as db_del:
                                user_to_deactivate = db_del.query(User).get(u.id)
                                user_to_deactivate.is_active = False
                                db_del.commit()
                            st.success(f"{u.name} deactivated.")
                            st.rerun()
                    else:
                        if col6.button("Reactivate", key=f"react_{u.id}", help="Set user active"):
                            with get_db() as db_act:
                                user_to_activate = db_act.query(User).get(u.id)
                                user_to_activate.is_active = True
                                db_act.commit()
                            st.success(f"{u.name} reactivated.")
                            st.rerun()

            st.markdown("#### Add / Update User")
            with st.form("admin_user_form", clear_on_submit=True):
                name = st.text_input("Full name")
                email = st.text_input("Email", placeholder=f"user@{ALLOWED_EMAIL_DOMAIN}")
                role = st.selectbox("Role", ["user", "manager", "admin"])
                active = st.checkbox("Active", value=True)
                pw = st.text_input("Set password (optional)", type="password")
                submit = st.form_submit_button("Save User")
                if submit:
                    if not name or not email:
                        st.error("Name and email required.")
                    elif not valid_org_email(email):
                        st.error("Email domain not permitted.")
                    else:
                        with get_db() as db2:
                            existing = db2.query(User).filter(func.lower(User.email) == email.lower()).first()
                            if existing:
                                existing.name = name
                                existing.role = role
                                existing.is_active = active
                                if pw:
                                    existing.password_hash = hash_password(pw)
                                db2.commit()
                                st.success("User updated.")
                            else:
                                u = User(name=name, email=email, role=role, is_active=active,
                                         password_hash=hash_password(pw) if pw else None)
                                db2.add(u)
                                db2.commit()
                                st.success("User created.")
                        st.rerun()

    with tab2:
        st.subheader("System Settings")
        st.caption("The app uses environment variables. See `.env.example` for configuration.")
        st.write({
            "DATABASE_URL": DATABASE_URL,
            "ALLOWED_EMAIL_DOMAIN": ALLOWED_EMAIL_DOMAIN,
            "UPLOAD_DIR": UPLOAD_DIR,
            "TEAMS_WEBHOOK_URL": "configured" if TEAMS_WEBHOOK_URL else "(not set)",
            "ALLOW_SELF_SIGNUP": ALLOW_SELF_SIGNUP,
            "EMAIL_SMTP": "configured" if email_configured() else "(not set)",
            "APP_BASE_URL": APP_BASE_URL or "(not set)"
        })

        # Test email functionality
        st.markdown("#### Test Email")
        if st.button("Send test email to ADMIN_EMAIL"):
            ok, msg = send_email(ADMIN_EMAIL, "[ATIX] SMTP test", "If you see this, SMTP works.")
            if ok:
                st.success(f"✅ Email sent successfully: {msg}")
            else:
                st.error(f"❌ Email failed: {msg}")

        if st.button("Rebuild DB metadata (safe)"):
            Base.metadata.create_all(bind=engine)
            st.success("Schema ensured.")


# ---------------------------
# 16) SETTINGS / PROFILE
# ---------------------------
def settings_view():
    require_login()
    user = current_user()
    st.header("Settings / Profile")

    with get_db() as db:
        me = db.query(User).get(user.id)
        with st.form("profile_form"):
            name = st.text_input("Name", value=me.name)
            teams = st.text_input("My Teams webhook (optional)", value=me.teams_webhook or "")
            pw1 = st.text_input("New password (optional)", type="password")
            pw2 = st.text_input("Confirm new password", type="password")
            save = st.form_submit_button("Save")
            if save:
                if pw1 and pw1 != pw2:
                    st.error("Passwords do not match.")
                else:
                    me.name = name.strip() or me.name
                    me.teams_webhook = teams.strip() or None
                    if pw1:
                        me.password_hash = hash_password(pw1)
                    db.commit()
                    set_current_user(me)
                    st.success("Profile updated.")

# ---------------------------
# 17) HELP PAGE
# ---------------------------
def help_view():
    st.header("Help")
    st.markdown(f"""
- **Creating Tickets:** Use **Create Ticket** to submit requests. Attach files/screenshots as needed.
- **Assignments:** You can assign tickets on creation and from the **Update Ticket** tab. The assignee receives an email notification.
- **Statuses:** *New → In Progress → Resolved → Closed.* Approval adds *Awaiting Approval/Approved/Rejected.*
- **Approvals:** Project Managers see **Approvals** for tickets that requested project charges.
- **Teams & Email Notifications:** Configure a channel **Incoming Webhook** (`TEAMS_WEBHOOK_URL`) and SMTP (see **Admin → System**).
- **Security:** Access is restricted to *@{ALLOWED_EMAIL_DOMAIN}* emails. Admins can manage accounts and projects.
- **Users:** Admins **Deactivate/Reactivate** users instead of deleting to preserve history.
- **Archiving:** Admins can **Archive/Unarchive tickets** from the ticket detail page. Archived tickets are read-only and hidden from lists by default.
- **Approval Emails:** PMs are emailed automatically when approval is requested, and you can resend from the Approval tab while Pending.
""")

# ---------------------------
# 18) ROUTER
# ---------------------------
def router():
    page = sidebar_nav()
    if page == "Create Ticket":
        create_ticket_view()
    elif page == "My Tickets":
        my_tickets_view()
    elif page == "Team Tickets":
        team_tickets_view()
    elif page == "Approvals":
        approvals_view()
    elif page == "Dashboard":
        dashboard_view()
    elif page == "Projects":
        projects_view()
    elif page == "Admin":
        admin_view()
    elif page == "Settings / Profile":
        settings_view()
    elif page == "Help":
        help_view()

# ---------------------------
# 19) MAIN
# ---------------------------
if __name__ == "__main__":
    router()
