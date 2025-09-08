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

# --- your other imports can follow ---
import io
import re
import uuid
import json
import time
import math
import shutil
import hashlib
import requests
import datetime as dt
from typing import Optional, Tuple, List

import pandas as pd
from sqlalchemy import (
    create_engine, Column, Integer, String, Text, DateTime, Boolean,
    ForeignKey, func
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, scoped_session


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

# statuses + priorities
STATUSES = ["New", "In Progress", "Awaiting Approval", "Approved", "Rejected", "On Hold", "Resolved", "Closed"]

# New priority scheme
PRIORITIES = ["P1 - Productivity Impacted (SLA: Same Day)", "P2 - Productivity Not Immediately Impacted (SLA: 2-5 Business Days)", "P3 - Priority (SLA: 5+ Business Days)"]

CATEGORIES = ["Civil Engineering", "Data Engineering", "Operations", "Admin/HR", "Other"]

# ---------------------------
# 1) DB SETUP (SQLAlchemy)
# ---------------------------
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = scoped_session(sessionmaker(bind=engine, autocommit=False, autoflush=False))
Base = declarative_base()

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
    password_hash = Column(String(255), nullable=True)  # not required if using SSO later
    teams_webhook = Column(String(500), nullable=True)  # optional per-user webhook
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
    priority = Column(String(100), default="P2 - Productivity Not Immediately Impacted (SLA: 2-5 Business Days)")
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
    action = Column(String(200))       # e.g., "status_change", "assignment", "created", "comment", "approval"
    from_status = Column(String(50), nullable=True)
    to_status = Column(String(50), nullable=True)
    note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    ticket = relationship("Ticket")
    actor = relationship("User")

# ---------------------------
# 3) UTIL: SECURITY, TEAMS, IDs
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
    # Count tickets for the year to create a sequence. For heavy concurrency use a DB sequence.
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

def add_history(db, ticket_id: int, actor_id: int, action: str, from_status: Optional[str] = None,
                to_status: Optional[str] = None, note: Optional[str] = None):
    h = History(ticket_id=ticket_id, actor_id=actor_id, action=action,
                from_status=from_status, to_status=to_status, note=note)
    db.add(h)
    db.commit()

# ---------------------------
# 4) DB INIT + SEED (+ priority migration)
# ---------------------------
def migrate_priorities(db):
    """Map any legacy priorities to the new P1/P2/P3 scheme."""
    legacy_to_new = {
        "Urgent": "P1 - Productivity Impacted (SLA: Same Day)",
        "High": "P2 - Productivity Not Immediately Impacted (SLA: 2-5 Business Days)",
        "Medium": "P3 - Priority (SLA: 5+ Business Days)",
        "Low": "P3 - Priority (SLA: 5+ Business Days)",
        # Also handle any old P1/P2/P3 formats that might exist
        "P1 - Urgent": "P1 - Productivity Impacted (SLA: Same Day)",
        "P2 - High": "P2 - Productivity Not Immediately Impacted (SLA: 2-5 Business Days)",
        "P3 - Normal": "P3 - Priority (SLA: 5+ Business Days)",
    }
    updated = 0
    for legacy, newv in legacy_to_new.items():
        updated += db.query(Ticket).filter(Ticket.priority == legacy).update(
            {Ticket.priority: newv},
            synchronize_session=False
        )
    if updated:
        db.commit()


def init_db():
    Base.metadata.create_all(bind=engine)
    ensure_dirs()
    db = SessionLocal()
    try:
        # One-time migration in case there are old records
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
    - Receive real-time notifications in Teams when your tickets are approved, updated, or completed. 

    **Why choose ATIX?:**
    - Secure and Reliable: Restricted access to only ADVANTEC employees.
    - Professional Data Engineering on demand:
        - AI Consulting and Implementation Services
        - Track Performance with KPI Dashboards
        - Forecasting and Predictive Analytics
        - Graphic Data Visualization
        - Finding and Compiling datasets 
        - Corridor Analysis for Transportaion Studies 
    """)
st.markdown("---")

# ---------------------------
# 6) AUTH HELPERS
# ---------------------------
def get_db():
    return SessionLocal()

def current_user() -> Optional[User]:
    return st.session_state.get("user_obj")

def set_current_user(u: Optional[User]):
    st.session_state["user_obj"] = u

def require_login():
    if not current_user():
        st.warning("Please log in to continue.")
        st.stop()

def require_role(*roles):
    user = current_user()
    if not user or user.role not in roles:
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
        st.sidebar.markdown(f"**Signed in as:** {user.name}  \n*Role:* `{user.role}`")
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
        for o in options:
            if o in ["Team Tickets", "Projects", "Approvals"] and user.role not in ["manager", "admin"]:
                # 'Approvals' still visible for project managers via project assignment
                if o == "Approvals":
                    visible.append(o)  # keep visible; actual gate inside
                continue
            if o == "Admin" and user.role != "admin":
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
            # default to P2
            priority = st.selectbox("Priority", PRIORITIES, index=1)
        with col2:
            category = st.selectbox("Category", CATEGORIES, index=CATEGORIES.index("Other"))
        with col3:
            # Some Streamlit versions don't like None; you can set a date and clear later if needed
            due_at = st.date_input("Due date (optional)")
        col4, col5 = st.columns(2)
        with col4:
            project_choice = st.selectbox("Project (optional)", proj_options, index=0)
        with col5:
            request_charge = st.checkbox("Request project charge approval", value=False)

        assign_to_me = st.checkbox("Assign to me", value=False)
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

                t = Ticket(
                    short_id=generate_short_id(db),
                    title=title.strip(), description=desc.strip(),
                    status="Awaiting Approval" if request_charge else "New",
                    priority=priority, category=category,
                    created_by_id=user.id,
                    assigned_to_id=user.id if assign_to_me else None,
                    project_id=project_id,
                    request_project_charge=bool(request_charge),
                    approval_status="Pending" if request_charge else "Not Requested",
                    due_at=dt.datetime.combine(due_at, dt.time(17, 0)) if isinstance(due_at, dt.date) else None
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

    with get_db() as db:
        # filters
        colf1, colf2, colf3 = st.columns(3)
        with colf1:
            status = st.multiselect("Status", STATUSES, default=STATUSES)
        with colf2:
            prio = st.multiselect("Priority", PRIORITIES, default=PRIORITIES)
        with colf3:
            mine_tab = st.selectbox("View", ["Created by me", "Assigned to me"], index=0)

        qs = db.query(Ticket)
        if mine_tab == "Created by me":
            qs = qs.filter(Ticket.created_by_id == user.id)
        else:
            qs = qs.filter(Ticket.assigned_to_id == user.id)

        qs = qs.filter(Ticket.status.in_(status), Ticket.priority.in_(prio)).order_by(Ticket.updated_at.desc())
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
    if user.role not in ("manager", "admin"):
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

        qs = db.query(Ticket).order_by(Ticket.updated_at.desc())
        qs = qs.filter(Ticket.status.in_(status), Ticket.priority.in_(prio))
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

def ticket_detail_viewope(ticket_id: int):
    require_login()
    user = current_user()
    with get_db() as db:
        t = db.query(Ticket).filter(Ticket.id == ticket_id).first()
        if not t:
            st.error("Ticket not found.")
            return

        # Compact header
        st.subheader(f"🎫 {t.short_id} — {t.title}")
        
        # Quick status overview
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Status", t.status)
        col2.metric("Priority", t.priority.split(' - ')[0] if ' - ' in t.priority else t.priority)
        col3.metric("Assigned", t.assigned_to.name if t.assigned_to else "Unassigned")
        col4.metric("Attachments", t.attachments_count)
        
        st.markdown("---")

        # Tabbed interface
        tab1, tab2, tab3, tab4 = st.tabs(["📝 Details", "⚙️ Update", "📎 Files", "💬 Comments"])
        
        with tab1:
            st.markdown("**Description:**")
            st.write(t.description)
            st.caption(f"Created by {t.created_by.name} on {t.created_at.strftime('%Y-%m-%d %H:%M UTC')}")
            if t.project:
                st.write(f"**Project:** {t.project.name}")
            if t.due_at:
                st.write(f"**Due:** {t.due_at.strftime('%Y-%m-%d %H:%M UTC')}")
        
        with tab2:
            # ... update form here ...
        
        with tab3:
            # ... attachments here ...
        
        with tab4:
            # ... comments here ...

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
        qs = db.query(Ticket).filter(
            Ticket.approval_status == "Pending",
            Ticket.project_id.in_(my_project_ids)
        ).order_by(Ticket.created_at.asc())

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
    user = current_user()
    if user.role not in ["manager", "admin"]:
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
        total = db.query(func.count(Ticket.id)).scalar() or 0
        open_cnt = db.query(func.count(Ticket.id)).filter(Ticket.status.notin_(["Resolved", "Closed"])).scalar() or 0
        closed_cnt = db.query(func.count(Ticket.id)).filter(Ticket.status.in_(["Resolved", "Closed"])).scalar() or 0
        awaiting = db.query(func.count(Ticket.id)).filter(Ticket.status == "Awaiting Approval").scalar() or 0

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Tickets", total)
        c2.metric("Open", open_cnt)
        c3.metric("Resolved/Closed", closed_cnt)
        c4.metric("Awaiting Approval", awaiting)

        # By status
        st.markdown("#### Tickets by Status")
        data_status = []
        for s in STATUSES:
            cnt = db.query(func.count(Ticket.id)).filter(Ticket.status == s).scalar() or 0
            data_status.append({"Status": s, "Count": cnt})
        st.bar_chart(pd.DataFrame(data_status).set_index("Status"))

        # By priority
        st.markdown("#### Tickets by Priority")
        data_prio = []
        for p in PRIORITIES:
            cnt = db.query(func.count(Ticket.id)).filter(Ticket.priority == p).scalar() or 0
            data_prio.append({"Priority": p, "Count": cnt})
        st.bar_chart(pd.DataFrame(data_prio).set_index("Priority"))

        # Trend (last 30 days)
        st.markdown("#### Opened per Day (last 30 days)")
        today = dt.datetime.utcnow().date()
        daily = []
        for i in range(29, -1, -1):
            day = today - dt.timedelta(days=i)
            next_day = day + dt.timedelta(days=1)
            cnt = db.query(func.count(Ticket.id)).filter(
                Ticket.created_at >= dt.datetime.combine(day, dt.time.min),
                Ticket.created_at < dt.datetime.combine(next_day, dt.time.min)
            ).scalar() or 0
            daily.append({"Date": str(day), "Opened": cnt})
        st.line_chart(pd.DataFrame(daily).set_index("Date"))

        # Export
        if st.button("Export all tickets to CSV"):
            rows = []
            for t in db.query(Ticket).order_by(Ticket.created_at.asc()).all():
                rows.append({
                    "short_id": t.short_id, "title": t.title, "status": t.status, "priority": t.priority,
                    "category": t.category, "project": t.project.name if t.project else "",
                    "created_by": t.created_by.name, "assigned_to": t.assigned_to.name if t.assigned_to else "",
                    "created_at": t.created_at.isoformat(), "updated_at": t.updated_at.isoformat(),
                    "due_at": t.due_at.isoformat() if t.due_at else ""
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
            rows = []
            for u in db.query(User).order_by(User.is_active.desc(), User.name.asc()).all():
                rows.append({
                    "name": u.name, "email": u.email, "role": u.role,
                    "active": "Yes" if u.is_active else "No", "created": u.created_at.strftime("%Y-%m-%d"),
                    "id": u.id
                })
            st.dataframe(pd.DataFrame(rows)[["name", "email", "role", "active", "created"]], use_container_width=True, hide_index=True)

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
                        existing = db.query(User).filter(func.lower(User.email) == email.lower()).first()
                        if existing:
                            existing.name = name; existing.role = role; existing.is_active = active
                            if pw:
                                existing.password_hash = hash_password(pw)
                            db.commit()
                            st.success("User updated.")
                        else:
                            u = User(name=name, email=email, role=role, is_active=active,
                                     password_hash=hash_password(pw) if pw else None)
                            db.add(u); db.commit()
                            st.success("User created.")
                        st.rerun()
                        return
    with tab2:
        st.subheader("System Settings")
        st.caption("The app uses environment variables. See `.env.example` for configuration.")
        st.write({
            "DATABASE_URL": DATABASE_URL,
            "ALLOWED_EMAIL_DOMAIN": ALLOWED_EMAIL_DOMAIN,
            "UPLOAD_DIR": UPLOAD_DIR,
            "TEAMS_WEBHOOK_URL": "configured" if TEAMS_WEBHOOK_URL else "(not set)",
            "ALLOW_SELF_SIGNUP": ALLOW_SELF_SIGNUP,
        })
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
    st.markdown("""
- **Creating Tickets:** Use **Create Ticket** to submit requests. Attach files/screenshots as needed.
- **Assignments:** Managers/admins can assign any ticket. Users can assign to themselves.
- **Statuses:** *New → In Progress → Resolved → Closed.* Approval adds *Awaiting Approval/Approved/Rejected.*
- **Approvals:** Project Managers see **Approvals** for tickets that requested project charges.
- **Teams Notifications:** Configure a channel **Incoming Webhook** and set `TEAMS_WEBHOOK_URL` (or add your personal webhook under **Settings**).
- **Security:** Access is restricted to *@%s* emails. Admins can manage accounts and projects.
""" % ALLOWED_EMAIL_DOMAIN)

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
