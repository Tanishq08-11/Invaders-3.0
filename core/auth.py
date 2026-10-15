"""
Session authentication & role enforcement
==========================================
• Sessions use Flask's signed cookie (HttpOnly, SameSite=Lax; Secure via config).
  Only the user id is stored in it — never credentials.
• Roles: EMPLOYEE (file portal), SECURITY_ANALYST (SOC dashboard, read + triage) and
  ADMIN (SOC dashboard + service operations: collector, PCAP, replay, model management).
• `role_required` protects individual routes; `install_soc_guard` protects every
  SOC blueprint by URL prefix so new SOC routes are covered automatically.
• POST /api/v1/events (external ingestion) is not a SOC read: it is open by default
  for the ingestion team, or requires X-Ingest-Key when INGEST_API_KEY is configured.
"""
import csv
import hmac
import os
import secrets
import string
from functools import wraps

from flask import current_app, jsonify, request, session
from werkzeug.security import generate_password_hash

from core.database import db
from core.models import ROLE_ADMIN, ROLE_ANALYST, ROLE_EMPLOYEE, SOC_ROLES, StoredFile, User

# SOC data must never be readable by employees (or anonymous callers).
SOC_PREFIXES = (
    "/api/v1/alerts",
    "/api/v1/devices",
    "/api/v1/metrics",
    "/api/v1/stream",
    "/api/v1/model",
    "/api/v1/dataset",
    "/api/v1/collector",
    "/api/v1/events",       # GET (event log); POST ingestion is handled separately below
)

# Service operations: any non-GET request under these prefixes needs ADMIN.
OPERATOR_PREFIXES = (
    "/api/v1/collector",
    "/api/v1/stream",
    "/api/v1/model",
    "/api/v1/dataset",
)
INGEST_PATH = "/api/v1/events"


def _under(path, prefixes):
    return any(path == p or path.startswith(p + "/") for p in prefixes)


def current_user():
    """The signed-in, active user for this request, or None."""
    # Cached on the request (not `g`, which can outlive a request when an app context is reused).
    if hasattr(request, "_portal_user"):
        return request._portal_user
    uid = session.get("uid")
    user = db.session.get(User, uid) if uid is not None else None
    if user is not None and not user.is_active:
        user = None
    request._portal_user = user
    return user


def _deny(user):
    if user is None:
        return jsonify({"detail": "Authentication required."}), 401
    return jsonify({"detail": "You do not have permission to access this resource."}), 403


def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if user is None or (roles and user.role not in roles):
                return _deny(user)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def soc_auth_enabled() -> bool:
    return bool(current_app.config.get("SOC_AUTH_REQUIRED", True))


def is_soc_viewer() -> bool:
    """Signed-in analyst/admin, or SOC auth disabled (development/tests)."""
    if not soc_auth_enabled():
        return True
    user = current_user()
    return user is not None and user.role in SOC_ROLES


def _ingest_allowed() -> bool:
    key = current_app.config.get("INGEST_API_KEY") or ""
    if not key:
        return True
    supplied = request.headers.get("X-Ingest-Key", "")
    if supplied and hmac.compare_digest(supplied.encode(), key.encode()):
        return True
    user = current_user()
    return user is not None and user.role == ROLE_ADMIN


def install_soc_guard(app):
    @app.before_request
    def _soc_guard():
        if request.method == "OPTIONS":
            return None
        path = request.path
        if path == INGEST_PATH and request.method == "POST":
            if _ingest_allowed():
                return None
            return jsonify({"detail": "A valid X-Ingest-Key header is required for event ingestion."}), 401
        if not soc_auth_enabled():
            return None
        if _under(path, SOC_PREFIXES):
            user = current_user()
            if user is None or user.role not in SOC_ROLES:
                return _deny(user)
            if request.method not in ("GET", "HEAD") and _under(path, OPERATOR_PREFIXES) and user.role != ROLE_ADMIN:
                return jsonify({"detail": "This operation requires an administrator (collector operator) account."}), 403
        return None


# ---------------------------------------------------------------------------
# Account provisioning
# ---------------------------------------------------------------------------
DEPARTMENTS = [
    # (department, username prefix, headcount) — 20 workers in total
    ("Engineering", "eng", 4),
    ("Finance", "fin", 4),
    ("HR", "hr", 4),
    ("Sales & Marketing", "sales", 4),
    ("Management", "mgmt", 4),
]
ANALYSTS = 2
ADMIN_USERNAME = "admin01"
_PASSWORD_ALPHABET = string.ascii_letters + string.digits


def _new_password() -> str:
    return "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(12))


def seed_accounts(credentials_path: str) -> list:
    """
    If the users database is empty, create 20 worker accounts (EMPLOYEE), 2 analyst
    accounts and one shared folder per department, each account with its own random
    password. Only the scrypt hash is stored in the database; the generated
    credentials are written once to `credentials_path` (under instance/, gitignored)
    so they can be handed out. Returns the created [(username, password, role, department)].
    """
    if User.query.first() is not None:
        return []

    accounts = []
    for dept, prefix, count in DEPARTMENTS:
        for n in range(1, count + 1):
            accounts.append((f"{prefix}{n:02d}", f"{dept} Worker {n:02d}", ROLE_EMPLOYEE, dept))
        if StoredFile.query.filter_by(kind="folder", department=dept, parent_id=None).first() is None:
            db.session.add(StoredFile(name=f"{dept} Shared", kind="folder", department=dept))
    for n in range(1, ANALYSTS + 1):
        accounts.append((f"analyst{n:02d}", f"SOC Analyst {n:02d}", ROLE_ANALYST, "Security Operations"))

    created = []
    for username, display_name, role, dept in accounts:
        password = _new_password()
        db.session.add(User(
            username=username,
            password_hash=generate_password_hash(password),
            display_name=display_name,
            role=role,
            department=dept,
            email=f"{username}@veylix.local",
        ))
        created.append((username, password, role, dept))
    db.session.commit()

    os.makedirs(os.path.dirname(credentials_path), exist_ok=True)
    with open(credentials_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["username", "password", "role", "department"])
        writer.writerows(created)
    return created


def ensure_admin_account(credentials_path: str) -> list:
    """
    Create one ADMIN (collector operator) account when none exists — also for users
    databases seeded before the ADMIN role existed. The random password is appended to
    `credentials_path` (instance/, gitignored); only its hash is stored.
    """
    if User.query.filter_by(role=ROLE_ADMIN).first() is not None:
        return []
    username = ADMIN_USERNAME
    if User.query.filter(db.func.lower(User.username) == username).first() is not None:
        username = f"{ADMIN_USERNAME}-{secrets.token_hex(2)}"
    password = _new_password()
    db.session.add(User(
        username=username,
        password_hash=generate_password_hash(password),
        display_name="SOC Administrator",
        role=ROLE_ADMIN,
        department="Security Operations",
        email=f"{username}@veylix.local",
    ))
    db.session.commit()
    os.makedirs(os.path.dirname(credentials_path), exist_ok=True)
    new_file = not os.path.exists(credentials_path)
    with open(credentials_path, "a", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        if new_file:
            writer.writerow(["username", "password", "role", "department"])
        writer.writerow([username, password, ROLE_ADMIN, "Security Operations"])
    return [(username, password, ROLE_ADMIN, "Security Operations")]
