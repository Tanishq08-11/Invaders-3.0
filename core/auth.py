"""
Session authentication & role enforcement
==========================================
• Sessions use Flask's signed cookie (HttpOnly, SameSite=Lax; Secure via config).
  Only the user id is stored in it — never credentials.
• Roles: EMPLOYEE (file portal) and SECURITY_ANALYST (SOC dashboard).
• `role_required` protects individual routes; `install_soc_guard` protects every
  SOC blueprint by URL prefix so new SOC routes are covered automatically.
"""
import csv
import os
import secrets
import string
from functools import wraps

from flask import current_app, jsonify, request, session
from werkzeug.security import generate_password_hash

from core.database import db
from core.models import ROLE_ANALYST, ROLE_EMPLOYEE, StoredFile, User

# SOC data must never be readable by employees (or anonymous callers).
SOC_PREFIXES = (
    "/api/v1/alerts",
    "/api/v1/devices",
    "/api/v1/metrics",
    "/api/v1/stream",
    "/api/v1/model",
    "/api/v1/dataset",
    "/api/v1/collector",
)


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


def install_soc_guard(app):
    @app.before_request
    def _soc_guard():
        if request.method == "OPTIONS" or not current_app.config.get("SOC_AUTH_REQUIRED", True):
            return None
        path = request.path
        if any(path == p or path.startswith(p + "/") for p in SOC_PREFIXES):
            user = current_user()
            if user is None or user.role != ROLE_ANALYST:
                return _deny(user)
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
