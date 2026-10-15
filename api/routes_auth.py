"""
POST /api/v1/auth/login   — verify credentials, start a session (HttpOnly cookie).
GET  /api/v1/auth/me      — the signed-in user (401 without a session).
POST /api/v1/auth/logout  — end the session.
"""
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from core.auth import current_user
from core.database import db
from core.models import User

bp_auth = Blueprint("auth", __name__, url_prefix="/api/v1/auth")

# Compared against when the username is unknown so both failure paths cost the same.
_DUMMY_HASH = generate_password_hash("veylix-timing-equaliser")


@bp_auth.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username") or "").strip().lower()
    password = str(data.get("password") or "")
    if not username or not password:
        return jsonify({"detail": "Username and password are required."}), 400

    user = User.query.filter(db.func.lower(User.username) == username).first()
    ok = check_password_hash(user.password_hash if user else _DUMMY_HASH, password)
    if user is None or not ok or not user.is_active:
        return jsonify({"detail": "Invalid username or password."}), 401

    session.clear()
    session["uid"] = user.id
    session.permanent = True
    user.last_login_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({"user": user.to_dict()})


@bp_auth.route("/me", methods=["GET"])
def me():
    user = current_user()
    if user is None:
        return jsonify({"detail": "Not signed in."}), 401
    return jsonify(user.to_dict())


@bp_auth.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Signed out."})
