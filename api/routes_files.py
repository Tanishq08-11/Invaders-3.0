"""
Employee file portal
=====================
GET  /api/v1/files?folder_id=       — list a folder (root when omitted)
POST /api/v1/files                  — multipart upload: file, optional folder_id
GET  /api/v1/files/{id}/download    — authenticated download
GET  /api/v1/files/activity         — the caller's own file activity log
GET  /api/v1/employees/me           — the caller's profile

Access model: personal items are visible only to their owner; department shared
folders (and everything inside them) are visible to members of that department.
File contents, names and activity are never fed to the anomaly model, and SOC
analysts have no access to these routes.

Every operation (success, denial, failure) writes one FileActivity row and, through the
outbox in services/app_activity.py, one `application_activity` security event carrying
the authenticated user id, the client address seen by this server, the action/outcome
and file id/size/type — never file contents, storage keys or filesystem paths.
"""
import logging
import mimetypes
import os
import uuid

from flask import Blueprint, current_app, jsonify, request, send_file

from core.auth import current_user, role_required
from core.database import db
from core.models import ROLE_EMPLOYEE, FileActivity, StoredFile
from services import app_activity

log = logging.getLogger(__name__)

bp_files = Blueprint("files", __name__, url_prefix="/api/v1/files")
bp_employees = Blueprint("employees", __name__, url_prefix="/api/v1/employees")


def _can_access(user, item: StoredFile) -> bool:
    if item.department:
        return item.department == user.department
    return item.owner_id == user.id


def _item_permissions(item: StoredFile):
    return {"view": True, "upload": item.kind == "folder", "download": item.kind == "file"}


def _context(item, **extra):
    """Security-event context for a file/folder: identifiers and sizes only."""
    if item is None:
        return dict(extra)
    ctx = {
        "file_id": item.id,
        "kind": item.kind,
        "size_bytes": item.size_bytes,
        "mime_type": item.mime_type,
        "location": "department_shared" if item.department else "personal",
    }
    if item.department:
        ctx["department"] = item.department
    ctx.update(extra)
    return ctx


def _forward(act):
    """Record the security event after the activity row committed; retry older backlog."""
    if not app_activity.forward(act):
        log.warning("[files] security event for activity %s deferred (will be retried)", act.id)
        return
    try:
        app_activity.retry_pending(limit=10)
    except Exception:
        db.session.rollback()
        log.exception("[files] retrying pending security events failed")


def _log(user, action, result, file_name=None, detail=None, item=None, context=None):
    act = app_activity.new_activity(
        user, action, result, client_ip=request.remote_addr,
        file_name=file_name, detail=detail, context=context if context is not None else _context(item),
    )
    db.session.commit()
    _forward(act)
    return act


def _parse_id(raw):
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _load_folder(user, raw_id):
    """Returns (folder, error_response). folder is None for the root."""
    if raw_id in (None, ""):
        return None, None
    folder_id = _parse_id(raw_id)
    folder = db.session.get(StoredFile, folder_id) if folder_id is not None else None
    if folder is None or folder.kind != "folder":
        return None, (jsonify({"detail": "Folder not found."}), 404)
    if not _can_access(user, folder):
        _log(user, "denied", "denied", folder.name, "Folder access denied", item=folder)
        return None, (jsonify({"detail": "You do not have permission to access this folder."}), 403)
    return folder, None


@bp_files.route("", methods=["GET"])
@role_required(ROLE_EMPLOYEE)
def list_files():
    user = current_user()
    folder, err = _load_folder(user, request.args.get("folder_id"))
    if err:
        return err

    if folder is None:
        items = StoredFile.query.filter(
            StoredFile.parent_id.is_(None),
            db.or_(
                db.and_(StoredFile.department.is_(None), StoredFile.owner_id == user.id),
                StoredFile.department == user.department,
            ),
        )
    else:
        items = StoredFile.query.filter(StoredFile.parent_id == folder.id)
    items = [i for i in items.order_by(StoredFile.kind.desc(), StoredFile.name).all() if _can_access(user, i)]

    path, node = [], folder
    while node is not None:
        path.append({"id": node.id, "name": node.name})
        node = node.parent
    path.reverse()

    return jsonify({
        "items": [i.to_dict(_item_permissions(i)) for i in items],
        "path": path,
        "permissions": {"view": True, "upload": True, "download": True},
    })


@bp_files.route("", methods=["POST"])
@role_required(ROLE_EMPLOYEE)
def upload_file():
    user = current_user()
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return jsonify({"detail": "No file was provided."}), 400

    name = os.path.basename(upload.filename.replace("\\", "/")).strip()[:255]
    if not name:
        return jsonify({"detail": "Invalid file name."}), 400

    folder, err = _load_folder(user, request.form.get("folder_id"))
    if err:
        return err

    upload_dir = current_app.config["UPLOAD_DIR"]
    key = uuid.uuid4().hex
    path = os.path.join(upload_dir, key)
    location = {"location": "department_shared" if folder and folder.department else "personal"}
    try:
        os.makedirs(upload_dir, exist_ok=True)
        upload.save(path)
        size = os.path.getsize(path)
    except OSError as exc:
        log.error("[files] storing upload failed: %s", exc)
        if os.path.exists(path):
            os.remove(path)
        _log(user, "upload", "failed", name, "Storage error", context=location)
        return jsonify({"detail": "The file could not be stored. Try again later."}), 500

    if user.storage_used_bytes() + size > (user.storage_quota_bytes or 0):
        os.remove(path)
        _log(user, "upload", "failed", name, "Storage quota exceeded", context={**location, "size_bytes": size})
        return jsonify({"detail": "Upload exceeds your storage quota."}), 413

    item = StoredFile(
        name=name,
        kind="file",
        parent_id=folder.id if folder else None,
        owner_id=user.id,
        department=folder.department if folder else None,
        size_bytes=size,
        mime_type=upload.mimetype or mimetypes.guess_type(name)[0],
        storage_key=key,
    )
    db.session.add(item)
    try:
        db.session.flush()  # item.id for the activity context
        # The stored file and its activity row commit together — neither exists without the other.
        act = app_activity.new_activity(
            user, "upload", "success", client_ip=request.remote_addr, file_name=name,
            detail=f"Uploaded to {folder.name}" if folder else "Uploaded to My Files", context=_context(item),
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        os.remove(path)
        log.exception("[files] recording upload failed")
        _log(user, "upload", "failed", name, "Storage error", context=location)
        return jsonify({"detail": "The file could not be stored. Try again later."}), 500
    _forward(act)
    return jsonify(item.to_dict(_item_permissions(item))), 201


@bp_files.route("/<int:file_id>/download", methods=["GET"])
@role_required(ROLE_EMPLOYEE)
def download_file(file_id: int):
    user = current_user()
    item = db.session.get(StoredFile, file_id)
    if item is None or item.kind != "file":
        return jsonify({"detail": "File not found."}), 404
    if not _can_access(user, item):
        _log(user, "denied", "denied", item.name, "Download denied", item=item)
        return jsonify({"detail": "You do not have permission to download this file."}), 403

    path = os.path.join(current_app.config["UPLOAD_DIR"], item.storage_key or "")
    if not item.storage_key or not os.path.isfile(path):
        _log(user, "download", "failed", item.name, "Stored file is missing", item=item)
        return jsonify({"detail": "File not found."}), 404

    _log(user, "download", "success", item.name, item=item)
    # Always an attachment with a generic type so a stored file can never render inline.
    resp = send_file(path, as_attachment=True, download_name=item.name, mimetype="application/octet-stream")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@bp_files.route("/activity", methods=["GET"])
@role_required(ROLE_EMPLOYEE)
def activity():
    user = current_user()
    rows = (
        FileActivity.query.filter_by(user_id=user.id)
        .order_by(FileActivity.timestamp.desc())
        .limit(200)
        .all()
    )
    return jsonify({"items": [r.to_dict() for r in rows]})


@bp_employees.route("/me", methods=["GET"])
@role_required()
def employee_me():
    return jsonify(current_user().to_dict())
