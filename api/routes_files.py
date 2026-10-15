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
"""
import mimetypes
import os
import uuid

from flask import Blueprint, current_app, jsonify, request, send_file

from core.auth import current_user, role_required
from core.database import db
from core.models import ROLE_EMPLOYEE, FileActivity, StoredFile

bp_files = Blueprint("files", __name__, url_prefix="/api/v1/files")
bp_employees = Blueprint("employees", __name__, url_prefix="/api/v1/employees")


def _can_access(user, item: StoredFile) -> bool:
    if item.department:
        return item.department == user.department
    return item.owner_id == user.id


def _item_permissions(item: StoredFile):
    return {"view": True, "upload": item.kind == "folder", "download": item.kind == "file"}


def _log(user, action, result, file_name=None, detail=None):
    db.session.add(FileActivity(
        user_id=user.id, action=action, result=result,
        file_name=file_name[:255] if file_name else None,
        detail=detail[:255] if detail else None,
    ))
    db.session.commit()


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
        _log(user, "denied", "denied", folder.name, "Folder access denied")
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
    os.makedirs(upload_dir, exist_ok=True)
    key = uuid.uuid4().hex
    path = os.path.join(upload_dir, key)
    upload.save(path)
    size = os.path.getsize(path)

    if user.storage_used_bytes() + size > (user.storage_quota_bytes or 0):
        os.remove(path)
        _log(user, "upload", "failed", name, "Storage quota exceeded")
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
    db.session.commit()
    _log(user, "upload", "success", name, f"Uploaded to {folder.name}" if folder else "Uploaded to My Files")
    return jsonify(item.to_dict(_item_permissions(item))), 201


@bp_files.route("/<int:file_id>/download", methods=["GET"])
@role_required(ROLE_EMPLOYEE)
def download_file(file_id: int):
    user = current_user()
    item = db.session.get(StoredFile, file_id)
    if item is None or item.kind != "file":
        return jsonify({"detail": "File not found."}), 404
    if not _can_access(user, item):
        _log(user, "denied", "denied", item.name, "Download denied")
        return jsonify({"detail": "You do not have permission to download this file."}), 403

    path = os.path.join(current_app.config["UPLOAD_DIR"], item.storage_key or "")
    if not item.storage_key or not os.path.isfile(path):
        _log(user, "download", "failed", item.name, "Stored file is missing")
        return jsonify({"detail": "File not found."}), 404

    _log(user, "download", "success", item.name)
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
