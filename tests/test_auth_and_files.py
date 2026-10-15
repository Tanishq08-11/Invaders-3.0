"""
Portal auth, role enforcement, employee file portal and dashboard contract fields.
"""
import io

import pytest
from werkzeug.security import generate_password_hash

from app import create_app
from config import Config
from core.database import db
from core.models import ROLE_ANALYST, ROLE_EMPLOYEE, Alert, StoredFile, User

PASSWORD = "correct horse battery"


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"


@pytest.fixture
def app(tmp_path):
    app = create_app(TestConfig)
    app.config["SOC_AUTH_REQUIRED"] = True
    app.config["UPLOAD_DIR"] = str(tmp_path / "uploads")
    with app.app_context():
        db.create_all()
        fast = lambda: generate_password_hash(PASSWORD, method="pbkdf2:sha256:1000")  # noqa: E731
        db.session.add_all([
            User(username="eng01", password_hash=fast(), display_name="Eng One", role=ROLE_EMPLOYEE, department="Engineering"),
            User(username="fin01", password_hash=fast(), display_name="Fin One", role=ROLE_EMPLOYEE, department="Finance"),
            User(username="analyst01", password_hash=fast(), display_name="Analyst", role=ROLE_ANALYST, department="SOC"),
            StoredFile(name="Engineering Shared", kind="folder", department="Engineering"),
            StoredFile(name="Finance Shared", kind="folder", department="Finance"),
        ])
        db.session.commit()
        yield app
        db.session.remove()
        db.drop_all()


def login(client, username):
    return client.post("/api/v1/auth/login", json={"username": username, "password": PASSWORD})


def folder_id(name):
    return StoredFile.query.filter_by(name=name).first().id


# ---------------------------------------------------------------- auth
def test_login_me_logout(app):
    c = app.test_client()
    assert c.get("/api/v1/auth/me").status_code == 401
    res = login(c, "ENG01")  # usernames are case-insensitive
    assert res.status_code == 200
    user = res.get_json()["user"]
    assert user["role"] == "EMPLOYEE" and user["department"] == "Engineering"
    assert "password_hash" not in user
    assert "HttpOnly" in res.headers["Set-Cookie"]
    assert c.get("/api/v1/auth/me").get_json()["username"] == "eng01"
    assert c.post("/api/v1/auth/logout", json={}).status_code == 200
    assert c.get("/api/v1/auth/me").status_code == 401


def test_bad_credentials(app):
    c = app.test_client()
    assert c.post("/api/v1/auth/login", json={"username": "eng01", "password": "nope"}).status_code == 401
    assert c.post("/api/v1/auth/login", json={"username": "ghost", "password": "nope"}).status_code == 401
    assert c.post("/api/v1/auth/login", json={}).status_code == 400


# ---------------------------------------------------------------- roles
def test_soc_routes_require_analyst(app):
    anon, emp, analyst = app.test_client(), app.test_client(), app.test_client()
    login(emp, "eng01")
    login(analyst, "analyst01")
    for path in ("/api/v1/alerts", "/api/v1/metrics", "/api/v1/devices"):
        assert anon.get(path).status_code == 401
        assert emp.get(path).status_code == 403
        assert analyst.get(path).status_code == 200
    assert anon.get("/api/v1/health").status_code == 200  # connection probe stays public


def test_files_require_employee(app):
    analyst = app.test_client()
    login(analyst, "analyst01")
    assert analyst.get("/api/v1/files").status_code == 403
    assert app.test_client().get("/api/v1/files").status_code == 401


# ---------------------------------------------------------------- files
def test_upload_list_download_and_isolation(app):
    eng, fin = app.test_client(), app.test_client()
    login(eng, "eng01")
    login(fin, "fin01")

    root = eng.get("/api/v1/files").get_json()
    assert [i["name"] for i in root["items"]] == ["Engineering Shared"]

    eng_folder = folder_id("Engineering Shared")
    res = eng.post("/api/v1/files", data={"file": (io.BytesIO(b"design notes"), "..\\spec.txt"), "folder_id": str(eng_folder)},
                   content_type="multipart/form-data")
    assert res.status_code == 201
    item = res.get_json()
    assert item["name"] == "spec.txt" and item["size_bytes"] == 12

    listing = eng.get(f"/api/v1/files?folder_id={eng_folder}").get_json()
    assert [i["name"] for i in listing["items"]] == ["spec.txt"]
    assert listing["path"] == [{"id": eng_folder, "name": "Engineering Shared"}]

    dl = eng.get(f"/api/v1/files/{item['id']}/download")
    assert dl.status_code == 200 and dl.data == b"design notes"
    assert dl.headers["Content-Type"] == "application/octet-stream"

    # Another department can neither list, upload into, nor download from it
    assert fin.get(f"/api/v1/files?folder_id={eng_folder}").status_code == 403
    assert fin.get(f"/api/v1/files/{item['id']}/download").status_code == 403
    assert fin.post("/api/v1/files", data={"file": (io.BytesIO(b"x"), "x.txt"), "folder_id": str(eng_folder)},
                    content_type="multipart/form-data").status_code == 403
    assert fin.get("/api/v1/files/9999/download").status_code == 404

    acts = eng.get("/api/v1/files/activity").get_json()["items"]
    assert {(a["action"], a["result"]) for a in acts} == {("upload", "success"), ("download", "success")}
    fin_acts = fin.get("/api/v1/files/activity").get_json()["items"]
    assert all(a["result"] == "denied" for a in fin_acts) and len(fin_acts) == 3

    me = eng.get("/api/v1/employees/me").get_json()
    assert me["storage_used_bytes"] == 12


def test_personal_files_are_private(app):
    eng, fin = app.test_client(), app.test_client()
    login(eng, "eng01")
    login(fin, "fin01")
    item = eng.post("/api/v1/files", data={"file": (io.BytesIO(b"mine"), "mine.txt")},
                    content_type="multipart/form-data").get_json()
    assert "mine.txt" in [i["name"] for i in eng.get("/api/v1/files").get_json()["items"]]
    assert "mine.txt" not in [i["name"] for i in fin.get("/api/v1/files").get_json()["items"]]
    assert fin.get(f"/api/v1/files/{item['id']}/download").status_code == 403


def test_quota_enforced(app):
    with app.app_context():
        u = User.query.filter_by(username="eng01").first()
        u.storage_quota_bytes = 5
        db.session.commit()
    eng = app.test_client()
    login(eng, "eng01")
    res = eng.post("/api/v1/files", data={"file": (io.BytesIO(b"too large"), "big.bin")}, content_type="multipart/form-data")
    assert res.status_code == 413


# ---------------------------------------------------------------- dashboard contract
def _make_alert():
    a = Alert(
        alert_uuid="ALT-TEST", severity="HIGH", risk_score=81.0, anomaly_score=1.2, z_score=6.0,
        src_ip="10.0.0.5", dst_ip="45.33.32.156", dst_port=443, bytes_transferred=900000,
        risk_factors_json='["Outbound transfer to external destination: 45.33.32.156", "Off-hours data transmission (evening/night or weekend)"]',
        evidence_json='[{"feature_name": "MI_dir_L5_weight", "display_name": "Burst volume", "contribution_pct": 42.0, "description": "d"}]',
        status="open",
    )
    db.session.add(a)
    db.session.commit()
    return a.id


def test_alert_contract_and_patch_aliases(app):
    with app.app_context():
        alert_id = _make_alert()
    c = app.test_client()
    login(c, "analyst01")

    listed = c.get("/api/v1/alerts?per_page=1000").get_json()
    item = listed["items"][0]
    assert item["device_id"] == "10.0.0.5" and item["destination"] == "45.33.32.156"
    assert {s["code"] for s in item["signals"]} == {"destination_external", "off_hours_activity"}
    assert item["created_at"].endswith("+00:00")

    detail = c.get(f"/api/v1/alerts/{alert_id}").get_json()
    assert detail["risk_contributions"][0]["contribution"] == 42.0
    assert "events" in detail

    res = c.patch(f"/api/v1/alerts/{alert_id}", json={"status": "false_positive", "note": "Backup job"})
    assert res.status_code == 200
    updated = res.get_json()["alert"]
    assert updated["status"] == "dismissed" and updated["disposition"] == "false_positive"
    assert updated["analyst_note"] == "Backup job"
    assert c.patch(f"/api/v1/alerts/{alert_id}", json={"status": "new"}).get_json()["alert"]["status"] == "open"

    m = c.get("/api/v1/metrics").get_json()
    assert m["open_incidents"] == 1 and m["high_priority_alerts"] == 1
    assert m["severity_distribution"] == {"high": 1}
