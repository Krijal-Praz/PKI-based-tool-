"""EndpointTrust end-to-end security workflow tests.

Run from the repository root with:
    pytest -q
"""
from __future__ import annotations

import base64
import importlib.util
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID


@pytest.fixture()
def endpointtrust(tmp_path, monkeypatch):
    monkeypatch.setenv("ENDPOINTTRUST_DB", str(tmp_path / "endpointtrust.db"))
    monkeypatch.setenv("ENDPOINTTRUST_CERT_DIR", str(tmp_path / "certs"))
    monkeypatch.setenv("ENDPOINTTRUST_SECURE_STORAGE", str(tmp_path / "secure_storage"))
    monkeypatch.setenv("ENDPOINTTRUST_PUBLIC_PREFIX", "/endpointtrust")
    monkeypatch.setenv("ENDPOINTTRUST_REBIND_IP", "true")
    module_path = Path(__file__).parents[1] / "endpointtrust" / "app.py"
    spec = importlib.util.spec_from_file_location("endpointtrust_test_app", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    module.app.config.update(TESTING=True)
    return module


def make_identity(device_id="LAP-HR-001", department="HR", serial="ASSET-001"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EndpointTrust Corporate Devices"),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, department),
                    x509.NameAttribute(NameOID.COMMON_NAME, device_id),
                    x509.NameAttribute(NameOID.SERIAL_NUMBER, serial),
                ]
            )
        )
        .sign(key, hashes.SHA256())
    )
    return key, csr.public_bytes(serialization.Encoding.PEM).decode()


def enrol(client, csr_pem, device_id="LAP-HR-001", user="Test Employee"):
    return client.post(
        "/api/enrollment/request",
        json={
            "device_id": device_id,
            "device_name": "HR Corporate Laptop",
            "assigned_user": user,
            "department": "HR",
            "serial_number": "ASSET-001",
            "hostname": "hr-laptop",
            "os_name": "Kali Linux",
            "mac_address": "00:11:22:33:44:55",
            "csr": csr_pem,
        },
        headers={"X-Real-IP": "127.0.0.1"},
    )


def verify_device(client, key, certificate_pem, device_id="LAP-HR-001"):
    challenge_response = client.post(
        "/api/auth/challenge",
        json={"device_id": device_id},
        headers={"X-Real-IP": "127.0.0.1"},
    )
    assert challenge_response.status_code == 200
    challenge = challenge_response.get_json()
    signature = key.sign(challenge["nonce"].encode(), padding.PKCS1v15(), hashes.SHA256())
    return client.post(
        "/api/auth/verify",
        json={
            "device_id": device_id,
            "challenge_id": challenge["challenge_id"],
            "signature": base64.b64encode(signature).decode(),
            "certificate_pem": certificate_pem,
        },
        headers={"X-Real-IP": "127.0.0.1"},
    )


def test_complete_trusted_endpoint_workflow(endpointtrust):
    client = endpointtrust.app.test_client()
    admin_auth = ("admin", "EndpointTrust@123")
    key, csr_pem = make_identity()

    request_response = enrol(client, csr_pem)
    assert request_response.status_code == 200
    request_id = request_response.get_json()["request_id"]

    # Before approval the request is visible only in Pending Enrolments.
    before = client.get("/api/admin/dashboard", auth=admin_auth).get_json()
    assert [row["request_id"] for row in before["pending"]] == [request_id]
    assert before["devices"] == []

    approval = client.post(f"/api/admin/enrollments/approve/{request_id}", auth=admin_auth)
    assert approval.status_code == 200

    # Approval immediately moves the device out of Pending and into Devices.
    after_approval = client.get("/api/admin/dashboard", auth=admin_auth).get_json()
    assert after_approval["pending"] == []
    assert len(after_approval["devices"]) == 1
    assert after_approval["devices"][0]["access_status"] == "Certificate issued — verification required"
    assert after_approval["sessions"] == []

    certificate_response = client.get("/api/certificates/device/LAP-HR-001")
    assert certificate_response.status_code == 200
    certificate_pem = certificate_response.get_json()["certificate_pem"]

    verification = verify_device(client, key, certificate_pem)
    assert verification.status_code == 200
    assert verification.get_json()["status"] == "allowed"
    assert "endpointtrust_session=" in verification.headers.get("Set-Cookie", "")

    # The same browser can immediately prove that its cookie maps to an active session.
    session_status = client.get("/api/auth/session-status", headers={"X-Real-IP": "127.0.0.1"})
    assert session_status.status_code == 200
    assert session_status.get_json()["active"] is True

    # Nginx's auth_request endpoint sees the same cookie and permits HR access.
    nginx_check = client.get("/auth/nginx-check", headers={"X-Real-IP": "127.0.0.1"})
    assert nginx_check.status_code == 200
    assert nginx_check.headers["X-EndpointTrust-Verified"] == "true"

    after_verify = client.get("/api/admin/dashboard", auth=admin_auth).get_json()
    assert len(after_verify["sessions"]) == 1
    assert after_verify["sessions"][0]["device_id"] == "LAP-HR-001"
    assert after_verify["devices"][0]["access_status"] == "HR access active"

    revocation = client.post(
        "/api/admin/certificates/revoke/LAP-HR-001",
        auth=admin_auth,
        json={"reason": "Security test revocation"},
    )
    assert revocation.status_code == 200
    assert client.get("/api/auth/session-status", headers={"X-Real-IP": "127.0.0.1"}).status_code == 401
    assert client.get("/auth/nginx-check", headers={"X-Real-IP": "127.0.0.1"}).status_code == 403


def test_duplicate_enrollment_is_blocked_for_certified_device(endpointtrust):
    client = endpointtrust.app.test_client()
    admin_auth = ("admin", "EndpointTrust@123")

    key, csr_pem = make_identity()
    request_id = enrol(client, csr_pem).get_json()["request_id"]
    assert client.post(f"/api/admin/enrollments/approve/{request_id}", auth=admin_auth).status_code == 200

    certificate = client.get("/api/certificates/device/LAP-HR-001").get_json()
    assert verify_device(client, key, certificate["certificate_pem"]).status_code == 200

    # A second CSR for the same registered device must be rejected.
    _new_key, new_csr = make_identity()
    duplicate = enrol(client, new_csr)
    assert duplicate.status_code == 409
    body = duplicate.get_json()
    assert body["status"] == "already_certified"
    assert body["device_id"] == "LAP-HR-001"
    assert body["certificate_serial"] == certificate["serial_number"]

    # Changing only the device ID must not bypass the hardware/asset check.
    _other_key, other_csr = make_identity(device_id="LAP-HR-999")
    duplicate_alias = enrol(client, other_csr, device_id="LAP-HR-999")
    assert duplicate_alias.status_code == 409
    assert duplicate_alias.get_json()["device_id"] == "LAP-HR-001"

    dashboard = client.get("/api/admin/dashboard", auth=admin_auth).get_json()
    assert dashboard["pending"] == []
    assert len(dashboard["devices"]) == 1
    assert len([c for c in dashboard["certificates"] if c["status"] == "active"]) == 1
    assert any(log["event_type"] == "DUPLICATE_ENROLLMENT_BLOCKED" for log in dashboard["logs"])
    assert all(log.get("incident_time") for log in dashboard["logs"])


def test_wrong_private_key_is_denied(endpointtrust):
    client = endpointtrust.app.test_client()
    admin_auth = ("admin", "EndpointTrust@123")
    _correct_key, csr_pem = make_identity()
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    request_id = enrol(client, csr_pem).get_json()["request_id"]
    assert client.post(f"/api/admin/enrollments/approve/{request_id}", auth=admin_auth).status_code == 200
    certificate_pem = client.get("/api/certificates/device/LAP-HR-001").get_json()["certificate_pem"]

    response = verify_device(client, wrong_key, certificate_pem)
    assert response.status_code == 403
    assert response.get_json()["message"] == "Signature verification failed"

    dashboard = client.get("/api/admin/dashboard", auth=admin_auth).get_json()
    assert dashboard["sessions"] == []


def test_admin_api_rejects_invalid_credentials(endpointtrust):
    client = endpointtrust.app.test_client()
    response = client.get("/api/admin/dashboard", auth=("admin", "wrong-password"))
    assert response.status_code == 401


def test_sensitive_data_is_encrypted_at_rest(endpointtrust):
    client = endpointtrust.app.test_client()
    admin_auth = ("admin", "EndpointTrust@123")
    key, csr_pem = make_identity()
    request = enrol(client, csr_pem, user="Sensitive Employee")
    assert request.status_code == 200
    request_id = request.get_json()["request_id"]

    with endpointtrust.db() as conn:
        pending = conn.execute("SELECT * FROM pending_enrollments WHERE request_id=?", (request_id,)).fetchone()
    assert pending["assigned_user"].startswith("enc:v1:")
    assert pending["serial_number"].startswith("enc:v1:")
    assert pending["hostname"].startswith("enc:v1:")
    assert pending["mac_address"].startswith("enc:v1:")
    assert pending["csr_pem"].startswith("file:v1:")
    csr_files = list((endpointtrust.SECURE_STORAGE_DIR / "encrypted_csrs").glob("*.csr.enc"))
    assert len(csr_files) == 1
    assert b"BEGIN CERTIFICATE REQUEST" not in csr_files[0].read_bytes()

    assert client.post(f"/api/admin/enrollments/approve/{request_id}", auth=admin_auth).status_code == 200
    certificate = client.get("/api/certificates/device/LAP-HR-001").get_json()
    verification = verify_device(client, key, certificate["certificate_pem"])
    assert verification.status_code == 200
    raw_token = verification.headers["Set-Cookie"].split("endpointtrust_session=", 1)[1].split(";", 1)[0]

    with endpointtrust.db() as conn:
        device = conn.execute("SELECT * FROM devices WHERE device_id='LAP-HR-001'").fetchone()
        stored_session = conn.execute("SELECT * FROM sessions WHERE device_id='LAP-HR-001'").fetchone()
        stored_log = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
    assert device["assigned_user"].startswith("enc:v1:")
    assert device["serial_number"].startswith("enc:v1:")
    assert raw_token not in stored_session["token"]
    assert raw_token not in stored_session["token_encrypted"]
    assert stored_session["token_encrypted"].startswith("enc:v1:")
    assert stored_log["detail"].startswith("enc:v1:")
    assert stored_log["source_ip"].startswith("enc:v1:")
    assert list((endpointtrust.SECURE_STORAGE_DIR / "encrypted_logs").glob("audit-*.log.enc"))

    dashboard = client.get("/api/admin/dashboard", auth=admin_auth).get_json()
    assert dashboard["devices"][0]["assigned_user"] == "Sensitive Employee"
    assert dashboard["logs"][0]["detail"]
