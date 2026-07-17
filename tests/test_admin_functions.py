"""Tests for administrator actions used by the Tkinter console."""

from conftest import enrol, make_identity


ADMIN_AUTH = ("admin", "EndpointTrust@123")


def test_admin_can_approve_pending_device(endpointtrust):
    client = endpointtrust.app.test_client()
    _key, csr_pem = make_identity()

    enrolment = enrol(client, csr_pem)
    assert enrolment.status_code == 200

    request_id = enrolment.get_json()["request_id"]

    approval = client.post(
        f"/api/admin/enrollments/approve/{request_id}",
        auth=ADMIN_AUTH,
    )

    assert approval.status_code == 200

    dashboard = client.get(
        "/api/admin/dashboard",
        auth=ADMIN_AUTH,
    ).get_json()

    assert dashboard["pending"] == []
    assert len(dashboard["devices"]) == 1
    assert dashboard["devices"][0]["device_id"] == "LAP-HR-001"
    assert len(dashboard["certificates"]) == 1
    assert dashboard["certificates"][0]["status"] == "active"


def test_admin_can_reject_pending_device(endpointtrust):
    client = endpointtrust.app.test_client()
    _key, csr_pem = make_identity()

    enrolment = enrol(client, csr_pem)
    assert enrolment.status_code == 200

    request_id = enrolment.get_json()["request_id"]

    rejection = client.post(
        f"/api/admin/enrollments/reject/{request_id}",
        auth=ADMIN_AUTH,
        json={
            "reason": "Device ownership could not be confirmed",
        },
    )

    assert rejection.status_code == 200

    dashboard = client.get(
        "/api/admin/dashboard",
        auth=ADMIN_AUTH,
    ).get_json()

    assert dashboard["pending"] == []
    assert dashboard["devices"] == []

    rejection_logs = [
        log
        for log in dashboard["logs"]
        if log["event_type"] == "ENROLLMENT_REJECTED"
    ]

    assert len(rejection_logs) == 1
    assert rejection_logs[0]["device_id"] == "LAP-HR-001"
    assert rejection_logs[0]["status"] == "DENIED"


def test_admin_can_revoke_certificate(endpointtrust):
    client = endpointtrust.app.test_client()
    _key, csr_pem = make_identity()

    enrolment = enrol(client, csr_pem)
    request_id = enrolment.get_json()["request_id"]

    approval = client.post(
        f"/api/admin/enrollments/approve/{request_id}",
        auth=ADMIN_AUTH,
    )

    assert approval.status_code == 200

    revocation = client.post(
        "/api/admin/certificates/revoke/LAP-HR-001",
        auth=ADMIN_AUTH,
        json={
            "reason": "Laptop reported lost",
        },
    )

    assert revocation.status_code == 200
    assert revocation.get_json()["status"] == "revoked"

    dashboard = client.get(
        "/api/admin/dashboard",
        auth=ADMIN_AUTH,
    ).get_json()

    assert dashboard["devices"][0]["status"] == "revoked"
    assert dashboard["certificates"][0]["status"] == "revoked"
    assert len(dashboard["revoked"]) == 1
    assert dashboard["revoked"][0]["device_id"] == "LAP-HR-001"


def test_admin_dashboard_contains_audit_logs(endpointtrust):
    client = endpointtrust.app.test_client()
    _key, csr_pem = make_identity()

    enrolment = enrol(client, csr_pem)
    assert enrolment.status_code == 200

    request_id = enrolment.get_json()["request_id"]

    approval = client.post(
        f"/api/admin/enrollments/approve/{request_id}",
        auth=ADMIN_AUTH,
    )

    assert approval.status_code == 200

    dashboard = client.get(
        "/api/admin/dashboard",
        auth=ADMIN_AUTH,
    )

    assert dashboard.status_code == 200

    logs = dashboard.get_json()["logs"]

    event_types = [log["event_type"] for log in logs]

    assert "ENROLLMENT_REQUESTED" in event_types
    assert "ENROLLMENT_APPROVED" in event_types


def test_invalid_admin_credentials_are_rejected(endpointtrust):
    client = endpointtrust.app.test_client()

    response = client.get(
        "/api/admin/dashboard",
        auth=("admin", "incorrect-password"),
    )

    assert response.status_code == 401
