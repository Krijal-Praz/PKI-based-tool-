"""Test the complete EndpointTrust authentication workflow."""

from conftest import enrol, make_identity, verify_device


def test_complete_trusted_endpoint_workflow(endpointtrust):
    client = endpointtrust.app.test_client()
    admin_auth = ("admin", "EndpointTrust@123")

    private_key, csr_pem = make_identity()

    # Submit the device enrolment request.
    request_response = enrol(client, csr_pem)

    assert request_response.status_code == 200

    request_id = request_response.get_json()["request_id"]

    # Confirm that the device appears as pending.
    before_approval = client.get(
        "/api/admin/dashboard",
        auth=admin_auth,
    ).get_json()

    pending_ids = [
        row["request_id"]
        for row in before_approval["pending"]
    ]

    assert pending_ids == [request_id]
    assert before_approval["devices"] == []

    # Approve the device and issue its certificate.
    approval_response = client.post(
        f"/api/admin/enrollments/approve/{request_id}",
        auth=admin_auth,
    )

    assert approval_response.status_code == 200

    after_approval = client.get(
        "/api/admin/dashboard",
        auth=admin_auth,
    ).get_json()

    assert after_approval["pending"] == []
    assert len(after_approval["devices"]) == 1
    assert after_approval["sessions"] == []

    # Retrieve the issued X.509 certificate.
    certificate_response = client.get(
        "/api/certificates/device/LAP-HR-001"
    )

    assert certificate_response.status_code == 200

    certificate_pem = certificate_response.get_json()[
        "certificate_pem"
    ]

    # Complete challenge-response verification.
    verification_response = verify_device(
        client,
        private_key,
        certificate_pem,
    )

    assert verification_response.status_code == 200
    assert verification_response.get_json()["status"] == "allowed"

    cookie_header = verification_response.headers.get(
        "Set-Cookie",
        "",
    )

    assert "endpointtrust_session=" in cookie_header

    # Confirm that the session is active.
    session_status = client.get(
        "/api/auth/session-status",
        headers={
            "X-Real-IP": "127.0.0.1",
        },
    )

    assert session_status.status_code == 200
    assert session_status.get_json()["active"] is True

    # Confirm that the Nginx access check succeeds.
    nginx_check = client.get(
        "/auth/nginx-check",
        headers={
            "X-Real-IP": "127.0.0.1",
        },
    )

    assert nginx_check.status_code == 200
    assert (
        nginx_check.headers["X-EndpointTrust-Verified"]
        == "true"
    )

    # Revoke the device certificate.
    revocation_response = client.post(
        "/api/admin/certificates/revoke/LAP-HR-001",
        auth=admin_auth,
        json={
            "reason": "Security test revocation",
        },
    )

    assert revocation_response.status_code == 200

    # The old session must no longer be accepted.
    denied_session = client.get(
        "/api/auth/session-status",
        headers={
            "X-Real-IP": "127.0.0.1",
        },
    )

    assert denied_session.status_code == 401

    denied_nginx = client.get(
        "/auth/nginx-check",
        headers={
            "X-Real-IP": "127.0.0.1",
        },
    )

    assert denied_nginx.status_code == 403
