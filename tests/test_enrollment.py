"""Test device re-enrolment and certificate replacement."""

from conftest import enrol, make_identity, verify_device


def test_reenrollment_replaces_old_certificate_and_session(
    endpointtrust,
):
    client = endpointtrust.app.test_client()
    admin_auth = ("admin", "EndpointTrust@123")

    # Create and approve the first device identity.
    old_key, old_csr = make_identity()

    old_request_response = enrol(client, old_csr)

    assert old_request_response.status_code == 200

    old_request_id = old_request_response.get_json()[
        "request_id"
    ]

    old_approval = client.post(
        f"/api/admin/enrollments/approve/{old_request_id}",
        auth=admin_auth,
    )

    assert old_approval.status_code == 200

    old_certificate = client.get(
        "/api/certificates/device/LAP-HR-001"
    ).get_json()

    old_verification = verify_device(
        client,
        old_key,
        old_certificate["certificate_pem"],
    )

    assert old_verification.status_code == 200

    # Generate a new key and CSR for the same laptop.
    new_key, new_csr = make_identity()

    reenrolment_response = enrol(client, new_csr)

    assert reenrolment_response.status_code == 200
    assert (
        "Re-enrollment"
        in reenrolment_response.get_json()["message"]
    )

    new_request_id = reenrolment_response.get_json()[
        "request_id"
    ]

    new_approval = client.post(
        f"/api/admin/enrollments/approve/{new_request_id}",
        auth=admin_auth,
    )

    assert new_approval.status_code == 200

    new_certificate = client.get(
        "/api/certificates/device/LAP-HR-001"
    ).get_json()

    assert (
        new_certificate["serial_number"]
        != old_certificate["serial_number"]
    )

    dashboard = client.get(
        "/api/admin/dashboard",
        auth=admin_auth,
    ).get_json()

    # The old trusted session must be removed.
    assert dashboard["sessions"] == []

    certificate_statuses = {
        row["serial_number"]: row["status"]
        for row in dashboard["certificates"]
    }

    assert (
        certificate_statuses[
            old_certificate["serial_number"]
        ]
        == "superseded"
    )

    assert (
        certificate_statuses[
            new_certificate["serial_number"]
        ]
        == "active"
    )

    # The previous private key must fail.
    old_key_attempt = verify_device(
        client,
        old_key,
        new_certificate["certificate_pem"],
    )

    assert old_key_attempt.status_code == 403

    # The new matching private key must succeed.
    new_key_attempt = verify_device(
        client,
        new_key,
        new_certificate["certificate_pem"],
    )

    assert new_key_attempt.status_code == 200
