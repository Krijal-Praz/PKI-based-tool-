"""Test that an unrelated private key is rejected."""

from cryptography.hazmat.primitives.asymmetric import rsa

from conftest import enrol, make_identity, verify_device


def test_wrong_private_key_is_denied(endpointtrust):
    client = endpointtrust.app.test_client()
    admin_auth = ("admin", "EndpointTrust@123")

    _correct_key, csr_pem = make_identity()

    wrong_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    enrolment_response = enrol(client, csr_pem)

    assert enrolment_response.status_code == 200

    request_id = enrolment_response.get_json()[
        "request_id"
    ]

    approval_response = client.post(
        f"/api/admin/enrollments/approve/{request_id}",
        auth=admin_auth,
    )

    assert approval_response.status_code == 200

    certificate_response = client.get(
        "/api/certificates/device/LAP-HR-001"
    )

    assert certificate_response.status_code == 200

    certificate_pem = certificate_response.get_json()[
        "certificate_pem"
    ]

    verification_response = verify_device(
        client,
        wrong_key,
        certificate_pem,
    )

    assert verification_response.status_code == 403
    assert (
        verification_response.get_json()["message"]
        == "Signature verification failed"
    )

    dashboard = client.get(
        "/api/admin/dashboard",
        auth=admin_auth,
    ).get_json()

    assert dashboard["sessions"] == []
