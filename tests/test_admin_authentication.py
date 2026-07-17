"""Test administrator API authentication controls."""


def test_admin_api_rejects_invalid_credentials(endpointtrust):
    client = endpointtrust.app.test_client()

    response = client.get(
        "/api/admin/dashboard",
        auth=(
            "admin",
            "wrong-password",
        ),
    )

    assert response.status_code == 401
