"""Shared pytest fixtures and helper functions for EndpointTrust tests."""

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
    """Create an isolated EndpointTrust environment for each test."""

    monkeypatch.setenv(
        "ENDPOINTTRUST_DB",
        str(tmp_path / "endpointtrust.db"),
    )
    monkeypatch.setenv(
        "ENDPOINTTRUST_CERT_DIR",
        str(tmp_path / "certs"),
    )
    monkeypatch.setenv(
        "ENDPOINTTRUST_PUBLIC_PREFIX",
        "/endpointtrust",
    )
    monkeypatch.setenv(
        "ENDPOINTTRUST_REBIND_IP",
        "true",
    )

    module_path = (
        Path(__file__).parents[1]
        / "endpointtrust"
        / "app.py"
    )

    spec = importlib.util.spec_from_file_location(
        "endpointtrust_test_app",
        module_path,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load EndpointTrust Flask application")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    module.app.config.update(TESTING=True)

    return module


def make_identity(
    device_id: str = "LAP-HR-001",
    department: str = "HR",
    serial: str = "ASSET-001",
):
    """Generate an RSA-2048 private key and PKCS#10 CSR."""

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COUNTRY_NAME,
                        "NP",
                    ),
                    x509.NameAttribute(
                        NameOID.ORGANIZATION_NAME,
                        "EndpointTrust Corporate Devices",
                    ),
                    x509.NameAttribute(
                        NameOID.ORGANIZATIONAL_UNIT_NAME,
                        department,
                    ),
                    x509.NameAttribute(
                        NameOID.COMMON_NAME,
                        device_id,
                    ),
                    x509.NameAttribute(
                        NameOID.SERIAL_NUMBER,
                        serial,
                    ),
                ]
            )
        )
        .sign(private_key, hashes.SHA256())
    )

    csr_pem = csr.public_bytes(
        serialization.Encoding.PEM
    ).decode()

    return private_key, csr_pem


def enrol(
    client,
    csr_pem: str,
    device_id: str = "LAP-HR-001",
    user: str = "Test Employee",
):
    """Submit a device enrolment request."""

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
        headers={
            "X-Real-IP": "127.0.0.1",
        },
    )


def verify_device(
    client,
    private_key,
    certificate_pem: str,
    device_id: str = "LAP-HR-001",
):
    """Request a challenge, sign it and submit verification."""

    challenge_response = client.post(
        "/api/auth/challenge",
        json={
            "device_id": device_id,
        },
        headers={
            "X-Real-IP": "127.0.0.1",
        },
    )

    assert challenge_response.status_code == 200

    challenge = challenge_response.get_json()

    signature = private_key.sign(
        challenge["nonce"].encode(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    return client.post(
        "/api/auth/verify",
        json={
            "device_id": device_id,
            "challenge_id": challenge["challenge_id"],
            "signature": base64.b64encode(signature).decode(),
            "certificate_pem": certificate_pem,
        },
        headers={
            "X-Real-IP": "127.0.0.1",
        },
    )
