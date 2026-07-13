"""
EndpointTrust corporate laptop agent.

Secure enrolment model:
1. The laptop generates its own private key locally.
2. The laptop creates a CSR and submits a pending enrolment request.
3. IT admin approves the request from the EndpointTrust dashboard.
4. The laptop fetches its signed X.509 certificate.
5. The laptop proves device identity by signing a server challenge.

The private key is never sent to the EndpointTrust server.
"""
import base64
import json
import platform
import socket
import sys
import uuid
from pathlib import Path

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

AGENT_DIR = Path.home() / ".endpointtrust"
AGENT_DIR.mkdir(exist_ok=True)


def clean_server(server: str) -> str:
    return server.rstrip("/")


def key_path(device_id: str) -> Path:
    return AGENT_DIR / f"{device_id}_private_key.pem"


def csr_path(device_id: str) -> Path:
    return AGENT_DIR / f"{device_id}.csr.pem"


def cert_path(device_id: str) -> Path:
    return AGENT_DIR / f"{device_id}_certificate.pem"


def generate_key_and_csr(device_id: str, device_name: str, assigned_user: str, department: str, serial_number: str):
    key_file = key_path(device_id)
    if key_file.exists():
        key = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        key_file.chmod(0o600)

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EndpointTrust Corporate Devices"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, department),
            x509.NameAttribute(NameOID.COMMON_NAME, device_id),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, serial_number),
        ]))
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    csr_path(device_id).write_text(csr_pem)
    return key_file, csr_pem


def mac_address():
    mac = uuid.getnode()
    return ":".join(f"{(mac >> ele) & 0xff:02x}" for ele in range(40, -1, -8))


def enroll(server, device_id, device_name, assigned_user, department, serial_number):
    server = clean_server(server)
    device_id = device_id.upper()
    key_file, csr_pem = generate_key_and_csr(device_id, device_name, assigned_user, department, serial_number)
    payload = {
        "device_id": device_id,
        "device_name": device_name,
        "assigned_user": assigned_user,
        "department": department,
        "serial_number": serial_number.upper(),
        "hostname": socket.gethostname(),
        "os_name": platform.platform(),
        "mac_address": mac_address(),
        "csr": csr_pem,
    }
    r = requests.post(f"{server}/api/enrollment/request", json=payload, timeout=20)
    print(json.dumps(r.json(), indent=2))
    print(f"[+] Private key stored locally only: {key_file}")
    print(f"[+] CSR stored: {csr_path(device_id)}")
    print("[i] Ask IT admin to approve this request in the EndpointTrust dashboard.")


def fetch_cert(server, device_id):
    server = clean_server(server)
    device_id = device_id.upper()
    r = requests.get(f"{server}/api/certificates/device/{device_id}", timeout=20)
    if r.status_code != 200:
        print(r.text)
        raise SystemExit(1)
    data = r.json()
    cert_path(device_id).write_text(data["certificate_pem"])
    print(f"[+] Certificate downloaded: {cert_path(device_id)}")
    print(f"[+] Certificate serial: {data['serial_number']}")


def verify(server, device_id):
    server = clean_server(server)
    device_id = device_id.upper()
    kpath = key_path(device_id)
    cpath = cert_path(device_id)
    if not kpath.exists():
        print(f"[-] Missing private key: {kpath}")
        raise SystemExit(1)
    if not cpath.exists():
        print(f"[-] Missing certificate: {cpath}")
        print("[i] Run fetch-cert after IT admin approves enrolment.")
        raise SystemExit(1)

    challenge = requests.post(f"{server}/api/auth/challenge", json={"device_id": device_id}, timeout=20)
    if challenge.status_code != 200:
        print(challenge.text)
        raise SystemExit(1)
    chal = challenge.json()
    key = serialization.load_pem_private_key(kpath.read_bytes(), password=None)
    signature = key.sign(chal["nonce"].encode(), padding.PKCS1v15(), hashes.SHA256())
    payload = {
        "device_id": device_id,
        "challenge_id": chal["challenge_id"],
        "signature": base64.b64encode(signature).decode(),
        "certificate_pem": cpath.read_text(),
    }
    result = requests.post(f"{server}/api/auth/verify", json=payload, timeout=20)
    print(json.dumps(result.json(), indent=2))
    if result.status_code == 200:
        session_url = server + result.json()["session_url"] if result.json()["session_url"].startswith("/") else result.json()["session_url"]
        print("\n[+] Device verified successfully.")
        print(f"[+] Open this URL in your browser to access the protected HR system:\n{session_url}")


def usage():
    print("Usage:")
    print("  enroll:     python endpointtrust_agent.py enroll <server> <device_id> <device_name> <assigned_user> <department> <serial>")
    print("  fetch-cert: python endpointtrust_agent.py fetch-cert <server> <device_id>")
    print("  verify:     python endpointtrust_agent.py verify <server> <device_id>")
    print("Examples:")
    print('  python endpointtrust_agent.py enroll http://localhost:8080/endpointtrust LAP-001 "Finance Laptop" "Nirmal Shrestha" Finance LENOVO-ABC123')
    print("  python endpointtrust_agent.py fetch-cert http://localhost:8080/endpointtrust LAP-001")
    print("  python endpointtrust_agent.py verify http://localhost:8080/endpointtrust LAP-001")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()
        raise SystemExit(1)
    cmd = sys.argv[1].lower()
    if cmd == "enroll" and len(sys.argv) == 8:
        enroll(*sys.argv[2:])
    elif cmd == "fetch-cert" and len(sys.argv) == 4:
        fetch_cert(*sys.argv[2:])
    elif cmd == "verify" and len(sys.argv) == 4:
        verify(*sys.argv[2:])
    else:
        usage()
        raise SystemExit(1)
