"""AES-256-GCM protection helpers for EndpointTrust sensitive data."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "enc:v1:"
FILE_PREFIX = b"ETENC1\n"


def _decode_key(raw: str) -> bytes:
    raw = raw.strip()
    try:
        key = base64.urlsafe_b64decode(raw.encode())
    except Exception as exc:
        raise RuntimeError("ENDPOINTTRUST_AES_KEY must be URL-safe base64") from exc
    if len(key) != 32:
        raise RuntimeError("ENDPOINTTRUST_AES_KEY must decode to exactly 32 bytes")
    return key


def load_or_create_key(storage_root: Path) -> bytes:
    """Load a 256-bit key from env or a permission-restricted demo key file."""
    configured = os.environ.get("ENDPOINTTRUST_AES_KEY", "").strip()
    if configured:
        return _decode_key(configured)
    storage_root.mkdir(parents=True, exist_ok=True)
    key_file = storage_root / "master.key"
    if key_file.exists():
        return _decode_key(key_file.read_text().strip())
    key = AESGCM.generate_key(bit_length=256)
    key_file.write_text(base64.urlsafe_b64encode(key).decode())
    key_file.chmod(0o600)
    return key


class SecureStorage:
    def __init__(self, root: Path):
        self.root = root
        self.csr_dir = root / "encrypted_csrs"
        self.log_dir = root / "encrypted_logs"
        self.csr_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.key = load_or_create_key(root)
        self.aes = AESGCM(self.key)

    def encrypt_text(self, value: str, purpose: str = "field") -> str:
        if value is None or value == "":
            return ""
        if str(value).startswith(PREFIX):
            return str(value)
        nonce = os.urandom(12)
        aad = purpose.encode()
        ciphertext = self.aes.encrypt(nonce, str(value).encode(), aad)
        return PREFIX + base64.urlsafe_b64encode(nonce + ciphertext).decode()

    def decrypt_text(self, value: str, purpose: str = "field") -> str:
        if value is None or value == "":
            return ""
        text = str(value)
        if not text.startswith(PREFIX):
            return text  # migration compatibility with older databases
        raw = base64.urlsafe_b64decode(text[len(PREFIX):].encode())
        return self.aes.decrypt(raw[:12], raw[12:], purpose.encode()).decode()

    @staticmethod
    def lookup_hash(value: str, purpose: str = "lookup") -> str:
        normalized = str(value).strip().lower()
        return hashlib.sha256(f"{purpose}:{normalized}".encode()).hexdigest()

    @staticmethod
    def token_hash(token: str) -> str:
        return hashlib.sha256(str(token).encode()).hexdigest()

    def encrypt_bytes(self, data: bytes, purpose: str) -> bytes:
        nonce = os.urandom(12)
        return FILE_PREFIX + nonce + self.aes.encrypt(nonce, data, purpose.encode())

    def decrypt_bytes(self, blob: bytes, purpose: str) -> bytes:
        if not blob.startswith(FILE_PREFIX):
            return blob
        body = blob[len(FILE_PREFIX):]
        return self.aes.decrypt(body[:12], body[12:], purpose.encode())

    @staticmethod
    def safe_filename_part(value: str, fallback: str = "device") -> str:
        """Create a readable filename segment without allowing path traversal."""
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value).strip())
        cleaned = cleaned.strip("._-")
        return cleaned[:80] or fallback

    def save_csr(self, request_id: str, assigned_user: str, csr_pem: str) -> str:
        user_name = self.safe_filename_part(assigned_user, "unknown_user")
        filename = f"{user_name}_{request_id}.csr.enc"
        path = self.csr_dir / filename
        path.write_bytes(self.encrypt_bytes(csr_pem.encode(), f"csr:{request_id}"))
        path.chmod(0o600)
        return f"file:v1:{filename}"

    def load_csr(self, reference: str, request_id: str) -> str:
        if not str(reference).startswith("file:v1:"):
            return str(reference)
        filename = str(reference).split(":", 2)[2]
        path = self.csr_dir / Path(filename).name
        return self.decrypt_bytes(path.read_bytes(), f"csr:{request_id}").decode()

    def append_encrypted_log(self, event: dict[str, Any], date_name: str) -> None:
        """Append one independently encrypted JSON record to a daily binary log file."""
        path = self.log_dir / f"audit-{date_name}.log.enc"
        payload = json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode()
        blob = self.encrypt_bytes(payload, f"audit:{date_name}")
        with path.open("ab") as handle:
            handle.write(base64.urlsafe_b64encode(blob) + b"\n")
        path.chmod(0o600)
