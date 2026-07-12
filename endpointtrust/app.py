import base64
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from functools import wraps

from flask import Flask, jsonify, make_response, redirect, render_template, request, session
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from werkzeug.security import check_password_hash, generate_password_hash

APP_ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("ENDPOINTTRUST_DB", APP_ROOT / "data" / "endpointtrust.db"))
CERT_DIR = Path(os.environ.get("ENDPOINTTRUST_CERT_DIR", APP_ROOT / "certs"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
CERT_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("ENDPOINTTRUST_SECRET", secrets.token_hex(32))

# Published behind Nginx at /endpointtrust/.
PUBLIC_PREFIX = os.environ.get("ENDPOINTTRUST_PUBLIC_PREFIX", "/endpointtrust")
ADMIN_USERNAME = os.environ.get("ENDPOINTTRUST_ADMIN_USER", "admin")
# Password is never stored or compared in plaintext. Default demo password is
# "EndpointTrust@123" but only its salted hash lives in memory/env.
ADMIN_PASSWORD_HASH = os.environ.get(
    "ENDPOINTTRUST_ADMIN_PASS_HASH",
    generate_password_hash("EndpointTrust@123"),
)

# Risk-based re-verification: if a verified session's source IP changes
# mid-session, the session is killed and the device must re-run the
# challenge-response proof again. Mitigates session/cookie hijacking.
REBIND_SESSION_TO_IP = os.environ.get("ENDPOINTTRUST_REBIND_IP", "true").lower() == "true"
CHALLENGE_TTL_SECONDS = int(os.environ.get("ENDPOINTTRUST_CHALLENGE_TTL", "60"))


def public_url(path="/"):
    if not path.startswith("/"):
        path = "/" + path
    return PUBLIC_PREFIX.rstrip("/") + path


def admin_logged_in():
    return session.get("endpointtrust_admin") is True


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not admin_logged_in():
            return redirect(public_url("/login"))
        return fn(*args, **kwargs)
    return wrapper


def admin_api_required(fn):
    """Protects the JSON admin API used by the Tkinter desktop admin app.
    Uses HTTP Basic Auth (checked against the same hashed admin credentials
    as the web login) instead of browser sessions, since a desktop app has
    no cookie jar shared with a browser."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        if not auth or auth.username != ADMIN_USERNAME or not check_password_hash(ADMIN_PASSWORD_HASH, auth.password):
            log_event("ADMIN_API_AUTH_FAILED", "admin", "DENIED", "Invalid or missing admin API credentials")
            resp = jsonify({"status": "error", "message": "Authentication required"})
            resp.status_code = 401
            resp.headers["WWW-Authenticate"] = 'Basic realm="EndpointTrust Admin API"'
            return resp
        return fn(*args, **kwargs)
    return wrapper


@app.context_processor
def inject_public_prefix():
    return {"PUBLIC_PREFIX": PUBLIC_PREFIX.rstrip("/")}


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def log_event(event_type, device_id="-", status="INFO", detail=""):
    with db() as conn:
        conn.execute(
            "INSERT INTO audit_logs(event_time,event_type,device_id,status,detail,source_ip) VALUES(?,?,?,?,?,?)",
            (now_iso(), event_type, device_id, status, detail, request.headers.get("X-Real-IP", request.remote_addr or "-")),
        )
        conn.commit()


def init_db():
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS devices(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT UNIQUE NOT NULL,
                device_name TEXT NOT NULL,
                assigned_user TEXT NOT NULL,
                department TEXT NOT NULL,
                serial_number TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pending_enrollments(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT UNIQUE NOT NULL,
                device_id TEXT NOT NULL,
                device_name TEXT NOT NULL,
                assigned_user TEXT NOT NULL,
                department TEXT NOT NULL,
                serial_number TEXT NOT NULL,
                hostname TEXT NOT NULL,
                os_name TEXT NOT NULL,
                mac_address TEXT NOT NULL,
                csr_pem TEXT NOT NULL,
                public_key_fingerprint TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                requested_at TEXT NOT NULL,
                reviewed_at TEXT,
                reviewed_by TEXT,
                rejection_reason TEXT
            );
            CREATE TABLE IF NOT EXISTS certificates(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                serial_number TEXT UNIQUE NOT NULL,
                subject TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                certificate_pem TEXT NOT NULL,
                private_key_pem TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active'
            );
            CREATE TABLE IF NOT EXISTS revoked_certificates(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                certificate_serial TEXT UNIQUE NOT NULL,
                device_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                revoked_by TEXT NOT NULL,
                revoked_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS challenges(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                challenge_id TEXT UNIQUE NOT NULL,
                device_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                created_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sessions(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                device_id TEXT NOT NULL,
                certificate_serial TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                bound_ip TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS audit_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time TEXT NOT NULL,
                event_type TEXT NOT NULL,
                device_id TEXT NOT NULL,
                status TEXT NOT NULL,
                detail TEXT NOT NULL,
                source_ip TEXT NOT NULL
            );
            """
        )
        try:
            conn.execute("ALTER TABLE sessions ADD COLUMN bound_ip TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError:
            pass
        conn.commit()


def ca_paths():
    return CERT_DIR / "ca_key.pem", CERT_DIR / "ca_cert.pem"


def ensure_ca():
    ca_key_path, ca_cert_path = ca_paths()
    if ca_key_path.exists() and ca_cert_path.exists():
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EndpointTrust Demo CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "EndpointTrust Local Root CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False, key_cert_sign=True,
                                     key_agreement=False, content_commitment=False, data_encipherment=False,
                                     crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256())
    )
    ca_key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    ca_key_path.chmod(0o600)
    ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def load_ca():
    ca_key_path, ca_cert_path = ca_paths()
    key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
    cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
    return key, cert


def public_key_fingerprint_from_csr(csr):
    pub = csr.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    h = hashes.Hash(hashes.SHA256())
    h.update(pub)
    return h.finalize().hex()


def sign_csr_device_certificate(device, csr_pem):
    ensure_ca()
    ca_key, ca_cert = load_ca()
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    if not csr.is_signature_valid:
        raise ValueError("Invalid CSR signature")
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EndpointTrust Corporate Devices"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, device["department"]),
        x509.NameAttribute(NameOID.COMMON_NAME, device["device_id"]),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, device["serial_number"]),
    ])
    serial = x509.random_serial_number()
    issued = datetime.now(timezone.utc)
    expires = issued + timedelta(days=365)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial)
        .not_valid_before(issued - timedelta(minutes=1))
        .not_valid_after(expires)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False, key_cert_sign=False,
                                     key_agreement=False, content_commitment=False, data_encipherment=False,
                                     crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return (
        str(serial),
        subject.rfc4514_string(),
        issued.replace(microsecond=0).isoformat(),
        expires.replace(microsecond=0).isoformat(),
        cert.public_bytes(serialization.Encoding.PEM).decode(),
    )


def issue_server_generated_demo_certificate(device):
    """Admin-only lab fallback: creates key on server. Real enrolment uses CSR signing."""
    ensure_ca()
    ca_key, ca_cert = load_ca()
    device_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EndpointTrust Corporate Devices"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, device["department"]),
        x509.NameAttribute(NameOID.COMMON_NAME, device["device_id"]),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, device["serial_number"]),
    ])
    serial = x509.random_serial_number()
    issued = datetime.now(timezone.utc)
    expires = issued + timedelta(days=365)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(device_key.public_key())
        .serial_number(serial)
        .not_valid_before(issued - timedelta(minutes=1))
        .not_valid_after(expires)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return (
        str(serial), subject.rfc4514_string(), issued.replace(microsecond=0).isoformat(),
        expires.replace(microsecond=0).isoformat(), cert.public_bytes(serialization.Encoding.PEM).decode(),
        device_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    )


def certificate_status(cert_row):
    if not cert_row:
        return "unknown"
    expires = datetime.fromisoformat(cert_row["expires_at"])
    if expires < datetime.now(timezone.utc):
        return "expired"
    with db() as conn:
        revoked = conn.execute("SELECT 1 FROM revoked_certificates WHERE certificate_serial=?", (cert_row["serial_number"],)).fetchone()
    if revoked:
        return "revoked"
    if cert_row["status"] != "active":
        return cert_row["status"]
    return "active"


def valid_session(token, client_ip=None):
    if not token:
        return None
    with db() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE token=? AND active=1", (token,)).fetchone()
        if not row:
            return None
        if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
            return None
        if REBIND_SESSION_TO_IP and client_ip and row["bound_ip"] and client_ip != row["bound_ip"]:
            # Risk-based re-verification: the network location changed mid-session
            # (possible session hijack / stolen cookie). Kill the session instead
            # of trusting it, and force the device to re-run challenge-response.
            conn.execute("UPDATE sessions SET active=0 WHERE token=?", (token,))
            conn.commit()
            log_event("SESSION_IP_MISMATCH", row["device_id"], "DENIED",
                      f"Session bound to {row['bound_ip']} but request came from {client_ip}; session revoked, re-verification required")
            return None
        cert = conn.execute("SELECT * FROM certificates WHERE serial_number=?", (row["certificate_serial"],)).fetchone()
    if certificate_status(cert) != "active":
        return None
    return row


@app.before_request
def startup():
    if not getattr(app, "_ready", False):
        init_db()
        ensure_ca()
        app._ready = True


@app.route("/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session["endpointtrust_admin"] = True
            log_event("ADMIN_LOGIN", "admin", "SUCCESS", "IT administrator logged in")
            return redirect(public_url("/"))
        error = "Invalid administrator username or password"
        log_event("ADMIN_LOGIN_FAILED", "admin", "DENIED", "Invalid dashboard login attempt")
    return render_template("login.html", error=error)


@app.get("/admin/logout")
def admin_logout():
    session.pop("endpointtrust_admin", None)
    return redirect(public_url("/login"))


@app.get("/device-portal")
def device_portal():
    # Browser-based enrolment + verification. Keypair generation, CSR
    # construction and challenge signing all happen client-side via WebCrypto
    # so the private key never leaves the laptop. Replaces the CLI agent.
    return render_template("device_portal.html")


@app.route("/")
@admin_required
def dashboard():
    with db() as conn:
        pending = conn.execute("SELECT * FROM pending_enrollments ORDER BY id DESC").fetchall()
        devices = conn.execute("SELECT * FROM devices ORDER BY id DESC").fetchall()
        certs = conn.execute("SELECT * FROM certificates ORDER BY id DESC").fetchall()
        revoked = conn.execute("SELECT * FROM revoked_certificates ORDER BY id DESC").fetchall()
        logs = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 80").fetchall()
        sessions = conn.execute("SELECT * FROM sessions WHERE active=1 ORDER BY id DESC").fetchall()
    return render_template("dashboard.html", pending=pending, devices=devices, certs=certs, revoked=revoked, logs=logs, sessions=sessions)


@app.post("/enrollments/approve/<request_id>")
@admin_required
def approve_enrollment(request_id):
    with db() as conn:
        enr = conn.execute("SELECT * FROM pending_enrollments WHERE request_id=?", (request_id,)).fetchone()
        if not enr or enr["status"] != "pending":
            return redirect(public_url("/"))
        existing_device = conn.execute("SELECT * FROM devices WHERE device_id=?", (enr["device_id"],)).fetchone()
        existing_cert = conn.execute("SELECT * FROM certificates WHERE device_id=? AND status='active'", (enr["device_id"],)).fetchone()
        if not existing_device:
            conn.execute(
                "INSERT INTO devices(device_id,device_name,assigned_user,department,serial_number,status,created_at) VALUES(?,?,?,?,?,?,?)",
                (enr["device_id"], enr["device_name"], enr["assigned_user"], enr["department"], enr["serial_number"], "registered", now_iso()),
            )
        else:
            # Re-enrollment: reset revoked/suspended device back to registered
            conn.execute("UPDATE devices SET status='registered', device_name=?, assigned_user=?, department=? WHERE device_id=?",
                         (enr["device_name"], enr["assigned_user"], enr["department"], enr["device_id"]))
        if not existing_cert:
            serial, subject, issued, expires, cert_pem = sign_csr_device_certificate(enr, enr["csr_pem"])
            conn.execute(
                "INSERT INTO certificates(device_id,serial_number,subject,issued_at,expires_at,certificate_pem,private_key_pem,status) VALUES(?,?,?,?,?,?,?,?)",
                (enr["device_id"], serial, subject, issued, expires, cert_pem, "", "active"),
            )
        conn.execute("UPDATE pending_enrollments SET status='approved', reviewed_at=?, reviewed_by=? WHERE request_id=?", (now_iso(), "it_admin", request_id))
        conn.commit()
    log_event("ENROLLMENT_APPROVED", enr["device_id"], "SUCCESS", "CSR signed and device certificate issued")
    return redirect(public_url("/"))


@app.post("/enrollments/reject/<request_id>")
@admin_required
def reject_enrollment(request_id):
    reason = request.form.get("reason", "Device not found in asset inventory")
    with db() as conn:
        enr = conn.execute("SELECT * FROM pending_enrollments WHERE request_id=?", (request_id,)).fetchone()
        if enr:
            conn.execute("UPDATE pending_enrollments SET status='rejected', reviewed_at=?, reviewed_by=?, rejection_reason=? WHERE request_id=?",
                         (now_iso(), "it_admin", reason, request_id))
            conn.commit()
            log_event("ENROLLMENT_REJECTED", enr["device_id"], "DENIED", reason)
    return redirect(public_url("/"))


@app.post("/devices/register")
@admin_required
def register_device():
    """Manual lab import only. Real workflow is agent enrolment -> admin approval."""
    device_id = request.form.get("device_id", "LAP-001").strip().upper()
    name = request.form.get("device_name", "Finance Corporate Laptop").strip()
    user = request.form.get("assigned_user", "Nirmal Shrestha").strip()
    dept = request.form.get("department", "IT").strip()
    serial = request.form.get("serial_number", "LENOVO-DEMO-001").strip().upper()
    with db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO devices(device_id,device_name,assigned_user,department,serial_number,status,created_at) VALUES(?,?,?,?,?,?,?)",
            (device_id, name, user, dept, serial, "registered", now_iso()),
        )
        conn.commit()
    log_event("DEVICE_REGISTERED_MANUAL", device_id, "SUCCESS", f"Manual lab import for {name}")
    return redirect(public_url("/"))


@app.post("/certificates/issue/<device_id>")
@admin_required
def issue_cert(device_id):
    """Manual lab certificate issue for devices imported without CSR."""
    with db() as conn:
        device = conn.execute("SELECT * FROM devices WHERE device_id=?", (device_id,)).fetchone()
        if not device:
            log_event("CERTIFICATE_ISSUE_FAILED", device_id, "FAILED", "Device not found")
            return redirect(public_url("/"))
        existing = conn.execute("SELECT * FROM certificates WHERE device_id=? AND status='active'", (device_id,)).fetchone()
        if existing:
            return redirect(public_url("/"))
        serial, subject, issued, expires, cert_pem, key_pem = issue_server_generated_demo_certificate(device)
        conn.execute(
            "INSERT INTO certificates(device_id,serial_number,subject,issued_at,expires_at,certificate_pem,private_key_pem,status) VALUES(?,?,?,?,?,?,?,?)",
            (device_id, serial, subject, issued, expires, cert_pem, key_pem, "active"),
        )
        conn.commit()
    log_event("CERTIFICATE_ISSUED", device_id, "SUCCESS", f"Demo certificate serial {serial} issued")
    return redirect(public_url("/"))


@app.post("/certificates/revoke/<device_id>")
@admin_required
def revoke_cert(device_id):
    reason = request.form.get("reason", "Laptop stolen or no longer trusted")
    with db() as conn:
        cert = conn.execute("SELECT * FROM certificates WHERE device_id=? ORDER BY id DESC LIMIT 1", (device_id,)).fetchone()
        if cert:
            conn.execute("INSERT OR IGNORE INTO revoked_certificates(certificate_serial,device_id,reason,revoked_by,revoked_at) VALUES(?,?,?,?,?)",
                         (cert["serial_number"], device_id, reason, "it_admin", now_iso()))
            conn.execute("UPDATE certificates SET status='revoked' WHERE serial_number=?", (cert["serial_number"],))
            conn.execute("UPDATE devices SET status='revoked' WHERE device_id=?", (device_id,))
            conn.execute("UPDATE sessions SET active=0 WHERE device_id=?", (device_id,))
            conn.commit()
            log_event("CERTIFICATE_REVOKED", device_id, "SUCCESS", reason)
    return redirect(public_url("/"))


# ----------------------------- Desktop admin JSON API -----------------------------
# Used by the Tkinter desktop admin app (scripts/endpointtrust_admin_app.py)
# instead of a browser. Same underlying logic as the HTML dashboard routes
# above, just returning/accepting JSON and authenticated via HTTP Basic Auth.

@app.get("/api/admin/ping")
@admin_api_required
def api_admin_ping():
    return jsonify({"status": "ok", "message": "Authenticated"})


@app.get("/api/admin/dashboard")
@admin_api_required
def api_admin_dashboard():
    with db() as conn:
        pending = [dict(r) for r in conn.execute("SELECT * FROM pending_enrollments ORDER BY id DESC").fetchall()]
        devices = [dict(r) for r in conn.execute("SELECT * FROM devices ORDER BY id DESC").fetchall()]
        certs = [dict(r) for r in conn.execute("SELECT * FROM certificates ORDER BY id DESC").fetchall()]
        revoked = [dict(r) for r in conn.execute("SELECT * FROM revoked_certificates ORDER BY id DESC").fetchall()]
        logs = [dict(r) for r in conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 150").fetchall()]
        sessions = [dict(r) for r in conn.execute("SELECT * FROM sessions WHERE active=1 AND expires_at>? ORDER BY id DESC", (now_iso(),)).fetchall()]
    for c in certs:
        c.pop("private_key_pem", None)
        c["status"] = certificate_status(c)
    return jsonify({"pending": pending, "devices": devices, "certificates": certs,
                     "revoked": revoked, "logs": logs, "sessions": sessions})


@app.post("/api/admin/enrollments/approve/<request_id>")
@admin_api_required
def api_admin_approve(request_id):
    with db() as conn:
        enr = conn.execute("SELECT * FROM pending_enrollments WHERE request_id=?", (request_id,)).fetchone()
        if not enr or enr["status"] != "pending":
            return jsonify({"status": "error", "message": "Request not found or already reviewed"}), 404
        existing_device = conn.execute("SELECT * FROM devices WHERE device_id=?", (enr["device_id"],)).fetchone()
        existing_cert = conn.execute("SELECT * FROM certificates WHERE device_id=? AND status='active'", (enr["device_id"],)).fetchone()
        if not existing_device:
            conn.execute(
                "INSERT INTO devices(device_id,device_name,assigned_user,department,serial_number,status,created_at) VALUES(?,?,?,?,?,?,?)",
                (enr["device_id"], enr["device_name"], enr["assigned_user"], enr["department"], enr["serial_number"], "registered", now_iso()),
            )
        else:
            # Re-enrollment: reset revoked/suspended device back to registered
            conn.execute("UPDATE devices SET status='registered', device_name=?, assigned_user=?, department=? WHERE device_id=?",
                         (enr["device_name"], enr["assigned_user"], enr["department"], enr["device_id"]))
        if not existing_cert:
            serial, subject, issued, expires, cert_pem = sign_csr_device_certificate(enr, enr["csr_pem"])
            conn.execute(
                "INSERT INTO certificates(device_id,serial_number,subject,issued_at,expires_at,certificate_pem,private_key_pem,status) VALUES(?,?,?,?,?,?,?,?)",
                (enr["device_id"], serial, subject, issued, expires, cert_pem, "", "active"),
            )
        conn.execute("UPDATE pending_enrollments SET status='approved', reviewed_at=?, reviewed_by=? WHERE request_id=?", (now_iso(), "it_admin", request_id))
        conn.commit()
    log_event("ENROLLMENT_APPROVED", enr["device_id"], "SUCCESS", "CSR signed and device certificate issued via desktop admin app")
    return jsonify({"status": "approved", "device_id": enr["device_id"]})


@app.post("/api/admin/enrollments/reject/<request_id>")
@admin_api_required
def api_admin_reject(request_id):
    data = request.get_json(silent=True) or {}
    reason = str(data.get("reason", "Device not found in asset inventory")).strip()
    if not reason:
        return jsonify({"status": "error", "message": "A rejection reason is required"}), 400
    with db() as conn:
        enr = conn.execute("SELECT * FROM pending_enrollments WHERE request_id=?", (request_id,)).fetchone()
        if not enr or enr["status"] != "pending":
            return jsonify({"status": "error", "message": "Request not found or already reviewed"}), 409
        conn.execute("UPDATE pending_enrollments SET status='rejected', reviewed_at=?, reviewed_by=?, rejection_reason=? WHERE request_id=?",
                     (now_iso(), "it_admin", reason, request_id))
        conn.commit()
    log_event("ENROLLMENT_REJECTED", enr["device_id"], "DENIED", reason)
    return jsonify({"status": "rejected", "device_id": enr["device_id"]})


@app.post("/api/admin/certificates/revoke/<device_id>")
@admin_api_required
def api_admin_revoke(device_id):
    data = request.get_json(silent=True) or {}
    device_id = device_id.strip().upper()
    reason = str(data.get("reason", "Laptop stolen or no longer trusted")).strip()
    if not reason:
        return jsonify({"status": "error", "message": "A revocation reason is required"}), 400
    with db() as conn:
        cert = conn.execute("SELECT * FROM certificates WHERE device_id=? ORDER BY id DESC LIMIT 1", (device_id,)).fetchone()
        if not cert:
            return jsonify({"status": "error", "message": "No certificate found for device"}), 404
        if certificate_status(cert) != "active":
            return jsonify({"status": "error", "message": f"Certificate is already {certificate_status(cert)}"}), 409
        conn.execute("INSERT OR IGNORE INTO revoked_certificates(certificate_serial,device_id,reason,revoked_by,revoked_at) VALUES(?,?,?,?,?)",
                     (cert["serial_number"], device_id, reason, "it_admin", now_iso()))
        conn.execute("UPDATE certificates SET status='revoked' WHERE serial_number=?", (cert["serial_number"],))
        conn.execute("UPDATE devices SET status='revoked' WHERE device_id=?", (device_id,))
        conn.execute("UPDATE sessions SET active=0 WHERE device_id=?", (device_id,))
        conn.commit()
    log_event("CERTIFICATE_REVOKED", device_id, "SUCCESS", f"{reason} (via desktop admin app)")
    return jsonify({"status": "revoked", "device_id": device_id})


@app.post("/auth/verify-demo/<device_id>")
@admin_required
def verify_demo(device_id):
    """Admin-only fallback for server-generated demo keys."""
    challenge_id = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(32)
    with db() as conn:
        cert = conn.execute("SELECT * FROM certificates WHERE device_id=? ORDER BY id DESC LIMIT 1", (device_id,)).fetchone()
        if not cert or not cert["private_key_pem"]:
            log_event("ACCESS_DENIED", device_id, "FAILED", "No server-side demo private key available; use Python agent verify")
            return redirect(public_url("/"))
        if certificate_status(cert) != "active":
            log_event("ACCESS_DENIED", device_id, "FAILED", f"Certificate status: {certificate_status(cert)}")
            return redirect(public_url("/"))
        conn.execute("INSERT INTO challenges(challenge_id,device_id,nonce,created_at,used) VALUES(?,?,?,?,0)", (challenge_id, device_id, nonce, now_iso()))
        conn.commit()
    private_key = serialization.load_pem_private_key(cert["private_key_pem"].encode(), password=None)
    signature = private_key.sign(nonce.encode(), padding.PKCS1v15(), hashes.SHA256())
    public_cert = x509.load_pem_x509_certificate(cert["certificate_pem"].encode())
    try:
        public_cert.public_key().verify(signature, nonce.encode(), padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        log_event("ACCESS_DENIED", device_id, "FAILED", "Signed challenge verification failed")
        return redirect(public_url("/"))
    token = create_verified_session(device_id, cert["serial_number"])
    log_event("DEVICE_VERIFIED", device_id, "SUCCESS", "Admin demo challenge-response successful")
    return redirect(public_url(f"/auth/session/{token}"))


def create_verified_session(device_id, certificate_serial):
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    with db() as conn:
        conn.execute(
            "INSERT INTO sessions(token,device_id,certificate_serial,created_at,expires_at,active,bound_ip) VALUES(?,?,?,?,?,1,?)",
            (token, device_id, certificate_serial, now_iso(), expires.replace(microsecond=0).isoformat(), client_ip),
        )
        conn.commit()
    return token


# ----------------------------- Public agent APIs -----------------------------
@app.post("/api/enrollment/request")
def api_enrollment_request():
    data = request.get_json(silent=True) or {}
    required = ["device_id", "device_name", "assigned_user", "department", "serial_number", "hostname", "os_name", "mac_address", "csr"]
    missing = [k for k in required if not str(data.get(k, "")).strip()]
    if missing:
        return jsonify({"status": "error", "message": "Missing fields", "missing": missing}), 400
    device_id = str(data["device_id"]).strip().upper()
    csr_pem = data["csr"]
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        if not csr.is_signature_valid:
            raise ValueError("CSR signature invalid")
        fingerprint = public_key_fingerprint_from_csr(csr)
    except Exception as exc:
        log_event("ENROLLMENT_FAILED", device_id, "DENIED", f"Invalid CSR: {exc}")
        return jsonify({"status": "error", "message": "Invalid CSR"}), 400
    with db() as conn:
        existing_active = conn.execute("SELECT 1 FROM devices WHERE device_id=? AND status='registered'", (device_id,)).fetchone()
        if existing_active:
            return jsonify({"status": "exists", "message": "Device already registered", "device_id": device_id}), 409
        existing_pending = conn.execute("SELECT * FROM pending_enrollments WHERE device_id=? AND status='pending'", (device_id,)).fetchone()
        if existing_pending:
            return jsonify({"status": "pending", "message": "Enrollment already pending", "request_id": existing_pending["request_id"], "device_id": device_id}), 200
        request_id = "ENR-" + secrets.token_hex(5).upper()
        conn.execute(
            """INSERT INTO pending_enrollments(request_id,device_id,device_name,assigned_user,department,serial_number,hostname,os_name,mac_address,csr_pem,public_key_fingerprint,status,requested_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (request_id, device_id, data["device_name"].strip(), data["assigned_user"].strip(), data["department"].strip(),
             data["serial_number"].strip().upper(), data["hostname"].strip(), data["os_name"].strip(), data["mac_address"].strip(),
             csr_pem, fingerprint, "pending", now_iso()),
        )
        conn.commit()
    log_event("ENROLLMENT_REQUESTED", device_id, "PENDING", "Laptop submitted CSR and device metadata for admin approval")
    return jsonify({"status": "pending", "request_id": request_id, "device_id": device_id, "message": "Enrollment request submitted. Wait for IT admin approval."})


@app.get("/api/enrollment/status/<device_id>")
def api_enrollment_status(device_id):
    device_id = device_id.upper()
    with db() as conn:
        enr = conn.execute("SELECT * FROM pending_enrollments WHERE device_id=? ORDER BY id DESC LIMIT 1", (device_id,)).fetchone()
        cert = conn.execute("SELECT serial_number, certificate_pem, expires_at, status FROM certificates WHERE device_id=? ORDER BY id DESC LIMIT 1", (device_id,)).fetchone()
    return jsonify({
        "device_id": device_id,
        "enrollment": dict(enr) if enr else None,
        "certificate": dict(cert) if cert else None,
    })


@app.get("/api/certificates/device/<device_id>")
def api_download_certificate(device_id):
    device_id = device_id.upper()
    with db() as conn:
        cert = conn.execute("SELECT serial_number, certificate_pem, expires_at, status FROM certificates WHERE device_id=? ORDER BY id DESC LIMIT 1", (device_id,)).fetchone()
    if not cert:
        return jsonify({"status": "not_found", "message": "Certificate not issued yet"}), 404
    if certificate_status(cert) != "active":
        return jsonify({"status": certificate_status(cert), "message": "Certificate is not active"}), 403
    return jsonify({"status": "active", "device_id": device_id, "serial_number": cert["serial_number"], "expires_at": cert["expires_at"], "certificate_pem": cert["certificate_pem"]})


@app.post("/api/auth/challenge")
def api_auth_challenge():
    data = request.get_json(silent=True) or {}
    device_id = str(data.get("device_id", "")).strip().upper()
    if not device_id:
        return jsonify({"status": "error", "message": "device_id required"}), 400
    with db() as conn:
        device = conn.execute("SELECT * FROM devices WHERE device_id=?", (device_id,)).fetchone()
        cert = conn.execute("SELECT * FROM certificates WHERE device_id=? ORDER BY id DESC LIMIT 1", (device_id,)).fetchone()
    if not device or device["status"] != "registered":
        log_event("CHALLENGE_DENIED", device_id or "unknown", "DENIED", "Device not registered")
        return jsonify({"status": "denied", "message": "Device is not registered"}), 403
    if certificate_status(cert) != "active":
        log_event("CHALLENGE_DENIED", device_id, "DENIED", f"Certificate status: {certificate_status(cert)}")
        return jsonify({"status": "denied", "message": f"Certificate status: {certificate_status(cert)}"}), 403
    challenge_id = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(32)
    with db() as conn:
        conn.execute("INSERT INTO challenges(challenge_id,device_id,nonce,created_at,used) VALUES(?,?,?,?,0)", (challenge_id, device_id, nonce, now_iso()))
        conn.commit()
    return jsonify({"status": "challenge", "challenge_id": challenge_id, "nonce": nonce, "certificate_serial": cert["serial_number"], "expires_in_seconds": CHALLENGE_TTL_SECONDS})


@app.post("/api/auth/verify")
def api_auth_verify():
    data = request.get_json(silent=True) or {}
    device_id = str(data.get("device_id", "")).strip().upper()
    challenge_id = str(data.get("challenge_id", "")).strip()
    signature_b64 = str(data.get("signature", "")).strip()
    certificate_pem = data.get("certificate_pem", "")
    if not all([device_id, challenge_id, signature_b64, certificate_pem]):
        return jsonify({"status": "error", "message": "device_id, challenge_id, signature and certificate_pem are required"}), 400
    with db() as conn:
        cert = conn.execute("SELECT * FROM certificates WHERE device_id=? ORDER BY id DESC LIMIT 1", (device_id,)).fetchone()
        chal = conn.execute("SELECT * FROM challenges WHERE challenge_id=? AND device_id=? AND used=0", (challenge_id, device_id)).fetchone()
    if not cert or certificate_status(cert) != "active" or not chal:
        log_event("ACCESS_DENIED", device_id, "DENIED", "Invalid certificate status or challenge")
        return jsonify({"status": "denied", "message": "Invalid certificate status or challenge"}), 403
    challenge_age = (datetime.now(timezone.utc) - datetime.fromisoformat(chal["created_at"])).total_seconds()
    if challenge_age > CHALLENGE_TTL_SECONDS:
        with db() as conn:
            conn.execute("UPDATE challenges SET used=1 WHERE challenge_id=?", (challenge_id,))
            conn.commit()
        log_event("ACCESS_DENIED", device_id, "DENIED", "Authentication challenge expired")
        return jsonify({"status": "denied", "message": "Authentication challenge expired; request a new challenge"}), 403
    # Require that the presented certificate exactly matches the certificate issued by EndpointTrust.
    if cert["certificate_pem"].strip() != certificate_pem.strip():
        log_event("ACCESS_DENIED", device_id, "DENIED", "Presented certificate does not match issued certificate")
        return jsonify({"status": "denied", "message": "Certificate mismatch"}), 403
    try:
        public_cert = x509.load_pem_x509_certificate(certificate_pem.encode())
        signature = base64.b64decode(signature_b64.encode(), validate=True)
        public_cert.public_key().verify(signature, chal["nonce"].encode(), padding.PKCS1v15(), hashes.SHA256())
    except Exception as exc:
        log_event("ACCESS_DENIED", device_id, "DENIED", f"Signature verification failed: {exc}")
        return jsonify({"status": "denied", "message": "Signature verification failed"}), 403
    with db() as conn:
        result = conn.execute("UPDATE challenges SET used=1 WHERE challenge_id=? AND used=0", (challenge_id,))
        conn.commit()
    if result.rowcount != 1:
        log_event("ACCESS_DENIED", device_id, "DENIED", "Challenge replay or concurrent reuse detected")
        return jsonify({"status": "denied", "message": "Challenge has already been used"}), 403
    token = create_verified_session(device_id, cert["serial_number"])
    log_event("DEVICE_VERIFIED", device_id, "SUCCESS", "Agent challenge-response authentication successful")
    return jsonify({"status": "allowed", "device_id": device_id, "session_url": public_url(f"/auth/session/{token}"), "internal_url": "/internal/", "message": "Device verified. Open session_url in browser to set access cookie."})


@app.get("/auth/session/<token>")
def browser_session(token):
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    row = valid_session(token, client_ip)
    if not row:
        return make_response("Invalid or expired EndpointTrust session token", 403)
    resp = make_response(redirect("/internal/"))
    resp.set_cookie("endpointtrust_session", token, httponly=True, samesite="Lax", path="/", max_age=3600)
    return resp


@app.get("/auth/nginx-check")
def nginx_check():
    token = request.cookies.get("endpointtrust_session")
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    row = valid_session(token, client_ip)
    if not row:
        log_event("NGINX_ACCESS_CHECK", "unknown", "DENIED", "Missing/invalid session, or risk-based re-verification triggered")
        return ("denied", 403)
    log_event("NGINX_ACCESS_CHECK", row["device_id"], "ALLOWED", "Valid verified laptop session")
    resp = make_response("ok", 200)
    resp.headers["X-EndpointTrust-Device"] = row["device_id"]
    resp.headers["X-EndpointTrust-Cert"] = row["certificate_serial"]
    resp.headers["X-EndpointTrust-Verified"] = "true"
    return resp


@app.get("/api/status")
def api_status():
    with db() as conn:
        return jsonify({
            "pending_enrollments": conn.execute("SELECT COUNT(*) c FROM pending_enrollments WHERE status='pending'").fetchone()["c"],
            "devices": conn.execute("SELECT COUNT(*) c FROM devices").fetchone()["c"],
            "certificates": conn.execute("SELECT COUNT(*) c FROM certificates").fetchone()["c"],
            "revoked": conn.execute("SELECT COUNT(*) c FROM revoked_certificates").fetchone()["c"],
            "active_sessions": conn.execute("SELECT COUNT(*) c FROM sessions WHERE active=1").fetchone()["c"],
        })


@app.get("/logout")
def logout():
    token = request.cookies.get("endpointtrust_session")
    if token:
        with db() as conn:
            conn.execute("UPDATE sessions SET active=0 WHERE token=?", (token,))
            conn.commit()
    resp = make_response(redirect(public_url("/login")))
    resp.delete_cookie("endpointtrust_session", path="/")
    return resp


@app.get("/download/device/<device_id>/<kind>")
@admin_required
def download_device_material(device_id, kind):
    with db() as conn:
        cert = conn.execute("SELECT * FROM certificates WHERE device_id=? ORDER BY id DESC LIMIT 1", (device_id,)).fetchone()
    if not cert:
        return "not found", 404
    if kind == "cert":
        content = cert["certificate_pem"]
        filename = f"{device_id}_certificate.pem"
    elif kind == "key" and cert["private_key_pem"]:
        content = cert["private_key_pem"]
        filename = f"{device_id}_private_key.pem"
    else:
        return "Private key is not stored on the server for agent-enrolled devices.", 404
    resp = make_response(content)
    resp.headers["Content-Type"] = "application/x-pem-file"
    resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return resp


if __name__ == "__main__":
    init_db()
    ensure_ca()
    app.run(host="0.0.0.0", port=5000, debug=False)
