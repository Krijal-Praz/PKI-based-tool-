import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory, session

ROOT = Path(__file__).resolve().parent
DB = ROOT / "hr_verified_users.db"
app = Flask(__name__, static_folder=str(ROOT), static_url_path="")
app.secret_key = "internal-hr-demo-secret"


def init_db():
    with sqlite3.connect(DB) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS verified_entries(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            certificate_serial TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            visits INTEGER NOT NULL DEFAULT 1
        )
        """)
        conn.commit()


@app.before_request
def ready():
    init_db()


@app.route("/")
def index():
    return send_from_directory(ROOT, "index.html")


@app.route("/api/verified-entry", methods=["POST"])
def verified_entry():
    # Nginx sets these headers only after EndpointTrust allows the device.
    if request.headers.get("X-EndpointTrust-Verified") != "true":
        return jsonify({"ok": False, "error": "not verified"}), 403
    device_id = request.headers.get("X-EndpointTrust-Device", "verified-device")
    cert = request.headers.get("X-EndpointTrust-Cert", "unknown-cert")
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    # Count each browser session once, then update visit count on reload.
    if not session.get("hr_user_recorded"):
        with sqlite3.connect(DB) as conn:
            conn.execute("INSERT INTO verified_entries(device_id, certificate_serial, first_seen, last_seen, visits) VALUES(?,?,?,?,1)", (device_id, cert, now, now))
            conn.commit()
        session["hr_user_recorded"] = True
    else:
        with sqlite3.connect(DB) as conn:
            conn.execute("UPDATE verified_entries SET last_seen=?, visits=visits+1 WHERE id=(SELECT MAX(id) FROM verified_entries WHERE device_id=?)", (now, device_id))
            conn.commit()
    return jsonify({"ok": True})


@app.route("/api/hr-users")
def hr_users():
    with sqlite3.connect(DB) as conn:
        conn.row_factory = sqlite3.Row
        rows = [dict(r) for r in conn.execute("SELECT * FROM verified_entries ORDER BY id DESC").fetchall()]
    return jsonify({"count": len(rows), "users": rows})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5001)
