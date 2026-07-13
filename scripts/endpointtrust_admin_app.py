#!/usr/bin/env python3
"""EndpointTrust PKI desktop administration console.

Primary functions:
- Review and approve/reject corporate laptop enrolment requests.
- Inspect registered devices and the latest X.509 certificate state.
- Revoke a lost, stolen, compromised, or retired laptop certificate.
- Monitor verified endpoint sessions and security audit events.

The application talks only to the EndpointTrust JSON admin API. Network calls run
outside Tk's UI thread; all widget updates are scheduled on the Tk event loop.
"""
from __future__ import annotations

import json
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from typing import Any, Callable

try:
    import requests
except ImportError as exc:  # pragma: no cover - friendly startup message
    raise SystemExit("Install the required dependency with: pip install requests") from exc

APP_TITLE = "EndpointTrust PKI — IT Administration Console"
DEFAULT_SERVER = "http://localhost:8080/endpointtrust"
REFRESH_MS = 5_000
REQUEST_TIMEOUT = (4, 12)  # connect, read

PENDING_COLUMNS = (
    "request_id", "device_id", "device_name", "assigned_user", "department",
    "hostname", "mac_address", "public_key_fingerprint", "status", "requested_at",
)
DEVICE_COLUMNS = (
    "device_id", "device_name", "assigned_user", "department", "status",
    "serial_number", "expires_at", "certificate_status", "access_status",
)
SESSION_COLUMNS = ("device_id", "certificate_serial", "bound_ip", "created_at", "expires_at")
LOG_COLUMNS = ("event_time", "event_type", "device_id", "status", "detail", "source_ip")


class LoginDialog(simpledialog.Dialog):
    """Collect API connection details without storing the password on disk."""

    def __init__(self, parent: tk.Misc, server: str, username: str):
        self.initial_server = server
        self.initial_username = username
        self.result: tuple[str, str, str] | None = None
        super().__init__(parent, title="Connect to EndpointTrust")

    def body(self, master: tk.Misc) -> tk.Widget:
        ttk.Label(master, text="Server URL:").grid(row=0, column=0, sticky="e", padx=6, pady=5)
        ttk.Label(master, text="Admin username:").grid(row=1, column=0, sticky="e", padx=6, pady=5)
        ttk.Label(master, text="Admin password:").grid(row=2, column=0, sticky="e", padx=6, pady=5)

        self.url_entry = ttk.Entry(master, width=48)
        self.user_entry = ttk.Entry(master, width=48)
        self.password_entry = ttk.Entry(master, width=48, show="•")
        self.url_entry.insert(0, self.initial_server)
        self.user_entry.insert(0, self.initial_username)
        self.url_entry.grid(row=0, column=1, padx=6, pady=5)
        self.user_entry.grid(row=1, column=1, padx=6, pady=5)
        self.password_entry.grid(row=2, column=1, padx=6, pady=5)
        return self.password_entry

    def validate(self) -> bool:
        server = self.url_entry.get().strip().rstrip("/")
        username = self.user_entry.get().strip()
        password = self.password_entry.get()
        if not server.startswith(("http://", "https://")):
            messagebox.showwarning("Invalid server URL", "The server URL must begin with http:// or https://.", parent=self)
            return False
        if not username or not password:
            messagebox.showwarning("Missing credentials", "Enter both the administrator username and password.", parent=self)
            return False
        return True

    def apply(self) -> None:
        self.result = (
            self.url_entry.get().strip().rstrip("/"),
            self.user_entry.get().strip(),
            self.password_entry.get(),
        )


class EndpointTrustAdminApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1280x760")
        self.minsize(1020, 640)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.base_url = DEFAULT_SERVER
        self.username = "admin"
        self.auth: tuple[str, str] | None = None
        self.session = requests.Session()
        self.connected = False
        self.request_in_progress = False
        self.closing = False
        self.refresh_job: str | None = None
        self.last_data: dict[str, Any] = {}

        self._configure_style()
        self._build_header()
        self._build_summary()
        self._build_tabs()
        self._build_status_bar()
        self._set_connected(False)
        self.after(250, self.connect)

    # ------------------------------ UI construction ---------------------------
    def _configure_style(self) -> None:
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("Subtitle.TLabel", foreground="#4b5563")
        style.configure("Summary.TLabel", font=("Segoe UI", 11, "bold"))
        style.configure("Treeview", rowheight=27)
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _build_header(self) -> None:
        header = ttk.Frame(self, padding=(12, 10, 12, 4))
        header.pack(fill="x")
        text = ttk.Frame(header)
        text.pack(side="left", fill="x", expand=True)
        ttk.Label(text, text="EndpointTrust PKI", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            text,
            text="Certificate-based corporate laptop enrolment, trust monitoring, and revocation",
            style="Subtitle.TLabel",
        ).pack(anchor="w")

        self.refresh_button = ttk.Button(header, text="Refresh now", command=lambda: self.refresh(show_errors=True))
        self.refresh_button.pack(side="right", padx=(6, 0))
        self.connect_button = ttk.Button(header, text="Connect…", command=self.connect)
        self.connect_button.pack(side="right")

    def _build_summary(self) -> None:
        frame = ttk.LabelFrame(self, text="Trust overview", padding=8)
        frame.pack(fill="x", padx=12, pady=(4, 6))
        self.summary_vars = {
            "pending": tk.StringVar(value="Pending: —"),
            "trusted": tk.StringVar(value="Trusted devices: —"),
            "sessions": tk.StringVar(value="Active sessions: —"),
            "denied": tk.StringVar(value="Recent denied events: —"),
        }
        for variable in self.summary_vars.values():
            ttk.Label(frame, textvariable=variable, style="Summary.TLabel").pack(side="left", padx=(8, 28))

    def _build_tabs(self) -> None:
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=12, pady=6)

        self.pending_tab = ttk.Frame(self.notebook, padding=6)
        self.devices_tab = ttk.Frame(self.notebook, padding=6)
        self.sessions_tab = ttk.Frame(self.notebook, padding=6)
        self.logs_tab = ttk.Frame(self.notebook, padding=6)
        self.notebook.add(self.pending_tab, text="Pending Enrolments")
        self.notebook.add(self.devices_tab, text="Devices & Certificates")
        self.notebook.add(self.sessions_tab, text="Verified Sessions")
        self.notebook.add(self.logs_tab, text="Security Audit Log")

        self.pending_tree = self._make_tree(self.pending_tab, PENDING_COLUMNS)
        actions = ttk.Frame(self.pending_tab)
        actions.pack(fill="x", pady=(7, 0))
        self.approve_button = ttk.Button(actions, text="Approve & issue certificate", command=self.approve_selected)
        self.approve_button.pack(side="left")
        self.reject_button = ttk.Button(actions, text="Reject request…", command=self.reject_selected)
        self.reject_button.pack(side="left", padx=6)
        ttk.Button(actions, text="View selected details", command=lambda: self.show_details(self.pending_tree, PENDING_COLUMNS)).pack(side="left")
        ttk.Label(
            actions,
            text="Verify the public-key fingerprint with the employee or asset record before approval.",
            style="Subtitle.TLabel",
        ).pack(side="left", padx=14)

        ttk.Label(
            self.devices_tab,
            text="Approved devices appear here immediately. 'Verification required' means the certificate is issued, but the laptop must still complete Step 4 in the Device Portal before HR access is active.",
            style="Subtitle.TLabel",
            wraplength=1180,
        ).pack(fill="x", pady=(0, 6))
        self.devices_tree = self._make_tree(self.devices_tab, DEVICE_COLUMNS)
        actions = ttk.Frame(self.devices_tab)
        actions.pack(fill="x", pady=(7, 0))
        self.revoke_button = ttk.Button(actions, text="Revoke selected certificate…", command=self.revoke_selected)
        self.revoke_button.pack(side="left")
        ttk.Button(actions, text="View selected details", command=lambda: self.show_details(self.devices_tree, DEVICE_COLUMNS)).pack(side="left", padx=6)

        ttk.Label(
            self.sessions_tab,
            text="A session is created only after the certificate's matching private key successfully signs the server challenge. Certificate approval alone never creates an active session.",
            style="Subtitle.TLabel",
            wraplength=1180,
        ).pack(fill="x", pady=(0, 6))
        self.sessions_tree = self._make_tree(self.sessions_tab, SESSION_COLUMNS)
        actions = ttk.Frame(self.sessions_tab)
        actions.pack(fill="x", pady=(7, 0))
        ttk.Button(actions, text="View selected details", command=lambda: self.show_details(self.sessions_tree, SESSION_COLUMNS)).pack(side="left")

        self.logs_tree = self._make_tree(self.logs_tab, LOG_COLUMNS)
        actions = ttk.Frame(self.logs_tab)
        actions.pack(fill="x", pady=(7, 0))
        ttk.Button(actions, text="View selected event", command=lambda: self.show_details(self.logs_tree, LOG_COLUMNS)).pack(side="left")

    def _build_status_bar(self) -> None:
        frame = ttk.Frame(self, padding=(12, 4, 12, 8))
        frame.pack(fill="x")
        self.status_var = tk.StringVar(value="Not connected")
        self.last_refresh_var = tk.StringVar(value="")
        ttk.Label(frame, textvariable=self.status_var).pack(side="left")
        ttk.Label(frame, textvariable=self.last_refresh_var, style="Subtitle.TLabel").pack(side="right")

    def _make_tree(self, parent: ttk.Frame, columns: tuple[str, ...]) -> ttk.Treeview:
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        widths = {
            "detail": 360, "public_key_fingerprint": 300, "event_time": 185,
            "requested_at": 185, "created_at": 185, "expires_at": 185,
            "certificate_serial": 260, "serial_number": 230, "access_status": 255,
        }
        for column in columns:
            tree.heading(column, text=column.replace("_", " ").title())
            tree.column(column, width=widths.get(column, 145), minwidth=90, anchor="w", stretch=True)
        vertical = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        horizontal = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        tree.bind("<Double-1>", lambda _event: self.show_details(tree, columns))
        return tree

    # ------------------------------ connection and requests -------------------
    def connect(self) -> None:
        dialog = LoginDialog(self, self.base_url, self.username)
        if not dialog.result:
            return
        server, username, password = dialog.result
        self._set_busy(True, "Connecting to EndpointTrust…")

        def worker() -> None:
            try:
                response = self.session.get(
                    f"{server}/api/admin/ping",
                    auth=(username, password),
                    timeout=REQUEST_TIMEOUT,
                )
                if response.status_code != 200:
                    raise RuntimeError(self._response_error(response))
                self.after(0, lambda: self._connection_succeeded(server, username, password))
            except (requests.RequestException, RuntimeError) as exc:
                self.after(0, lambda: self._connection_failed(str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    def _connection_succeeded(self, server: str, username: str, password: str) -> None:
        self.base_url = server
        self.username = username
        self.auth = (username, password)
        self.connected = True
        self._set_busy(False, f"Connected securely to {server} as {username}")
        self._set_connected(True)
        self.refresh(show_errors=True)
        self._schedule_refresh()

    def _connection_failed(self, error: str) -> None:
        self._set_busy(False, "Connection failed")
        self._set_connected(False)
        messagebox.showerror("Unable to connect", error, parent=self)

    def _schedule_refresh(self) -> None:
        if self.refresh_job:
            self.after_cancel(self.refresh_job)
        if not self.closing:
            self.refresh_job = self.after(REFRESH_MS, self._auto_refresh)

    def _auto_refresh(self) -> None:
        self.refresh_job = None
        if self.connected and not self.request_in_progress:
            self.refresh(show_errors=False)
        self._schedule_refresh()

    def refresh(self, show_errors: bool = False) -> None:
        if not self.connected or not self.auth or self.request_in_progress:
            return
        self._set_busy(True, "Refreshing trust information…")

        def worker() -> None:
            try:
                response = self.session.get(
                    f"{self.base_url}/api/admin/dashboard",
                    auth=self.auth,
                    timeout=REQUEST_TIMEOUT,
                )
                if response.status_code == 401:
                    raise PermissionError("The administrator session was rejected. Reconnect with valid credentials.")
                response.raise_for_status()
                data = response.json()
                self.after(0, lambda: self._refresh_succeeded(data))
            except (requests.RequestException, ValueError, PermissionError) as exc:
                self.after(0, lambda: self._refresh_failed(str(exc), show_errors))

        threading.Thread(target=worker, daemon=True).start()

    def _refresh_succeeded(self, data: dict[str, Any]) -> None:
        self.last_data = data
        self._render(data)
        self._set_busy(False, f"Connected to {self.base_url} as {self.username}")
        self.last_refresh_var.set("Dashboard updated")

    def _refresh_failed(self, error: str, show_errors: bool) -> None:
        self._set_busy(False, f"Refresh failed: {error}")
        if show_errors:
            messagebox.showerror("Refresh failed", error, parent=self)

    def _post_action(
        self,
        path: str,
        payload: dict[str, Any] | None,
        success_message: str,
        success_tab: ttk.Frame | None = None,
    ) -> None:
        if not self.connected or not self.auth:
            messagebox.showwarning("Not connected", "Connect to the EndpointTrust server first.", parent=self)
            return
        self._set_busy(True, "Submitting administrator action…")

        def worker() -> None:
            try:
                response = self.session.post(
                    f"{self.base_url}{path}",
                    auth=self.auth,
                    json=payload,
                    timeout=REQUEST_TIMEOUT,
                )
                if not response.ok:
                    raise RuntimeError(self._response_error(response))
                self.after(0, lambda: self._action_succeeded(success_message, success_tab))
            except (requests.RequestException, RuntimeError) as exc:
                self.after(0, lambda: self._action_failed(str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    def _action_succeeded(self, message: str, success_tab: ttk.Frame | None = None) -> None:
        self._set_busy(False, message)
        if success_tab is not None:
            self.notebook.select(success_tab)
        messagebox.showinfo("EndpointTrust", message, parent=self)
        self.refresh(show_errors=True)

    def _action_failed(self, error: str) -> None:
        self._set_busy(False, f"Action failed: {error}")
        messagebox.showerror("Action failed", error, parent=self)

    @staticmethod
    def _response_error(response: requests.Response) -> str:
        try:
            body = response.json()
            return str(body.get("message") or body.get("error") or body)
        except (ValueError, json.JSONDecodeError):
            text = response.text.strip()
            return text[:500] if text else f"Server returned HTTP {response.status_code}."

    # ------------------------------ data display -------------------------------
    def _render(self, data: dict[str, Any]) -> None:
        pending = [item for item in data.get("pending", []) if str(item.get("status", "")).lower() == "pending"]
        certificates = data.get("certificates", [])
        devices = data.get("devices", [])
        sessions = data.get("sessions", [])
        logs = data.get("logs", [])

        self._fill_tree(self.pending_tree, pending, PENDING_COLUMNS)

        # API returns newest certificates first. Keep the first certificate for
        # each device rather than accidentally overwriting it with an older one.
        latest_certificate: dict[str, dict[str, Any]] = {}
        for certificate in certificates:
            latest_certificate.setdefault(str(certificate.get("device_id", "")), certificate)

        active_session_devices = {str(item.get("device_id", "")) for item in sessions}
        device_rows: list[dict[str, Any]] = []
        for device in devices:
            device_id = str(device.get("device_id", ""))
            certificate = latest_certificate.get(device_id, {})
            row = dict(device)
            row["serial_number"] = certificate.get("serial_number", device.get("serial_number", ""))
            row["expires_at"] = certificate.get("expires_at", "")
            row["certificate_status"] = certificate.get("status", "not issued")
            row["access_status"] = device.get("access_status") or (
                "HR access active" if device_id in active_session_devices
                else "Certificate issued — verification required"
            )
            device_rows.append(row)
        self._fill_tree(self.devices_tree, device_rows, DEVICE_COLUMNS)
        self._fill_tree(self.sessions_tree, sessions, SESSION_COLUMNS)
        self._fill_tree(self.logs_tree, logs, LOG_COLUMNS)

        pending_count = sum(1 for item in pending if str(item.get("status", "")).lower() == "pending")
        trusted_count = sum(1 for item in device_rows if str(item.get("certificate_status", "")).lower() == "active")
        denied_count = sum(1 for item in logs[:50] if str(item.get("status", "")).upper() in {"DENIED", "FAILED"})
        self.summary_vars["pending"].set(f"Pending: {pending_count}")
        self.summary_vars["trusted"].set(f"Trusted devices: {trusted_count}")
        self.summary_vars["sessions"].set(f"Active sessions: {len(sessions)}")
        self.summary_vars["denied"].set(f"Recent denied events: {denied_count}")

    @staticmethod
    def _fill_tree(tree: ttk.Treeview, rows: list[dict[str, Any]], columns: tuple[str, ...]) -> None:
        tree.delete(*tree.get_children())
        for row in rows:
            values = ["" if row.get(column) is None else row.get(column, "") for column in columns]
            tree.insert("", "end", values=values)

    @staticmethod
    def _selected_values(tree: ttk.Treeview, columns: tuple[str, ...]) -> dict[str, Any] | None:
        selected = tree.selection()
        if not selected:
            return None
        values = tree.item(selected[0], "values")
        return dict(zip(columns, values))

    def show_details(self, tree: ttk.Treeview, columns: tuple[str, ...]) -> None:
        row = self._selected_values(tree, columns)
        if not row:
            messagebox.showinfo("No selection", "Select a row first.", parent=self)
            return
        window = tk.Toplevel(self)
        window.title("EndpointTrust record details")
        window.geometry("720x480")
        window.transient(self)
        text = tk.Text(window, wrap="word", padx=14, pady=14, font=("Consolas", 10))
        text.pack(fill="both", expand=True)
        for key, value in row.items():
            text.insert("end", f"{key.replace('_', ' ').title()}\n", "heading")
            text.insert("end", f"{value}\n\n")
        text.tag_configure("heading", font=("Segoe UI", 10, "bold"))
        text.configure(state="disabled")

    # ------------------------------ admin actions ------------------------------
    def approve_selected(self) -> None:
        row = self._selected_values(self.pending_tree, PENDING_COLUMNS)
        if not row:
            messagebox.showinfo("No selection", "Select a pending enrolment request first.", parent=self)
            return
        if str(row["status"]).lower() != "pending":
            messagebox.showinfo("Already reviewed", "Only pending requests can be approved.", parent=self)
            return
        prompt = (
            f"Approve {row['device_id']} ({row['device_name']}) and issue an X.509 device certificate?\n\n"
            f"Assigned user: {row['assigned_user']}\n"
            f"Department: {row['department']}\n"
            f"Public-key fingerprint:\n{row['public_key_fingerprint']}\n\n"
            "Approval should occur only after the device and fingerprint have been verified."
        )
        if messagebox.askyesno("Confirm certificate issuance", prompt, parent=self):
            self._post_action(
                f"/api/admin/enrollments/approve/{row['request_id']}",
                None,
                f"{row['device_id']} was approved, removed from Pending Enrolments, and moved to Devices & Certificates. The laptop must now fetch the certificate and complete Step 4 (private-key proof) before an active HR access session appears.",
                self.devices_tab,
            )

    def reject_selected(self) -> None:
        row = self._selected_values(self.pending_tree, PENDING_COLUMNS)
        if not row:
            messagebox.showinfo("No selection", "Select a pending enrolment request first.", parent=self)
            return
        if str(row["status"]).lower() != "pending":
            messagebox.showinfo("Already reviewed", "Only pending requests can be rejected.", parent=self)
            return
        reason = simpledialog.askstring(
            "Reject enrolment request",
            "Record the reason for rejection:",
            initialvalue="Device could not be verified against the corporate asset inventory",
            parent=self,
        )
        if reason is None:
            return
        reason = reason.strip()
        if not reason:
            messagebox.showwarning("Reason required", "Enter a meaningful rejection reason.", parent=self)
            return
        self._post_action(
            f"/api/admin/enrollments/reject/{row['request_id']}",
            {"reason": reason},
            f"Enrolment request for {row['device_id']} was rejected.",
        )

    def revoke_selected(self) -> None:
        row = self._selected_values(self.devices_tree, DEVICE_COLUMNS)
        if not row:
            messagebox.showinfo("No selection", "Select a registered device first.", parent=self)
            return
        certificate_status = str(row.get("certificate_status", "")).lower()
        if certificate_status in {"revoked", "expired", "not issued", "none", ""}:
            messagebox.showinfo(
                "Certificate not active",
                f"The selected device certificate is {certificate_status or 'not available'} and cannot be revoked again.",
                parent=self,
            )
            return
        reason = simpledialog.askstring(
            "Revoke device certificate",
            "Record the revocation reason:",
            initialvalue="Laptop is lost, retired, compromised, or no longer trusted",
            parent=self,
        )
        if reason is None:
            return
        reason = reason.strip()
        if not reason:
            messagebox.showwarning("Reason required", "Enter a meaningful revocation reason.", parent=self)
            return
        prompt = (
            f"Revoke the active certificate for {row['device_id']}?\n\n"
            "This immediately terminates active EndpointTrust sessions and blocks access to the protected HR portal."
        )
        if messagebox.askyesno("Confirm certificate revocation", prompt, parent=self):
            self._post_action(
                f"/api/admin/certificates/revoke/{row['device_id']}",
                {"reason": reason},
                f"Certificate for {row['device_id']} was revoked and active sessions were terminated.",
            )

    # ------------------------------ state helpers ------------------------------
    def _set_busy(self, busy: bool, status: str) -> None:
        self.request_in_progress = busy
        self.status_var.set(status)
        self.configure(cursor="watch" if busy else "")
        if self.connected:
            self.refresh_button.configure(state="disabled" if busy else "normal")

    def _set_connected(self, connected: bool) -> None:
        self.connected = connected
        state = "normal" if connected else "disabled"
        self.refresh_button.configure(state=state)
        self.approve_button.configure(state=state)
        self.reject_button.configure(state=state)
        self.revoke_button.configure(state=state)
        if not connected:
            self.auth = None

    def _on_close(self) -> None:
        self.closing = True
        if self.refresh_job:
            self.after_cancel(self.refresh_job)
            self.refresh_job = None
        self.session.close()
        self.destroy()


if __name__ == "__main__":
    EndpointTrustAdminApp().mainloop()
