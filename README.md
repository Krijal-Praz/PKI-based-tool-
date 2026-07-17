# EndpointTrust PKI v7

**Certificate-Based Corporate Laptop Access Verification System**

EndpointTrust PKI protects a Docker-hosted internal HR portal behind an Nginx access gateway. A laptop is allowed to reach the HR portal only after it:

1. generates its own RSA private/public key pair in the browser;
2. submits a PKCS#10 Certificate Signing Request (CSR);
3. is approved by an IT administrator through the Tkinter admin console;
4. fetches the X.509 certificate issued by the EndpointTrust CA;
5. proves possession of the matching private key by signing a fresh server challenge; and
6. receives an active trusted-device session cookie checked by Nginx before every request to `/internal/`.

The private key is generated and kept in the device browser. It is never sent to the EndpointTrust server.


## AES-256-GCM Data Protection

EndpointTrust encrypts sensitive device data at rest using AES-256-GCM. Assigned user names, asset serial numbers, hostnames, MAC addresses, audit details, source IP addresses, session-token ciphertext, and CSR files are protected before storage. Session tokens are located using a SHA-256 hash, while the decryptable token copy remains AES-encrypted. Encrypted CSRs and audit records are stored in separate secure folders.

The application creates a local demo key in `endpointtrust/secure_storage/master.key`. For deployment, provide a 32-byte URL-safe base64 key through `ENDPOINTTRUST_AES_KEY` and keep it outside Git.

## Main Components

- **Device Portal** — browser-based laptop enrolment and private-key proof.
- **Tkinter IT Administration Console** — approve/reject enrolments, view devices and certificates, monitor active sessions, revoke certificates, and review audit logs.
- **EndpointTrust PKI Server** — local CA, CSR signing, certificate lifecycle, challenge-response verification, sessions, and audit logging.
- **Nginx Access Gateway** — blocks the HR portal unless the browser has a valid EndpointTrust session.
- **Internal HR Portal** — isolated Docker service reachable only through the Nginx gateway.
- **SQLite Database** — stores enrolments, devices, certificates, revocations, challenges, sessions, and audit events.

## Important Trust States

EndpointTrust deliberately separates certificate approval from active access:

```text
Pending enrolment
        ↓ IT approves
Certificate issued — verification required
        ↓ laptop signs fresh challenge with matching private key
HR access active
        ↓ certificate revoked / session expires
HR access blocked
```

An approved certificate **does not** create an active session by itself. This is intentional: the laptop must still prove that it owns the corresponding private key.

## Kali Linux — Clean Start

From the extracted project folder:

```bash
chmod +x scripts/*.sh
./scripts/clean_start.sh
```

The script removes old EndpointTrust containers, starts v5 with fresh project-specific volumes, waits for the services, and prints the URLs.

Open:

```text
Device Portal: http://localhost:8080/endpointtrust/device-portal
Protected HR:  http://localhost:8080/internal/
```

Before device verification, the HR URL must show **Access denied by EndpointTrust PKI**.

## Run the Tkinter Admin Console

On Kali, install Tkinter once:

```bash
sudo apt update
sudo apt install -y python3-tk python3-venv
```

Then launch the admin console:

```bash
./scripts/run_admin.sh
```

Connection details:

```text
Server URL: http://localhost:8080/endpointtrust
Username:   admin
Password:   EndpointTrust@123
```

## Correct End-to-End Workflow

### 1. Submit enrolment from the Device Portal

Open:

```text
http://localhost:8080/endpointtrust/device-portal
```

Enter the Device ID, device name, assigned user, and department, then click:

```text
Generate keypair & Enrol
```

The browser creates the private key and CSR locally. Only the CSR and device metadata are sent to the server.

### 2. Approve from Tkinter

In the **Pending Enrolments** tab:

1. select the request;
2. verify the device information and CSR fingerprint;
3. click **Approve & issue certificate**.

After approval, the request is removed from Pending and the admin console automatically opens **Devices & Certificates**.

The device will show:

```text
Certificate status: Active
Access status: Certificate issued — verification required
```

### 3. Fetch and validate the certificate

Return to the Device Portal and click:

```text
Check enrolment status
Fetch my certificate
```

The portal locally checks that the fetched certificate matches the private key stored in that browser. A mismatched certificate is rejected before authentication.

### 4. Prove private-key ownership and unlock HR

Click:

```text
Verify & connect to HR system
```

The server sends a fresh 60-second, single-use challenge. The browser signs it with the private key. After successful verification:

- the server creates the active device session;
- the API sets the trusted-device cookie directly;
- the Device Portal verifies that the cookie is active;
- the browser redirects to `/internal/`;
- the device appears immediately in the Tkinter **Verified Sessions** tab; and
- the Devices tab changes to **HR access active**.

### 5. Revoke and block the device

In **Devices & Certificates**, select the device and click:

```text
Revoke selected certificate
```

Revocation immediately:

- changes the certificate status to revoked;
- terminates active sessions; and
- blocks the HR portal on the next request.

## Fixes in v5

- Approved requests are returned only in Pending while their status is actually `pending`.
- Approval immediately moves the device to **Devices & Certificates**.
- The Devices table has a separate **Access Status** column.
- Certificate approval is clearly separated from active private-key verification.
- Successful `/api/auth/verify` responses now set the trusted-device cookie directly.
- The portal confirms the cookie by calling `/api/auth/session-status` before redirecting to HR.
- Nginx and Flask now use the same client-IP source for session binding.
- Nginx forwards the browser cookie consistently to the internal auth subrequest.
- Re-enrolment with a new CSR is supported if browser key storage was lost or replaced.
- Approving a re-enrolment issues a new certificate, supersedes the old certificate, and terminates old sessions.
- The portal checks that the certificate public key matches the stored private key before Step 4.
- v5 uses a new browser local-storage namespace to avoid carrying broken v4 key state into a fresh deployment.
- v5 uses a dedicated Docker Compose project name so old volumes are not silently reused.
- Active-session counts exclude expired sessions.
- Tkinter automatically switches to the Devices tab after approval and explains the next required device step.

## Stop

```bash
./scripts/stop_endpointtrust.sh
```

To remove v5 containers and all v5 demo data manually:

```bash
docker compose down -v --remove-orphans
```

## Automated Tests

Create a development environment and run:

```bash
python3 -m venv .test-venv
source .test-venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```

The tests cover:

- pending request → approval → device movement;
- certificate issuance;
- successful challenge-response verification;
- direct session-cookie creation;
- active-session visibility in the admin API;
- Nginx authorisation endpoint acceptance;
- certificate revocation and immediate blocking;
- wrong-private-key denial; and
- re-enrolment with old-certificate supersession.

## Coursework / Production Note

This is a local coursework prototype. Before real deployment, use HTTPS/TLS, replace the default administrator password, protect the CA private key with a dedicated keystore/HSM or TPM-backed design, and replace browser local storage with stronger platform-backed private-key storage where available.

## Licence

MIT License. See [LICENSE](LICENSE).
