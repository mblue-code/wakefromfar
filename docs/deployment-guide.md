# Deployment Guide (With and Without Reverse Proxy)

This guide covers production-style deployment of the WoL backend in these modes:

1. Docker, no reverse proxy
2. Docker, behind reverse proxy
3. No Docker, no reverse proxy
4. No Docker, behind reverse proxy

It also includes multi-network (multiple NIC) Wake-on-LAN setup.

Current repo stance for the clean-slate refactor:

- local and pre-production backend environments are disposable
- schema changes should prefer DB rebuilds over preserving historical local SQLite states
- the canonical local reset flow lives in `/Users/max/projekte/wakefromfar/docs/local-reset-workflow.md`
- the production-style sections below describe runtime topology, not a requirement to preserve backward-compatible schema/data rollout
- Sprint-8 pre-production verification is documented in `/Users/max/projekte/wakefromfar/docs/security-preproduction-checklist.md`

Current supported product surface:

- admin device CRUD via `/admin/devices`
- admin device access management via `/admin/device-memberships`
- admin scheduled wake CRUD via `/admin/scheduled-wakes` plus `/admin/ui/scheduled-wakes`
- user/device app contract via `/me/devices`, including favorites, grouped presentation fields, permissions, and `scheduled_wake_summary`

## 1. Core Networking Model (Important)

When the server has multiple NICs/networks, each target device should use network-specific WoL settings:

- `broadcast`: broadcast address of the target LAN (for example `192.168.1.255` or `10.0.0.255`)
- `source_ip`: source IP bound on the sender side (IP of the NIC in that LAN)
- `interface` (optional): interface name such as `eth0`, `enp3s0`, `enx...`

Why `source_ip` and optional `interface`:

- Ensures packets leave through the correct NIC.
- Prevents wrong-route issues when policy routing or overlapping/private ranges exist.
- In containers, `source_ip` is usually the most reliable option.
- For non-root container processes, `source_ip` is the preferred setting because explicit interface binding can require additional network capabilities.

Device examples:

- Device in network A: `broadcast=192.168.1.255`, `source_ip=192.168.1.10`
- Device in network B: `broadcast=10.0.0.255`, `source_ip=10.0.0.2`

## 2. Prerequisites

- Linux host with access to target LANs
- Docker + Docker Compose (for Docker deployments)
- Tailscale or your preferred secure access path
- Open TCP access to backend port (`8080`) only from trusted networks/proxy

Recommended validation commands on host:

```bash
ip -4 addr show
ip route
```

## 3. Environment Variables

Create `.env` from `.env.example`:

```bash
cp .env.example .env
```

Minimum required to change:

- `APP_SECRET`
- `ADMIN_PASS`

Exposure guardrails:

- Bottom line for operators:
  - Reverse proxy is optional.
  - DNS is optional.
  - A trusted HTTPS endpoint is the normal deployment target for mobile clients.
  - If clients connect directly to an IP, the certificate must include that IP as a SAN and the devices must trust it.
  - Private-network HTTP remains an explicit exception path, not the recommended default for mobile app access.
- The backend now fails closed by default.
- `ENFORCE_IP_ALLOWLIST=true` is the code-level default.
- `IP_ALLOWLIST_CIDRS` must contain at least one valid CIDR when allowlisting is enabled.
- `REQUIRE_TLS_FOR_AUTH=true` is the code-level default.
- `ALLOW_INSECURE_PRIVATE_HTTP=true` only permits HTTP for auth/authenticated flows when the client IP is also inside `PRIVATE_HTTP_ALLOWED_CIDRS`.
- Default `PRIVATE_HTTP_ALLOWED_CIDRS`: `127.0.0.1/32`, `::1/128`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `fd7a:115c:a1e0::/48`.
- `ADMIN_UI_ENABLED=true` is the code-level default for the browser admin surface.
- `ADMIN_IP_ALLOWLIST_CIDRS` is a second, narrower fence for the admin plane only.
- Admin plane means `/admin/*` and `/admin/ui/*`.
- Default `ADMIN_IP_ALLOWLIST_CIDRS`: `127.0.0.1/32`, `::1/128`, `100.64.0.0/10`, `fd7a:115c:a1e0::/48`.
- Keep `ADMIN_IP_ALLOWLIST_CIDRS` narrower than `IP_ALLOWLIST_CIDRS` whenever possible.
- When `ADMIN_UI_ENABLED=false`, `/admin/ui/*` returns `404`, `/` no longer redirects into the admin UI, and `/admin/*` APIs remain available behind admin auth plus the admin allowlist.
- Browser-admin MFA rollout defaults to safe upgrade mode: `ADMIN_MFA_REQUIRED=false`.
- `ADMIN_MFA_ISSUER=WakeFromFar` controls the authenticator-app issuer/label.
- `ADMIN_MFA_PENDING_EXPIRES_SECONDS=300` limits pending login/setup cookies.
- `ADMIN_MFA_VERIFY_RATE_LIMIT_PER_MINUTE=10` limits TOTP verification attempts.
- Sprint 6 architecture decision for mobile "only our apps" proof is documented in `docs/mobile-app-proof-architecture.md`.
- Sprint 7 app-proof is now implemented and staged behind `APP_PROOF_MODE`.
- `APP_PROOF_MODE=disabled|report_only|soft_enforce|enforce_login` controls whether mobile bearer-session issuance is only observed, softly enforced, or hard blocked without proof.
- `APP_PROOF_CHALLENGE_TTL_SECONDS=300` controls one-time challenge lifetime.
- `APP_PROOF_DEGRADED_GRACE_SECONDS=86400` defines the bounded soft-enforce grace window for previously trusted installations.
- `APP_PROOF_REQUIRE_ON_ADMIN_BEARER_LOGIN=false` is the Sprint-7 default; browser-admin MFA remains unchanged and admin bearer-token app-proof rollout is deferred by default one step behind mobile user rollout.
- Android verification needs `APP_PROOF_ANDROID_PACKAGE_NAME`, `APP_PROOF_ANDROID_ALLOWED_CERT_SHA256`, `APP_PROOF_ANDROID_CLOUD_PROJECT_NUMBER`, and either `APP_PROOF_ANDROID_SERVICE_ACCOUNT_JSON` or `APP_PROOF_ANDROID_SERVICE_ACCOUNT_JSON_PATH`.
- iOS verification needs `APP_PROOF_IOS_TEAM_ID` and `APP_PROOF_IOS_BUNDLE_ID`; `APP_PROOF_IOS_ALLOW_DEVICECHECK_REPORT_ONLY=true` only documents that DeviceCheck may be logged later, not enforced.
- When `ADMIN_MFA_REQUIRED=false`, non-enrolled browser admins may still log in with password-only, but already enrolled browser admins are still challenged for TOTP.
- When `ADMIN_MFA_REQUIRED=true`, non-enrolled browser admins are restricted to MFA setup until TOTP is enabled; they do not receive a full `admin_session` first.
- Public HTTP auth is blocked even if you intentionally disable the broader IP allowlist for testing.
- If you intentionally want an unsafe local/testing/manual setup, set `ENFORCE_IP_ALLOWLIST=false` and `ALLOW_UNSAFE_PUBLIC_EXPOSURE=true`.
- `ALLOW_UNSAFE_PUBLIC_EXPOSURE=true` is an explicit escape hatch only; it is unsafe and not recommended.
- Product recommendation is unchanged: private-network-only deployment remains the intended model.

Proxy-related variables:

- `TRUST_PROXY_HEADERS=false` if clients connect directly to backend
- `TRUST_PROXY_HEADERS=true` if backend sits behind reverse proxy
- `TRUSTED_PROXY_CIDRS` must contain only proxy source networks

Startup validation notes:

- `ENFORCE_IP_ALLOWLIST=false` without `ALLOW_UNSAFE_PUBLIC_EXPOSURE=true` will fail startup.
- Empty `IP_ALLOWLIST_CIDRS` values will fail startup.
- Malformed `IP_ALLOWLIST_CIDRS` entries will fail startup instead of being ignored.
- Empty `ADMIN_IP_ALLOWLIST_CIDRS` values will fail startup unless `ALLOW_UNSAFE_PUBLIC_EXPOSURE=true` is explicitly set.
- Malformed `ADMIN_IP_ALLOWLIST_CIDRS` entries will fail startup instead of being ignored, unless `ALLOW_UNSAFE_PUBLIC_EXPOSURE=true` is explicitly set for an acknowledged unsafe setup.
- Malformed `PRIVATE_HTTP_ALLOWED_CIDRS` entries will fail startup instead of silently widening or disabling the private HTTP exception.

Auth transport policy:

- `POST /auth/login` requires HTTPS unless `REQUIRE_TLS_FOR_AUTH=false`, or the request is plain HTTP from an allowed private CIDR and `ALLOW_INSECURE_PRIVATE_HTTP=true`.
- Bearer-authenticated `/me/*` and `/admin/*` requests follow the same rule.
- Admin UI session login and session-backed pages/actions follow the same rule.
- `/admin/*` and `/admin/ui/*` also require the client IP to match `ADMIN_IP_ALLOWLIST_CIDRS`, using the same trusted-proxy client-IP resolution as the rest of the backend.
- Browser-admin POSTs under `/admin/ui/*` also require a valid server-issued CSRF token, including `/admin/ui/login`.
- Browser-admin POSTs under `/admin/ui/*` also require same-origin browser metadata: `Origin` must match the effective admin origin, and only when `Origin` is absent will a strict same-origin `Referer` be accepted.
- Pending MFA verify/setup routes inherit the same admin-plane controls: admin allowlist, HTTPS/auth transport policy, CSRF, and same-origin checks.
- Sprint 5 intentionally hardens the browser admin UI first. `POST /auth/login` for admin bearer-token issuance remains password-only in this release and still needs a later MFA design.
- These browser checks are defense-in-depth on top of `ADMIN_IP_ALLOWLIST_CIDRS`, HTTPS/auth transport policy, and the existing `HttpOnly` + `SameSite=Strict` admin cookies.
- Rejected admin-plane requests return `403` with `Admin access is not allowed from this network`.
- Rejected requests return `403` with an explicit HTTPS-required message.
- This transport policy does not make public internet exposure a supported deployment model.

App-proof rollout notes:

- Enforcement point in Sprint 7 is mobile bearer-token login/session issuance, not every authenticated request.
- Official mobile clients first request `/auth/app-proof/challenge`, then submit platform proof, then call `/auth/login` with `installation_id` plus a short-lived `proof_ticket`.
- Successful mobile sessions are bound to installation records and later requests must present `X-WFF-Installation-ID` that matches the JWT installation claims.
- `soft_enforce` allows only bounded degraded login for previously trusted installations; first-seen or revoked installations are still denied.
- `enforce_login` blocks new mobile bearer sessions without valid proof.
- Revocation is available through `GET /admin/app-installations` and `POST /admin/app-installations/{installation_id}/revoke`.
- This does not yet implement all-request proof-of-possession, mTLS, or DeviceCheck-as-enforcement.

Operator diagnostics and readiness:

- `GET /admin/security-status` is the primary Sprint-8 operator snapshot:
  - hardening mode summary
  - risky-but-allowed warnings
  - explicit deferred items
  - app-proof installation counts by platform/state
  - recent app-proof failure categories
- `GET /admin/metrics` now includes both runtime counters and the same security-status snapshot.
- `GET /admin/app-installations?platform=android|ios&status=pending|trusted|report_only|revoked&limit=100` is the read-only installation inspection API.
- Use these endpoints during fresh deployment and beta verification. Do not build migration plans around old installations; there are no production users/systems yet.

Examples:

- Proxy on same host: `TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128`
- Proxy in Docker bridge network: use that bridge subnet, for example `172.18.0.0/16`
- Dedicated proxy VLAN: for example `192.168.50.0/24`

## 4. Docker Deployment (No Reverse Proxy)

This repository uses `network_mode: host` for the backend, which is ideal for WoL broadcast traffic.
The backend image itself runs as the non-root user `appuser`; host networking is used for LAN reachability, not because the process runs as root.

Important for operators:

- "No reverse proxy" does not mean "no TLS".
- For standard phone/app usage, expose the backend through a trusted HTTPS endpoint even if the backend is reached directly on its own port.
- If you expose the backend directly by IP, the certificate must cover that IP address as a SAN and be trusted by the client devices.
- `ALLOW_INSECURE_PRIVATE_HTTP=true` preserves a private-network HTTP exception, but that is an explicit compatibility/controlled-lab path rather than the recommended mobile deployment model.

Steps:

```bash
cp .env.example .env
# edit .env:
# ENFORCE_IP_ALLOWLIST=true
# IP_ALLOWLIST_CIDRS=100.64.0.0/10,fd7a:115c:a1e0::/48,127.0.0.1/32,::1/128
# REQUIRE_TLS_FOR_AUTH=true
# ALLOW_INSECURE_PRIVATE_HTTP=true
# PRIVATE_HTTP_ALLOWED_CIDRS=127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,fd7a:115c:a1e0::/48
# ADMIN_UI_ENABLED=true
# ADMIN_IP_ALLOWLIST_CIDRS=127.0.0.1/32,::1/128,100.64.0.0/10,fd7a:115c:a1e0::/48
# ADMIN_MFA_REQUIRED=false
# ADMIN_MFA_ISSUER=WakeFromFar
# ADMIN_MFA_PENDING_EXPIRES_SECONDS=300
# ADMIN_MFA_VERIFY_RATE_LIMIT_PER_MINUTE=10
# TRUST_PROXY_HEADERS=false
docker compose up -d --build
```

Minimal compose variant:

```bash
cp .env.example .env
# edit .env:
# ENFORCE_IP_ALLOWLIST=true
# IP_ALLOWLIST_CIDRS=100.64.0.0/10,fd7a:115c:a1e0::/48,127.0.0.1/32,::1/128
# REQUIRE_TLS_FOR_AUTH=true
# ALLOW_INSECURE_PRIVATE_HTTP=true
# PRIVATE_HTTP_ALLOWED_CIDRS=127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,fd7a:115c:a1e0::/48
# ADMIN_UI_ENABLED=true
# ADMIN_IP_ALLOWLIST_CIDRS=127.0.0.1/32,::1/128,100.64.0.0/10,fd7a:115c:a1e0::/48
# ADMIN_MFA_REQUIRED=false
# ADMIN_MFA_ISSUER=WakeFromFar
# ADMIN_MFA_PENDING_EXPIRES_SECONDS=300
# ADMIN_MFA_VERIFY_RATE_LIMIT_PER_MINUTE=10
# TRUST_PROXY_HEADERS=false
docker compose -f docker-compose.simple.yml up -d --build
```

For a dedicated testing environment (separate DB volume), use:

```bash
docker compose -f docker-compose.yml -f docker-compose.testing.yml up -d --build
```

For ongoing clean-slate refactor work, treat this testing stack as the default local environment and reset it with `down -v` when schema-changing work lands.

Check:

```bash
curl http://127.0.0.1:8080/health
```

Add devices (admin API example):

```bash
TOKEN=$(curl -fsS http://127.0.0.1:8080/auth/login \
  -H 'content-type: application/json' \
  -d "{\"username\":\"${ADMIN_USER:-admin}\",\"password\":\"${ADMIN_PASS}\"}" | jq -r '.token')

curl -fsS http://127.0.0.1:8080/admin/devices \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name":"NAS-A",
    "display_name":"NAS A",
    "mac":"AA:BB:CC:DD:EE:01",
    "broadcast":"192.168.1.255",
    "source_ip":"192.168.1.10",
    "interface":"eth0",
    "check_method":"tcp",
    "check_target":"192.168.1.50",
    "check_port":80
  }'

curl -fsS http://127.0.0.1:8080/admin/devices \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name":"PC-B",
    "display_name":"PC B",
    "mac":"AA:BB:CC:DD:EE:02",
    "broadcast":"10.0.0.255",
    "source_ip":"10.0.0.2",
    "interface":"enx001122334455",
    "check_method":"tcp",
    "check_target":"10.0.0.20",
    "check_port":22
  }'
```

Important:

- `check_target` + `check_port` are required for reliable power state in app/admin UI.
- If missing, `/me/devices` can only report `unknown`, and logs will show `missing_check_target` or `missing_check_port`.
- Prefer `source_ip` over `interface` unless you have confirmed the container runtime has the capability needed for interface binding.

### 4.1 Storage defaults

The current compose files use named Docker volumes for `/data`:

- `wol-data`
- `wol-data-simple`
- `wol-data-testing`
- `wol-data-prod`

This keeps the default deployment simpler and avoids host-path ownership drift on rebuilds.
For local refactor work, prefer rebuilding the testing volume instead of carrying old DB state forward.

## 5. Docker Deployment Behind Reverse Proxy

### 5.1 Backend settings

In `.env`:

```env
ENFORCE_IP_ALLOWLIST=true
IP_ALLOWLIST_CIDRS=<trusted-client-networks>
ADMIN_UI_ENABLED=true
ADMIN_IP_ALLOWLIST_CIDRS=<narrower-admin-networks>
ADMIN_MFA_REQUIRED=false
ADMIN_MFA_ISSUER=WakeFromFar
TRUST_PROXY_HEADERS=true
TRUSTED_PROXY_CIDRS=<your-proxy-network>
REQUIRE_TLS_FOR_AUTH=true
ALLOW_INSECURE_PRIVATE_HTTP=false
```

Important:

- Do not disable the allowlist for normal deployments.
- Keep `ADMIN_IP_ALLOWLIST_CIDRS` narrower than the broader app/client allowlist.
- If you do not need the browser UI on a server, set `ADMIN_UI_ENABLED=false` rather than leaving `/admin/ui/*` exposed.
- Enable `ADMIN_MFA_REQUIRED=true` only after at least one browser admin has enrolled TOTP, or be prepared to complete enrollment immediately on next login.
- Recovery is shell-based by design for self-hosted installs: `python -m app.cli admin-disable-mfa --username <adminname>`.
- If you publish the admin UI behind a reverse proxy, preserve the original scheme and host so same-origin `Origin` checks keep matching the browser-visible admin URL.
- For internet-facing reverse proxies, keep `ALLOW_INSECURE_PRIVATE_HTTP=false` so login and authenticated traffic require end-user HTTPS.
- Admin API bearer-token issuance via `POST /auth/login` remains outside the Sprint-5 MFA enforcement scope, so protect that path with the same private-network-first stance and admin-plane network fencing.
- If you bypass allowlisting for local/manual testing, you must also set `ALLOW_UNSAFE_PUBLIC_EXPOSURE=true`, and that mode remains unsupported for public exposure.
- Never set overly broad proxy CIDRs.
- Only trust IP ranges where your reverse proxy actually runs.

### 5.2 Proxy header requirements

Proxy must forward:

- `X-Forwarded-For`
- `X-Real-IP`
- `X-Forwarded-Proto`
- `Host`

The backend only trusts `X-Forwarded-Proto=https` when both conditions are true:

- `TRUST_PROXY_HEADERS=true`
- the direct peer is inside `TRUSTED_PROXY_CIDRS`

### 5.3 NGINX example

```nginx
server {
    listen 443 ssl http2;
    server_name wol.example.com;

    # tls config...

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_read_timeout 60s;
    }
}
```

### 5.4 Start

```bash
docker compose up -d --build
sudo nginx -t && sudo systemctl reload nginx
```

For production with dedicated DB volume, use:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

For global rate limits across multiple backend instances, add shared Redis:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.redis.yml up -d --build
```

Note:

- Redis is optional unless you need shared/distributed rate limits.
- A published prebuilt container image would make deployment even closer to UpSnap-style "pull and run", but this repo currently builds from source.

Validation:

- `https://wol.example.com/health` returns `{"ok":"true"}`
- Admin UI login works
- IP allowlist behaves correctly for real client IPs (not proxy IP)

### 5.5 Traefik (file provider) with host-network backend

If backend runs with `network_mode: host`, route Traefik to the host endpoint instead of container labels.

Example dynamic config file:

```yaml
http:
  routers:
    wakefromfar:
      rule: "Host(`wakefromfar.example.com`)"
      service: wakefromfar
      entryPoints:
        - websecure
      tls:
        certResolver: cloudflare
  services:
    wakefromfar:
      loadBalancer:
        servers:
          - url: "http://172.18.0.1:8080"
```

Then set:

- `TRUST_PROXY_HEADERS=true`
- `TRUSTED_PROXY_CIDRS` to the Traefik network subnet(s), for example `172.18.0.0/16`

## 6. Non-Docker Deployment (No Reverse Proxy)

### 6.1 App setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 6.2 Runtime env

```bash
export APP_SECRET='replace-me-with-a-long-random-secret'
export ADMIN_USER='admin'
export ADMIN_PASS='replace-me-with-a-strong-password'
export DATA_DIR='/opt/wakefromfar/data'
export DB_FILENAME='wol.db'
export ENFORCE_IP_ALLOWLIST='true'
export IP_ALLOWLIST_CIDRS='100.64.0.0/10,fd7a:115c:a1e0::/48,127.0.0.1/32,::1/128'
export ADMIN_UI_ENABLED='true'
export ADMIN_IP_ALLOWLIST_CIDRS='127.0.0.1/32,::1/128,100.64.0.0/10,fd7a:115c:a1e0::/48'
export TRUST_PROXY_HEADERS='false'
```

Important:

- For direct non-proxy mobile access, plan for a trusted HTTPS endpoint on the backend itself.
- Reverse proxy and DNS are optional, but a certificate-backed HTTPS endpoint is still the practical requirement for normal mobile use.
- Plain HTTP on a private IP remains an explicit operator exception path, not the recommended default.

### 6.3 Start server

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

## 7. Non-Docker Deployment Behind Reverse Proxy

Use same backend setup as Section 6, but set:

```bash
export ENFORCE_IP_ALLOWLIST='true'
export IP_ALLOWLIST_CIDRS='<trusted-client-networks>'
export ADMIN_UI_ENABLED='true'
export ADMIN_IP_ALLOWLIST_CIDRS='<narrower-admin-networks>'
export TRUST_PROXY_HEADERS='true'
export TRUSTED_PROXY_CIDRS='127.0.0.1/32,::1/128'
```

Put NGINX/Caddy/Traefik in front of `127.0.0.1:8080` and forward headers.

## 8. Optional systemd service (Non-Docker)

Example service file `/etc/systemd/system/wakefromfar.service`:

```ini
[Unit]
Description=WakeFromFar Backend
After=network-online.target
Wants=network-online.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/wakefromfar/backend
EnvironmentFile=/opt/wakefromfar/.env
ExecStart=/opt/wakefromfar/backend/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8080
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Activate:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wakefromfar
sudo systemctl status wakefromfar
```

## 9. Device Provisioning Checklist (Multi-NIC)

For each device:

1. Determine target LAN and broadcast IP.
2. Determine sender NIC IP in that LAN (`source_ip`).
3. Optionally set interface name for additional routing control.
4. Configure power check fields — **required for power state to work**:
   - `check_method`: must be `tcp` (ICMP is not implemented)
   - `check_target`: IP or hostname of the device (usually the same as its LAN IP)
   - `check_port`: any TCP port that is open and responsive when the device is on (e.g. `80`, `443`, `445`, `22`)
   - If either `check_target` or `check_port` is left blank, power state will always show `unknown`
   - To find open ports: `nmap -p 22,80,443,445 <device-ip>` or check the device's admin UI

If WoL fails:

- Verify sender host can reach the broadcast domain.
- Confirm `broadcast` is correct for that subnet.
- Confirm `source_ip` belongs to the intended NIC.
- If using `interface` binding inside container, ensure required permissions; prefer `source_ip`.

## 10. Reverse Proxy Security Checklist

- Backend not exposed publicly without auth and allowlist.
- `TRUST_PROXY_HEADERS=true` only when proxy is in front.
- `TRUSTED_PROXY_CIDRS` only includes proxy ranges.
- TLS terminated at proxy with valid certs.
- Access logs enabled on proxy for audit/debugging.

## 11. Smoke Test Flow

1. `GET /health`
2. Admin login
3. Create one device per network (A and B)
4. Create a device membership for the test user
5. Optionally create one scheduled wake in the admin UI or via `/admin/scheduled-wakes`
6. Trigger wake for both devices
7. Check `/admin/wake-logs` and verify `sent_to` network targets
8. Run power checks and verify non-`unknown` state:
   - `POST /me/devices/{id}/power-check`
   - if result is `unknown` with `missing_check_target`/`missing_check_port`, set `check_target` + `check_port` on the device

## 12. Backup / Restore

Before upgrades, create a DB backup:

```bash
python3 backend/scripts/backup_db.py
```

Restore from backup:

```bash
python3 backend/scripts/restore_db.py backups/<backup-file>.db --force
```

## 13. Horizontal Scaling Note

- Default `RATE_LIMIT_BACKEND=redis` enables durable/shared limits.
- `RATE_LIMIT_BACKEND=memory` remains available for simple single-instance setups but is process-local.

## 14. Common Failure Patterns

- Docker daemon not running: start Docker engine/Desktop first.
- Wrong proxy CIDR: backend ignores forwarded headers and sees proxy source IP only.
- Wrong broadcast: packet sent successfully but target never wakes.
- Missing check target/port: if `check_target` or `check_port` is not set, power state always returns `unknown` (`missing_check_target` / `missing_check_port`) — this is a configuration gap, not a connectivity failure. Set both fields on the device.
- Non-host Docker network for backend: broadcast can be dropped or routed incorrectly.
