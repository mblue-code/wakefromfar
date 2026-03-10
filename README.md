# WakeFromFar

WakeFromFar is a self-hosted Wake-on-LAN relay with mobile clients and an admin surface for managing devices, access, scheduled wakes, and operational checks.

The project is designed for private-network use. It is intended to run behind Tailscale, WireGuard, a trusted reverse proxy, or a similarly controlled network path. Open public internet exposure is not a supported default deployment model.

## Repository Layout

- `backend/` - FastAPI backend for auth, device access, Wake-on-LAN, scheduled wakes, discovery, shutdown requests, admin APIs, and the browser admin UI
- `android-client/` - Kotlin/Compose Android client
- `ios-client/` - SwiftUI iPhone client
- `docs/` - deployment, release, privacy, and operational docs
- `docs/archive/` - historical planning and sprint material kept for reference

## Core Capabilities

- User login and device access control through `device_memberships`
- Wake-on-LAN for assigned devices
- Power-state checks using TCP reachability
- Admin browser UI for users, devices, memberships, scheduled wakes, logs, diagnostics, and discovery
- Admin mobile activity feed and shutdown-request flow
- Optional browser-admin MFA
- Optional mobile app attestation rollout for Android and iPhone

## Quick Start

Requirements:

- Docker
- Docker Compose
- A private-network deployment path such as Tailscale, WireGuard, or a trusted reverse proxy

Create a local `.env` first:

```bash
cp .env.example .env
# then set at least APP_SECRET and ADMIN_PASS
```

Start the default stack:

```bash
docker compose up -d --build
```

Check health:

```bash
curl http://localhost:8080/health
```

The default Docker setup uses:

- named Docker volumes instead of bind mounts for `/data`
- `RATE_LIMIT_BACKEND=memory` for single-instance startup without Redis
- host networking because it is the most reliable path for real WoL/LAN traffic on Linux

## Compose Variants

Minimal Docker setup:

```bash
cp .env.example .env
docker compose -f docker-compose.simple.yml up -d --build
```

Testing stack with separate data volume:

```bash
cp .env.example .env
docker compose -f docker-compose.yml -f docker-compose.testing.yml up -d --build
```

Production topology reference:

```bash
cp .env.example .env
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

Production with shared Redis rate limits:

```bash
cp .env.example .env
docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.redis.yml up -d --build
```

Redis is optional. It is only needed when you want shared/distributed rate limits across multiple backend instances.

## Example: GHCR Image with Traefik

If you later publish a prebuilt image to GitHub Container Registry, the recommended Linux deployment pattern is still:

- run the backend with `network_mode: host`
- keep Traefik on its own network or host setup
- route Traefik to the host endpoint through a dynamic config file instead of Docker labels

Example compose file:

```yaml
services:
  wol-backend:
    image: ghcr.io/mblue-code/wakefromfar:latest
    container_name: wol-backend
    restart: unless-stopped
    network_mode: host
    env_file:
      - .env
    environment:
      DATA_DIR: /data
      DB_FILENAME: wol.db
    volumes:
      - wol-data-prod:/data
      - /etc/resolv.conf:/etc/resolv.conf:ro
      - /var/run/avahi-daemon/socket:/var/run/avahi-daemon/socket:ro
    healthcheck:
      test:
        [
          "CMD",
          "python",
          "-c",
          "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).read()",
        ]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s

volumes:
  wol-data-prod:
```

Example Traefik dynamic config:

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
        passHostHeader: true
        servers:
          - url: "http://172.18.0.1:8080"
```

This pattern keeps the backend on the Linux host network, which is the preferred path for reliable Wake-on-LAN and LAN-bound behavior. If you switch to a Traefik-label-only bridge-network model, treat that as a networking change and re-validate WoL behavior carefully.

## macOS and Docker Desktop

This repo uses `network_mode: host` for the backend. That is the native and preferred path on a normal Linux Docker Engine host.

On macOS, Docker Desktop runs Linux containers inside a VM. If `docker compose up -d --build` succeeds but `curl http://127.0.0.1:8080/health` still fails, check Docker Desktop first:

1. Sign in to Docker Desktop.
2. Open `Settings`.
3. Go to `Resources -> Network`.
4. Enable `Enable host networking`.
5. Apply the change and restart Docker Desktop.

If you only need local HTTP access to the API or admin UI on a Mac, a Mac-specific compose override with published ports is the simpler approach. For real Wake-on-LAN or LAN-behavior validation, Linux remains the more reliable environment.

## Security Model

WakeFromFar is private-network-first. Current defaults and supported guardrails include:

- `ENFORCE_IP_ALLOWLIST=true`
- default allowlists for Tailscale plus loopback
- `REQUIRE_TLS_FOR_AUTH=true`
- optional reverse-proxy trust via `TRUST_PROXY_HEADERS=true` and `TRUSTED_PROXY_CIDRS`
- separate admin-plane allowlisting via `ADMIN_IP_ALLOWLIST_CIDRS`
- browser-admin CSRF protection and same-origin enforcement
- optional browser-admin TOTP MFA
- optional mobile app attestation rollout via `APP_PROOF_MODE`

Public internet exposure is not made safe merely by enabling these controls. The intended model remains a controlled private network.

## Admin Bootstrap and Operations

The initial admin account is created from environment variables:

- `ADMIN_USER`
- `ADMIN_PASS`

The browser admin UI is available at:

- `http://localhost:8080/admin/ui/login` for local-only testing on the host
- your trusted HTTPS endpoint for normal remote use

The admin UI can be disabled with:

- `ADMIN_UI_ENABLED=false`

For repeatable local reset and reseed workflows, use:

- [docs/local-reset-workflow.md](docs/local-reset-workflow.md)

For a sanitized homelab reverse-proxy example, use:

- [docs/homelab-traefik-beta.md](docs/homelab-traefik-beta.md)

## API Surface

Common active endpoints:

- `POST /auth/login`
- `GET /me/devices`
- `PATCH /me/devices/{id}/preferences`
- `POST /me/devices/{id}/wake`
- `POST /me/devices/{id}/power-check`
- `POST /me/devices/{id}/shutdown-poke`
- `GET/POST/PATCH/DELETE /admin/users`
- `GET/POST/PATCH/DELETE /admin/devices`
- `GET/POST/PATCH/DELETE /admin/device-memberships`
- `GET/POST/PATCH/DELETE /admin/scheduled-wakes`
- `GET /admin/scheduled-wakes/runs`
- `GET /admin/wake-logs`
- `GET /admin/power-check-logs`
- `GET /admin/mobile/events`
- `GET /admin/shutdown-pokes`
- `POST /admin/shutdown-pokes/{id}/seen`
- `POST /admin/shutdown-pokes/{id}/resolve`
- `GET /admin/discovery/networks`
- `GET/POST /admin/discovery/runs`
- `GET /admin/discovery/runs/{id}`
- `GET /admin/discovery/runs/{id}/candidates`
- `POST /admin/discovery/runs/{id}/import-bulk`
- `POST /admin/discovery/candidates/{id}/validate-wake`
- `POST /admin/discovery/candidates/{id}/import`

Retired legacy paths such as `/hosts` and `/admin/hosts` are not part of the current API surface.

Example admin login:

```json
{
  "username": "admin",
  "password": "..."
}
```

Example device creation through the admin API:

```bash
TOKEN=$(curl -s http://localhost:8080/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"YOUR_ADMIN_PASS"}' | jq -r .token)

curl -s http://localhost:8080/admin/devices \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name":"NAS",
    "mac":"AA:BB:CC:DD:EE:FF",
    "broadcast":"192.168.178.255",
    "source_ip":"192.168.178.2",
    "interface":"eth0",
    "udp_port":9,
    "check_method":"tcp",
    "check_target":"192.168.178.50",
    "check_port":80
}'
```

Power-state support requires `check_method`, `check_target`, and `check_port`. Only `tcp` is currently supported.

## Mobile Clients

### Android

Open `android-client/` in Android Studio and run the app from there.

Current Android app behavior includes:

- username/password login
- encrypted local session storage
- grouped devices with favorites and scheduled-wake summaries
- wake actions and power-state presentation
- admin activity feed with shutdown-request actions
- optional Google Play Billing Pro unlock in official Play builds

Notes:

- legacy invite-claim UI/code paths still exist in the Android client, but invite onboarding is not part of the currently supported product surface
- debug/testing builds allow cleartext traffic; release builds set `usesCleartextTraffic=false`
- release signing is injected via environment variables:
  - `WFF_RELEASE_STORE_FILE`
  - `WFF_RELEASE_STORE_PASSWORD`
  - `WFF_RELEASE_KEY_ALIAS`
  - `WFF_RELEASE_KEY_PASSWORD`

### iPhone

The iPhone client uses the same `/me/devices` contract for favorites, grouping, and scheduled-wake summaries.

The current shipping model documented in this repo is:

- paid-upfront App Store distribution
- no iPhone free tier
- no iPhone in-app Pro unlock flow

See [docs/ios-release-readiness.md](docs/ios-release-readiness.md) for the iPhone release checklist.

## Development

Local backend development without Docker:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
APP_SECRET=dev-secret-please-change ADMIN_USER=admin ADMIN_PASS=admin123456 uvicorn app.main:app --reload --port 8080
```

SQLite backup:

```bash
python3 backend/scripts/backup_db.py
```

SQLite restore:

```bash
python3 backend/scripts/restore_db.py backups/<backup-file>.db --force
```

## Verification

Backend:

```bash
.venv-test/bin/python -m pytest -q \
  backend/tests/test_api_smoke.py \
  backend/tests/test_admin_ui.py \
  backend/tests/test_shutdown_pokes_api.py \
  backend/tests/test_scheduled_wakes_api.py \
  backend/tests/test_scheduled_wakes_runner.py
```

iPhone:

```bash
xcodebuild -project ios-client/WakeFromFar.xcodeproj \
  -scheme WakeFromFar \
  -destination 'platform=iOS Simulator,name=iPhone 17' \
  test CODE_SIGNING_ALLOWED=NO
```

Android:

```bash
export JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home'
gradle -p android-client :app:testDebugUnitTest
```

The Android repo currently does not include a checked-in `gradlew` wrapper.

## Project Docs

Primary docs:

- [docs/deployment-guide.md](docs/deployment-guide.md)
- [docs/release-gates.md](docs/release-gates.md)
- [docs/security-preproduction-checklist.md](docs/security-preproduction-checklist.md)
- [docs/local-reset-workflow.md](docs/local-reset-workflow.md)
- [docs/mobile-app-proof-architecture.md](docs/mobile-app-proof-architecture.md)
- [docs/privacy-policy.en.md](docs/privacy-policy.en.md)
- [docs/privacy-policy.de.md](docs/privacy-policy.de.md)

Community and policy docs:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [SUPPORT.md](SUPPORT.md)
- [DISTRIBUTION.md](DISTRIBUTION.md)
- [TRADEMARKS.md](TRADEMARKS.md)

## License

This repository is licensed under the MIT License. See [LICENSE](LICENSE).
