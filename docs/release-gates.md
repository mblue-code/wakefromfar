# Release Gates (Testing And Production)

This checklist is the final gate before promoting builds.

## Gate 1: Before Testing

1. Backend tests pass:
   ```bash
   cd backend
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements-dev.txt
   pytest -q
   ```
2. Android CI jobs pass (`testDebugUnitTest`, `lintDebug`, `assembleRelease`).
3. Android admin activity feed prerequisites are present:
   - Admin login on Android opens `Devices` + `Activity` tabs
   - `GET /admin/mobile/events` succeeds for admin session
   - Android device card allows `Request shutdown` with optional note
4. Environment file is prepared from `.env.example` and secrets are replaced:
   - `APP_SECRET`
   - `ADMIN_PASS`
   - Shutdown poke rate-limit knobs are set for the environment profile:
     - `SHUTDOWN_POKE_REQUEST_RATE_LIMIT_PER_MINUTE`
     - `SHUTDOWN_POKE_SEEN_RATE_LIMIT_PER_MINUTE`
     - `SHUTDOWN_POKE_RESOLVE_RATE_LIMIT_PER_MINUTE`
5. Compose target is explicit:
   - testing: `docker compose -f docker-compose.yml -f docker-compose.testing.yml up -d --build`
6. Smoke test succeeds:
   - `/health`
   - admin login
   - invite claim
   - `/me/devices`
   - wake path (`already_on` and `sent`)
   - shutdown poke path:
     - `POST /me/devices/{id}/shutdown-poke` returns 201 for assigned user/admin
     - `GET /admin/shutdown-pokes?status=open` returns 200 for admin
     - `POST /admin/shutdown-pokes/{id}/seen` then `.../resolve` return 200 for admin
     - poke endpoint limits return 429 when limit is exceeded (request/seen/resolve)
     - admin shutdown-poke endpoints return 403 for non-admin token
   - admin mobile activity feed:
     - `GET /admin/mobile/events?type=wake&limit=20` returns 200 for admin
     - `GET /admin/mobile/events?type=poke&limit=20` returns 200 for admin
     - pagination works with `cursor=<last_id>` and returns older ids only
     - same endpoint returns 403 for non-admin user token
   - metrics counters in `/admin/metrics` increase for:
     - `activity_events.created`
     - `activity_feed.poll_requests`
     - `activity_feed.poll_errors` (trigger at least one forced failure in staging)
     - `shutdown_pokes.open`
     - `shutdown_pokes.resolved`

## Gate 2: Before Production

1. Deploy with prod overlay:
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
   ```
2. Security config confirmed:
   - `TOKEN_EXPIRES_SECONDS=28800`
   - `ENFORCE_IP_ALLOWLIST=true`
   - `TRUST_PROXY_HEADERS=true` only when behind proxy
   - `TRUSTED_PROXY_CIDRS` contains only proxy networks
   - For multiple backend instances: `RATE_LIMIT_BACKEND=redis` and shared `RATE_LIMIT_REDIS_URL`
3. Backup created before rollout:
   ```bash
   python3 backend/scripts/backup_db.py
   ```
4. Admin observability endpoints verified:
   - `/admin/audit-logs`
   - `/admin/metrics`
   - `/admin/diagnostics/devices`
   - `/admin/pilot-metrics`
   - `/admin/metrics` includes Sprint-4 counters (`activity_events.created`, `activity_feed.*`, `shutdown_pokes.*`)
5. Android release artifact is signed using release keystore env vars:
   - `WFF_RELEASE_STORE_FILE`
   - `WFF_RELEASE_STORE_PASSWORD`
   - `WFF_RELEASE_KEY_ALIAS`
   - `WFF_RELEASE_KEY_PASSWORD`
6. Rollback plan is ready:
   - previous image tag available
   - latest DB backup path recorded

## Note

- `RATE_LIMIT_BACKEND=memory` is valid for single-instance deployments.
- Use shared Redis backend for global limits across multiple backend instances.
- Admin mobile notifications remain backend-driven/in-app (no Firebase/FCM dependency).
