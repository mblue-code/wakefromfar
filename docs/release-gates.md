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
3. Environment file is prepared from `.env.example` and secrets are replaced:
   - `APP_SECRET`
   - `ADMIN_PASS`
4. Compose target is explicit:
   - testing: `docker compose -f docker-compose.yml -f docker-compose.testing.yml up -d --build`
5. Smoke test succeeds:
   - `/health`
   - admin login
   - invite claim
   - `/me/devices`
   - wake path (`already_on` and `sent`)

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
