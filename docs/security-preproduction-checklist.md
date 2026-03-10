# Security Pre-Production Checklist

Use this checklist before any private beta, shared testing, or broader network exposure.

There are no production users or production installations yet. Do not spend time on migration steps for Sprint 8. Validate fresh deployment behavior instead.

## 1. Secure Startup

1. Start from a fresh `.env` copied from `.env.example`.
2. Replace `APP_SECRET` and `ADMIN_PASS`.
3. Confirm the default hardening posture:
   - `ENFORCE_IP_ALLOWLIST=true`
   - `REQUIRE_TLS_FOR_AUTH=true`
   - `ADMIN_UI_ENABLED=true` only if the browser admin plane is intentionally in use
   - `APP_PROOF_MODE` is set explicitly for the rollout stage
4. Start the backend and confirm `/health` returns `200`.
5. Confirm the backend fails closed if you intentionally remove required allowlist CIDRs or leave invalid CIDRs in place.

## 2. Transport And Network Controls

1. Verify public HTTP login is blocked:
   - `POST /auth/login` from a non-private client over HTTP must return `403`.
2. Verify authenticated public HTTP API traffic is blocked:
   - bearer-authenticated `/me/*` and `/admin/*` over HTTP must return `403`.
3. Verify admin-plane isolation:
   - `/admin/*` and `/admin/ui/*` must reject requests from non-admin CIDRs.
4. If `ALLOW_INSECURE_PRIVATE_HTTP=true`, verify the HTTP exception only works from the intended private CIDRs.

## 3. Browser Admin Plane

1. If `ADMIN_UI_ENABLED=false`, verify `/admin/ui/*` returns `404`.
2. If `ADMIN_UI_ENABLED=true`, verify admin login works only from the admin allowlist.
3. Verify all admin UI POSTs reject:
   - missing CSRF token
   - invalid CSRF token
   - wrong `Origin`
   - wrong fallback `Referer`
4. Verify browser MFA behavior:
   - non-enrolled admin reaches setup when `ADMIN_MFA_REQUIRED=true`
   - enrolled admin is challenged for TOTP
   - invalid TOTP is rejected
   - pending MFA state expires cleanly

## 4. App-Proof Rollout

1. `APP_PROOF_MODE=report_only`
   - login without proof still succeeds
   - `/admin/security-status` shows `report_only`
   - `/admin/metrics` increments the report-only missing-proof counter
2. `APP_PROOF_MODE=enforce_login`
   - login without proof is blocked with `403`
   - `/admin/security-status` shows recent app-proof failures by category
3. `APP_PROOF_MODE=soft_enforce`
   - previously trusted installation can use bounded degraded allow only inside the grace window
4. Confirm admin bearer-token login remains deferred by default unless `APP_PROOF_REQUIRE_ON_ADMIN_BEARER_LOGIN=true`.

## 5. Mobile Wiring Sanity

1. Android:
   - challenge request succeeds
   - verify request hits `/auth/app-proof/verify/android`
   - signing cert/package config matches deployment values
2. iOS:
   - App Attest enrollment/assert paths match backend config
   - `DeviceContractTests` passes
3. Confirm installation-bound sessions send `X-WFF-Installation-ID` on authenticated mobile requests.

## 6. Operator Diagnostics

1. Authenticate as an admin and review:
   - `GET /admin/security-status`
   - `GET /admin/metrics`
   - `GET /admin/app-installations?limit=100`
2. Confirm diagnostics show:
   - hardening mode summary
   - app-proof mode
   - risky-but-allowed warnings
   - explicit deferred items
   - installation counts by platform/state
   - recent app-proof failure categories
3. Confirm diagnostics do not expose:
   - secrets
   - bearer tokens
   - raw attestation payloads

## 7. Deferred Controls Confirmation

Confirm these items are still deferred and documented before beta use:

- all-request proof-of-possession
- mTLS
- DeviceCheck as enforcement
- admin bearer-login app-proof rollout by default
- public-internet deployment as a supported product mode
