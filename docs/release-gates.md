# Release Gates

This gate is for fresh deployments and pre-production rollout. There are no production users or production installations yet, so Sprint 8 does not add migration tooling or migration steps.

Use `/Users/max/projekte/wakefromfar/docs/security-preproduction-checklist.md` as the executable runbook. The list below is the release sign-off summary.

## Gate 1: Backend Hardening

1. Backend tests pass from the repo virtualenv or CI.
2. Startup validation still fails closed for:
   - disabled IP allowlist without `ALLOW_UNSAFE_PUBLIC_EXPOSURE=true`
   - empty or malformed `IP_ALLOWLIST_CIDRS`
   - empty or malformed `ADMIN_IP_ALLOWLIST_CIDRS`
   - malformed `PRIVATE_HTTP_ALLOWED_CIDRS`
3. Secure defaults are explicitly reviewed in `.env`:
   - `ENFORCE_IP_ALLOWLIST=true`
   - `REQUIRE_TLS_FOR_AUTH=true`
   - `APP_PROOF_MODE` set intentionally
   - `ADMIN_UI_ENABLED` and `ADMIN_MFA_REQUIRED` set intentionally

## Gate 2: Transport And Admin Plane

1. Public HTTP login is blocked.
2. Public HTTP authenticated `/me/*` and `/admin/*` traffic is blocked.
3. Admin-plane isolation is verified:
   - `/admin/*` and `/admin/ui/*` reject non-admin CIDRs
   - `ADMIN_UI_ENABLED=false` returns `404` for browser admin paths
4. Browser admin POST protections are verified:
   - CSRF rejects missing/invalid token
   - `Origin` / fallback `Referer` enforcement rejects cross-site requests

## Gate 3: Browser Admin MFA

1. MFA setup flow works for non-enrolled admin accounts when required.
2. Enrolled admins must verify TOTP before receiving a full browser admin session.
3. Invalid TOTP and expired pending-MFA state are rejected cleanly.
4. Break-glass recovery procedure is documented and tested if browser admin MFA is enabled.

## Gate 4: Mobile App Proof

1. Rollout mode is explicit:
   - `disabled`
   - `report_only`
   - `soft_enforce`
   - `enforce_login`
2. `report_only` behavior is verified in diagnostics and metrics.
3. `enforce_login` blocks missing proof at `/auth/login`.
4. Android Play Integrity configuration is present and verified.
5. iOS App Attest configuration is present and verified.
6. Session binding to installation ID still works on authenticated mobile requests.
7. Admin bearer-token login rollout remains explicitly deferred unless `APP_PROOF_REQUIRE_ON_ADMIN_BEARER_LOGIN=true`.

## Gate 5: Operator Diagnostics

1. `/admin/security-status` is reachable for admins and shows:
   - hardening mode
   - risky-but-allowed warnings
   - explicit deferred items
   - app-proof installation counts by platform/state
   - recent app-proof failure categories
2. `/admin/metrics` exposes runtime counters plus the security-status snapshot.
3. `/admin/app-installations` supports read-only installation inspection for pre-production support.
4. Diagnostics do not expose secrets, bearer tokens, or raw attestation payloads.

## Gate 6: Explicit Deferred Items

Before release, confirm these remain documented and understood:

- all-request proof-of-possession is not implemented
- mTLS is deferred
- DeviceCheck is not an enforcement substitute
- admin bearer-login app proof is deferred by default
- WakeFromFar remains private-network-first and public internet exposure is still unsupported
