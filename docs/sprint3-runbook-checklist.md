# Sprint 3 Runbook And Release Checklist

## Security Hardening

- Confirm `TOKEN_EXPIRES_SECONDS=28800` (8h) in production.
- Confirm rate limits are set and monitored:
  - `LOGIN_RATE_LIMIT_PER_MINUTE`
  - `ONBOARDING_RATE_LIMIT_PER_MINUTE`
  - `WAKE_RATE_LIMIT_PER_MINUTE`
- Verify audit coverage in `/admin/audit-logs` for:
  - user/device CRUD
  - assignment create/delete
  - invite create/revoke

## Reliability Hardening

- Validate wake retry behavior with temporary packet-send failure:
  - first attempt fails, second succeeds (`WAKE_SEND_MAX_ATTEMPTS >= 2`).
- Validate power-check categorization:
  - timeout/refused/unreachable => `off`
  - DNS/config/runtime exceptions => `unknown`
- Verify graceful fallback:
  - misconfigured check still allows wake request and logs precheck detail.

## Observability

- Confirm structured logs are emitted for:
  - login/onboarding success/failure/rate-limit
  - wake outcomes
  - power-check outcomes
  - admin mutations
- Confirm counters endpoint `/admin/metrics` is accessible to admins.
- Validate diagnostics hints:
  - `/admin/diagnostics/devices`
  - `/admin/ui/diagnostics`

## Pilot Rollout (5-10 Users)

- Create invites for pilot users.
- Record claim time and first successful wake.
- Track completion KPI in `/admin/pilot-metrics`:
  - target: >= 90% first successful wake within 2 minutes.
- Collect top 3 failure themes and remediation notes.

## Production Release Gates

- All backend tests pass in CI (`.github/workflows/backend-tests.yml`).
- No critical auth/access findings open.
- Dry-run executed:
  - new user invite claim
  - assigned device visible
  - wake with `already_on` and `sent` paths
  - audit + logs + metrics visible
