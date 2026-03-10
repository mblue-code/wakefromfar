# Security Hardening Plan

Status: draft implementation plan
Date: 2026-03-09

## Goal

Keep the product position unchanged:

- WakeFromFar is intended for private networking such as Tailscale or a trusted VPN.
- Direct open-internet exposure remains unsupported and discouraged.

At the same time, harden the system so that if an operator exposes the backend anyway, the backend fails closed by default and has materially better baseline protection.

## Current Security Posture Summary

Current strengths:

- Passwords are hashed.
- Placeholder secrets are rejected at startup.
- User and admin authorization are role- and membership-based.
- Login and wake-related rate limits exist.
- Android stores session data in encrypted preferences.
- iOS stores the auth token in Keychain.
- The Docker path already defaults to a Tailscale-oriented allowlist.

Current gaps to address:

1. Backend exposure can become permissive outside the default Docker path because code-level defaults do not fail closed.
2. TLS is not enforced for login and authenticated API traffic.
3. Admin access is not separately fenced from normal app access.
4. Admin UI POST actions do not use CSRF tokens or strict Origin checks.
5. There is no meaningful proof that requests come from the official mobile apps rather than any generic HTTP client.

## Threat Model

This plan addresses these realistic threats:

- An operator accidentally or intentionally binds the backend to a public or semi-public network.
- An attacker reaches the login endpoint from outside the intended private network.
- An attacker reuses stolen credentials or bearer tokens from a non-app client.
- An attacker reaches the admin UI or admin APIs from a broader network than intended.
- A browser-based admin session is targeted with cross-site form submission.

This plan does not attempt to make open public exposure "safe". It aims to make it fail closed by default and significantly harder to misuse.

## Hardening Principles

1. Fail closed on startup.
2. Separate user-plane and admin-plane controls.
3. Require encrypted transport for authentication and privileged operations.
4. Do not rely on weak client identifiers such as `User-Agent`, bundle ID strings, or embedded shared app secrets.
5. Roll out in layers so each sprint leaves the system safer than before.

## Recommended Sprint Sequence

Recommended order:

1. Sprint 1: Exposure fail-closed and startup guardrails
2. Sprint 2: TLS enforcement for auth and authenticated traffic
3. Sprint 3: Admin plane isolation and control switches
4. Sprint 4: Admin UI CSRF and browser-origin hardening
5. Sprint 5: Admin MFA
6. Sprint 6: Mobile app proof architecture spike and decision
7. Sprint 7: Mobile app proof implementation
8. Sprint 8: Rollout, observability, migration support, and release gating

## Sprint 1: Exposure Fail-Closed

### Objective

Ensure the backend refuses risky startup combinations unless the operator explicitly opts into unsafe exposure.

### Scope

Backend only.

### Changes

- Change code-level defaults so network protection is safe even outside Docker Compose.
- Add an explicit unsafe override such as:
  - `ALLOW_UNSAFE_PUBLIC_EXPOSURE=false`
- Add startup validation that refuses to boot when all of the following are true:
  - the service is network reachable beyond loopback/private expectations
  - IP allowlisting is disabled or empty
  - the unsafe override is not set
- Keep private-network use cases workable:
  - loopback
  - Tailscale CGNAT range
  - Tailscale IPv6 range
  - RFC1918 private IPv4
  - local link or explicitly allowed private CIDRs
- Add a distinct startup error message telling the operator exactly which environment variables must be set to proceed safely.
- Update all non-Docker startup docs to reflect the new fail-closed behavior.

### Planned Environment Variables

- `ENFORCE_IP_ALLOWLIST=true`
- `IP_ALLOWLIST_CIDRS=...`
- `ALLOW_UNSAFE_PUBLIC_EXPOSURE=false`

### Target Files

- `backend/app/config.py`
- `backend/app/main.py`
- `backend/app/request_context.py`
- `backend/tests/test_sprint3_hardening.py`
- `docs/deployment-guide.md`
- `README.md`

### Acceptance Criteria

- Starting the backend without an allowlist on a network-accessible interface fails with a clear error.
- Existing Docker Compose defaults keep working.
- Local development has an explicit documented safe path.
- Tests cover safe and unsafe startup combinations.

## Sprint 2: TLS Enforcement

### Objective

Require HTTPS for login and authenticated operations whenever the request is not from loopback, Tailscale, or explicitly private-approved networks.

### Scope

Backend, Android, iOS, docs.

### Changes

- Add backend request policy:
  - reject `POST /auth/login` over insecure HTTP unless the request comes from loopback, Tailscale, or an explicitly allowed private CIDR
  - reject all bearer-authenticated endpoints over insecure HTTP under the same policy
  - reject admin UI login and admin UI session usage over insecure HTTP under the same policy
- Apply HSTS at the full application level when TLS is active, not only the admin UI.
- Add explicit config for private-network HTTP exceptions, for example:
  - `ALLOW_INSECURE_PRIVATE_HTTP=true`
  - `PRIVATE_HTTP_ALLOWED_CIDRS=127.0.0.1/32,::1/128,100.64.0.0/10,...`
- Improve proxy-aware HTTPS detection and keep reverse-proxy deployments supported.
- Android:
  - remove HTTP as the release default backend URL
  - keep cleartext disabled in release
  - add login-time validation messaging that explains HTTP is private-network-only
- iOS:
  - remove HTTP as the default backend URL
  - keep ATS strict
  - reject HTTP URLs in normal production flow unless an explicitly private-network mode is enabled by product decision

### Planned Environment Variables

- `REQUIRE_TLS_FOR_AUTH=true`
- `ALLOW_INSECURE_PRIVATE_HTTP=true`
- `PRIVATE_HTTP_ALLOWED_CIDRS=...`

### Target Files

- `backend/app/main.py`
- `backend/app/request_context.py`
- `backend/app/config.py`
- `backend/tests/test_request_context.py`
- `android-client/app/build.gradle.kts`
- `android-client/app/src/main/java/com/wakefromfar/wolrelay/data/SecurePrefs.kt`
- `android-client/app/src/main/java/com/wakefromfar/wolrelay/data/ApiClient.kt`
- `ios-client/Services/API/APIClient.swift`
- `ios-client/Persistence/AppPreferences.swift`
- `README.md`
- `docs/deployment-guide.md`

### Acceptance Criteria

- Public HTTP login attempts fail.
- Public HTTP authenticated API calls fail.
- Reverse-proxy HTTPS setups continue to work with trusted proxy CIDRs.
- Android release and iOS production builds no longer steer operators toward HTTP defaults.

## Sprint 3: Admin Plane Isolation

### Objective

Separate admin exposure controls from standard mobile-user API access.

### Scope

Backend, admin UI, docs.

### Changes

- Add `ADMIN_UI_ENABLED` so operators can disable the browser admin plane entirely.
- Add `ADMIN_IP_ALLOWLIST_CIDRS` as a second network fence that applies only to:
  - `/admin/ui/*`
  - `/admin/*`
- Add middleware or dependency helpers so admin API and admin UI traffic is checked against the admin allowlist before role checks proceed.
- Keep user-plane endpoints available to normal app clients without automatically exposing the admin plane to the same networks.
- Add admin-specific startup validation:
  - if admin UI is enabled and admin allowlist is empty in a risky network posture, refuse startup unless explicitly overridden
- Consider a separate switch for API-only admin paths if future product decisions want mobile-admin activity while browser admin stays disabled.

### Planned Environment Variables

- `ADMIN_UI_ENABLED=true`
- `ADMIN_IP_ALLOWLIST_CIDRS=127.0.0.1/32,::1/128,100.64.0.0/10,...`
- Optional later split:
  - `ADMIN_API_ENABLED=true`

### Target Files

- `backend/app/config.py`
- `backend/app/main.py`
- `backend/app/admin_ui.py`
- `backend/tests/test_admin_ui.py`
- backend admin API tests
- `README.md`
- `docs/deployment-guide.md`

### Acceptance Criteria

- Admin UI can be fully disabled.
- Admin API and admin UI can be restricted to a narrower network than user API traffic.
- A user reachable from an app-facing network cannot automatically reach the admin plane unless that network is also admin-allowed.

## Sprint 4: Admin UI CSRF and Browser Hardening

### Objective

Protect cookie-authenticated admin POST actions against browser-based cross-site abuse.

### Scope

Admin UI only.

### Changes

- Add CSRF tokens to all state-changing admin UI forms.
- Bind CSRF tokens to the admin session.
- Add strict `Origin` validation for admin UI POST requests.
- Add `Referer` fallback validation for older browser edge cases if needed.
- Preserve `SameSite=Strict` and `HttpOnly` cookie settings.
- Review CSP and inline-script usage after CSRF work lands.

### Preferred Implementation

- Hidden form token in every admin UI POST form
- Server-side token validation on every POST route
- Reject missing or invalid token with `403`
- Also reject requests whose `Origin` is not the configured admin origin when present

### Target Files

- `backend/app/admin_ui.py`
- admin UI tests

### Acceptance Criteria

- Every admin UI POST route rejects missing or invalid CSRF tokens.
- Cross-origin form submissions fail even if a browser sends the cookie.
- Existing admin UI workflows remain usable.

## Sprint 5: Admin MFA

### Objective

Reduce admin compromise impact beyond password-only authentication.

### Scope

Backend, admin UI, mobile admin impact review, docs.

### Recommended Approach

Phase 1:

- TOTP-based MFA for admin accounts

Phase 2:

- Optional WebAuthn for admin UI browser logins

### Changes

- Extend admin user model with MFA fields.
- Add enrollment flow in admin UI.
- Require MFA challenge after password login for admin UI.
- Decide whether admin API bearer-token login should:
  - remain password-only for now
  - require app-password or token bootstrap
  - move to a more explicit admin token issuance flow

### Planned Environment Variables

- `ADMIN_MFA_REQUIRED=true`
- `ADMIN_MFA_ISSUER=WakeFromFar`

### Target Files

- backend auth and DB files
- `backend/app/admin_ui.py`
- backend tests
- docs

### Acceptance Criteria

- Admin UI password-only login is no longer sufficient when MFA is required.
- Recovery and bootstrap flows are documented.

## Sprint 6: Mobile App Proof Architecture Spike

### Objective

Choose a real proof-of-client mechanism that can support the product without fake security.

### Scope

Design sprint with prototype notes, API contract, and rollout decision.

### Explicit Non-Solutions

Do not implement:

- shared app secret embedded in the app
- `User-Agent` checks
- bundle ID or package-name string checks without cryptographic proof

### Candidate A: mTLS with Provisioned Client Certificates

Pros:

- Strong cryptographic client identity
- Backend can reject non-certificate clients before app auth
- Works without Google or Apple attestation APIs once provisioned

Cons:

- Hard certificate provisioning and lifecycle management
- Harder mobile UX
- Revocation and re-enrollment complexity
- More difficult support burden for self-hosted operators

### Candidate B: Platform Attestation Bound to Session Issuance

Android:

- Play Integrity

iOS:

- App Attest, with DeviceCheck fallback only if necessary

Pros:

- Better fit for "official app" proof
- No client cert UX for end users
- Better resistance to generic script clients

Cons:

- More backend complexity
- Dependency on Google and Apple attestation services
- More moving parts in self-hosted environments

### Decision Output

Sprint 6 decision:

- Primary path: platform attestation bound to login issuance and installation enrollment
- Android: Play Integrity standard requests
- iOS: App Attest
- DeviceCheck: telemetry/risk signal only, not an enforced substitute for App Attest
- mTLS: explicitly not the Sprint 7 baseline and not the default product path

Authoritative design doc:

- `docs/mobile-app-proof-architecture.md`

Decision highlights:

- Protect `/auth/login` for mobile bearer-token issuance first.
- Bind issued sessions to backend installation records.
- Do not require full provider-backed proof on every authenticated request in Sprint 7.
- Plan later privileged reauth for higher-risk request classes.
- Extend the later rollout to admin bearer-token login as well, so the current Sprint 5 gap does not become permanent.

### Acceptance Criteria

- There is a written architecture decision record.
- The team explicitly chooses one primary path and one fallback path.

## Sprint 7: Mobile App Proof Implementation

### Objective

Implement the chosen app-proof mechanism and bind it to authenticated backend use.

### Scope

Backend, Android, iOS, tests, docs.

### If Attestation Is Chosen

Backend:

- add app-proof challenge endpoints and short-lived proof tickets
- verify Android Play Integrity server-side and iOS App Attest server-side
- store installation records and iOS attested key state
- bind attested installation identity to backend-issued sessions
- extend JWT claims with installation/session binding data
- reject mobile bearer-token login without valid proof when policy requires it

Android:

- integrate Play Integrity standard requests
- bind `requestHash` to backend-issued login challenges
- persist a durable installation id
- submit proof before `/auth/login`

iOS:

- integrate App Attest
- store App Attest key id and installation id in secure storage
- perform first-run attestation enrollment
- use assertions for later login and privileged reauth flows

### Policy Recommendation

Roll out in phases:

1. report-only
2. soft-enforcement for mobile bearer-token logins
3. enforcement for mobile bearer-token logins
4. optional enforcement for all authenticated mobile traffic after session-binding telemetry is proven

Mode names and behavior are specified in `docs/mobile-app-proof-architecture.md`.

### Acceptance Criteria

- A generic HTTP client without app proof is rejected when enforcement is enabled.
- Android and iOS can still log in and function normally under enforcement.

## Sprint 8: Rollout, Telemetry, Migration, and Release Gates

### Objective

Make the new controls operable in production-like environments.

### Scope

Backend metrics, logs, docs, release checklist, support guidance.

### Changes

- Add metrics for:
  - blocked insecure HTTP auth attempts
  - blocked admin-network requests
  - blocked CSRF requests
  - blocked missing-app-proof requests
  - MFA enrollment and challenge failures
  - provider outage and quota failures for app proof
  - session issuance with and without verified app proof
  - installation revocation and binding mismatches
- Add structured logs with actionable reasons.
- Add migration notes for existing operators.
- Add release-gate tests and manual QA checklist for:
  - direct private-network deployment
  - reverse proxy deployment
  - admin UI disabled deployment
  - app-proof enabled deployment
- Update privacy and operator documentation as needed.

### Acceptance Criteria

- Operators can understand why requests are blocked.
- Release docs clearly describe safe and unsafe deployment modes.
- A regression test suite exists for each major hardening layer.

## Cross-Sprint Implementation Notes

### Recommended Default Policies at End State

- `ENFORCE_IP_ALLOWLIST=true`
- `ALLOW_UNSAFE_PUBLIC_EXPOSURE=false`
- `REQUIRE_TLS_FOR_AUTH=true`
- `ALLOW_INSECURE_PRIVATE_HTTP=true` only for explicitly private-network CIDRs
- `ADMIN_UI_ENABLED=true` for private-network deployments, with clear recommendation to disable it when not needed
- `ADMIN_IP_ALLOWLIST_CIDRS` narrower than general app allowlist
- `ADMIN_MFA_REQUIRED=true`
- App proof:
  - `APP_PROOF_MODE=report_only` initially
  - later `APP_PROOF_MODE=soft_enforce`
  - later `APP_PROOF_MODE=enforce_login`
  - only later, if justified, `APP_PROOF_MODE=enforce_all_authenticated`

### Suggested New Tests

- startup fails when allowlist is disabled in risky posture
- admin requests blocked outside admin CIDRs
- insecure HTTP login blocked from public IPs
- insecure HTTP auth allowed only from explicitly approved private CIDRs
- admin UI POST rejected without CSRF token
- admin UI POST rejected with bad Origin
- admin MFA enrollment and login challenge tests
- non-app client rejected when app proof enforcement is on

### Suggested Delivery Strategy

- Deliver Sprint 1 and Sprint 2 before any public or beta deployment changes.
- Deliver Sprint 3 and Sprint 4 before broadening admin usage.
- Treat Sprint 5 through Sprint 7 as a separate hardening track with architecture review.

## Recommended Immediate Priorities

If capacity is limited, prioritize in this order:

1. Sprint 1
2. Sprint 2
3. Sprint 3
4. Sprint 4

Those four sprints materially improve safety even before app-proof work begins.

## Final Recommendation

The strongest practical near-term outcome is:

- fail-closed startup behavior
- TLS-required auth policy
- separate admin-plane network controls
- CSRF protection
- admin MFA

The strongest long-term outcome for "only our apps" is:

- platform attestation as the baseline product control, rolled out gradually and enforced first at mobile bearer-token session issuance, with later privileged reauth and optional stricter session-binding enforcement

Until the app-proof sprints are complete, the system should still be described as:

- private-network-first
- not intended for open public internet exposure
- protected primarily by network controls, TLS, and user/admin authentication
