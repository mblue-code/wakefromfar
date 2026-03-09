# Mobile App Proof Architecture

Status: accepted architecture decision for Sprint 6
Date: 2026-03-09
Owners: backend + mobile clients
Scope: mobile bearer-token login and session issuance for Android and iOS

## 1. Problem Statement

WakeFromFar currently authenticates mobile clients with username/password and then issues a bearer token from `/auth/login`. That proves the user knows valid credentials. It does not prove the caller is the official Android or iOS app.

That gap matters because the stated goal is not only "valid user" but "only our apps" for mobile bearer-token flows. A generic HTTP client with valid credentials can currently log in and then use the API exactly like the official apps. The current model therefore does not distinguish:

- official app versus `curl`, Postman, or a custom script
- official app versus a repackaged or tampered app
- official app versus a stolen bearer token replayed elsewhere

Weak client identifiers do not solve this:

- `User-Agent` is trivially forged
- package names and bundle IDs are just strings unless a platform trust service vouches for them
- embedded shared secrets are recoverable from shipped binaries and then become copyable to any client
- custom headers or obfuscation-only checks raise friction, not trust

Sprint 6 therefore needs a cryptographically meaningful design that can tell the backend "this login attempt came from an official app instance on a supported platform" without pretending that string checks are security.

## 2. Current State

Current backend and client behavior:

- `POST /auth/login` accepts `username` and `password`, verifies them, and issues an HS256 JWT bearer token.
- The token currently contains `sub`, `role`, `ver`, and `exp`.
- Authenticated requests use standard bearer auth through `Authorization: Bearer <token>`.
- `backend/app/main.py` enforces transport policy for login and authenticated traffic, but it does not require any mobile app proof.
- `backend/app/security.py` creates and verifies bearer tokens only; there is no installation binding or app-proof claim today.
- Android uses `OkHttp` and calls `/auth/login` directly, then stores the token in encrypted shared preferences and replays it on later requests.
- iOS uses `URLSession` and calls `/auth/login` directly, then stores the token in Keychain and replays it on later requests.
- The product stance remains private-network-first. Reverse proxies and private HTTP exceptions exist, but open public internet exposure is still unsupported.
- Browser admin MFA from Sprint 5 covers only the browser admin UI session flow. It does not cover bearer-token issuance through `/auth/login`.
- The current staged rollout gap is intentional: admin API bearer-token login and normal mobile bearer-token login are still unchanged and not app-proof protected.

## 3. Requirements

The chosen design must satisfy these requirements:

1. It must be cryptographically meaningful, not a string check.
2. It must not rely on a static secret embedded in the app.
3. It should work for self-hosted deployments without requiring public exposure of the backend.
4. It must preserve the repo's private-network-first stance and not claim to make public exposure supported.
5. It must allow staged rollout with `disabled`, report-only, soft enforcement, and hard enforcement modes.
6. It must support observability, operator support, revocation, and recovery.
7. It should not permanently brick users during transient Apple/Google/provider failures unless the operator explicitly chooses a stricter fail-closed mode.
8. It must support Android and iOS with the actual trust primitives those platforms provide today.
9. It should fit the current codebase without redesigning the full auth system in Sprint 7.
10. It should make first-party mobile bearer-token login harder for generic HTTP clients, while being honest about residual bearer-token theft risk after session issuance.

## 4. Threat Model

This design targets these threats:

- Generic HTTP client with valid or stolen credentials:
  - attacker sends `/auth/login` directly from `curl` or a script
  - attacker bypasses official app distribution entirely
- Replay attempts:
  - reuse of a captured Android integrity token
  - reuse of an iOS challenge/assertion pair
  - reuse of a previously valid login proof outside its allowed window
- Rooted, jailbroken, tampered, or instrumented clients:
  - attacker modifies app behavior
  - attacker attempts to bypass or hook local checks
  - attacker runs the app on compromised devices
- App binary extraction and reverse engineering:
  - attacker recovers strings, endpoints, bundle IDs, or embedded secrets
  - attacker replays protocol calls without the real platform proof
- Self-hosted operator misconfiguration:
  - backend exposed too broadly
  - incorrect proxy or allowlist setup
  - assumption that app proof makes public exposure safe
- Attestation/provider outage:
  - Google Play Integrity decode failures, quota exhaustion, or transient client/service errors
  - Apple App Attest availability issues for new enrollment or app-side attestation calls
- Token theft after session issuance:
  - token copied from a client device or logs
  - token replayed from a different host after successful login
- Device replacement, reinstall, and account switching:
  - App Attest keys are installation-bound and do not survive reinstall
  - users change devices or sign into a different account on the same device
- Operational revocation needs:
  - operator must be able to revoke one installation or all proof for a user
  - operator must recover from bad enrollments or compromised devices

This design does not claim to fully defeat an attacker who can operate through a still-trusted live device session or steal a valid bearer token after issuance.

## 5. Explicit Non-Solutions

These are explicitly rejected as the primary control:

- `User-Agent` checks
- package name or bundle ID checks by themselves
- hardcoded shared app secret
- simple custom header such as `X-Official-App: true`
- obfuscation-only approaches

They may exist as telemetry or UX hints, but they are not meaningful security boundaries.

## 6. Candidate Options

### Option A: Platform Attestation Bound to Session Issuance

Android:

- Google Play Integrity standard requests

iOS:

- App Attest
- DeviceCheck only as a secondary risk signal or degraded-mode telemetry path, not as equivalent proof

Security properties:

- Best fit for proving "official app on supported platform" because the platform vendor vouches for app identity and device/app integrity signals.
- Android can bind an integrity token to a specific request via `requestHash` and Google automatically mitigates replay for standard requests.
- iOS App Attest gives a per-installation key, server-validated attestation, and server-verifiable assertions for later protected actions.

Operational complexity:

- Moderate. Requires new backend challenge/verification endpoints, installation records, and platform-specific verification logic.
- Requires Google Cloud/Play Console setup for Android.
- Requires Apple App Attest capability and server-side validation logic for iOS.

Self-hosted fit:

- Good enough for WakeFromFar's model.
- Backend remains self-hosted and private-network-first.
- Android requires backend egress to Google for token decode.
- iOS App Attest verification is mostly server-side cryptographic validation plus app-side Apple service use during attestation; it does not require public exposure of the backend.

UX complexity:

- Lower than mTLS.
- Mostly invisible when healthy.
- Needs degraded-mode messaging for unsupported devices, first-run enrollment, quota issues, or provider outages.

Rollout complexity:

- Good staged rollout fit. Can start report-only on `/auth/login`, then enforce login, then consider stricter session binding later.

Revocation model:

- Revoke per installation by marking backend installation records revoked.
- Revoke per user by bumping existing token version plus revoking installation records if needed.

Offline/outage behavior:

- Android is provider-dependent at proof time.
- iOS new attestation depends on Apple service availability, but repeated App Attest assertions do not require Apple on each request.
- Requires explicit degraded-mode policy to avoid needless lockout during transient outages.

Implementation effort in this codebase:

- Moderate and acceptable for Sprint 7.
- Fits current JWT-based auth if installation/session binding is added without a full auth rewrite.

Support burden:

- Real but manageable.
- Mostly around unsupported devices, Play services issues, App Attest enrollment failures, and operator config.

Protects login only or later requests:

- Strongest and most practical at login/session issuance.
- Can also protect later privileged reauth flows.
- Not ideal to call full attestation for every authenticated request, especially cross-platform.

What it does not solve:

- Does not fully stop replay of a stolen bearer token after login if later requests remain bearer-only.
- Does not make public exposure supported.
- Does not turn rooted/jailbroken devices into trusted devices.

### Option B: mTLS with Provisioned Client Certificates

Security properties:

- Strong possession proof of a client certificate on every TLS connection.
- Useful for closed fleets or managed devices.

Operational complexity:

- High. Requires CA, enrollment, issuance, secure import/storage, rotation, revocation, and support for mobile client-certificate UX.

Self-hosted fit:

- Mixed.
- Self-hosting a CA is possible, but now every operator effectively owns a PKI and certificate lifecycle.
- Hard to make this sane across app-store clients and ad hoc user enrollments.

UX complexity:

- High.
- Certificate bootstrap on mobile is materially more fragile than store-backed attestation.

Rollout complexity:

- High.
- Reverse proxies, TLS termination, certificate forwarding, and mobile networking stacks all become more complex.

Revocation model:

- Good in principle, but only if operators can actually manage cert issuance and revocation correctly.

Offline/outage behavior:

- Better after enrollment because no Apple/Google attestation call is needed for every login.
- Worse for operator support because enrollment and recovery are more fragile.

Implementation effort in this codebase:

- High and disproportionate to Sprint 7.
- Would require proxy/topology guidance, cert management UX, and likely more auth redesign than this repo should absorb in one sprint.

Support burden:

- High.
- Support tickets become PKI and device-cert support tickets.

Protects login only or later requests:

- Protects all TLS-authenticated traffic if enforced end to end.

What it does not solve:

- mTLS proves possession of a certificate, not that the caller is the official app, unless certificate issuance itself already solved the harder bootstrap problem.
- A script that obtains the cert can still act as the client until revocation.

### Option C: Hybrid or Phased Model

Attestation first, mTLS optional for specialized deployments.

Security properties:

- Uses platform attestation for the baseline "official app" problem.
- Leaves room for future operator-managed mTLS in bespoke environments that want an extra transport credential.

Operational complexity:

- Acceptable if the product chooses one baseline and treats the other as optional later work.
- Harmful if both are treated as co-equal mandatory paths.

Self-hosted fit:

- Stronger than pure mTLS as a default because most operators can run official mobile apps without becoming PKI operators.

UX complexity:

- Baseline remains reasonable.
- Optional mTLS can stay out of the default user path.

Rollout complexity:

- Good if Sprint 7 does attestation only and explicitly defers mTLS.

Revocation model:

- Baseline revocation through installation records.
- Optional future mTLS adds cert revocation only for deployments that opt in.

Offline/outage behavior:

- Same as attestation baseline unless mTLS is layered later for special cases.

Implementation effort in this codebase:

- Good only if the team is disciplined about not trying to build both now.

What it does not solve:

- Still leaves bearer-token theft as a residual risk unless later request proof-of-possession is added.

## 7. Recommended Decision

Decision:

- Primary architecture: platform attestation bound to login issuance and installation enrollment.
- Android path: Play Integrity standard requests.
- iOS path: App Attest for the primary proof.
- DeviceCheck: report-only risk signal or recovery telemetry only; not sufficient to satisfy enforced app proof.
- mTLS: not part of Sprint 7 and not the default product path. It may be documented later as an optional operator-managed overlay for niche high-security deployments.

Why this is the right path for this repo:

- WakeFromFar wants "only our apps", not "only clients holding a user-installed certificate".
- mTLS would force self-hosted operators into certificate lifecycle work that is heavier than the current product and still would not directly answer the official-app question.
- Android already has a request-bound, replay-resistant standard flow in Play Integrity.
- iOS App Attest gives a better long-lived installation identity than DeviceCheck and supports later local assertions without calling Apple every time.
- This fits the current private-network-first stance: the backend remains self-hosted, but mobile apps can still rely on platform trust services.

Scope recommendation:

- Sprint 7 should enforce app proof at login issuance for mobile bearer-token logins.
- Later authenticated requests should be session-bound to the attested installation record, but Sprint 7 should not require full provider-backed proof on every request.
- For later phases, add proof re-checks for privileged request classes and reauthentication flows before considering any all-request proof-of-possession redesign.
- Admin API bearer-token logins should be covered by the same app-proof rollout later because the current Sprint 5 gap is specifically that `/auth/login` is still unprotected for bearer-token admin use.

This is a deliberate attestation-first decision, not indecision. Optional mTLS is explicitly out of the baseline architecture.

## 8. Proposed Protocol / Contract

### Summary

The protocol should separate:

1. challenge issuance
2. platform proof verification
3. login/session issuance
4. later installation-bound request validation

### 8.1 Common backend entities

Add an installation record model and a short-lived challenge model.

Likely new tables:

- `app_proof_challenges`
  - `id`
  - `purpose` (`enroll`, `login`, `reauth`)
  - `platform` (`android`, `ios`)
  - `installation_id`
  - `username_hint` nullable
  - `challenge_nonce`
  - `expires_at`
  - `consumed_at`
  - `created_at`
  - `client_ip`
- `app_installations`
  - `installation_id` primary key
  - `platform`
  - `status` (`pending`, `trusted`, `report_only`, `revoked`)
  - `user_id` nullable
  - `session_version`
  - `app_id` (Android package name or iOS bundle ID)
  - `app_version`
  - `os_version`
  - `last_verified_at`
  - `last_login_at`
  - `last_seen_ip`
  - `last_provider_status`
  - `last_provider_error`
  - `last_verdict_json`
  - `created_at`
  - `updated_at`
  - `revoked_at` nullable
  - `revoked_reason` nullable
- `ios_app_attest_keys`
  - `installation_id`
  - `key_id`
  - `public_key_pem`
  - `sign_count`
  - `receipt_b64` nullable
  - `last_asserted_at`
  - `created_at`
  - `updated_at`

Android-specific structured fields can live either in `app_installations.last_verdict_json` or a separate table if the team wants queryable columns later.

### 8.2 Challenge endpoint

`POST /auth/app-proof/challenge`

Request:

```json
{
  "platform": "android",
  "purpose": "login",
  "installation_id": "client-generated-installation-uuid",
  "username": "alice",
  "app_version": "1.4.0",
  "os_version": "android-15"
}
```

Response:

```json
{
  "challenge_id": "uuid",
  "challenge": "base64url-random",
  "purpose": "login",
  "expires_in": 300,
  "binding": {
    "canonical_fields": [
      "purpose",
      "challenge_id",
      "challenge",
      "installation_id",
      "username"
    ]
  }
}
```

Rules:

- Challenge is one-time use and expires quickly.
- Canonical binding fields must be documented exactly so mobile and backend hash the same content.
- The challenge payload should never include raw secrets.

### 8.3 Android verification contract

Recommended Android proof flow:

1. Client calls `/auth/app-proof/challenge` with `purpose=login`.
2. Client computes `request_hash = sha256(canonical_json(...))`.
3. Client uses Play Integrity standard request with that `requestHash`.
4. Client submits the integrity token to backend verification.

`POST /auth/app-proof/verify/android`

Request:

```json
{
  "challenge_id": "uuid",
  "installation_id": "client-generated-installation-uuid",
  "request_hash": "base64url-sha256",
  "integrity_token": "opaque-google-token",
  "app_version": "1.4.0",
  "os_version": "android-15"
}
```

Backend verification requirements:

- Decode integrity token with Google Play server-side API.
- Verify `requestDetails.requestHash` matches backend recomputation.
- Verify `requestDetails.requestPackageName` matches configured Android package name.
- Verify `appIntegrity.appRecognitionVerdict == PLAY_RECOGNIZED`.
- Verify configured signing certificate digest matches `certificateSha256Digest`.
- Verify `deviceIntegrity.deviceRecognitionVerdict` contains `MEETS_DEVICE_INTEGRITY`.
- Record but do not necessarily hard-fail on optional signals like app licensing or app access risk during the first enforce phase.
- Reject reused or expired challenges.

Response:

```json
{
  "proof_ticket": "short-lived-backend-token",
  "proof_expires_in": 300,
  "installation_status": "trusted"
}
```

The backend-signed `proof_ticket` decouples `/auth/login` from vendor-specific payload formats.

### 8.4 iOS verification contract

Recommended iOS flow has two phases:

1. first install: key generation + attestation enrollment
2. later login/protected actions: assertion with the already-attested key

#### First enrollment

1. Client calls `/auth/app-proof/challenge` with `purpose=enroll`.
2. Client uses `DCAppAttestService.generateKey()`.
3. Client calls `attestKey(keyId, clientDataHash: ...)`.
4. Client submits attestation object to backend.

`POST /auth/app-proof/verify/ios`

Request:

```json
{
  "mode": "attest",
  "challenge_id": "uuid",
  "installation_id": "client-generated-installation-uuid",
  "key_id": "apple-app-attest-key-id",
  "attestation_object": "base64",
  "receipt": "base64-optional",
  "app_version": "1.4.0",
  "os_version": "ios-18.3"
}
```

Backend verification requirements:

- Verify challenge freshness and one-time use.
- Reconstruct the nonce from the challenge-bound `clientDataHash`.
- Verify the App Attest certificate chain and nonce binding.
- Verify the attested app identity matches configured bundle/team identity.
- Store the attested public key and initial counter state.
- Mark installation as `trusted` only after successful server validation.

Response:

```json
{
  "installation_status": "trusted"
}
```

#### Later login or privileged reauth

1. Client calls `/auth/app-proof/challenge` with `purpose=login` or `reauth`.
2. Client computes canonical payload digest.
3. Client calls `generateAssertion(keyId, clientDataHash: ...)`.
4. Client sends assertion to backend.

`POST /auth/app-proof/verify/ios`

Request:

```json
{
  "mode": "assert",
  "challenge_id": "uuid",
  "installation_id": "client-generated-installation-uuid",
  "key_id": "apple-app-attest-key-id",
  "assertion_object": "base64",
  "app_version": "1.4.0",
  "os_version": "ios-18.3"
}
```

Backend verification requirements:

- Verify challenge freshness and one-time use.
- Reconstruct the nonce from the same canonical payload.
- Verify assertion signature against stored public key.
- Verify attested app identity data in authenticator data.
- Verify the monotonic counter increased.
- Reject assertions for revoked or unknown installations.

Response:

```json
{
  "proof_ticket": "short-lived-backend-token",
  "proof_expires_in": 300,
  "installation_status": "trusted"
}
```

### 8.5 Login/session issuance contract

Keep `/auth/login`, but extend it.

Request:

```json
{
  "username": "alice",
  "password": "secret",
  "installation_id": "client-generated-installation-uuid",
  "proof_ticket": "short-lived-backend-token"
}
```

Response:

```json
{
  "token": "jwt",
  "expires_in": 28800
}
```

JWT additions recommended for Sprint 7:

- `aid`: installation id
- `apm`: app-proof method (`android_play_integrity`, `ios_app_attest`)
- `asv`: installation session version

Backend login rules:

- In `disabled`, behave as today.
- In `report_only`, issue token even without valid proof, but log the absence or mismatch.
- In `soft_enforce`, require proof unless a bounded degraded-mode exception applies.
- In `enforce_login` and stricter modes, require a valid `proof_ticket` for mobile bearer-token logins.
- Bind issued token to the installation record by embedding `aid` and `asv`.

### 8.6 Later authenticated requests

Sprint 7 should not require full platform proof on every authenticated request.

Instead:

- mobile clients send `X-WFF-Installation-ID`
- backend compares header with token `aid`
- backend verifies installation exists, is not revoked, and `session_version` still matches `asv`

This provides session-to-installation binding and revocation hooks without full auth redesign.

Later work may add a dedicated `reauth` proof check for privileged request classes, for example:

- admin mobile actions
- token refresh or session reissue
- high-risk account actions

### 8.7 Device/installation record model

`installation_id` should be generated client-side and stored like other local durable identifiers:

- Android: encrypted shared preferences
- iOS: Keychain or similarly durable store, not plain `UserDefaults`

Important lifecycle rules:

- iOS App Attest keys are installation-bound and do not survive reinstall, so reinstall creates a new installation identity.
- account switch on the same installation should update the linked `user_id`, not reuse stale user binding blindly
- operator revocation should be per installation, not only per user

### 8.8 Config/env vars likely needed

Recommended new settings:

- `APP_PROOF_MODE=disabled`
- `APP_PROOF_CHALLENGE_TTL_SECONDS=300`
- `APP_PROOF_DEGRADED_GRACE_SECONDS=86400`
- `APP_PROOF_REQUIRE_ON_ADMIN_BEARER_LOGIN=false`
- `APP_PROOF_ANDROID_ENABLED=true`
- `APP_PROOF_ANDROID_PACKAGE_NAME=com.wakefromfar.wolrelay`
- `APP_PROOF_ANDROID_ALLOWED_CERT_SHA256=<comma-separated>`
- `APP_PROOF_ANDROID_CLOUD_PROJECT_NUMBER=<value>`
- `APP_PROOF_ANDROID_REQUIRE_DEVICE_INTEGRITY=true`
- `APP_PROOF_ANDROID_REQUIRE_PLAY_RECOGNIZED=true`
- `APP_PROOF_ANDROID_REQUIRE_LICENSED=false`
- `APP_PROOF_IOS_ENABLED=true`
- `APP_PROOF_IOS_TEAM_ID=<team-id>`
- `APP_PROOF_IOS_BUNDLE_ID=<bundle-id>`
- `APP_PROOF_IOS_ALLOW_DEVICECHECK_REPORT_ONLY=true`

### 8.9 Metrics/logging fields likely needed

At minimum include:

- platform
- purpose
- installation_id
- username hash or username when appropriate for auth logs
- user_id after successful login
- enforcement mode
- provider outcome
- verdict class
- challenge age
- session installation id
- revoke status
- degraded-mode reason

## 9. Rollout Modes

Recommended single mode flag:

- `disabled`
  - no app-proof requirement
  - no blocking
  - mobile login behaves as today
- `report_only`
  - collect challenges and proof data
  - log missing proof, bad verdicts, unsupported devices, and mismatches
  - still issue sessions without valid proof
- `soft_enforce`
  - require valid proof for new/healthy flows
  - allow bounded degraded-mode exceptions for previously trusted installations during provider outages or explicitly configured unsupported-device grace
  - every exception must log loudly
- `enforce_login`
  - require valid proof for mobile bearer-token session issuance
  - reject missing or invalid proof
  - only allow degraded-mode exceptions if the product explicitly accepts them
- `enforce_all_authenticated`
  - everything in `enforce_login`
  - also reject authenticated mobile requests whose installation binding is missing, mismatched, revoked, or stale according to policy

Optional later split if needed:

- `APP_PROOF_REQUIRE_ON_ADMIN_BEARER_LOGIN`
- `APP_PROOF_REQUIRE_ON_USER_BEARER_LOGIN`

But the default recommendation is one common mobile bearer-login policy so admin API bearer login does not become a permanent exception.

## 10. Failure Modes and Recovery

### Google or Apple outage

- `report_only`: log and allow.
- `soft_enforce`: allow only previously trusted installations within a bounded grace window; deny first-seen installations.
- `enforce_login`: recommended default is deny first-time enrollment and first-time login without proof, while allowing already-issued sessions to continue until expiry. Whether to allow prior trusted installations to log in during outage is a product choice and should stay explicit.

### Invalid attestation or bad verdict

- Reject.
- This is not an outage case.
- Examples:
  - Android package/cert mismatch
  - Android device integrity missing when required
  - iOS attestation/assertion signature failure
  - nonce/challenge mismatch
  - reused challenge

### Stale device state

- Mark installation as stale if it has not produced a successful proof within a configured age.
- In `report_only`, log.
- In stronger modes, require fresh login proof before new session issuance.

### App reinstall

- Android reinstall should usually generate a new local `installation_id`.
- iOS reinstall invalidates the App Attest key and must create a new installation enrollment.
- Old installation record remains revocable/auditable but no longer active.

### Changed device

- Treat as new installation.
- Old installation can be revoked separately if desired.

### Revoked enrollment

- Reject new logins from that installation.
- Reject later authenticated requests in `enforce_all_authenticated`.

### Token replay after attested login

- Session-to-installation binding helps detect some misuse, but a stolen bearer token can still be replayed if later request proof-of-possession is not required.
- This remains a residual risk and must be documented honestly.

### Admin recovery / operator support path

- Operator must be able to:
  - revoke one installation
  - clear installation-user binding
  - force re-enrollment
  - temporarily lower mode from `soft_enforce` or `enforce_login` to `report_only`

### Migration for existing installed apps and users

- Ship clients that can perform app-proof challenge/verification before enforcement.
- Keep backend in `report_only` long enough to learn platform coverage and error rates.
- Only then move to `soft_enforce`, then later to `enforce_login`.

## 11. Observability

Required Sprint 7 logs and metrics:

- `app_proof.challenge_issued`
- `app_proof.challenge_consumed`
- `app_proof.challenge_expired`
- `app_proof.verify_success`
- `app_proof.verify_failed`
- `app_proof.invalid_nonce`
- `app_proof.replay_detected`
- `app_proof.installation_revoked_used`
- `app_proof.provider_timeout`
- `app_proof.provider_quota`
- `app_proof.unsupported_device`
- `app_proof.degraded_allow`
- `app_proof.enforcement_blocked`
- `app_proof.session_issued_without_proof`
- `app_proof.session_issued_with_proof`
- `app_proof.installation_binding_mismatch`
- `app_proof.android.play_recognized`
- `app_proof.android.device_integrity_missing`
- `app_proof.ios.attest_success`
- `app_proof.ios.assert_success`
- `app_proof.ios.counter_regression`

Metrics should be sliceable by:

- platform
- app version
- OS version
- enforcement mode
- purpose (`enroll`, `login`, `reauth`)
- provider outcome

## 12. Security Boundaries and Residual Risks

What this improves:

- Blocks generic HTTP clients from obtaining mobile bearer-token sessions in enforce modes unless they can obtain valid platform proof.
- Makes package/bundle identity and request binding cryptographically meaningful.
- Adds per-installation revocation and observability.
- Makes Android replay materially harder through standard-request replay mitigation plus request binding.
- Makes iOS protected requests bind to a server-known App Attest key and monotonic counter.

What this still does not solve:

- A stolen bearer token may still be usable after an attested login if later requests remain bearer-only.
- A live attack routed through a genuine device session can still succeed.
- Rooted/jailbroken device risk is reduced, not eliminated.
- Self-hosted operators can still misconfigure exposure; app proof is not a substitute for allowlists, TLS, and private-network deployment.
- DeviceCheck is not equivalent to App Attest and must not be treated as an enforced substitute.

## 13. Sprint 7 Implementation Blueprint

Implementation outcome on 2026-03-09:

- Backend challenge/verify/login flow landed with installation-bound JWT claims (`aid`, `apm`, `asv`).
- Android client now requests backend challenges, performs Play Integrity standard requests, and includes installation binding on authenticated calls.
- iOS client now stores installation/App Attest material in Keychain, performs App Attest enroll/assert flows when supported, and includes installation binding on authenticated calls.
- Default operator choice for the remaining open admin-bearer timing question is conservative: `APP_PROOF_REQUIRE_ON_ADMIN_BEARER_LOGIN=false` by default in Sprint 7.
- Default soft-enforce grace is `APP_PROOF_DEGRADED_GRACE_SECONDS=86400`.
- Unsupported iOS/App Attest environments are allowed only in `disabled`/`report_only`; they are not treated as an enforced equivalent in `soft_enforce` or `enforce_login`.
- Receipt risk metrics and all-request proof-of-possession remain deferred beyond Sprint 7.

### Backend files likely to change

- `backend/app/main.py`
  - new challenge/proof/login flow
  - installation binding checks
- `backend/app/security.py`
  - JWT claim extensions for installation binding
  - proof-ticket signing/verification helper
- `backend/app/config.py`
  - app-proof settings
- `backend/app/schemas.py`
  - challenge/proof request-response models
- `backend/app/db.py`
  - new installation/challenge tables and queries
- `backend/app/admin_ui.py`
  - optional operator visibility for installation status later
- `backend/tests/*`
  - challenge lifecycle
  - proof mode enforcement
  - login/session binding

### Android files likely to change

- `android-client/app/src/main/java/com/wakefromfar/wolrelay/data/ApiClient.kt`
  - challenge + proof + login calls
- `android-client/app/src/main/java/com/wakefromfar/wolrelay/data/SecurePrefs.kt`
  - durable `installation_id`
- `android-client/app/src/main/java/com/wakefromfar/wolrelay/ui/MainViewModel.kt`
  - login orchestration and degraded-mode UX
- Android build/config files
  - Play Integrity dependency and cloud project config

### iOS files likely to change

- `ios-client/Services/API/APIClient.swift`
  - challenge + proof + login calls
- `ios-client/Services/Auth/SessionStore.swift`
  - enrollment/login orchestration
- `ios-client/Persistence/KeychainStore.swift`
  - durable App Attest key id and installation id storage
- `ios-client/Persistence/AppPreferences.swift`
  - remove any installation identity from plain preferences

### Test plan

Backend automated tests:

- challenge issuance, expiry, and single-use behavior
- report-only versus enforce mode behavior
- login rejected without proof in enforce modes
- revoked installation rejected
- installation/session version mismatch rejected
- Android request-hash mismatch rejected
- iOS nonce mismatch rejected
- iOS counter regression rejected

Manual/QA:

- Android happy path with valid Play Integrity verdict
- Android degraded path for transient Play services/network errors
- iOS first install App Attest enrollment
- iOS repeated login with assertion only
- reinstall on iOS creates fresh enrollment
- admin bearer login under report-only and enforce modes

### Migration steps

1. Ship backend challenge/proof endpoints in `disabled`.
2. Ship Android and iOS clients that use them.
3. Enable `report_only` in test/beta.
4. Measure unsupported-device rate, provider failures, and false negatives.
5. Move to `soft_enforce`.
6. Only after stable evidence, move selected deployments to `enforce_login`.

### Release-gate checklist

- official package/bundle identifiers configured correctly
- Android signing cert digest configured correctly
- Google Play Integrity decode path verified
- iOS App Attest entitlement and server validation verified
- rollout metrics visible in `/admin/metrics` or equivalent
- documented operator recovery path exists
- admin bearer-login behavior explicitly tested

### Rough work breakdown

1. Backend data model and config
2. Challenge and proof verification endpoints
3. JWT/session binding changes
4. Android Play Integrity integration
5. iOS App Attest enrollment + assertion integration
6. Tests, observability, docs, and rollout runbook

## 14. Open Questions

1. Should Android `appLicensingVerdict == LICENSED` become required in the first enforce phase, or only recorded initially?
2. What exact degraded-mode grace window is acceptable for previously trusted installations during provider outages?
3. Should unsupported iOS App Attest environments ever be allowed past `soft_enforce`, or should they remain permanently blocked once `enforce_login` is enabled?
4. Should admin bearer-token logins move to enforcement at the same time as user bearer-token logins, or one release later after telemetry settles?
5. Does Sprint 7 need an operator-facing installation revocation UI, or is CLI/admin API enough for the first release?
6. Should iOS App Attest receipt risk metrics be part of Sprint 7 or explicitly deferred to Sprint 8+?
7. Should later privileged request classes use a dedicated `reauth` assertion before any future move toward all-request proof-of-possession?

## Primary Sources

- Google Play Integrity overview: <https://developer.android.com/google/play/integrity/overview>
- Google Play Integrity standard requests: <https://developer.android.com/google/play/integrity/standard>
- Google Play Integrity verdicts: <https://developer.android.com/google/play/integrity/verdicts>
- Google Play Integrity setup: <https://developer.android.com/google/play/integrity/setup>
- Google Play Integrity standard error codes: <https://developer.android.com/google/play/integrity/reference/com/google/android/play/core/integrity/model/StandardIntegrityErrorCode>
- Apple Security Overview, DeviceCheck and App Attest: <https://developer.apple.com/security/>
- Apple WWDC21, "Mitigate fraud with App Attest and DeviceCheck": <https://developer.apple.com/videos/play/wwdc2021/10244/>
