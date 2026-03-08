# WakeFromFar Detailed Implementation Plan (Historical / Superseded)

This document is retained as historical context only.

Use `/Users/max/projekte/wakefromfar/refactorplan.md` for current refactor work.

The following assumptions in this older plan are now superseded:

- preserving DB history through additive migrations
- keeping `/hosts` and other compatibility endpoints during a migration window
- planning around a production-compatible rollout instead of a disposable pre-production rebuild

## 1. Objective

Deliver a production-ready v1 where:

- Non-technical Android users can wake assigned devices with minimal setup.
- System/network admins manage hosts, users, assignments, and diagnostics in a more technical admin panel.
- Device power state is part of v1, including "already on" handling before sending WoL.

## 2. Personas and Core Journeys

### 2.1 End User (non-technical)

- Installs Android app.
- Opens invite link / scans QR.
- Logs in once.
- Sees only "My Devices" with clear status (`On`, `Off`, `Unknown`).
- Taps `Wake`.
- If device is already on, sees "Device is already on" instead of a fake success.

### 2.2 Admin (technical)

- Logs into web admin panel.
- Creates and manages users/devices.
- Configures network details (MAC, broadcast/subnet/interface).
- Configures power-state check method per device.
- Assigns devices to users/groups.
- Generates invites and reviews wake/audit logs.

## 3. v1 Scope

### 3.1 In Scope

- Android onboarding by invite (deep link + optional QR scanning).
- Role-based access (`admin`, `user`).
- User-to-device assignment model.
- Technical admin panel (web) for users/devices/assignments/invites/logs.
- Device power-state checks in API and Android UI.
- Wake action with pre-check:
  - If `On`, return `already_on` and do not send magic packet.
  - If `Off`/`Unknown`, send magic packet and return action result.
- Audit logs for wake and power check outcomes.

### 3.2 Out of Scope (v1)

- Native iOS app.
- Multi-tenant organization model.
- Push notifications.
- Guaranteed real-time state stream (polling/cached checks only in v1).

## 4. Technical Architecture (Target)

- **Backend**: FastAPI + SQLite (current), API + server-rendered admin views.
- **Android**: Kotlin/Compose, invite-first UX, "My Devices" experience.
- **Network**: Tailscale-only access + IP allowlist + host firewall on `tailscale0`.
- **Power state**: Backend probes from LAN-adjacent host using configurable method per device.

## 5. Data Model Changes

Historical note: this migration-based schema plan is superseded by the clean-slate refactor plan. Upcoming work should implement the target schema directly and reset local DBs instead of extending migration history for old local states.

### 5.1 New Tables

- `user_device_access`
  - `user_id` (FK users.id)
  - `device_id` (FK hosts.id)
  - unique `(user_id, device_id)`
- `invite_tokens`
  - `id` (uuid)
  - `token_hash`
  - `username`
  - `backend_url_hint`
  - `expires_at`
  - `claimed_at` (nullable)
  - `created_by`
  - `created_at`
- `power_check_logs`
  - `id` (autoincrement)
  - `device_id`
  - `method` (`tcp`, `icmp`)
  - `result` (`on`, `off`, `unknown`)
  - `detail`
  - `latency_ms` (nullable)
  - `created_at`

### 5.2 Existing Table Changes

- `hosts` add:
  - `display_name` (nullable, for user-facing naming if needed)
  - `check_method` (`tcp`, `icmp`, default `tcp`)
  - `check_target` (IP or hostname in LAN, optional if derivable)
  - `check_port` (nullable; required for `tcp`)
  - `last_power_state` (`on`, `off`, `unknown`, default `unknown`)
  - `last_power_checked_at` (nullable)
- `wake_logs` add:
  - `result` (`sent`, `already_on`, `failed`)
  - `error_detail` (nullable)
  - `precheck_state` (`on`, `off`, `unknown`)

## 6. API Plan

### 6.1 End-User API

- `POST /onboarding/claim`
  - Input: invite token + desired password (or temporary credential flow).
  - Output: JWT + profile + backend URL hint.
- `GET /me/devices`
  - Returns only assigned devices with power state fields.
- `POST /me/devices/{id}/wake`
  - Server runs pre-check:
    - `on` => return `result=already_on`.
    - else try WoL => `result=sent` or `failed`.
- `POST /me/devices/{id}/power-check` (optional for manual refresh)
  - Returns current state from fresh probe.

### 6.2 Admin API

- User management:
  - `GET/POST/PATCH/DELETE /admin/users`
- Device management:
  - `GET/POST/PATCH/DELETE /admin/devices`
- Assignment management:
  - `POST /admin/assignments`
  - `DELETE /admin/assignments/{user_id}/{device_id}`
- Invite management:
  - `POST /admin/invites`
  - `GET /admin/invites`
  - `POST /admin/invites/{id}/revoke`
- Logs:
  - `GET /admin/wake-logs`
  - `GET /admin/power-check-logs`

### 6.3 Backward Compatibility

Superseded by the clean-slate refactor plan:

- do not preserve `/hosts` or `/hosts/{id}/wake` for a migration period
- remove compatibility endpoints when the refactor branch cuts over

## 7. Device Power-State Design (v1)

### 7.1 Required Behavior

- App must show a best-effort state badge per device.
- Wake call must avoid sending WoL when device is already on.

### 7.2 Probe Methods

- `tcp` (default): connect to configured `check_target:check_port` with short timeout.
- `icmp` (optional): ping `check_target` if environment supports it.

Admin chooses method per device. Default to `tcp` because it avoids raw-socket privilege issues in many deployments.

### 7.3 State Evaluation

- `On`: successful TCP connect or successful ICMP echo.
- `Off`: timeout/refused based on method-specific rules.
- `Unknown`: config missing, DNS failure, probe exception, or policy block.

### 7.4 Caching and Freshness

- Cache power state on host record.
- Freshness TTL: 20 seconds.
- `GET /me/devices`: reuse cached state if fresh, otherwise probe in background and return current cached + `is_stale` flag.
- `POST .../wake`: always perform a fresh check before sending magic packet.

### 7.5 Wake Flow

1. Authorize user + verify assignment.
2. Perform fresh power check.
3. If `on`: log `already_on`, return early.
4. If `off/unknown`: send WoL packet.
5. Log result and return response with outcome message.

## 8. Admin Panel Plan (Server-Rendered v1)

### 8.1 Views

- Dashboard (quick stats, failed wakes, stale devices).
- Devices list + detail (network + power-check config).
- Users list + detail.
- Assignments matrix.
- Invite generation (link + QR code).
- Wake and power-check logs.

### 8.2 UX Principles

- Technical labels are acceptable.
- Strong validation with inline error details.
- Fast keyboard workflow for admins (forms, filtering, bulk assignment).

## 9. Android Plan (Non-Technical v1)

### 9.1 Onboarding

- Add app link/deep link handling.
- Parse invite data and prefill backend URL.
- Single clear onboarding path: claim account -> sign in -> show devices.

### 9.2 Main UI

- Screen title: "My Devices".
- Device card:
  - Name
  - Power badge (`On`, `Off`, `Unknown`)
  - Last checked text
  - Primary `Wake` button
- Pull-to-refresh for status updates.
- Plain-language errors only.

### 9.3 Interaction Rules

- Disable `Wake` button while wake request is in progress.
- If API returns `already_on`, show explicit success message.
- Persist session securely (existing EncryptedSharedPreferences remains).

## 10. Security and Compliance

- Keep IP allowlist/Tailscale restrictions enabled in production.
- Add admin action audit entries (create/edit/delete, invite revoke).
- Password rules:
  - min length 12 for admin-created accounts.
- Token policy:
  - Shorten access token lifetime (for example 8h) + refresh token flow, or keep 24h for v1 with forced re-login on sensitive failures.
- Rate limits:
  - Extend beyond login to onboarding claim and wake endpoint.

## 11. Sprint Plan (3 Sprints, 2 Weeks Each)

Historical note: this sprint plan predates the clean-slate reset strategy and should not be used for current sprint execution.

Sprint cadence:

- Sprint length: 2 weeks
- Ceremony baseline: Sprint Planning (Day 1), Mid-sprint review (Day 5-6), Sprint Review + Retrospective (Day 10)
- Release strategy: internal release after Sprint 2, production release after Sprint 3

### 11.1 Sprint 1 (Weeks 1-2): Backend Foundation + Power-State Core

Sprint goal:

- Establish the new data model and API foundations, including v1 power-state checks and `already_on` wake behavior.

Backlog items:

- DB migration framework with schema version table.
- Add new tables: `user_device_access`, `invite_tokens`, `power_check_logs`.
- Extend `hosts` and `wake_logs` with power-check and wake result fields.
- Implement assignment authorization layer for "only assigned devices".
- Implement power-check service (`tcp` method first) with timeout and error mapping.
- Add new user endpoints:
  - `GET /me/devices`
  - `POST /me/devices/{id}/wake` with pre-check and `already_on`
  - `POST /me/devices/{id}/power-check` (manual refresh)
- Add initial admin endpoints for users/devices/assignments/invites (API only, no UI yet).
- Keep old `/hosts` endpoints and mark deprecated in API docs.

Definition of done:

- Historical only: this older plan expected migrations on fresh and existing DBs; the active clean-slate plan prefers DB rebuilds.
- Wake endpoint returns one of: `already_on`, `sent`, `failed`.
- Authorization tests prove users cannot wake unassigned devices.
- Unit + integration tests for power-check and wake pre-check pass in CI.

Sprint review demo:

- API demo showing:
  - assigned device listing
  - device already-on response
  - successful magic packet send for off device
  - audit row creation

### 11.2 Sprint 2 (Weeks 3-4): Admin Panel + Android Onboarding

Sprint goal:

- Deliver admin-operable setup and a non-technical onboarding path in Android.

Backlog items:

- Build server-rendered admin panel with auth guards.
- Admin pages:
  - users CRUD
  - devices CRUD (including network and power-check config)
  - assignments management
  - invite generation with QR
  - wake + power-check log views with filters
- Add admin-side validation and "test power-check" action on device detail.
- Android:
  - deep link / app link handling for invite onboarding
  - onboarding claim flow to obtain session
  - switch primary feed from generic hosts to "My Devices"
  - show power-state badge and last-checked time
  - handle `already_on` response with explicit user message

Definition of done:

- Admin can configure a new device and assign it without CLI usage.
- Fresh Android install can complete invite onboarding without manual backend URL entry.
- Android list only displays assigned devices and renders state badges.
- Logs visible in admin panel for wake and power checks.

Sprint review demo:

- End-to-end demo:
  - Admin creates user/device/assignment/invite
  - User opens invite and logs in
  - User triggers wake and sees already-on or sent result
  - Admin sees corresponding logs

### 11.3 Sprint 3 (Weeks 5-6): Hardening, Pilot, and Release

Sprint goal:

- Stabilize behavior in real networks and ship production-ready v1.

Backlog items:

- Security hardening:
  - tighten token/session policy
  - extend rate limits to onboarding + wake endpoints
  - improve sensitive action audit coverage
- Reliability hardening:
  - retry/backoff policy where applicable
  - improved failure categorization (`off` vs `unknown`)
  - graceful fallback when power checks are misconfigured
- Observability:
  - structured logs and key counters
  - admin diagnostics hints for common misconfigurations
- Pilot rollout with 5-10 non-technical users in staging/real tailnet.
- Fix pilot findings and finalize operational runbook/checklist.

Definition of done:

- >= 90% pilot users complete first successful wake within 2 minutes.
- No critical auth/access bugs open.
- Known high-severity pilot issues are fixed or accepted with mitigation.
- Production deployment checklist completed and dry-run validated.

Sprint review demo:

- Pilot metrics report, final walkthrough of onboarding + wake + admin troubleshooting.

## 12. Testing Strategy

### 12.1 Backend

- Unit tests:
  - MAC normalization, target resolution, power-check methods.
  - Assignment authorization logic.
- Integration tests:
  - Invite claim flow.
  - Wake pre-check (`already_on`, `sent`, `failed`).
  - Admin CRUD lifecycle.

### 12.2 Android

- ViewModel tests:
  - Onboarding success/failure.
  - Wake state transitions and user messaging.
- UI tests:
  - Device list renders power badge states.
  - Wake button disabled during request.

### 12.3 End-to-End

- Staging tailnet with at least:
  - 1 always-on host
  - 1 sleeping WoL-capable host
  - 1 unreachable host (unknown/off scenarios)

## 13. Operational Runbook (v1)

- Backup SQLite database daily.
- Document how to configure host firewall + Tailscale ACL.
- Provide admin troubleshooting page for:
  - invalid MAC
  - wrong broadcast/subnet
  - power-check misconfiguration
  - unreachable backend

## 14. Risks and Mitigations

- **Risk**: Power state false positives/negatives.
  - Mitigation: configurable check method and target; explicit `Unknown` state.
- **Risk**: ICMP may require extra privileges.
  - Mitigation: default `tcp` method; enable ICMP only where environment supports it.
- **Risk**: Non-technical users blocked by manual setup.
  - Mitigation: invite/deep-link onboarding and simplified UI copy.
- **Risk**: Admin misconfiguration of network fields.
  - Mitigation: validation + test button in admin device form.

## 15. Release Gates (Must Pass for v1)

- End users only see assigned devices.
- Wake endpoint returns `already_on` when applicable.
- Android shows power state badges and clear wake outcomes.
- Admin can complete full setup without CLI usage.
- Audit logs contain actor, device, result, timestamp.
