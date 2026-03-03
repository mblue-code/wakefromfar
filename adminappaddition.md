# Admin App Additions: Detailed Implementation Plan and Sprint Breakdown

> Decision update (March 3, 2026): Firebase push is out of scope. Admin notifications are backend-driven in-app notices based on `/admin/mobile/events` polling while the app is online.

## 1. Objective

Extend the Android app with an **admin mode** that includes:

- Compact activity feed (`who did what when`) tailored for mobile.
- In-app admin notifications for key events (initially wake + shutdown poke).
- A non-destructive "poke admin to shutdown" flow for regular users.
- Explicit support for admins keeping all normal user capabilities (including waking machines).

This intentionally avoids remote shutdown execution and privileged host actions.

## 2. Product Scope

### 2.1 In Scope

- Admin user can use all current "normal user" machine actions in Android (`/me/devices`, wake flow).
- Admin-only compact event feed in Android.
- Backend activity event model + API for mobile feed.
- Admin in-app notifications via backend activity polling.
- User "Finished, request shutdown" action that notifies admin (no shutdown automation).
- Basic read/acknowledge state for poke requests.

### 2.2 Out of Scope

- Automatic shutdown execution on hosts.
- Host-level privileged agents/services.
- Per-app, per-service deep usage analytics (Plex session introspection remains future scope).
- iOS implementation.

## 3. Current-State Notes (Repo-Aligned)

- Backend already has role-based auth (`admin`, `user`) and `/me/devices` already returns all hosts for admins.
- Backend already logs wake actions and admin audit actions.
- Android app currently consumes `/me/devices` and wake APIs; admin activity and in-app notification UX are being expanded.

Implication: admin wake capability is mostly present server-side; the work is mainly mobile UX + event pipeline.

## 4. Target Architecture

### 4.1 Backend

- Add new `activity_events` table (single stream for compact mobile feed).
- Emit activity events from existing backend actions:
  - wake requested/sent/failed/already_on
  - shutdown poke requested
  - optional future: login success, assignment changes
- Provide admin-only feed endpoint with pagination and compact projection.
- Provide endpoints for:
  - create poke request
  - mark poke request seen/resolved

### 4.2 Android

- Decode role from JWT claims to enable admin UI sections without extra roundtrip.
- Keep existing "My Devices" screen for all users (including admins).
- Add admin-only "Activity" tab:
  - compact event rows
  - filter chips (Wake, Pokes, Errors, All)
  - server grouping (optional in v1)
- Add user action on device card: `Request shutdown (notify admin)`.
- Add in-app notification behavior:
  - poll activity endpoint while admin app is online
  - surface new events as compact in-app notices
  - open Activity tab to review details

## 5. Data Model and Migrations

### 5.1 New Tables

- `activity_events`
  - `id` INTEGER PK
  - `event_type` TEXT (e.g. `wake_sent`, `wake_failed`, `shutdown_poke_requested`)
  - `actor_user_id` INTEGER nullable
  - `actor_username` TEXT
  - `target_type` TEXT (`device`, `system`, `request`)
  - `target_id` TEXT nullable
  - `server_id` TEXT nullable (host id when relevant)
  - `summary` TEXT (short human-readable sentence)
  - `metadata_json` TEXT (small JSON for details)
  - `created_at` TEXT (UTC ISO timestamp)
- `shutdown_poke_requests`
  - `id` TEXT PK (uuid)
  - `server_id` TEXT NOT NULL
  - `requester_user_id` INTEGER NOT NULL
  - `requester_username` TEXT NOT NULL
  - `message` TEXT nullable
  - `status` TEXT CHECK(`open`,`seen`,`resolved`) default `open`
  - `created_at` TEXT
  - `seen_at` TEXT nullable
  - `resolved_at` TEXT nullable
  - `resolved_by_user_id` INTEGER nullable

### 5.2 Indexes

- `activity_events(created_at DESC)`
- `activity_events(event_type, created_at DESC)`
- `activity_events(server_id, created_at DESC)`
- `shutdown_poke_requests(status, created_at DESC)`

## 6. API Additions

### 6.1 Auth/Profile

- Keep existing auth endpoints.
- Add optional `GET /me/profile` returning `{id, username, role}` for cleaner mobile role handling (recommended).

### 6.2 Activity Feed

- `GET /admin/mobile/events?cursor=<id>&limit=50&type=wake,poke,error`
  - Admin-only.
  - Returns compact records sorted newest-first.
  - Cursor pagination by `id` for stable mobile paging.

### 6.3 Shutdown Poke Flow

- `POST /me/devices/{host_id}/shutdown-poke`
  - Allowed for assigned users and admins.
  - Creates `shutdown_poke_requests` row.
  - Emits `activity_events` entry.
  - Becomes visible to admin app polling flow.
- `GET /admin/shutdown-pokes?status=open&limit=50`
  - Admin-only list for activity follow-up.
- `POST /admin/shutdown-pokes/{id}/seen`
- `POST /admin/shutdown-pokes/{id}/resolve`

## 7. Event Emission Design

- Introduce helper `emit_activity_event(...)` in backend service layer.
- Call helper in:
  - wake endpoint paths (`already_on`, `sent`, `failed`)
  - shutdown poke creation endpoint
  - optional admin mutations later
- Keep payload compact and deterministic.
- Keep event production idempotent where possible to avoid duplicate UI notices during retry paths.

## 8. Security and Privacy

- Admin feed endpoints require admin role.
- Non-admins can only create poke requests on authorized devices.
- Activity summaries must not include sensitive network values (MAC, private IP, broadcast).
- Add audit entries for poke state transitions (`seen`, `resolved`).

## 9. Android UX Specification

### 9.1 Navigation

- Keep existing authenticated device list as default.
- Add top-level tabs:
  - `Devices` (all users)
  - `Activity` (admins only)

### 9.2 Activity Row Format

- One-line title:
  - `"Max woke Plex Server"`
  - `"Lena requested shutdown for Plex Server"`
- Secondary line:
  - relative time + optional status (`open`, `seen`, `resolved` for pokes)

### 9.3 Device Card Addition

- Add secondary action button:
  - `Request shutdown`
- Tap opens small confirm dialog with optional short note.
- Success feedback:
  - `"Admin notified"`

### 9.4 In-App Notification Behavior

- While admin app session is online: poll activity feed at fixed interval (for example, 30s).
- If new events arrive: show compact in-app snackbar/banner and refresh feed list.
- If app is offline/backgrounded: no guaranteed delivery; events appear on next foreground refresh.

## 10. Delivery Plan by Sprint

Assume 2-week sprints. Team can run backend + Android in parallel after migration contracts are set.

### 10.1 Proposed Calendar (if started March 9, 2026)

| Sprint | Dates | Primary Outcome |
| --- | --- | --- |
| Sprint 1 | March 9-20, 2026 | Event pipeline + admin activity tab baseline |
| Sprint 2 | March 23-April 3, 2026 | Android in-app notification polling + wake event notice UX |
| Sprint 3 | April 6-17, 2026 | Shutdown poke flow end-to-end |
| Sprint 4 | April 20-May 1, 2026 | Hardening, QA, rollout readiness |

### 10.2 Dependency Order

- Sprint 1 migration and feed API must land before Android activity feed can stabilize.
- Sprint 2 polling/notice UX depends on stable event IDs and pagination contracts from Sprint 1.
- Sprint 3 poke actions depend on Sprint 1 event infrastructure and Sprint 2 in-app notice baseline.
- Sprint 4 release checklist depends on all endpoint contracts being frozen.

## Sprint 1: Event Foundations + Admin Capability Baseline

### Goals

- Ensure admin retains full normal-user wake flow in Android.
- Introduce backend activity event storage and minimal read API.

### Backend Tasks

- Add migration `v6` for `activity_events`.
- Implement `emit_activity_event`.
- Emit events from `/me/devices/{host_id}/wake` outcomes.
- Add `GET /admin/mobile/events` with pagination and filters.
- Add tests for auth, pagination, and event writes.

### Android Tasks

- Decode JWT role from token (or call `/me/profile` if implemented).
- Add role-aware UI state (`isAdmin`).
- Preserve existing wake UX for admins in `Devices` tab.
- Create basic `Activity` tab with list rendering.

### Acceptance Criteria

- Admin logs in and can wake machines exactly like normal user.
- Wake actions produce visible admin feed rows within one refresh cycle.
- Non-admin cannot access admin feed API.

## Sprint 2: In-App Notification Infrastructure + Wake Notices

### Goals

- Deliver wake-related admin notices reliably while app is online, without third-party push services.

### Backend Tasks

- Ensure `GET /admin/mobile/events` supports efficient polling (`cursor`, `limit`, stable ordering).
- Extend wake event metadata to support compact mobile notice text.
- Add/update tests for repeated polling and cursor correctness.

### Android Tasks

- Add periodic polling while admin session is active.
- Track last seen event id locally and compute new-event delta.
- Show in-app snackbar notice for new events.
- Keep manual refresh + activity tab behavior consistent.

### Acceptance Criteria

- Admin receives an in-app wake notice within one poll cycle while online.
- Repeated polls do not duplicate already seen notices.
- New notices still appear after app restart with preserved last-seen state.

## Sprint 3: Shutdown Poke End-to-End

### Goals

- Deliver user-requested shutdown poke workflow with admin review controls.

### Backend Tasks

- Add migration `v8` for `shutdown_poke_requests`.
- Add `POST /me/devices/{host_id}/shutdown-poke`.
- Add admin list and state transition endpoints (`seen`, `resolve`).
- Emit corresponding activity events for mobile feed + notice polling.
- Add authorization tests (assigned users only; admins all devices).

### Android Tasks

- Add `Request shutdown` action in device card.
- Add optional message field in confirmation dialog.
- Add Activity tab row actions for admins:
  - mark as seen
  - mark as resolved
- Update filters/chips for poke status.

### Acceptance Criteria

- User can submit poke for authorized device only.
- Admin sees poke event in activity list and receives in-app notice while online.
- Admin can transition poke state and transitions are persisted.

## Sprint 4: Hardening, Polish, and Rollout

### Goals

- Production readiness and UX polish.

### Backend Tasks

- Add rate limits for new endpoints (`shutdown-poke` and related state transitions).
- Add metrics counters:
  - `activity_events.created`
  - `activity_feed.poll_requests`, `activity_feed.poll_errors`
  - `shutdown_pokes.open/resolved`
- Backfill utility (optional) to synthesize recent wake logs into activity stream for initial UI population.
- Documentation updates in `README`/`docs`.

### Android Tasks

- Improve list perf (paging/incremental load).
- Empty/error states for Activity tab.
- Localization additions (`strings.xml`, `values-de/strings.xml`).
- QA pass for app lifecycle (polling start/stop, app resume, offline recovery).

### Acceptance Criteria

- New endpoints covered by automated tests and pass in CI.
- No role escalation paths found in security review.
- Pilot admins confirm feed readability and useful notification signal-to-noise ratio.

## 11. Test Strategy

- Backend unit/integration:
  - event creation correctness
  - role/access enforcement
  - poke state machine (`open -> seen -> resolved`)
  - mobile feed cursor/polling correctness
- Android instrumentation/manual:
  - admin vs user UI separation
  - in-app notice behavior during periodic polling
  - wake + poke flows with offline/timeout handling

## 12. Risks and Mitigations

- No realtime alerts while app is offline/backgrounded.
  - Mitigation: in-app feed is source of truth; show catch-up notices on next foreground sync.
- Notice spam for frequent wakes.
  - Mitigation: client-side batching/coalescing of notice text and configurable poll interval later.
- Role mismatch due to stale token.
  - Mitigation: validate role server-side on every admin endpoint; refresh token on login.

## 13. Definition of Done

- Admin can wake machines from Android exactly as regular users can.
- Admin has a compact, mobile-optimized "who did what when" feed.
- Wake and shutdown-poke in-app notices appear for online admin sessions.
- No automatic shutdown execution is introduced.
- Documentation and release checklist updated with operational guidance.
