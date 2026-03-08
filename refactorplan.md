# WakeFromFar Clean-Slate Refactor Plan

Status: implemented through Sprint 7 on 2026-03-08; retained as the canonical refactor record and future-work boundary.

Current end-state summary:

- legacy `/hosts` and `/admin/hosts` endpoints are removed
- memberships are the only supported device-access model
- admin scheduled wake CRUD ships in API and admin UI
- Android and iPhone consume the same `/me/devices` contract with read-only `scheduled_wake_summary`

This document replaces the older incremental mindset. It assumes:

- there is no production deployment yet
- the current test system can be rebuilt at any time
- backend, Android, iPhone, and admin UI can move together
- we prefer simpler long-term architecture over compatibility shims

## 1. Refactor Goals

This refactor should deliver four concrete product outcomes:

1. Per-device permissions instead of the current binary assignment model.
2. Better user-facing device organization with favorites and grouped device lists.
3. Scheduled wake jobs managed by admins.
4. A cleaner backend contract that removes legacy endpoints and duplicated concepts.

Secondary goals:

- reduce code paths that only exist for backward compatibility
- keep auth and security posture unchanged or stricter
- keep the admin UI as the primary control plane for technical configuration
- make Android and iPhone clients consume the same device contract

## 2. Current Baseline

The current codebase already has these important building blocks:

- FastAPI backend with auth, devices, power checks, wake flow, activity feed, shutdown poke flow, and admin UI
- Android client with login, device list, wake, activity feed, shutdown request flow, and settings
- iPhone client with native SwiftUI device list, wake flow, shutdown request flow, and admin activity flow
- server-rendered admin UI for device management, user management, assignments, and discovery

Key current files:

- `backend/app/db.py`
- `backend/app/main.py`
- `backend/app/schemas.py`
- `backend/app/admin_ui.py`
- `android-client/app/src/main/java/com/wakefromfar/wolrelay/data/ApiClient.kt`
- `android-client/app/src/main/java/com/wakefromfar/wolrelay/ui/MainViewModel.kt`
- `android-client/app/src/main/java/com/wakefromfar/wolrelay/ui/WolRelayApp.kt`
- `ios-client/Services/API/APIClient.swift`
- `ios-client/Services/API/Models.swift`
- `ios-client/Features/Devices/DevicesView.swift`
- `ios-client/Features/Devices/DevicesViewModel.swift`

The current weak point is the domain model around device access:

- `user_device_access` only answers "is assigned?"
- favorites do not exist as a first-class backend concept
- permissions are effectively inferred from global role plus assignment
- schedules do not exist

That is the part we should redesign cleanly.

## 3. Core Design Decisions

### 3.1 Keep global user roles

Keep `admin` and `user` roles. Do not invent organization-level roles right now.

- `admin` keeps full device access and full control over admin APIs
- `user` gets device-specific capabilities through memberships

### 3.2 Replace assignments with memberships

The current assignment model should be replaced by a richer `device_memberships` table.

This new table should own:

- whether a user is linked to a device at all
- which actions they can perform
- whether they favorited the device
- how the device is sorted for that user

### 3.3 Treat favorites as user-device state, not device metadata

Favorites are user-specific. They should not live on the device row itself.

### 3.4 Keep groups simple

Keep `group_name` on the device record for now.

Do not create a dedicated `device_groups` table in this refactor unless later needs force it. The current `group_name` concept is sufficient for:

- grouped list presentation
- group filtering
- optional group wake later

### 3.5 Scheduled wake only

Do not add generic remote command execution, script hooks, remote shutdown actions, or arbitrary automation. This refactor only adds scheduled wake jobs.

### 3.6 Clean cut over compatibility

Because the system is disposable:

- we can rebuild the DB
- we can remove deprecated endpoints
- we can update clients and backend in the same branch
- we should not spend time on compatibility layers that permanently complicate the codebase

## 4. Target Data Model

This section describes the target schema, not an additive migration path.

### 4.1 `users`

Keep the current table shape with only small cleanup if needed.

Fields:

- `id INTEGER PRIMARY KEY AUTOINCREMENT`
- `username TEXT UNIQUE NOT NULL`
- `password_hash TEXT NOT NULL`
- `role TEXT NOT NULL CHECK(role IN ('admin', 'user'))`
- `token_version INTEGER NOT NULL DEFAULT 0`
- `created_at TEXT NOT NULL`

Notes:

- no change in auth model is required
- password and token invalidation logic can stay structurally the same

### 4.2 `devices`

We can continue using the physical table name `hosts` internally if that is cheaper, but the domain concept and API contract should move to `devices`.

Required fields:

- `id TEXT PRIMARY KEY`
- `name TEXT NOT NULL`
- `display_name TEXT`
- `mac TEXT NOT NULL`
- `group_name TEXT`
- `broadcast TEXT`
- `subnet_cidr TEXT`
- `udp_port INTEGER NOT NULL DEFAULT 9`
- `interface TEXT`
- `source_ip TEXT`
- `source_network_cidr TEXT`
- `check_method TEXT NOT NULL CHECK(check_method IN ('tcp', 'icmp')) DEFAULT 'tcp'`
- `check_target TEXT`
- `check_port INTEGER`
- `last_power_state TEXT NOT NULL CHECK(last_power_state IN ('on', 'off', 'unknown')) DEFAULT 'unknown'`
- `last_power_checked_at TEXT`
- `provisioning_source TEXT NOT NULL DEFAULT 'manual' CHECK(provisioning_source IN ('manual', 'discovery'))`
- `discovery_confidence TEXT CHECK(discovery_confidence IN ('high', 'medium', 'low', 'unknown'))`
- `last_discovered_at TEXT`
- `created_at TEXT NOT NULL`
- `updated_at TEXT NOT NULL`

Notes:

- `updated_at` should be added for easier auditing and sync semantics
- the current discovery-related columns should stay because they already fit the future model

### 4.3 `device_memberships`

This is the central new table and replaces `user_device_access`.

Fields:

- `id TEXT PRIMARY KEY`
- `user_id INTEGER NOT NULL`
- `device_id TEXT NOT NULL`
- `can_view_status INTEGER NOT NULL DEFAULT 1`
- `can_wake INTEGER NOT NULL DEFAULT 1`
- `can_request_shutdown INTEGER NOT NULL DEFAULT 1`
- `can_manage_schedule INTEGER NOT NULL DEFAULT 0`
- `is_favorite INTEGER NOT NULL DEFAULT 0`
- `sort_order INTEGER NOT NULL DEFAULT 0`
- `created_at TEXT NOT NULL`
- `updated_at TEXT NOT NULL`

Constraints and indexes:

- `UNIQUE(user_id, device_id)`
- index on `(user_id, is_favorite DESC, sort_order ASC, updated_at DESC)`
- index on `(device_id)`

Notes:

- permission flags are integers for SQLite friendliness
- `sort_order` is user-specific
- favorite state is user-specific
- no separate preference table is needed

### 4.4 `scheduled_wake_jobs`

Fields:

- `id TEXT PRIMARY KEY`
- `device_id TEXT NOT NULL`
- `created_by_user_id INTEGER NOT NULL`
- `label TEXT NOT NULL`
- `enabled INTEGER NOT NULL DEFAULT 1`
- `timezone TEXT NOT NULL`
- `days_of_week_json TEXT NOT NULL`
- `local_time TEXT NOT NULL`
- `next_run_at TEXT`
- `last_run_at TEXT`
- `created_at TEXT NOT NULL`
- `updated_at TEXT NOT NULL`

Constraints and indexes:

- index on `(enabled, next_run_at)`
- index on `(device_id, enabled)`

Notes:

- `local_time` should use `HH:MM`
- `days_of_week_json` can store an array like `["mon","tue","wed"]`
- compute `next_run_at` server-side only

### 4.5 `scheduled_wake_runs`

Fields:

- `id TEXT PRIMARY KEY`
- `job_id TEXT NOT NULL`
- `device_id TEXT NOT NULL`
- `started_at TEXT NOT NULL`
- `finished_at TEXT`
- `result TEXT NOT NULL CHECK(result IN ('sent', 'already_on', 'failed', 'skipped'))`
- `detail TEXT`
- `wake_log_id INTEGER`

Indexes:

- index on `(job_id, started_at DESC)`
- index on `(device_id, started_at DESC)`

Notes:

- this table is separate from `wake_logs` because it tracks scheduler intent and execution outcome
- `wake_logs` continues to log the actual wake action

### 4.6 Existing tables to keep

Keep and adapt as needed:

- `wake_logs`
- `power_check_logs`
- `activity_events`
- `shutdown_poke_requests`
- `admin_audit_logs`
- `discovery_runs`
- `discovery_candidates`
- `discovery_events`
- `notification_devices`

### 4.7 DB strategy

Recommended approach for this repo:

1. Implement the target schema directly in `init_db()`.
2. Remove obsolete migration complexity that only existed to preserve older local states.
3. Rebuild the test DB from scratch.
4. Seed representative users and devices manually or through CLI/test fixtures.
5. For Docker-based local work, treat `docker-compose.yml` plus `docker-compose.testing.yml` as the canonical disposable stack and reset it with `docker compose -f docker-compose.yml -f docker-compose.testing.yml down -v`.
6. Do not preserve old migrations or compatibility branches solely to upgrade existing local SQLite files.

This is preferable to adding more migration layers into `backend/app/db.py`.

## 5. Target API Contract

This section describes the desired API shape after the refactor.

### 5.1 Remove legacy endpoints

Remove these endpoints entirely:

- `GET /hosts`
- `POST /hosts/{host_id}/wake`
- `GET /admin/hosts`
- `POST /admin/hosts`

Rationale:

- they duplicate the device-oriented API
- they create extra serialization and auth paths
- they are only valuable for compatibility, which we do not need

### 5.2 Keep auth endpoints

Keep these:

- `POST /auth/login`

Keep the current JWT-based auth approach and bearer middleware.

### 5.3 User device endpoints

#### `GET /me/devices`

Returns only devices that the current user may see through a membership, unless the current user is admin.

Each device should include:

- `id`
- `name`
- `display_name`
- `mac`
- `group_name`
- `last_power_state`
- `last_power_checked_at`
- `is_stale`
- `is_favorite`
- `sort_order`
- `permissions`
  - `can_view_status`
  - `can_wake`
  - `can_request_shutdown`
  - `can_manage_schedule`
- optional `schedule_summary`

Sorting behavior:

- favorites first
- then `group_name`
- then `sort_order`
- then device display label

#### `POST /me/devices/{device_id}/wake`

Authorization:

- allowed for admins
- allowed for users with `can_wake = true`

Behavior:

- preserve current pre-check behavior
- preserve current `already_on | sent | failed` semantics
- emit activity events as today
- log wake attempts as today

#### `POST /me/devices/{device_id}/power-check`

Authorization:

- allowed for admins
- allowed for users with `can_view_status = true`

Behavior:

- preserve current power-check logic

#### `POST /me/devices/{device_id}/shutdown-poke`

Authorization:

- allowed for admins
- allowed for users with `can_request_shutdown = true`

Behavior:

- preserve current shutdown poke lifecycle

#### `PATCH /me/devices/{device_id}/preferences`

Allowed fields:

- `is_favorite`
- `sort_order`

Authorization:

- only for the current user’s own membership row

Purpose:

- lets Android and iPhone persist local device organization in the backend

### 5.4 Admin device endpoints

Keep and standardize:

- `GET /admin/devices`
- `POST /admin/devices`
- `PATCH /admin/devices/{device_id}`
- `DELETE /admin/devices/{device_id}`

Behavior:

- keep current core fields
- return the unified admin device shape
- optionally support query/filter params later

### 5.5 Admin membership endpoints

Replace the current assignment API with a device membership API.

Remove:

- `GET /admin/assignments`
- `POST /admin/assignments`
- `DELETE /admin/assignments/{user_id}/{device_id}`

Add:

- `GET /admin/device-memberships`
- `POST /admin/device-memberships`
- `PATCH /admin/device-memberships/{membership_id}`
- `DELETE /admin/device-memberships/{membership_id}`

Membership payload:

- `user_id`
- `device_id`
- `can_view_status`
- `can_wake`
- `can_request_shutdown`
- `can_manage_schedule`
- `is_favorite`
- `sort_order`

Notes:

- admins should be able to create a membership with any permission combination
- admin UI should expose the capability flags clearly
- `is_favorite` and `sort_order` may be included in admin membership views for debugging and support, even if usually user-managed

### 5.6 Admin scheduled wake endpoints

Add:

- `GET /admin/scheduled-wakes`
- `POST /admin/scheduled-wakes`
- `PATCH /admin/scheduled-wakes/{job_id}`
- `DELETE /admin/scheduled-wakes/{job_id}`
- `GET /admin/scheduled-wakes/runs`

Create/update payload:

- `device_id`
- `label`
- `enabled`
- `timezone`
- `days_of_week`
- `local_time`

Response:

- job fields
- `next_run_at`
- optional latest execution result

### 5.7 Discovery endpoints

Keep the current discovery APIs.

No schema or contract redesign is required in this refactor except:

- when importing candidates, continue mapping into the new canonical device model
- admin UI should route imported devices into the new device management flow naturally

## 6. Backend Implementation Plan

### 6.1 `backend/app/db.py`

Refactor responsibilities:

- simplify schema setup
- remove obsolete assignment model functions
- add membership CRUD
- add membership-aware device listing
- add scheduled wake job and run CRUD

Planned changes:

1. Replace `user_device_access` with `device_memberships`.
2. Add CRUD helpers:
   - `create_device_membership`
   - `update_device_membership`
   - `delete_device_membership`
   - `get_device_membership_by_id`
   - `get_device_membership_for_user_device`
   - `list_device_memberships`
3. Add membership-aware listing helpers:
   - `list_visible_devices_for_user`
   - `list_admin_visible_devices`
4. Add scheduled wake helpers:
   - `create_scheduled_wake_job`
   - `update_scheduled_wake_job`
   - `delete_scheduled_wake_job`
   - `list_scheduled_wake_jobs`
   - `list_due_scheduled_wake_jobs`
   - `mark_scheduled_wake_job_run`
   - `record_scheduled_wake_run`
   - `list_scheduled_wake_runs`
5. Add `updated_at` handling for device and membership updates.

Recommended cleanup:

- keep old migration function names only if needed for readability, but stop treating the DB as an in-place upgraded historical artifact
- if simpler, create a fresh schema initializer and remove dead migration branches

### 6.2 `backend/app/schemas.py`

Add or refactor these models:

- `DevicePermissionsOut`
- `MyDevicePreferencesUpdate`
- `DeviceMembershipCreate`
- `DeviceMembershipUpdate`
- `DeviceMembershipOut`
- `ScheduledWakeCreate`
- `ScheduledWakeUpdate`
- `ScheduledWakeOut`
- `ScheduledWakeRunOut`

Refactor these existing models:

- `MyDeviceOut`
  - add `is_favorite`
  - add `sort_order`
  - add `permissions`
  - optional `schedule_summary`
- `AdminDeviceOut`
  - keep as technical full device view

Remove:

- assignment-specific request/response models once routes are migrated

### 6.3 `backend/app/main.py`

Refactor areas:

1. Remove legacy endpoints and serializers related only to `/hosts`.
2. Replace assignment route handlers with membership route handlers.
3. Replace `_get_authorized_host()` with a capability-aware authorization helper.
4. Ensure `/me/devices` lists devices through memberships and includes user-specific fields.
5. Add `PATCH /me/devices/{id}/preferences`.
6. Add scheduled wake CRUD endpoints.
7. Add scheduler startup/shutdown logic through the FastAPI lifespan.

New helper design:

- `_get_authorized_device_for_action(current_user, device_id, action)`
- valid actions:
  - `view`
  - `power_check`
  - `wake`
  - `shutdown_poke`
  - `manage_schedule`

Authorization rules:

- admin bypasses membership checks
- user requires membership and corresponding capability

Scheduler design:

- run inside a background task started from `app_lifespan`
- poll due jobs every 15 to 30 seconds
- atomically claim jobs before execution
- compute next run immediately after a job fires
- reuse the existing wake flow logic instead of implementing a second wake path

Environment controls:

- `SCHEDULED_WAKE_RUNNER=true|false`
- `SCHEDULED_WAKE_POLL_SECONDS`

Even though only one test system exists now, keeping the scheduler runner flag is still useful.

### 6.4 `backend/app/admin_ui.py`

This file should remain the main technical control plane.

Planned changes:

1. Replace assignments pages/forms with membership pages/forms.
2. Show permission checkboxes per membership:
   - view status
   - wake
   - request shutdown
   - manage schedule
3. Add favorites/sort display for support visibility.
4. Add scheduled wake management pages:
   - schedule list
   - create/edit form
   - recent run history
5. Link schedules from device detail or device list.

UX priorities:

- make permissions explicit and obvious
- show the effective user-device relationship on one screen
- keep schedule editing narrow and easy to reason about

### 6.5 Scheduler execution notes

The scheduler should:

1. Fetch due enabled jobs.
2. Claim a job safely.
3. Load the target device.
4. Execute the same wake behavior used by user-triggered wake:
   - fresh power check
   - skip sending if already on
   - send WoL if needed
5. Log:
   - wake log
   - scheduled wake run
   - activity event if useful
   - admin audit event only for CRUD, not every run
6. Compute and store the next run.

Do not:

- run overlapping duplicate executions for the same job
- create a separate magic-packet path that bypasses existing validation

## 7. Android Refactor Plan

### 7.1 API/data layer

Files:

- `android-client/app/src/main/java/com/wakefromfar/wolrelay/data/ApiClient.kt`
- `android-client/app/src/main/java/com/wakefromfar/wolrelay/data/Models.kt`

Planned changes:

1. Update `MyDeviceDto` to include:
   - `isFavorite`
   - `sortOrder`
   - `permissions`
   - optional `scheduleSummary`
2. Add models for:
   - device membership admin views if needed later
   - schedule summary display if surfaced client-side
3. Add API call:
   - `updateDevicePreferences(hostId, isFavorite, sortOrder?)`
4. Keep existing wake, power-check, and shutdown poke API calls, but assume permission-aware failures may occur.

### 7.2 ViewModel layer

File:

- `android-client/app/src/main/java/com/wakefromfar/wolrelay/ui/MainViewModel.kt`

Planned changes:

1. Update `AppUiState.devices` consumption so list order comes from the backend.
2. Add actions for:
   - toggling favorite
   - optionally reordering later
3. Stop assuming every visible device can always be woken.
4. Expose disabled-state reasons for UI copy if needed.

### 7.3 UI layer

File:

- `android-client/app/src/main/java/com/wakefromfar/wolrelay/ui/WolRelayApp.kt`

Planned changes:

1. Split device list into:
   - favorites section
   - grouped device sections
2. Add favorite affordance on each device row.
3. Disable or hide action buttons based on permissions:
   - wake
   - shutdown request
4. Show schedule summary text when present.
5. Keep refresh and admin activity behavior intact.

Recommended v1 UX:

- favorites are shown first
- group sections are collapsible only if that is cheap
- no drag-and-drop ordering in the first pass

## 8. iPhone Refactor Plan

### 8.1 API/models

Files:

- `ios-client/Services/API/APIClient.swift`
- `ios-client/Services/API/Models.swift`

Planned changes:

1. Extend `MyDevice` / device DTO mapping with:
   - `isFavorite`
   - `sortOrder`
   - permissions object
   - optional schedule summary
2. Add API method for:
   - `PATCH /me/devices/{id}/preferences`

### 8.2 Device view model

File:

- `ios-client/Features/Devices/DevicesViewModel.swift`

Planned changes:

1. Preserve backend ordering instead of purely local ordering.
2. Add favorite toggle action.
3. Gate wake and shutdown actions by permissions.
4. Keep follow-up refresh behavior after wake.
5. Surface better permission-specific feedback instead of generic failure copy.

### 8.3 Device UI

File:

- `ios-client/Features/Devices/DevicesView.swift`

Planned changes:

1. Render:
   - favorites section
   - grouped sections for non-favorites
2. Add favorite star/button in the row.
3. Disable or hide wake/shutdown buttons based on permissions.
4. Show schedule summary when available.
5. Keep pull-to-refresh and current row layout quality.

Recommended first pass:

- no custom drag reorder
- no separate device details screen required unless needed for schedule visibility

## 9. Admin UX Scope

The server-rendered admin UI should be the first-class configuration surface for this refactor.

Required additions:

1. Membership management
   - create a membership
   - edit permission flags
   - remove membership
2. Scheduled wake management
   - create a job
   - edit a job
   - enable/disable a job
   - view next run
   - view recent run history
3. Device list support
   - show group name clearly
   - show active schedules count later if useful

Recommended screen design:

- replace "Assignments" with "Device Access"
- give each membership one row with user, device, and capability flags
- make schedule editing reachable from device rows

## 10. Sprint Plan

This plan is intentionally broken into sprints that leave the system usable after each one.

### Sprint 0: Branch, cleanup target, and reset strategy

Goal:

- prepare the repo for a clean cut

Scope:

1. Create a working branch for the refactor.
2. Decide whether to preserve old migration helpers or replace schema setup wholesale.
3. Remove dead plan assumptions about compatibility from docs.
4. Define a repeatable local reset flow:
   - delete DB
   - start backend
   - recreate admin user
   - seed a few test devices and users

Deliverables:

- documented reset command sequence
- explicit decision on DB rebuild strategy

Exit criteria:

- team can wipe and recreate the test environment quickly

### Sprint 1: Backend schema and membership model

Goal:

- replace assignments with memberships in the backend

Scope:

1. Implement target DB schema for:
   - `device_memberships`
   - `devices.updated_at`
2. Remove or stop using `user_device_access`.
3. Add membership CRUD helpers in `backend/app/db.py`.
4. Refactor schemas in `backend/app/schemas.py`.
5. Replace assignment endpoints with membership endpoints in `backend/app/main.py`.
6. Add membership-aware device listing for `/me/devices`.
7. Add capability-aware authorization helper.

Tests:

- membership CRUD tests
- `GET /me/devices` visibility tests
- permission enforcement tests for wake/power-check/shutdown poke

Exit criteria:

- all user-facing device access is controlled by `device_memberships`
- assignment routes are gone

### Sprint 2: Admin UI migration to memberships

Goal:

- make the new access model operable from the admin UI

Scope:

1. Replace assignment pages/forms with membership pages/forms in `backend/app/admin_ui.py`.
2. Add permission checkboxes.
3. Add membership list page or section with:
   - user
   - device
   - permissions
   - favorite flag
   - sort order
4. Update audit logging to reflect membership CRUD.

Tests:

- admin UI form submission tests
- permission update tests through UI routes if practical

Exit criteria:

- admin can manage per-device permissions end to end from the web UI

### Sprint 3: Android and iPhone contract adoption

Goal:

- move both native clients to the new device contract

Scope:

1. Update device models in Android and iPhone.
2. Update `/me/devices` parsing.
3. Add favorite toggle endpoint support.
4. Gate action buttons on permissions.
5. Improve feedback copy for permission-denied cases.

Android files:

- `data/Models.kt`
- `data/ApiClient.kt`
- `ui/MainViewModel.kt`
- `ui/WolRelayApp.kt`

iPhone files:

- `Services/API/Models.swift`
- `Services/API/APIClient.swift`
- `Features/Devices/DevicesViewModel.swift`
- `Features/Devices/DevicesView.swift`

Tests:

- Android DTO parsing tests
- iPhone API/model tests if present
- backend-client manual verification on real flows

Exit criteria:

- both clients can log in and use the refactored backend without compatibility branches

### Sprint 4: Favorites and grouped device UX

Goal:

- improve day-to-day usability of the device list

Scope:

1. Add `PATCH /me/devices/{id}/preferences`.
2. Persist favorite toggles in `device_memberships`.
3. Return sorted/grouped-ready device data from `/me/devices`.
4. Update Android and iPhone UI to:
   - show favorites first
   - group non-favorites by `group_name`
   - preserve backend ordering
5. Optionally add group filter chips or segmented controls.

Tests:

- preference update tests
- sorting tests
- favorite persistence tests

Exit criteria:

- user favorites persist across sessions and devices
- device list feels intentionally organized

### Sprint 5: Scheduled wake backend

Goal:

- add scheduled wake job management and execution

Scope:

1. Add:
   - `scheduled_wake_jobs`
   - `scheduled_wake_runs`
2. Add schedule CRUD helpers.
3. Add schedule CRUD API endpoints.
4. Add scheduler background loop in `backend/app/main.py`.
5. Reuse existing wake logic for scheduled runs.
6. Add run history listing.

Tests:

- next-run calculation tests
- due-job execution tests
- duplicate-execution prevention tests
- schedule enable/disable tests

Exit criteria:

- admin can create a schedule and observe a real scheduled wake execution

### Sprint 6: Admin UI for schedules and client schedule visibility

Goal:

- expose scheduled wake in the product UI

Scope:

1. Add scheduled wake management screens in `backend/app/admin_ui.py`.
2. Show `next_run_at` and latest run result.
3. Add schedule summary to `/me/devices`.
4. Surface schedule summary in Android and iPhone device rows or details.

Tests:

- admin UI schedule CRUD tests
- schedule summary serialization tests

Exit criteria:

- admin can manage schedules without using raw API calls
- end users and admins can see that a device has a wake schedule

### Sprint 7: Cleanup and polish

Goal:

- remove leftover legacy assumptions and tighten the product surface

Scope:

1. Remove old endpoint references from docs and clients.
2. Remove dead code paths in backend serializers and admin UI.
3. Review activity logging and telemetry naming.
4. Consider optional enhancements only after the base refactor is stable:
   - group wake
   - delegated schedule management
   - client-side reorder UI
   - better "booting / verifying" state after wake

Exit criteria:

- no legacy API surface remains
- docs match actual behavior
- codebase uses one coherent access model

Status:

- completed on 2026-03-08

## 11. Testing Strategy

### 11.1 Backend

Add or update tests for:

- membership CRUD
- device visibility by user
- permission-gated wake
- permission-gated power check
- permission-gated shutdown poke
- preference update behavior
- scheduled wake job CRUD
- scheduled wake execution
- scheduler next-run calculation

Existing test areas likely to extend:

- `backend/tests/test_api_smoke.py`
- `backend/tests/test_sprint1_membership_and_wake.py`
- `backend/tests/test_shutdown_pokes_api.py`
- `backend/tests/test_admin_ui.py`

Some current assignment-focused tests should be renamed to membership-focused tests.

### 11.2 Android

Add or update tests for:

- device DTO parsing with permissions and favorite state
- favorite toggle behavior
- permission-disabled UI states where practical

### 11.3 iPhone

Add or update tests for:

- device decoding with permissions and favorites
- view-model favorite toggle flow
- disabled action states

### 11.4 Manual verification checklist

Per sprint, verify at least:

1. Admin creates device.
2. Admin creates membership for user.
3. User sees only assigned devices.
4. Permission changes take effect immediately.
5. Favorite toggle persists across refresh.
6. Scheduled wake triggers and logs correctly.

## 12. Documentation Updates

Update after implementation stabilizes:

- `README.md`
- admin usage sections
- endpoint lists
- test/reset workflow
- any old references to assignments where memberships are now the source of truth

Recommended wording changes:

- "assignment" becomes "device access" or "membership"
- "host" becomes "device" in user-facing docs wherever practical

## 13. Implementation Notes and Guardrails

These notes should guide engineering decisions during the refactor.

### 13.1 Prefer replacement over adaptation

If a subsystem is primarily structured around the old assignment model, replace it cleanly instead of layering new logic on top.

### 13.2 Avoid split-brain APIs

Do not keep both assignments and memberships alive in parallel. That will create long-term confusion.

### 13.3 Reuse wake logic

Scheduled wake must call the same core wake logic as user-triggered wake. Do not copy the magic packet flow into a second implementation.

### 13.4 Keep favorites server-side

Do not store favorites independently in Android SharedPreferences or iPhone UserDefaults once backend support exists. Local fallback state will drift and create support problems.

### 13.5 Keep schedule editing admin-first

Even if the data model supports `can_manage_schedule`, do not build delegated schedule editing until the admin-only flow is stable.

### 13.6 Preserve security posture

This refactor is not a reason to loosen:

- auth requirements
- IP allowlist behavior
- audit logging for admin changes
- shutdown poke authorization

### 13.7 Accept temporary churn

Because the system is not deployed, it is acceptable to:

- break old local DB files
- reseed test data
- update both clients in lockstep
- delete deprecated routes immediately

That is cheaper and technically cleaner than maintaining artificial compatibility.

## 14. Recommended Immediate Next Step

Start with Sprint 1 and implement the backend membership model before touching either client UI.

Reason:

- it establishes the correct domain model
- it defines the new canonical `/me/devices` contract
- it lets Android and iPhone migrate against a stable backend shape

After Sprint 1 lands, Sprint 2 and Sprint 3 can proceed in parallel if needed:

- one thread on admin UI membership management
- one thread on Android/iPhone contract adoption
