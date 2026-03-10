# Sprint 4 Implementation Note

## What Was Built

- Added APNs-backed admin notification delivery for shutdown requests across the backend and native iPhone client.
- Added authenticated APNs device registration and deregistration endpoints on the backend.
- Added backend persistence for iOS/APNs device registrations, including invalidation state and optional server-side visible-alert throttling.
- Added a real iOS notification coordinator that requests permission only when an admin enters the activity flow, registers for remote notifications, submits the device token to the backend, and routes notification taps into the admin activity tab.

## APNs Architecture

- Backend:
  - `notification_devices` stores one APNs registration per installation/provider pair.
  - `POST /me/notification-devices/apns` upserts the current authenticated installation-to-token association.
  - `DELETE /me/notification-devices/apns/{installation_id}` deactivates the installation on logout or account switch.
  - Shutdown-poke creation schedules an event-driven APNs dispatch path through `backend/app/apns.py`.
  - APNs credentials stay environment-driven through `APNS_*` settings. No secrets are hardcoded.
- iOS:
  - `APNSNotificationCoordinator` owns permission status, APNs registration, token persistence, backend sync, and notification routing.
  - The app requests notification permission when an admin opens the activity flow or explicitly manages notification settings.
  - Device tokens are persisted locally in `UserDefaults`, then associated with the authenticated admin session on the backend.

## Delivery Policy

- APNs is the primary background alert path for iOS admins.
- Notification payloads are intentionally minimal and generic. They route to the admin activity feed and avoid device names, requester notes, or other unnecessary sensitive content.
- Foreground behavior uses Apple’s system banner/list presentation rather than a custom in-app duplicate notification.
- Optional server-side rate limiting is supported with `APNS_ADMIN_ALERT_MIN_VISIBLE_INTERVAL_SECONDS`.
  - `0` keeps every shutdown request eligible for a visible APNs alert.
  - A non-zero value suppresses repeated visible alerts inside the window and aggregates the next eligible alert body instead.
- Full shutdown event history remains in the in-app admin feed regardless of notification throttling.

## Apple Compliance Decisions

- No periodic iOS background polling was added.
- No unsupported background modes or Android-style foreground-service behavior were added.
- Silent/background push is not used as a scheduler or primary alert path.
- Push capability usage stays minimal:
  - APNs entitlement only
  - no `remote-notification` background mode

## Open Risks And Follow-Up

- End-to-end APNs delivery still requires valid Apple signing, entitlements, a provisioning profile with Push Notifications enabled, and real APNs credentials in the backend environment.
- This sprint does not add a notification service extension, badge-count reconciliation, or richer deep links beyond routing admins into the activity tab.
- If production wants a strict “one visible alert per hour” policy, it should explicitly set `APNS_ADMIN_ALERT_MIN_VISIBLE_INTERVAL_SECONDS=3600` in the backend environment.
