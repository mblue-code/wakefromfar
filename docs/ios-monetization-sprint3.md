# iPhone Monetization Refactor: Sprint 3

Date: 2026-03-06

## What was removed

- Deleted the legacy iPhone entitlement routes from `backend/app/main.py`:
  - `GET /me/entitlements`
  - `POST /me/entitlements/app-store/sync`
- Removed the retired entitlement request/response schemas from `backend/app/schemas.py`.
- Removed iPhone-only legacy config from `backend/app/config.py`.
- Removed runtime helpers for `ios_entitlements` from `backend/app/db.py`.
- Added schema migration `11` to drop `ios_entitlements` on upgraded databases and avoid recreating it on fresh databases.
- Replaced the retired entitlement compatibility test with cleanup tests that assert the routes and OpenAPI surface are gone.

## Definitive product truth after Sprint 3

- iPhone App Store distribution is paid upfront.
- No iPhone free tier exists.
- No iPhone Pro unlock runtime exists.
- Normal iPhone operation does not depend on StoreKit entitlement refresh or backend entitlement sync.
- Source-built or self-hosted usage outside the App Store remains intentionally outside App Store monetization enforcement.

## Repo cleanup completed

- Updated release-readiness and privacy-policy docs to describe the paid-upfront iPhone model.
- Updated iPhone settings/legal strings to remove dead monetization keys and leftover StoreKit-oriented identifiers.
- Marked older sprint notes that describe the retired hybrid model as historical.

## Remaining manual work outside the repo

- Set the final paid-app price tier in App Store Connect.
- Finish App Store Connect metadata, screenshots, privacy labels, and review notes for the paid-upfront iPhone release.
- Complete real-device APNs, login/logout, wake, shutdown-request, and accessibility QA before submission.
