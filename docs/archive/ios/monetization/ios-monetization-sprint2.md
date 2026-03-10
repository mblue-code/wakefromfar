# iPhone Monetization Refactor: Sprint 2

Historical note: this snapshot describes the temporary compatibility window after Sprint 2. Sprint 3 removed the deprecated backend entitlement endpoints and `ios_entitlements` persistence on 2026-03-06.

## What changed

- The iPhone app no longer constructs or bootstraps a billing coordinator during normal startup.
- `RootView` now restores session state and APNs state without any entitlement refresh step.
- The iPhone client no longer calls `GET /me/entitlements` or `POST /me/entitlements/app-store/sync`.
- Legacy client-side StoreKit runtime files were removed from the iPhone target:
  - `StoreKitBillingCoordinator.swift`
  - `BillingConfiguration.swift`
  - `BillingView.swift`
- Legacy client entitlement request/response models were removed from the iPhone API layer.
- The backend-scoped App Store attachment cache was removed from `AppPreferences`.
- Legal/privacy copy now reflects the paid-upfront App Store model without implying that normal iPhone use still performs entitlement sync.

## What remains and why

- The backend still exposes `/me/entitlements` and `/me/entitlements/app-store/sync`.
- Those endpoints are now marked as deprecated legacy compatibility endpoints for older iPhone builds that may still try to read or sync App Store attachment data.
- The backend `ios_entitlements` table and related helpers remain in place for the same reason.
- The legacy payload shape is intentionally preserved so older dev/TestFlight builds are less likely to break during transition.

## Current product truth after Sprint 2

- App Store iPhone distribution is paid upfront.
- No iPhone free tier exists.
- Assigned device visibility on iPhone does not depend on backend entitlement sync.
- Normal signed-in iPhone operation no longer depends on StoreKit refresh or backend App Store attachment state.
- Source-built and self-hosted usage remains outside App Store monetization enforcement.

## Sprint 3 follow-up

- Decide when it is safe to remove the deprecated backend entitlement endpoints entirely.
- Remove the remaining backend entitlement config and persistence once support for older iPhone builds is no longer required.
- Review backend release notes and operational docs for any leftover references to iPhone Pro unlock or entitlement attachment flows.
