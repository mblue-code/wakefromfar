# iPhone Monetization Refactor: Sprint 1

Historical note: superseded by Sprint 3 on 2026-03-06. The legacy StoreKit and entitlement surfaces mentioned below were later removed and are not part of the supported iPhone product anymore.

## What changed

- The iPhone device list now shows every device assigned to the signed-in account.
- `DevicesViewModel` no longer applies free-tier visibility limits, hidden-device counts, or billing-driven filtering.
- The device list no longer shows hidden-device messaging, upgrade banners, or upgrade entry points.
- Free-tier device-order persistence was removed from `AppPreferences`.
- Settings and billing screens now describe the iPhone app as a paid App Store app instead of a free tier with an optional Pro unlock.
- English and German iPhone copy was updated to remove free-tier and device-cap messaging.
- Legal/privacy copy now reflects the narrower local storage and billing claims used after Sprint 1.

## Old monetization behavior that still exists internally

- `StoreKitBillingCoordinator` still exists and still bootstraps with the current session.
- Legacy StoreKit product loading, purchase observation, entitlement refresh, and backend sync code still remain in the iPhone client.
- The backend-scoped App Store attachment cache in `AppPreferences` still remains for that legacy billing path.
- Backend entitlement endpoints and related API models remain untouched.

These remaining pieces no longer control device visibility or the normal signed-in iPhone settings flow. They remain only to avoid a broad backend-coupled deletion during Sprint 1.

## Sprint 2 cleanup targets

- Remove `StoreKitBillingCoordinator` from the normal iPhone runtime if the migration path is no longer needed.
- Delete the remaining legacy StoreKit purchase and restore flow, including unused billing strings and App Store attachment cache code.
- Remove the iPhone dependency on backend entitlement endpoints and clean up the related backend/client models and tests.
- Revisit project wiring and release docs once the legacy billing seam is fully retired.
