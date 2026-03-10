# Sprint 5 Implementation Note

Historical note: the hybrid StoreKit plus backend entitlement model described below was retired during the iPhone monetization Sprint 3 cleanup on 2026-03-06. It is not the current shipping iPhone monetization model.

## Entitlement Model

- Chosen model: hybrid.
- StoreKit 2 on iPhone is the authority for whether the Apple purchase currently exists and is verified.
- The backend is the authority for which authenticated WakeFromFar account on a given backend instance the App Store purchase is attached to.
- Effective Pro access on iPhone requires both:
  - a locally verified active StoreKit entitlement for the Pro product
  - a matching backend entitlement attachment for the signed-in account
- The app caches backend attachment ids per `backend URL + username` so the same account can relaunch offline without immediately losing Pro access, while avoiding entitlement leakage across account switches on the same phone.
- Cross-platform sharing is not claimed or implied. The Sprint 5 implementation only covers iPhone StoreKit-based Pro access.

## What Was Built

- Backend:
  - added `ios_entitlements` persistence with migration 10
  - added `GET /me/entitlements`
  - added `POST /me/entitlements/app-store/sync`
  - added conflict protection so one App Store original transaction id cannot silently attach to multiple WakeFromFar accounts on the same backend
  - added backend tests for entitlement sync, clearing, and cross-account conflict handling
- iPhone client:
  - replaced the billing placeholder seam with a real `StoreKitBillingCoordinator`
  - added centralized billing configuration for the Pro product id and free-tier device limit
  - added StoreKit 2 product loading, verified purchase flow, restore flow, and transaction update observation
  - added backend entitlement fetch/sync integration plus account-scoped local caching
  - added a native Pro management screen in Settings and upgrade entry points from the device list when free-tier gating hides devices
  - added free-tier gating that mirrors Android’s first-come-first-served visible-device ordering, but scopes the stored order per backend account
  - updated legal/privacy and billing copy in English and German

## Sprint 6 And Sprint 7 Remaining Work

- Sprint 6:
  - full accessibility pass for the new billing UI and gated-device messaging
  - copy polish and localization QA on physical devices
  - final privacy/disclosure review against App Store Connect answers
- Sprint 7:
  - end-to-end StoreKit sandbox verification with a real `.storekit` config or App Store Connect product
  - real-device login/logout/account-switch QA against production-like backend data
  - release-readiness checks, screenshots, review notes, and rollout validation

## Open Risks

- StoreKit purchase and restore code compiles and is wired end to end, but real App Store sandbox transactions are still unverified in this environment.
- The shipped Pro product id is centralized as `wakefromfar_pro_unlock`; App Store Connect product setup still has to match it exactly.
- The backend attachment model intentionally blocks silent reassignment of one App Store purchase to another WakeFromFar account on the same backend. If product policy later wants a transfer flow, that will need explicit UX and backend support.
- Refund and revocation handling depends on StoreKit transaction updates or a later entitlement refresh reaching the app; there is no App Store Server integration in Sprint 5.
