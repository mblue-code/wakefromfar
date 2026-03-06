# Refactor Plan: Apple Monetization Without A Free Tier

Status on 2026-03-06: complete. Sprint 3 removed the remaining legacy iPhone entitlement backend compatibility surface, dropped runtime use of `ios_entitlements`, and aligned the repo with a paid-upfront iPhone App Store model. The execution plan below is kept as the implementation record.

## Goal

Refactor the iPhone product so App Store users must pay once to use WakeFromFar on iPhone, and then receive full iPhone functionality with no free-tier device cap.

The intended product shape is:

- iPhone users pay once through Apple
- after purchase, all assigned devices are available
- no iPhone free tier
- no hidden-device gating on iPhone
- users who self-host and build from source can still run the open-source app outside the App Store flow

## Recommendation

Use a **paid App Store app** instead of a free app with a mandatory in-app unlock.

Reasoning:

- it matches the business rule exactly: every App Store iPhone user pays before use
- it removes the awkward "install free app, then immediately hit mandatory paywall" flow
- it is simpler to explain in App Review
- it lets us remove most iPhone-specific entitlement complexity
- it eliminates the current iPhone free-tier device gating logic entirely
- it reduces backend coupling to App Store purchase attachment state

## Pricing Guidance

Do not hardcode `3 USD` or `3 EUR` in app copy or code.

Use an App Store price tier that lands around:

- `$2.99` in the United States
- `€2.99` in Euro markets

Important detail:

- Apple pricing is tier-based and region-specific
- VAT and regional conversion mean exact cross-market symmetry is not guaranteed
- product copy should say "paid once through the App Store" rather than promising an exact number inside the app

## Product Decision

### Target model

- App Store distribution: paid upfront app
- Source build / sideload / self-hosted developer builds: unchanged, no App Store purchase enforcement

### Explicitly not targeted

- iPhone free tier
- hidden-device preview limited to first `N` devices
- "unlock Pro" as an iPhone upsell concept
- account-level App Store entitlement attachment as a shipping requirement for iPhone

## Why This Refactor Is Bigger Than A Copy Change

The current iPhone implementation was built around a hybrid StoreKit 2 entitlement model:

- `ios-client/Services/Billing/StoreKitBillingCoordinator.swift`
- `ios-client/Services/Billing/BillingConfiguration.swift`
- `ios-client/Features/Settings/BillingView.swift`
- `ios-client/Features/Devices/DevicesView.swift`
- `ios-client/Features/Devices/DevicesViewModel.swift`
- `backend/app/main.py`
- `backend/app/schemas.py`
- `backend/tests/test_ios_billing_entitlements.py`

That model assumes:

- the iPhone app can be used for free
- Pro unlock removes the free-device cap
- the backend stores App Store purchase attachment state per WakeFromFar account

The new product direction removes those assumptions.

## Target End State

### iPhone app behavior

- App Store users download a paid app
- after login, assigned devices are shown directly
- no iPhone billing banner on the device list
- no iPhone "hidden devices because free tier includes X" message
- no "unlock Pro" CTA in normal iPhone use
- no restore-purchases screen unless we intentionally keep a minimal legacy recovery path

### Backend behavior

- backend no longer needs iPhone App Store entitlement attachment to decide whether the iPhone app may show all devices
- iPhone client does not need `/me/entitlements` to decide free-vs-pro device visibility
- backend can keep existing entitlement APIs temporarily for migration safety, but they should become legacy

### Product language

- "WakeFromFar Pro" should be retired from iPhone copy if the paid-app model is adopted
- iPhone copy should describe the app as a paid App Store app, not as a free app with an optional upgrade

## Refactor Scope

## Phase 0: Lock The Monetization Decision

### Required decision

Commit to one of these paths:

1. **Preferred**: paid App Store app, no iPhone IAP unlock
2. **Fallback**: free App Store app with a mandatory non-consumable StoreKit unlock before device access

### Recommendation

Choose `1`.

### Why the fallback is worse

- worse first-run UX
- more App Review explanation
- more entitlement state management
- more restore/account-attachment edge cases
- more backend and test surface to maintain

## Phase 1: Product And Release Policy Updates

### Tasks

- update `porttoiphoneplan.md` and release docs to state that iPhone distribution is paid-upfront
- update any sprint notes or release-readiness notes that describe iPhone free tier or Pro unlock as part of the shipping model
- document that source builds are outside App Store monetization and therefore intentionally not purchase-gated

### Deliverables

- one canonical repo note that says:
  - App Store iPhone app is paid upfront
  - no iPhone free tier exists
  - source builds remain open-source and self-managed

## Phase 2: Remove iPhone Free-Tier Product Logic

### iOS code changes

#### `ios-client/Services/Billing/BillingConfiguration.swift`

- remove `freeDeviceLimit`
- decide whether `proProductID` and `proProductIDs` are still needed
- if moving fully to paid app, this file may shrink to zero or be deleted

#### `ios-client/Features/Devices/DevicesViewModel.swift`

- remove:
  - `hiddenFreeDeviceCount`
  - `freeDeviceLimit`
  - `isEntitlementLoading` as a device-gating concern
  - `freeTierVisibleDevices(...)`
  - device-order persistence for free-tier ranking
- make assigned-device visibility equal to `allAssignedDevices`
- keep normal auth/session/network error handling

#### `ios-client/Features/Devices/DevicesView.swift`

- remove the billing banner shown when devices are hidden
- remove the upgrade CTA from the device list
- remove text that explains hidden devices due to the free tier
- preserve wake and shutdown actions unchanged

#### `ios-client/Persistence/AppPreferences.swift`

- remove free-tier device ordering storage:
  - `freeTierDeviceOrderPrefix`
  - `freeTierDeviceOrder(...)`
  - `setFreeTierDeviceOrder(...)`
- update comments and privacy/legal references accordingly

### UX result

- device list becomes a normal assigned-devices view
- no artificial visibility cap remains on iPhone

## Phase 3: Simplify Or Remove iPhone Billing UI

### Preferred paid-app path

#### `ios-client/Features/Settings/BillingView.swift`

- remove the purchase/restore management screen entirely, or replace it with a short informational screen if a settings entry must remain temporarily

#### `ios-client/Features/Settings/SettingsView.swift`

- remove:
  - Pro status
  - price row
  - manage purchase entry
  - upgrade-specific footer copy
- if desired, replace with a simple static section:
  - "This iPhone app is purchased through the App Store."

#### Localization cleanup

- remove or rewrite strings such as:
  - `billing_upgrade_button`
  - `billing_hidden_devices_message_format`
  - `billing_device_limit_free_format`
  - `billing_status_free`
  - `billing_status_pro`
  - `settings_billing_manage_entry`
  - `settings_billing_footer`

### Result

- no visible "Pro" upsell concept remains in the iPhone UI
- no misleading purchase-management UX remains for a paid-upfront app

## Phase 4: Retire The Current iPhone Entitlement Architecture

### Preferred paid-app path

#### `ios-client/Services/Billing/StoreKitBillingCoordinator.swift`

Refactor options:

1. **Best long-term**: remove this service from the iPhone runtime entirely
2. **Short-term migration**: keep a tiny stub service so the app architecture does not need a wide immediate rewrite

### Recommended migration sequence

#### Step 1: shrink the service

- stop using entitlement state to gate device visibility
- stop depending on `/me/entitlements` during normal app startup
- stop syncing App Store entitlements to backend on every session bootstrap

#### Step 2: replace with a simpler app-access model

- either:
  - no billing coordinator at all
- or:
  - a minimal `AppDistributionMode` / `AppStoreBuildPolicy` service that only exposes static app behavior

### Side effects to remove

- `BillingState.Access.free`
- `BillingState.Access.pro`
- `BillingState.Access.attachedElsewhere`
- account-attachment conflict UX that only exists because of the current IAP model

## Phase 5: Backend Contract Simplification

### Current backend billing surface

The current iPhone entitlement APIs include:

- `GET /me/entitlements`
- `POST /me/entitlements/app-store/sync`

### Preferred paid-app path

These endpoints are no longer needed for normal iPhone app function.

### Recommended backend approach

#### Step 1: deprecate, do not immediately delete

- keep the endpoints temporarily so old TestFlight/dev builds do not crash
- mark them legacy in code comments and release notes

#### Step 2: remove iPhone dependency on them

- once no shipping iPhone client depends on them, remove:
  - entitlement sync logic in `backend/app/main.py`
  - entitlement response models in `backend/app/schemas.py` if no longer used elsewhere
  - entitlement persistence helpers in `backend/app/db.py` if they are truly iPhone-only

#### Step 3: decide whether backend should keep any product metadata

- if Android still needs billing-related backend coordination, keep only what Android needs
- do not leave iPhone-specific attachment logic in place just because it already exists

## Phase 6: App Store Connect And Distribution Changes

### Paid-app path

#### App Store Connect

- convert the iPhone app from free distribution with IAP expectations to a paid app listing
- set the paid price tier around:
  - `$2.99`
  - `€2.99`
- remove or stop using the iPhone non-consumable product if it was created only for this unlock flow

### Required checks

- verify metadata no longer advertises "free tier" or "upgrade to Pro"
- verify screenshots do not show old upgrade banners
- verify review notes explain:
  - this is a paid upfront iPhone app
  - backend credentials are still provided by an admin

## Phase 7: Legal, Privacy, And Marketing Copy Cleanup

### iOS copy updates

Replace text that currently says:

- free tier exists
- Pro removes the device cap
- purchases are attached to backend accounts
- restore purchases is a normal required workflow

With text that reflects:

- the iPhone app is purchased through the App Store
- the app stores only normal local settings and auth/session data
- backend login still requires admin-provided credentials

### Files likely affected

- `ios-client/Resources/Localization/en.lproj/Localizable.strings`
- `ios-client/Resources/Localization/de.lproj/Localizable.strings`
- `ios-client/Features/Settings/LegalPrivacyView.swift`
- repo privacy/release notes that currently mention iPhone Pro unlock and entitlement sync

## Phase 8: Testing Refactor

### iOS tests / validation

Re-test these flows after the refactor:

- first run
- login
- logout
- session restore
- device list shows all assigned devices immediately
- wake flow
- shutdown request flow
- admin activity flow
- settings screen without billing regression

### Backend tests

Current tests that will need removal or rewrite:

- `backend/tests/test_ios_billing_entitlements.py`

### Replace with

- tests that confirm the iPhone app no longer depends on entitlement sync for normal device visibility
- if legacy entitlement endpoints remain temporarily, mark tests as legacy and narrow coverage to backward compatibility only

## Phase 9: Migration Strategy

### Existing local/dev/test builds

There may already be builds that expect:

- StoreKit 2 product loading
- entitlement sync
- free-tier device gating

### Migration approach

#### Release 1

- remove UI/device gating first
- leave backend legacy entitlement endpoints intact
- keep runtime stable for existing development builds

#### Release 2

- remove unused iPhone entitlement code from backend and app

This two-step path reduces rollout risk.

## Phase 10: Definition Of Done

The refactor is complete when all of the following are true:

- App Store iPhone distribution is paid upfront
- no iPhone free tier exists in product behavior or copy
- all assigned devices are visible on iPhone after login
- no upgrade banner or hidden-device logic remains on iPhone
- the device list does not depend on StoreKit or entitlement sync
- the settings screen no longer presents iPhone Pro management as a core feature
- privacy/legal/release docs no longer describe the removed iPhone free-tier model
- legacy entitlement code is either removed or clearly marked transitional

## Risks And Watchouts

### 1. Do not half-remove the old model

If UI copy is updated but:

- device visibility still depends on entitlement state
- backend still returns meaningful iPhone free-tier assumptions
- settings still show Pro management

then the product will become internally inconsistent.

### 2. Do not hardcode price text in app strings

Apple pricing changes by region and tax policy. The App Store should be the source of truth for price.

### 3. Be explicit about source builds

If the app remains open source, self-built versions will not inherit App Store purchase enforcement. That is a business choice and should be treated as intentional, not as a bug.

### 4. Re-check Apple compliance language

If you use the paid-app model, the app should stop talking about StoreKit restore/unlock flows as if they are part of the normal iPhone experience.

## Fallback Plan If You Refuse The Paid-App Model

If you insist on keeping the app free to download but still want mandatory payment for all App Store iPhone users, then:

- keep StoreKit 2
- replace the free tier with a hard gate
- block device list access until purchase is verified
- keep restore purchases
- keep at least some entitlement sync logic
- keep a paywall after login or before login completion

This is workable, but it is a worse product and a more complex codebase than the paid-upfront app.

## Recommended Execution Order

1. Lock product decision: paid app, not mandatory post-install IAP.
2. Remove iPhone free-tier device gating from `DevicesViewModel` and `DevicesView`.
3. Remove iPhone billing management UI from Settings.
4. Stop using entitlement sync during normal iPhone startup.
5. Update localization, legal, privacy, and release docs.
6. Ship a transition build while backend legacy endpoints remain.
7. Remove legacy iPhone entitlement backend code after the transition is stable.
