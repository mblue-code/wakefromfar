# Port WakeFromFar From Android To A Native iOS App

Status update on 2026-03-06: the iPhone app now ships with paid-upfront App Store distribution. Older planning references in this document to iPhone StoreKit purchases, Pro unlock, or entitlement sync are historical unless they explicitly refer to Android.

## Goal

Build a native iPhone app so WakeFromFar is usable beyond Android and is realistic for broad end-user adoption. In practice, that means:

- feature parity for the core user flow
- a usable admin experience on iPhone
- accessible, localized, App Store-ready UX
- platform-correct iOS implementation instead of a thin Android clone
- Apple-compliant product, technical, privacy, billing, and background-execution behavior

## Main Pillars

The iOS port should be driven by these pillars from the start:

- broad usability and accessibility
- native iPhone-quality UX
- Apple compliance as a release blocker, not a final polish item
- secure handling of auth, purchases, and notifications
- feature parity for the flows users actually need

## What Exists Today

### Current product shape

The repo already has:

- a FastAPI backend in `backend/`
- a native Android app in `android-client/`

The Android app currently covers:

- login with backend URL, username, password
- device list for assigned devices
- wake action
- power-state display from backend
- admin activity feed
- shutdown request flow
- local settings for theme and language
- Android notifications and background polling for admin alerts
- Google Play Billing-based Pro unlock work

Relevant source files:

- `android-client/app/src/main/java/com/wakefromfar/wolrelay/ui/MainViewModel.kt`
- `android-client/app/src/main/java/com/wakefromfar/wolrelay/data/ApiClient.kt`
- `android-client/app/src/main/java/com/wakefromfar/wolrelay/ui/WolRelayApp.kt`
- `android-client/app/src/main/java/com/wakefromfar/wolrelay/ui/AdminActivityPollingWorker.kt`
- `android-client/app/src/main/java/com/wakefromfar/wolrelay/ui/AdminAlertForegroundService.kt`
- `backend/app/main.py`
- `backend/app/schemas.py`

### Important constraints discovered in the codebase

1. Invite onboarding is no longer part of the supported product flow.
   `backend/app/main.py` returns an error for `POST /onboarding/claim`, and new users are expected to receive credentials directly from an admin.

2. Android admin background alerts rely on `WorkManager` plus a foreground service.
   That model does not port directly to iOS. iOS will not allow an equivalent always-on 10-minute polling service.

3. Android monetization uses Google Play Billing.
   The shipped iPhone app uses paid-upfront App Store distribution instead of an in-app StoreKit unlock flow.

4. The app currently supports English and German.
   Broad adoption should keep both and make localization easier to extend.

## Recommended Product Scope For iOS v1

Ship the iPhone app in two layers:

### Must-have for v1

- login
- backend URL configuration
- assigned device list
- wake action
- power-state display
- shutdown request flow
- admin activity feed
- settings for language, appearance, privacy/legal
- local notifications where permitted
- paid-upfront App Store distribution language from launch
- accessibility baseline
- English and German

### Decide before implementation

- final APNs delivery policy and rate limits for admin alerts

### Defer unless explicitly needed

- iPad-specific layout work
- Apple Watch companion
- widgets/live activities
- full offline mode

## Architecture Recommendation

Build a fully native Swift/SwiftUI app, not a Kotlin Multiplatform or wrapper approach.

Reasoning:

- the backend contract is already HTTP/JSON and portable
- the current Android code contains multiple platform-specific behaviors
- native iOS is the fastest path to a correct App Store-quality product
- the user-facing surface is moderate in size, not large enough to justify cross-platform complexity
- Apple compliance is easier to maintain with standard native frameworks and platform-correct behaviors

### Suggested technical stack

- SwiftUI for UI
- Swift concurrency (`async/await`) for networking and state actions
- `URLSession` for API calls
- `Codable` models mapped from `backend/app/schemas.py`
- Keychain for auth token storage
- `UserDefaults` for non-sensitive settings
- App Store Connect paid-app configuration for iPhone distribution
- `UserNotifications` for local notifications
- `BGTaskScheduler` only for best-effort refresh, not guaranteed polling

### Suggested app structure

- `App/`: app entry, navigation, environment wiring
- `Features/Auth/`
- `Features/Devices/`
- `Features/AdminActivity/`
- `Features/Settings/`
- `Services/API/`
- `Services/Auth/`
- `Services/Notifications/`
- `Services/Billing/`
- `Persistence/`
- `Resources/Localization/`

### Apple compliance guardrails

These should be treated as architecture constraints, not optional cleanup:

- use only Apple-supported background mechanisms for their intended purpose
- do not simulate Android foreground-service behavior on iOS
- do not imply an iPhone in-app unlock flow when the paid-app model is used
- keep privacy disclosures aligned with actual device, backend, and payment data flows
- treat accessibility as part of release readiness
- avoid features or APIs that create avoidable App Review risk

## Android To iOS Feature Mapping

### Authentication and session

Android today:

- token stored in encrypted shared preferences
- backend URL stored locally
- role inferred from JWT payload

iOS replacement:

- store token in Keychain
- store backend URL, theme, language, and UI flags in `UserDefaults`
- decode JWT role locally only for client UX; still trust backend authorization for real access control

Tasks:

- define `SessionStore`
- define auth/network interceptor for bearer token
- add logout that clears token and admin notification watermarks

### Device list and wake flow

Android today:

- loads `/me/devices`
- wakes via `/me/devices/{id}/wake`
- surfaces state badges and stale status

iOS replacement:

- SwiftUI device list with pull-to-refresh
- wake button per device
- confirmation/loading state matching backend response semantics
- good VoiceOver labels for state, stale data, and last checked time

Tasks:

- model `MyDeviceOut` and `MeWakeResponse`
- build device row component
- define user-facing copy for `already_on`, `sent`, `failed`

### Admin activity and shutdown flow

Android today:

- admin feed from `/admin/mobile/events`
- load-more pagination by cursor
- shutdown requests can be marked seen/resolved
- users can submit shutdown poke requests

iOS replacement:

- admin activity tab with filter chips or segmented controls
- pagination and pull-to-refresh
- actions for seen/resolved
- request shutdown modal from device row

Tasks:

- map `ActivityEventOut` and `ShutdownPokeOut`
- preserve backend event-type semantics
- keep UI responsive during action mutations

### Deep links and onboarding

Android today:

- parses `wakefromfar://claim?...`
- has claim UI

Supported product direction:

- invite onboarding is removed
- admins send backend URL, username, and password directly to new users

Implementation choice:

- do not implement invite claim in the native iOS app
- remove deep-link onboarding from the iOS scope unless a future product change reintroduces it
- keep first-run guidance that tells users they need admin-provided credentials and a backend URL

### Notifications and background behavior

Android today:

- foreground polling service
- periodic worker
- local notifications for shutdown requests

iOS reality:

- no equivalent long-running foreground polling for background monitoring
- `BGTaskScheduler` is opportunistic and cannot guarantee 10-minute checks

Recommendation:

- foreground refresh in-app for activity feed
- optional best-effort background refresh only as a fallback
- primary solution: backend-driven APNs push notifications for admin shutdown requests
- do not model iOS notifications as fixed-interval polling
- if rate limiting is desired, enforce it server-side, for example by capping background alert deliveries to at most one per device per hour while still showing the full event list in-app
- keep the implementation within Apple-approved notification and background-execution patterns

This is the biggest platform gap in the port.

### Billing

Android today:

- Google Play Billing with local entitlement unlock
- free tier device cap with Pro upgrade path

iOS replacement:

- paid App Store distribution
- no in-app Pro unlock
- no entitlement sync requirement for normal signed-in use

Recommendation:

- billing is in scope for iOS v1
- keep iPhone copy and release configuration aligned with the paid-upfront App Store model from the start
- treat self-built or self-hosted iPhone usage outside the App Store as intentionally outside App Store monetization enforcement

## Accessibility And “All People Can Use It”

If the intent is broad usability, the port should not stop at “same screens on iPhone.” It should include accessibility and inclusion as release criteria.

### Accessibility baseline

- full Dynamic Type support
- VoiceOver labels and hints for every interactive control
- minimum tappable target sizes
- semantic grouping for device cards and activity rows
- sufficient color contrast in light and dark appearances
- no meaning conveyed by color alone
- reduced-motion-safe transitions
- proper loading, error, and empty-state announcements

### Language and readability

- keep English and German from day one
- centralize strings in iOS localization files
- avoid text baked into custom views
- use plain-language status and error messages

### Device coverage

- support a minimum iOS version that still covers a wide install base
- recommendation: start at iOS 16 unless there is a strong reason to require newer APIs
- verify layout on small iPhones and large Pro Max sizes

## Backend Work Needed Before Or During iOS Port

The backend is already usable for most of the mobile contract, but these decisions need to be made explicitly.

Backend work should also support Apple compliance directly, especially for APNs, entitlement handling, and privacy disclosures.

### Required decisions

1. Notifications:
   Use APNs for real iOS admin alerts and define the delivery/rate-limit policy.

2. Monetization:
   Keep the paid-upfront iPhone App Store model explicit and avoid reintroducing entitlement-sync requirements.

### Recommended backend follow-ups

- generate an OpenAPI snapshot and treat it as the mobile contract
- document field-level compatibility guarantees for mobile endpoints
- add APNs token registration endpoints
- add backend delivery rules for APNs alerts, including a one-per-hour cap if that is the chosen product policy
- distinguish visible alert pushes from silent background refresh pushes
- add contract tests for endpoints used by both Android and iOS
- document what user, device, notification, and commerce data is stored so App Store privacy answers stay accurate

## Implementation Plan By Phase

## Phase 0: Product and technical decisions

Deliverables:

- written scope for iOS v1
- APNs delivery policy
- Apple compliance checklist covering background execution, notifications, billing, privacy, and accessibility
- target minimum iOS version

Tasks:

- audit Android feature set and mark each feature as ship, defer, or cut
- freeze the initial mobile API contract
- decide whether APNs sends one alert per shutdown request or an hourly-capped summary/update
- define which App Store rules and Apple platform constraints affect each feature area
- define App Store account, bundle id, signing, and environments

Exit criteria:

- no unresolved product or Apple-compliance questions that would force iOS rework

## Phase 1: Foundation and project setup

Deliverables:

- Xcode project
- app target and build configurations
- networking, persistence, session, and environment setup

Tasks:

- create `ios-client/` with a native SwiftUI app
- add debug and release configurations
- wire backend base URL configuration
- implement API client and shared error model
- implement Keychain-backed session store
- implement localization scaffolding for `en` and `de`
- implement appearance settings
- set up capabilities and entitlements only for features actually used, to minimize App Review risk

Exit criteria:

- app launches, persists session, and can log in against dev backend

## Phase 2: Core user feature parity

Deliverables:

- login flow
- device list
- wake action
- shutdown request action

Tasks:

- build auth screens
- build first-run guidance screen adapted from Android content
- build device list screen with refresh
- add wake CTA and result handling
- add shutdown request sheet with optional note
- add empty, error, and loading states

Exit criteria:

- a normal user can log in and manage assigned devices end to end

## Phase 3: Admin feature parity

Deliverables:

- admin activity feed
- pagination
- seen/resolved actions

Tasks:

- build admin-only navigation
- implement event feed loading and cursor pagination
- map event types into user-readable rows
- add seen/resolved actions with optimistic or guarded state transitions
- add admin-specific empty/error states

Exit criteria:

- an admin can review and act on shutdown events from iPhone

## Phase 4: Notifications and background strategy

Deliverables:

- documented iOS notification behavior
- implemented APNs-based admin notifications

Tasks:

- add notification permission UX
- support in-app refresh while foregrounded
- implement device token registration, notification handling, and navigation from taps
- add backend APNs send path for admin shutdown requests
- if the product wants “once every hour,” implement that as a backend rate limit or summary policy, not client polling
- keep `BGAppRefreshTask` only as a best-effort feed refresh fallback
- verify the notification design stays within Apple’s intended APNs and background-refresh usage

Exit criteria:

- notification behavior is technically correct for iOS, Apple-compliant, and product-approved

## Phase 5: App Store distribution and monetization

Deliverables:

- paid-upfront App Store distribution setup for iPhone v1

Tasks:

- set the paid-app price tier in App Store Connect
- confirm screenshots, metadata, and review notes do not imply a free tier or in-app Pro unlock
- verify the iPhone client does not depend on entitlement sync or StoreKit runtime during normal use
- review billing and distribution claims against current App Store requirements before release

Exit criteria:

- monetization behavior matches product rules and App Store policy

## Phase 6: Accessibility, localization, and polish

Deliverables:

- accessibility pass
- German and English copy review
- legal/privacy content adapted for iOS

Tasks:

- VoiceOver audit
- Dynamic Type audit
- contrast audit
- localization QA
- review App Store privacy disclosures against actual data flows
- confirm all permission prompts and privacy copy are specific, accurate, and minimal

Exit criteria:

- app is usable without blocking accessibility defects

## Phase 7: QA, release hardening, and launch

Deliverables:

- tested release candidate
- App Store submission assets
- rollout and support plan

Tasks:

- add unit tests for API models, session logic, JWT role parsing, link parsing if used
- add UI tests for login, wake, admin feed, shutdown request flows
- test against local backend and production-like environment
- verify network failures, expired sessions, allowlist rejections, and rate limits
- prepare screenshots, privacy labels, support URL, and review notes
- run a final Apple compliance review for background modes, notification behavior, purchase flow, privacy disclosures, and accessibility

Exit criteria:

- TestFlight build approved for external testing
- launch checklist completed

## Suggested Timeline

Assuming one experienced iOS engineer with occasional backend support:

- Phase 0: 3 to 5 days
- Phase 1: 1 week
- Phase 2: 1 to 2 weeks
- Phase 3: 1 to 1.5 weeks
- Phase 4: 3 days without APNs, 1 to 2 weeks with APNs backend work
- Phase 5: 3 days if deferred out of v1, 1 week if included
- Phase 6: 3 to 5 days
- Phase 7: 1 week

Rough total:

- with paid App Store distribution and APNs support: about 7 to 10 weeks

## Risks

### High risk

- trying to replicate Android background polling exactly on iOS
- shipping iPhone paid-distribution copy or configuration that still implies a runtime unlock, restore purchase, or entitlement sync flow
- treating Apple compliance as a late-stage review task instead of a design constraint

### Medium risk

- UI drift between Android and iOS product rules
- weak localization process leading to string regressions
- accessibility being left until the end

### Low risk

- core login/device/wake flows, because the backend contract already exists

## Recommended Sequencing

1. Freeze iOS v1 scope.
2. Finalize APNs, paid-distribution, and Apple compliance rules.
3. Build the native iOS foundation.
4. Ship core user flows first.
5. Add admin activity features.
6. Solve notifications in an iOS-correct way.
7. Finish accessibility, localization, and release work.

## Concrete Definition Of Done

The port is done when:

- iPhone users can log in and wake assigned machines reliably
- admins can review activity and handle shutdown requests
- secrets are stored securely with iOS-native mechanisms
- the app is accessible and localized in English and German
- background notification behavior is honest and platform-correct
- the app’s notifications, billing, privacy, permissions, and background behavior are Apple-compliant
- App Store submission requirements are complete

## First Actions To Start Immediately

- create `ios-client/` and commit the Xcode project skeleton
- extract a written mobile API contract from the backend
- remove invite onboarding from the mobile scope and copy
- lock the paid-upfront App Store distribution configuration for iPhone v1
- define the APNs alert policy, including the one-per-hour cap if that remains the product choice
- create a written Apple compliance checklist and keep it attached to every implementation phase
