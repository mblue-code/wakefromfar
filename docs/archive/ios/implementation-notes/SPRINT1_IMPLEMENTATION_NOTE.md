# iOS Sprint 1 Implementation Note

## Architecture decisions

- The iPhone client is a fully native SwiftUI app under `ios-client/` with an iPhone-only target and an iOS 16 deployment floor.
- App structure is split by responsibility:
  - `App/` for entry, root navigation, shared UI helpers
  - `Features/` for Auth, Devices, Admin Activity, and Settings screens/view models
  - `Services/API/` for HTTP transport and backend contract models
  - `Services/Auth/` for session bootstrap and JWT role decoding
  - `Persistence/` for Keychain and `UserDefaults`
  - `Services/Notifications/` and `Services/Billing/` for APNs and StoreKit 2 seams
- Swift concurrency (`async/await`) is used for networking and feature actions. No Android-style polling loop or wrapper architecture was introduced.
- Auth token storage is Keychain-backed and device-local. Backend URL, username hint, appearance, and language live in `UserDefaults`.
- The root shell restores a saved session on launch and routes to a native SwiftUI tab shell. Admin-only activity UI is gated by the JWT role claim for client UX only; backend authorization still controls real access.

## Backend contract mapping

Mapped directly from `backend/app/main.py` and `backend/app/schemas.py`:

- `POST /auth/login`
  - `LoginRequest`
  - `LoginResponse`
- `GET /me/devices`
  - `MyDevice`
- `POST /me/devices/{id}/wake`
  - `MeWakeResponse`
- `POST /me/devices/{id}/shutdown-poke`
  - `ShutdownPokeCreateRequest`
  - `ShutdownPoke`
- `GET /admin/mobile/events`
  - `ActivityEvent`
  - optional `cursor`, `limit`, `type` query handling

The iOS client intentionally does not implement `POST /onboarding/claim` because the backend marks invite onboarding as disabled (`410 Gone`).

## Apple-compliance guardrails

- No invite claim flow or deep-link onboarding path exists in the iOS client.
- No background polling worker, foreground service analogue, or unsupported background execution design was added.
- No entitlements or extra capabilities were added in Sprint 1.
- APNs is documented as the future admin-alert path.
- Billing is reserved behind a StoreKit 2-oriented coordinator seam instead of Android billing logic.

## Open risks

- This environment does not currently have a full Xcode developer directory selected, so `xcodebuild` verification is still blocked here.
- The project includes an app target and scheme, but final signing, launch, and simulator validation still need to run on a machine with full Xcode installed.
- Device list and admin activity UIs are intentionally thin. Sprint 2 should harden view states, pagination polish, error recovery, and accessibility pass details.
- APNs and StoreKit 2 are scaffolded only as seams; real entitlement and notification flows remain unimplemented.

## Sprint 2 next

- Build out production-ready device list UX, including richer state badges, wake feedback, and shutdown-request affordances.
- Expand admin activity into a proper feed with clearer event rendering, pagination polish, and action handling for shutdown-poke lifecycle changes.
- Implement APNs registration and admin alert delivery architecture.
- Replace billing scaffolding with real StoreKit 2 product loading, purchase, restore, and entitlement handling.
- Add unit tests for URL normalization, Keychain persistence, session restore, and API decoding.
