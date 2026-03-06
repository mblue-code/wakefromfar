# iOS Sprint 2 Implementation Note

## What was built

- Finished the signed-out to signed-in flow for normal users on top of the Sprint 1 foundation.
- Added a first-run guidance screen aligned with the current product policy:
  - backend setup is admin-managed
  - credentials come directly from an admin
  - protected private networking is required
  - no invite or deep-link onboarding exists on iPhone
- Persisted first-run acknowledgement in the existing `UserDefaults` preferences layer.
- Hardened the login screen with clearer product-policy copy, validation-driven button state, and retained secure session persistence through the existing `SessionStore` and Keychain storage.
- Upgraded the non-admin device list flow:
  - real `/me/devices` loading
  - dedicated empty state
  - dedicated first-load error state with retry
  - pull-to-refresh
  - richer per-device status presentation for power state, stale state, MAC, and last checked timestamp
- Implemented end-user wake feedback against `/me/devices/{id}/wake` using the real backend response semantics for `already_on`, `sent`, and `failed`.
- Implemented the user shutdown-request flow against `/me/devices/{id}/shutdown-poke`, including the optional note field and a local 280-character guardrail that matches the backend contract.
- Added English and German coverage for the new user-facing strings and improved VoiceOver labels so device status is not conveyed by color alone.

## What remains

- Admin activity parity and shutdown seen/resolved flows are still follow-up work.
- APNs is still only architectural groundwork; no registration, delivery, or notification handling shipped in Sprint 2.
- StoreKit 2 remains a seam only; no product loading, purchase flow, restore flow, or entitlement handling shipped in Sprint 2.
- Full simulator/device build verification still requires a machine with full Xcode selected.

## Open technical risks

- Backend-provided error strings may still arrive in backend/default language for some server failures because those messages come from the API, not the app bundle.
- Wake status can legitimately lag behind the wake request; the client now performs an immediate refresh and a follow-up refresh, but device power-state convergence still depends on backend checks and the target machine boot time.
- The legal/privacy screen is still a concise in-app summary rather than a fully productized legal surface.
