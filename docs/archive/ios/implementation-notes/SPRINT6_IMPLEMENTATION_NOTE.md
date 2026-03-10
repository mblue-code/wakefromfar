# Sprint 6 Implementation Note

Historical note: references below to StoreKit-backed entitlement attachment reflect the Sprint 6 state. Sprint 3 of the later monetization refactor removed that iPhone runtime and backend compatibility surface on 2026-03-06.

## What Was Built

- Completed a focused accessibility pass across the major iPhone flows shipped in Sprints 1 through 5.
- Hardened custom SwiftUI layouts so they behave more predictably under larger Dynamic Type sizes.
- Cleaned up English and German copy across login, devices, admin activity, billing, notifications, settings, and legal/privacy surfaces.
- Tightened legal/privacy language so it matches the current iPhone implementation for Keychain storage, UserDefaults usage, APNs registration, and StoreKit-backed entitlement attachment.
- Polished several user-facing states to reduce App Review friction and improve broad usability without changing the underlying feature set.

## Accessibility And UI Resilience

- Added or improved accessibility semantics on the custom non-Form surfaces:
  - first-run guidance
  - login
  - device list rows
  - shutdown request sheet
  - admin activity rows
  - empty states
  - in-app feedback banners
- Added explicit labels and hints where placeholder-only or icon-heavy UI was too implicit for VoiceOver.
- Preserved text labels for important state so power status, stale status, and admin event status are not conveyed by color alone.
- Reworked the densest custom layouts with `ViewThatFits` and multiline-safe text so they can stack cleanly when content size grows:
  - device title plus state badge
  - device action buttons
  - admin activity summary plus status badge
  - admin activity action buttons
- Ensured long legal/privacy, billing, and notification summary copy can wrap instead of clipping in `Form` and `List` rows.

## Localization And Copy Quality

- Updated English and German wording to remove implementation-note phrasing and reduce backend jargon leaking into the UI.
- Standardized shutdown-request terminology so user-facing copy is clearer and more consistent across device and admin flows.
- Improved sign-in copy with visible field labels, better prompts, and more specific validation guidance.
- Clarified billing language so it describes the actual hybrid model:
  - StoreKit 2 verifies the purchase on iPhone
  - the selected backend stores which authenticated WakeFromFar account that purchase is attached to
- Clarified admin notification wording so it matches the current APNs implementation:
  - permission is only requested in admin-specific contexts
  - there is no periodic background polling

## Privacy And Legal Alignment

- Updated the in-app legal/privacy summary so it now explicitly reflects the current implementation:
  - auth session token stays in iOS Keychain
  - backend URL, username hint, appearance, language, free-tier ordering, and backend-scoped entitlement attachment cache are stored locally in `UserDefaults`
  - APNs installation id and current device token are stored locally and registered with the selected backend when admin alerts are enabled
  - StoreKit 2 payment and backend entitlement attachment data are processed only as needed for Pro access on the signed-in account
- Narrowed compliance wording to avoid unsupported claims around invites, background behavior, purchase transfer, and notification behavior.

## Verification

- `xcodebuild -project ios-client/WakeFromFar.xcodeproj -scheme WakeFromFar -sdk iphonesimulator -configuration Debug build CODE_SIGNING_ALLOWED=NO`
  - succeeded on March 5, 2026
- `plutil -lint ios-client/Resources/Localization/en.lproj/Localizable.strings`
  - passed
- `plutil -lint ios-client/Resources/Localization/de.lproj/Localizable.strings`
  - passed
- `plutil -lint ios-client/WakeFromFar.entitlements ios-client/WakeFromFar.xcodeproj/project.pbxproj`
  - passed
- English and German localization key parity check
  - passed

## Remaining Sprint 7 Risks

- Real VoiceOver and very-large Dynamic Type behavior still need on-device/manual QA. This sprint improves the obvious code-level risks but cannot fully verify assistive-technology behavior locally.
- Real APNs delivery, permission prompting, and backend registration behavior still need validation with production-like credentials and physical devices.
- Real StoreKit sandbox or App Store Connect transaction verification is still unverified in this environment.
- Refund/revocation handling still depends on StoreKit refresh and transaction updates rather than App Store Server integration.
- Final App Store Connect privacy answers and App Review notes still need a product/release pass against the shipping build and production backend configuration.
