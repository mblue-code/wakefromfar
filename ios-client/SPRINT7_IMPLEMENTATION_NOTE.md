# Sprint 7 Implementation Note

Historical note: this note reflects the pre-refactor release state. Sprint 3 of the later monetization cleanup removed the iPhone entitlement sync flow and replaced it with a paid-upfront App Store model on 2026-03-06.

## What Changed

- Performed a final release-hardening pass focused on concrete production risks instead of new feature work.
- Hardened iPhone async session handling so stale responses from an old session cannot overwrite newer state or log out a different account during logout/account-switch transitions.
  - Applied to device loading/actions, admin activity loading/actions, APNs registration sync, and StoreKit entitlement refresh.
- Added targeted backend tests for launch-risk edges:
  - deactivated APNs registrations no longer receive shutdown alerts
  - unsupported iPhone product ids are rejected during entitlement sync
- Added release-readiness documentation and a concrete TestFlight/App Store checklist in `docs/ios-release-readiness.md`.
- Updated release docs and privacy-policy templates so repository guidance reflects the shipping iPhone/APNs/StoreKit behavior instead of only the earlier Android scope.

## Verification

- `xcodebuild -project ios-client/WakeFromFar.xcodeproj -scheme WakeFromFar -sdk iphonesimulator -configuration Debug build CODE_SIGNING_ALLOWED=NO`
  - succeeded on 2026-03-05
- `plutil -lint ios-client/Resources/Localization/en.lproj/Localizable.strings ios-client/Resources/Localization/de.lproj/Localizable.strings ios-client/WakeFromFar.entitlements ios-client/WakeFromFar.xcodeproj/project.pbxproj`
  - passed on 2026-03-05
- `.venv-test/bin/python -m pytest -q backend/tests/test_apns_notifications.py backend/tests/test_ios_billing_entitlements.py`
  - passed on 2026-03-05 with `7 passed`

## Remaining External Or Manual Work

- Real-device login/logout/account-switch QA
- Real-device wake, shutdown request, and admin flow QA
- VoiceOver and very-large Dynamic Type validation on physical hardware
- APNs end-to-end validation with production signing, provisioning, and Apple credentials
- StoreKit sandbox/App Store Connect purchase, restore, and revocation validation
- App Store Connect metadata, screenshots, support/privacy URLs, review notes, and signing/provisioning setup

## Release Assessment

- Code-complete: yes
- Ready for external validation and TestFlight preparation: yes
- Ready for App Store submission: not yet

The remaining blockers are outside local code verification rather than missing core implementation. Submission readiness now depends on external Apple service setup, real-device validation, and App Store Connect metadata completion.
