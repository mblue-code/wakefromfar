# iPhone Release Readiness

Last updated: 2026-03-06

This document is the operational launch checklist for the native iPhone app in `ios-client/`.

## Product Truth For Release

- The iPhone app is a paid-upfront App Store app.
- No iPhone free tier exists.
- No iPhone Pro unlock runtime exists.
- No iPhone entitlement sync or purchase restore flow exists.
- Login requires an admin-provided backend URL, username, and password.
- Invite-claim onboarding is not part of the supported iPhone flow.
- APNs is used for admin alerts only.
- Session tokens are stored in Keychain.
- Non-sensitive app settings are stored in `UserDefaults`, including backend URL, last username, appearance, language, first-run guidance state, APNs installation ID, and the current APNs device token.

## Repo-Backed Status

- Code-complete for the planned iPhone scope: yes.
- Local build/lint/test validation already completed: yes.
- Release-blocking defect found during this launch-prep audit: no.
- Ready for external validation and submission setup: yes.
- Ready for TestFlight/App Store submission today: no.

Submission is still blocked by external work: App Store Connect setup, signing/provisioning, real-device QA, APNs verification on hardware, accessibility QA on hardware, and final release-owner signoff.

## Verified In Repo

- Simulator build already passed on 2026-03-06:
  - `xcodebuild -project ios-client/WakeFromFar.xcodeproj -scheme WakeFromFar -sdk iphonesimulator -configuration Debug build CODE_SIGNING_ALLOWED=NO`
- Plist/project lint already passed on 2026-03-06:
  - `plutil -lint ios-client/Resources/Localization/en.lproj/Localizable.strings`
  - `plutil -lint ios-client/Resources/Localization/de.lproj/Localizable.strings`
  - `plutil -lint ios-client/WakeFromFar.entitlements ios-client/WakeFromFar.xcodeproj/project.pbxproj`
- Backend APNs/monetization cleanup tests already passed on 2026-03-06:
  - `.venv-test/bin/python -m pytest -q backend/tests/test_apns_notifications.py backend/tests/test_ios_monetization_cleanup.py`
- Release configuration matches the intended product model:
  - `ios-client/WakeFromFar.entitlements` only enables `aps-environment`
  - Debug uses `APS_ENVIRONMENT=development`
  - Release uses `APS_ENVIRONMENT=production`
  - no APNs keys or backend secrets are hardcoded in the iPhone target

## App Store Connect And Signing Checklist

Mark every item complete before uploading the first release candidate archive.

### App Record And Bundle Consistency

- [ ] Confirm the shipping bundle identifier in App Store Connect matches the Xcode target.
- [ ] If the shipping bundle identifier is not `com.wakefromfar.iosclient`, update Xcode and backend `APNS_TOPIC` together before archiving.
- [ ] Confirm app name, subtitle, primary category, age rating, and availability are final.
- [ ] Confirm the version and build number planned for upload match the App Store Connect record.
- [ ] Confirm the support URL is live and owned by the publisher.
- [ ] Confirm the privacy policy URL is live and points to the current iPhone-aware policy.

### Paid-App Pricing

- [ ] Set the iPhone app to the intended paid price tier.
- [ ] Review region availability and storefront pricing before saving the final price schedule.
- [ ] Confirm agreements, tax, and banking are complete for the publisher account.
- [ ] Confirm metadata and screenshots do not mention a free tier, Pro unlock, restore purchases, subscriptions, or trial language.

### Metadata

- [ ] Finalize the App Store description.
- [ ] Finalize the subtitle.
- [ ] Finalize keywords.
- [ ] Upload required iPhone screenshots for the supported device classes.
- [ ] Confirm screenshots show the current paid-app UI and do not show retired billing or invite-claim flows.

### Signing And Provisioning

- [ ] Confirm the shipping App ID has Push Notifications enabled in Apple Developer.
- [ ] Confirm the Release/App Store provisioning profile includes Push Notifications.
- [ ] Confirm Release signing uses the intended team, certificate, and provisioning profile.
- [ ] Confirm the archived build contains only the expected entitlements.
- [ ] Confirm the app icon, launch assets, and bundle display name match the App Store record.

## App Review Notes Draft

Use this as the submission note and replace bracketed placeholders before submission:

> WakeFromFar is a paid-upfront iPhone app for connecting to a self-hosted WakeFromFar backend. The app does not include an iPhone free tier, in-app purchase flow, or purchase restore flow. Login requires backend credentials supplied by the user’s administrator: backend URL, username, and password. User actions such as viewing assigned devices, sending wake requests, and submitting shutdown requests are performed against the user’s configured backend instance. Admin accounts can also open the activity feed and receive APNs alerts for admin activity. Review credentials for the staging instance: backend URL `[INSERT URL]`, username `[INSERT USERNAME]`, password `[INSERT PASSWORD]`.

## Privacy And App Store Disclosure Checklist

The privacy policy and App Store disclosures must match the actual shipped iPhone behavior.

- [ ] Fill the publisher identity, address, and privacy contact placeholders in both privacy-policy documents before publishing the privacy policy URL.
- [ ] Confirm the privacy policy states that the iPhone app is paid upfront and does not use an in-app entitlement sync or purchase restore flow.
- [ ] Confirm the privacy policy states that auth tokens are stored in Keychain on iPhone.
- [ ] Confirm the privacy policy states that non-sensitive settings are stored locally in `UserDefaults` on iPhone.
- [ ] Confirm the privacy policy states that APNs installation IDs and device tokens are registered for admin alerts.
- [ ] Confirm the privacy policy states that backend communication covers login, assigned devices, wake actions, shutdown requests, admin activity, and related audit/security processing.
- [ ] Confirm the App Store privacy questionnaire answers cover the actual iPhone data handling:
  - login/account data supplied by the user
  - backend URL and local settings stored on device
  - APNs installation ID and device token for admin alerts
  - backend-provided device assignment and admin activity data
  - backend-side request IP/security logging
- [ ] Confirm the App Store privacy questionnaire does not claim an iPhone purchase token, receipt sync, restore flow, or other retired entitlement runtime.

## Real-Device QA Checklist

Run this on physical iPhone hardware with the release candidate build. Record device model, iOS version, backend environment, tester, and pass/fail notes for every run.

### First Run And Authentication

- [ ] Fresh install shows first-run guidance and clearly indicates that backend URL and credentials must come from an administrator.
- [ ] First run does not show any invite-claim, free-tier, or purchase-restore flow.
- [ ] Invalid backend URL is rejected with a user-visible error.
- [ ] Invalid username/password is rejected with a user-visible error.
- [ ] Valid login lands on the signed-in app and shows the correct account role behavior.
- [ ] Cold launch after successful login restores the session without forcing a new login.
- [ ] Logout returns to the signed-out flow and a cold relaunch stays signed out.
- [ ] Account switch from admin to non-admin removes admin-only UI and does not keep admin notification behavior.
- [ ] Account switch from one admin account to another succeeds without stale username, device, or activity data leakage.

### Core User Flows

- [ ] Device list loads assigned devices only.
- [ ] Pull-to-refresh updates the device list and status timestamps.
- [ ] Wake action succeeds for an assigned offline device and shows the correct success copy.
- [ ] Wake action on an already-on device shows the correct already-on result.
- [ ] Unauthorized or unassigned-device access is not exposed through the UI.
- [ ] Shutdown request creation succeeds from the device flow and shows the expected confirmation state.

### Admin Flows

- [ ] Admin activity feed is visible only to admin accounts.
- [ ] Admin activity feed loads current items and paginates older items correctly.
- [ ] Admin seen and resolved actions succeed and update the UI correctly.
- [ ] Foreground refresh of admin activity remains stable after repeated pulls, pagination, and action mutations.

### Notifications

- [ ] A non-admin session is never prompted for notification permission from normal app use.
- [ ] An admin session is prompted only from the admin-notification path.
- [ ] After permission is granted, the app shows the authorized state in Settings.
- [ ] After permission is denied, the app shows the denied state in Settings and offers the Settings deep link.
- [ ] APNs alerts for admin activity arrive on real hardware and route to the Activity tab when tapped.

### Accessibility And Presentation

- [ ] English and German strings render correctly on device.
- [ ] Very large Dynamic Type keeps login, device list, wake, shutdown, activity, and settings flows usable.
- [ ] VoiceOver can identify and activate the main controls in login, device list, wake, shutdown request, activity, settings, and logout flows.
- [ ] VoiceOver announces enough context for device state and admin activity rows to complete the task.

## APNs Validation Checklist

This checklist must be completed on physical iPhone hardware. Simulator results do not count.

### Apple And Backend Configuration

- [ ] Push Notifications is enabled for the shipping App ID.
- [ ] The shipping provisioning profile includes Push Notifications.
- [ ] Backend production APNs settings are configured:
  - `APNS_ENABLED=true`
  - `APNS_TOPIC=<shipping bundle id>`
  - `APNS_ENVIRONMENT=production`
  - `APNS_TEAM_ID`
  - `APNS_KEY_ID`
  - `APNS_PRIVATE_KEY` or `APNS_PRIVATE_KEY_PATH`
- [ ] If alert throttling is part of the release policy, `APNS_ADMIN_ALERT_MIN_VISIBLE_INTERVAL_SECONDS` is set intentionally.

### Registration And Permission Flow

- [ ] Fresh admin login with notification status `not determined` does not register a backend device record until permission is granted and a device token exists.
- [ ] Granting notification permission on an admin account results in device-token registration with the backend.
- [ ] Denying notification permission on an admin account leaves the app in the denied state and does not keep a valid backend registration.
- [ ] A non-admin account does not create or refresh APNs backend registration.

### Delivery And Routing

- [ ] Foreground delivery on an admin device shows the expected visible alert and refreshes activity data without forcing tab navigation.
- [ ] Background delivery on an admin device shows the expected visible alert.
- [ ] Tapping a delivered admin alert opens the app to the Activity tab.
- [ ] Launching the app from a terminated state via notification tap still routes to the Activity tab.

### Deregistration And Account Changes

- [ ] Admin logout removes the backend APNs registration for that installation.
- [ ] Admin-to-user account switch removes the previous admin registration.
- [ ] Admin-to-admin account switch replaces the registration context cleanly and does not leave the prior account registered.
- [ ] If notification permission is later denied in iOS Settings, the next admin app session removes or invalidates the backend registration as expected.

## Final Go/No-Go Gate

Do not submit until every category below is green.

- [x] Code/build ready
  - simulator build, plist/project lint, and backend APNs/monetization cleanup tests already passed on 2026-03-06
  - no new release-blocking code defect was found in this launch-prep audit
- [ ] App Store Connect ready
  - blocked until pricing, region availability, metadata, privacy policy URL, support URL, review notes, and agreements are complete
- [ ] Signing ready
  - blocked until Release signing, App ID capabilities, and shipping provisioning are confirmed
- [ ] Real-device QA ready
  - blocked until the manual iPhone checklist above is completed on hardware
- [ ] APNs verified
  - blocked until production-like APNs registration, delivery, routing, and deregistration are verified on hardware
- [ ] Accessibility checked
  - blocked until Dynamic Type and VoiceOver passes are completed on hardware
- [ ] Submission-ready
  - blocked until every gate above is complete and the release owner confirms go/no-go

## Remaining External And Manual Blockers

- App Store Connect paid-app pricing and metadata still need to be completed.
- App Review notes still need final credentials and copy review.
- Real-device QA for login/logout, wake, shutdown, and admin flows still needs to be run.
- Real-device APNs validation still needs production-like credentials, signing, and hardware.
- Real-device accessibility QA still needs Dynamic Type and VoiceOver passes on hardware.
- Final signing/provisioning and launch-owner signoff still need to happen before submission.
