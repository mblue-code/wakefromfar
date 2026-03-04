# Google Play Publishing Plan (Organization Account)

Last updated: 2026-03-04  
Project: `wakefromfar` Android app (`android-client`)  
Scope: Public Google Play release (phone app)

## 1. Current Technical Baseline (from repo)

- [x] `compileSdk = 35` in `android-client/app/build.gradle.kts`
- [x] `targetSdk = 35` in `android-client/app/build.gradle.kts`
- [x] `minSdk = 26` (Android 8.0, released 2017-08-21) in `android-client/app/build.gradle.kts`
- [x] App bundle path exists via Android Gradle application setup (`.aab` release flow)
- [ ] Billing dependency upgrade needed before monetized production release:
  - Current in repo: `com.android.billingclient:billing-ktx:6.2.1`
  - Policy timeline: PBL 6 cutoff was 2025-08-31, PBL 7 cutoff is 2026-08-31, PBL 8 cutoff is 2027-08-31
  - Action: upgrade to supported billing version (recommended: latest stable, currently PBL 8 path)

## 2. Account and Access Setup (Org Account)

- [ ] Confirm organization account verification is fully completed in Play Console
- [ ] Confirm app owner/admin roles for release team
- [ ] Confirm Google Payments profile, payouts, and tax setup if paid app/IAP is used
- [ ] Confirm incident contacts (dev + policy/legal contact) are current

Note: The "12 testers for 14 days" gate applies to newly created personal accounts, not this org-account workflow.

## 3. Privacy and Legal Deliverables (GitHub + Play Console)

- [ ] Create privacy policy source file in repo, for example:
  - `docs/privacy-policy.en.md`
  - `docs/privacy-policy.de.md` (if you want full DE localization)
- [ ] Publish policy on a stable public URL (GitHub Pages recommended)
- [ ] Add privacy policy URL to:
  - Play Console -> App content -> Privacy policy
  - In-app legal/privacy screen (if not already linked externally)
  - `README.md` and/or `PRIVACY.md` in repo root
- [ ] Ensure policy content explicitly covers:
  - Data collected, processed, shared, and by whom
  - Purpose of processing
  - Retention and deletion
  - Security practices
  - User rights/contact method
  - Account deletion process (if accounts exist)

## 4. Billing and Monetization Readiness (if digital purchases/subscriptions)

- [ ] Upgrade Play Billing library to a supported version
- [ ] Define final product IDs and pricing model in Play Console
- [ ] Implement purchase, acknowledgement, restore, and entitlement checks
- [ ] Configure backend receipt validation (if server-side entitlements are used)
- [ ] Add license testers and run end-to-end purchase tests
- [ ] Confirm in-app wording and policy disclosures match actual billing behavior

Rule reminder: for in-app digital goods/services, Play-distributed apps must use Google Play billing unless an explicit policy exception applies.

## 5. Store Listing Assets and Copy

### Required metadata

- [ ] App name (<= 30 chars)
- [ ] Short description (<= 80 chars)
- [ ] Full description (<= 4000 chars)

### Required graphics

- [ ] App icon: 512 x 512 PNG (32-bit with alpha), max 1024 KB
- [ ] Feature graphic: 1024 x 500 JPEG or 24-bit PNG (no alpha)
- [ ] Screenshots: minimum 2 across device types, JPEG or 24-bit PNG, min 320 px, max 3840 px

### Recommended for discoverability

- [ ] At least 4 high-resolution app screenshots (1080+)
- [ ] EN + DE localized listing text and screenshots (if you target both languages)

## 6. Play Console App Content Declarations

- [ ] Privacy policy
- [ ] App access instructions (test credentials/steps if login is required)
- [ ] Ads declaration
- [ ] Data safety form
- [ ] Target audience and content questionnaire
- [ ] Content rating questionnaire
- [ ] Permissions declarations (if sensitive permissions apply)
- [ ] News declaration (only if applicable)

Gate: no release submission until App content tab has no unresolved required declarations.

## 7. Build, Signing, and Release Artifact Gate

- [ ] Build release `.aab`
- [ ] Verify Play App Signing enrollment
- [ ] Increment `versionCode` and set release `versionName`
- [ ] Confirm release keystore env vars for CI/manual release
- [ ] Upload native symbols / mapping file for crash deobfuscation
- [ ] Smoke test release build on real devices (Android 12/13/14/15 coverage if possible)

## 8. Testing and Rollout Plan

- [ ] Internal test track: basic functional + purchase smoke tests
- [ ] Closed test track: wider coverage and policy/content validation
- [ ] Pre-launch report checks and crash/ANR triage
- [ ] Production staged rollout plan:
  - [ ] 5%
  - [ ] 20%
  - [ ] 50%
  - [ ] 100%
- [ ] Managed publishing decision documented (on/off)
- [ ] Launch communications ready (release notes, changelog, support channel)

## 9. Review Timing and Risk Buffer

- [ ] Plan at least 7+ days buffer before hard launch date
- [ ] Avoid submitting extra changes during review unless necessary
- [ ] If policy rejection occurs, fix and resubmit with root-cause note in release log

## 10. Final Grammar and Localization QA Gate (English + German)

Do this immediately before submitting for final review.

### Text scope to check

- [ ] Play listing copy (name, short description, full description)
- [ ] Screenshot overlay text/captions (if used)
- [ ] In-app legal/privacy/billing user-facing text
- [ ] Privacy policy pages (EN + DE)
- [ ] Release notes/changelog text

### English QA checklist

- [ ] Grammar and spelling pass (tool + human pass)
- [ ] Consistent product naming ("WakeFromFar", features, pricing terms)
- [ ] No banned promotional wording (for example "Best", "#1", misleading claims)
- [ ] No outdated time-bound wording

### German QA checklist

- [ ] Grammar and spelling pass by native or near-native reviewer
- [ ] Formality consistency (`du` vs `Sie`) across all German text
- [ ] Technical terminology consistency (for example "Abonnement", "In-App-Kauf", "Datenschutzhinweis")
- [ ] Localized punctuation/wording natural for DE users

### Final sign-off

- [ ] EN approved by: `________________`
- [ ] DE approved by: `________________`
- [ ] Date/time approved: `________________`

## 11. Definition of Done

- [ ] All required Play Console tasks are complete
- [ ] Billing version is policy-compliant for release date
- [ ] Privacy policy is publicly reachable and linked everywhere required
- [ ] EN/DE grammar checks are completed and signed off
- [ ] Production rollout started with monitoring in place

## 12. Official References (re-check before final submission)

- Target API requirement: https://developer.android.com/google/play/requirements/target-sdk
- Billing deprecation timeline: https://developer.android.com/google/play/billing/deprecation-faq
- Payments policy: https://support.google.com/googleplay/android-developer/answer/9858738
- Prepare app for review / App content: https://support.google.com/googleplay/android-developer/answer/9859455
- Data safety form: https://support.google.com/googleplay/android-developer/answer/10787469
- Preview assets requirements: https://support.google.com/googleplay/android-developer/answer/9866151
- Create/setup app and listing limits: https://support.google.com/googleplay/android-developer/answer/9859152
- AAB requirement context: https://support.google.com/googleplay/android-developer/answer/9844279
- Publishing status/review timing note: https://support.google.com/googleplay/android-developer/answer/9859751
- Personal account testing requirement reference: https://support.google.com/googleplay/android-developer/answer/14151465
