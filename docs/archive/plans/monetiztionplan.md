# Monetization Plan (Play Store + Open Source)

## Summary

Use a **freemium app model** on Google Play:

- Keep backend functionality fully capable.
- In the Play Store Android app, allow free users to see only **2 devices**.
- Offer a **one-time Pro unlock** purchase to remove the limit.
- Keep the project open source; forks may remove limits, but the official Play build remains monetized.

This balances revenue with openness and keeps the UX simple.

## Product Model

### Free Tier

- User can connect/login normally.
- App shows at most **2 devices** in the UI.
- Additional devices are hidden/locked with an upgrade prompt.

### Pro Tier (One-Time)

- One-time in-app purchase (non-consumable) unlocks full device visibility.
- Purchase should be restorable after reinstall/new phone.

## Architecture Decision

Do **not** rely only on client-side checks.

### Required enforcement

- **Server-side entitlement check** determines whether user has Pro.
- Backend responses (or filtering layer) enforce the 2-device cap for non-Pro users.
- Android UI should reflect server entitlement, but UI gating alone is not sufficient.

Reason: client-only limits are easy to bypass in modded builds.

## Entitlement Flow

1. User taps “Upgrade to Pro” in Android app.
2. App completes Google Play Billing purchase for non-consumable product.
3. App sends purchase token + user auth to backend.
4. Backend verifies purchase and records entitlement (`pro = true`) for the account.
5. Device list endpoint applies rule:
   - `pro = false` -> return/show max 2 devices
   - `pro = true` -> return/show all devices
6. On app startup, app requests entitlement status from backend and updates UI.
7. “Restore purchases” triggers backend re-validation and entitlement sync.

## Data Model (Minimal)

- `users` table/record:
  - `is_pro` (bool)
  - `pro_source` (e.g., `google_play`)
  - `pro_updated_at`
- `purchases` table/record:
  - `user_id`
  - `platform`
  - `product_id`
  - `purchase_token`
  - `purchase_state`
  - timestamps/audit fields

## Android Implementation Notes

- Use Google Play Billing for one-time non-consumable product.
- Implement:
  - purchase flow
  - acknowledgment
  - restore/requery flow
  - error/retry handling
- Avoid storing authoritative Pro state only locally.

## Backend Implementation Notes

- Add entitlement API endpoint (read status).
- Add purchase verification endpoint (write/update entitlement).
- Gate device-list response by entitlement.
- Add logging/audit trail for verification outcomes.

## Open Source + Distribution Strategy

- Keep source code public.
- In official Play release:
  - enforce paid unlock policy as above.
- Accept that forks can remove limits; value of official app remains:
  - convenience
  - trusted binaries
  - updates/support

## Policy Notes (Date-Sensitive)

As of **March 2, 2026**:

- For digital unlocks, the most conservative global path is Google Play Billing.
- There are US policy changes from late 2025; if adopting alternatives, handle region/program eligibility explicitly.

References:

- Google Play Payments policy: https://support.google.com/googleplay/android-developer/answer/9858738?hl=en
- US policy update (Oct/Dec 2025): https://support.google.com/googleplay/android-developer/answer/15582165?hl=en

## Rollout Plan

1. Implement backend entitlement + verification.
2. Add Android billing + restore flow.
3. Add feature gating in device list and UI.
4. Internal testing (new purchase, restore, reinstall, account switch).
5. Staged rollout in Play Console.
6. Monitor billing/verification error rates and support tickets.

## Risks and Mitigations

- **Bypass risk (modded client):**
  - Mitigation: server-side enforcement.
- **Restore failures/friction:**
  - Mitigation: explicit restore button + backend reconciliation.
- **Policy drift over time:**
  - Mitigation: periodic Play policy review before major releases.

