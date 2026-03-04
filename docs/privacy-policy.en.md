# WakeFromFar Privacy Policy (English)

Effective date: 2026-03-04  
Last updated: 2026-03-04

This Privacy Policy explains how personal data is processed when you use the WakeFromFar Android app and related backend services.

Legal notice: This document is an operational policy template for this project and is not legal advice.

## 1. Who is responsible

### 1.1 App publisher (Google Play)

Controller for app distribution and support:

- Organization name: `[INSERT ORGANIZATION NAME]`
- Address: `[INSERT REGISTERED ADDRESS]`
- Email: `[INSERT PRIVACY CONTACT EMAIL]`

### 1.2 Backend operator (self-hosted environment)

WakeFromFar is designed for self-hosted use. The organization or administrator running your backend instance is typically the controller for backend data processed in that instance.

If your administrator operates the backend, please contact that administrator first for data requests related to backend logs, user accounts, and assigned devices.

## 2. Scope

This policy covers:

- WakeFromFar Android app
- WakeFromFar backend APIs and admin UI (if operated by or on behalf of the controller)
- Google Play Billing flows (if enabled in the app)

## 3. Data we process

The exact data depends on your role (user/admin) and enabled features.

### 3.1 Account and authentication data

- Username
- Password hash stored on backend (not plaintext password)
- Authentication token stored locally on device after login

### 3.2 App configuration and local app data (on your device)

- Backend URL
- Last-seen activity IDs for admin alerts
- App preferences (for example theme/language/onboarding state)
- Local monetization state (for example Pro unlock status and free-tier device ordering key)

Note: The app stores security-sensitive session data in encrypted shared preferences on Android.

### 3.3 Device and infrastructure data (backend)

- Assigned device metadata (for example device name, MAC address, broadcast/subnet/source IP configuration)
- Power-check settings and state (for example check target, check port, last known power state)

### 3.4 Operational logs and audit events (backend)

- Wake events (actor, target, result, timestamp)
- Power-check events (method, result, detail, latency, timestamp)
- Admin audit logs (actor, action, target, detail, timestamp)
- Invite token metadata (hashed token, username, creation and claim status)
- Discovery events/candidates (for network/device discovery features, if used)

### 3.5 Network and security metadata

- Request IP address and related metadata used for authentication protection, rate limiting, and abuse prevention

### 3.6 Billing data (only if purchases are enabled)

- Product identifiers and purchase tokens/transaction identifiers needed for entitlement verification
- Payment processing is performed by Google Play under Google terms
- Full payment card data is not processed by the WakeFromFar backend

## 4. Why we process data (purposes)

We process data to:

- Provide login, onboarding, and authenticated app access
- Show assigned devices and their current status
- Execute wake and power-check actions
- Provide admin activity, diagnostics, and security/audit functions
- Operate anti-abuse protections (for example rate limits)
- Deliver and validate paid features (if billing is enabled)
- Maintain service reliability, debugging, and incident response

## 5. Legal bases (GDPR, where applicable)

Depending on context, processing is based on:

- Art. 6(1)(b) GDPR (performance of a contract / service delivery)
- Art. 6(1)(f) GDPR (legitimate interests: security, fraud prevention, service integrity, troubleshooting)
- Art. 6(1)(c) GDPR (legal obligations), where required

If special categories of personal data are processed (normally not intended for this service), additional legal bases are required.

## 6. Data sharing

We do not sell personal data.

Data may be shared with:

- Hosting/infrastructure providers used by the backend operator
- Service providers acting under instructions (processors)
- Google (for Play Store distribution and Play Billing, when enabled)
- Authorities, where required by law

## 7. International transfers

If providers process data outside your country/EEA, appropriate safeguards should be implemented by the relevant controller (for example standard contractual clauses where required).

## 8. Retention

- App publisher does not operate a central wake-activity cloud by default for this project architecture.
- Backend data is retained by the backend operator for as long as needed for operations, security, and support, unless deleted earlier.
- Device-local app data remains on the device until removed by logout, app data reset, or uninstall.
- Billing-related identifiers are retained as needed for entitlement checks, accounting, and fraud prevention.

You should define and apply concrete retention windows in your operations policy.

## 9. Security measures

Measures may include:

- Token-based authentication
- Password hashing on backend
- Encrypted local storage for sensitive app session data
- Access controls and role separation (admin/user)
- Rate limiting and security logging
- Private network deployment guidance (for example WireGuard/Tailscale)

No system is completely risk-free; security controls are continuously reviewed and improved.

## 10. Your rights

Where applicable law grants these rights, you may request:

- Access to your personal data
- Rectification of inaccurate data
- Deletion of data
- Restriction of processing
- Data portability
- Objection to certain processing
- Withdrawal of consent (if processing is based on consent)

You may also lodge a complaint with your local data protection authority.

## 11. How to exercise rights

For backend-instance data, contact your backend administrator first.  
For app publisher requests, contact: `[INSERT PRIVACY CONTACT EMAIL]`.

We may require reasonable verification of identity before fulfilling requests.

## 12. Children's privacy

This service is not intended for children under the age required by applicable law for independent consent to digital services.

## 13. Changes to this policy

We may update this policy from time to time. Material changes will be reflected by updating the "Last updated" date and, where required, by additional notice.
