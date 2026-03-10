# Security Policy

## Reporting a vulnerability

Do not open a public GitHub issue for a suspected security vulnerability.

Use GitHub's private vulnerability reporting / security advisory workflow if it is enabled for this repository. If that is not available, contact the maintainer privately first and wait for acknowledgment before public disclosure.

Please include:

- affected component and version/commit
- deployment mode or platform
- reproduction steps
- impact assessment
- any suggested mitigation

## Scope

Security-sensitive areas in this project include:

- authentication and session handling
- admin-plane access controls
- TLS / transport enforcement
- IP allowlisting and proxy trust
- mobile app proof and platform attestation
- notification registration flows
- billing and entitlement-related Android logic

## Disclosure expectations

- We will try to acknowledge reports promptly.
- Please avoid public disclosure until a fix or mitigation is available.
- Coordinated disclosure is preferred.

## Non-security issues

For normal bugs, hardening ideas without an exploit path, or documentation mistakes, use the normal support/contribution channels instead.
