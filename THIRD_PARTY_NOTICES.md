# Third-Party Notices

This repository uses third-party open-source software.

This file is based on the dependency manifests currently in this repo:

- `backend/requirements.txt`
- `backend/requirements-dev.txt`
- `android-client/app/build.gradle.kts`
- `backend/Dockerfile`

Last reviewed: 2026-03-02

## Python Backend Dependencies (Direct)

- fastapi (`fastapi==0.116.1`) - MIT License - https://github.com/fastapi/fastapi
- uvicorn (`uvicorn[standard]==0.35.0`) - BSD-3-Clause - https://github.com/encode/uvicorn
- PyJWT (`PyJWT==2.10.1`) - MIT License - https://github.com/jpadilla/pyjwt
- passlib (`passlib[bcrypt]==1.7.4`) - BSD License - https://passlib.readthedocs.io/
- bcrypt (`bcrypt==4.0.1`) - Apache-2.0 - https://github.com/pyca/bcrypt
- pydantic-settings (`pydantic-settings==2.10.1`) - MIT License - https://github.com/pydantic/pydantic-settings
- python-multipart (`python-multipart==0.0.20`) - Apache-2.0 - https://github.com/Kludex/python-multipart
- redis (`redis==6.4.0`) - MIT License - https://github.com/redis/redis-py

## Python Development/Test Dependencies (Direct)

- pytest (`pytest==8.4.2`) - MIT License - https://github.com/pytest-dev/pytest
- httpx (`httpx==0.28.1`) - BSD-3-Clause - https://github.com/encode/httpx

## Python Transitive License Notes

The current resolved tree also includes, among others:

- certifi - MPL-2.0
- packaging - Apache-2.0 OR BSD-2-Clause
- typing_extensions - PSF-2.0
- uvloop - Apache-2.0 and MIT

## Android Dependencies (Direct)

All versions are from `android-client/app/build.gradle.kts`.

- Jetpack / AndroidX:
  - `androidx.core:core-ktx:1.15.0` - Apache-2.0
  - `androidx.appcompat:appcompat:1.7.0` - Apache-2.0
  - `androidx.activity:activity-compose:1.10.0` - Apache-2.0
  - `androidx.lifecycle:lifecycle-runtime-ktx:2.8.7` - Apache-2.0
  - `androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7` - Apache-2.0
  - `androidx.compose:compose-bom:2025.01.00` (and managed Compose artifacts) - Apache-2.0
  - `androidx.security:security-crypto:1.1.0-alpha06` - Apache-2.0
- Kotlin ecosystem:
  - `org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0` - Apache-2.0
  - `org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.0` - Apache-2.0
- Networking:
  - `com.squareup.okhttp3:okhttp:4.12.0` - Apache-2.0
  - `com.squareup.okhttp3:logging-interceptor:4.12.0` - Apache-2.0
- Test-only:
  - `junit:junit:4.13.2` - EPL-1.0

## Fonts

The Android app uses Google Fonts provider (`androidx.compose.ui:ui-text-google-fonts`) for:

- Outfit
- JetBrains Mono

These fonts are delivered via Google Fonts and are typically licensed under SIL Open Font License 1.1. Verify final font metadata in release builds.

## Container / OS Packages

The backend container image is based on `python:3.12-slim` and installs Debian packages:

- `iproute2`
- `libnss-mdns`

When redistributing images, keep corresponding package notices/source-offer obligations in mind for the exact Debian package versions included in the built image.

## Monetization-Related Dependency (Planned)

The monetization plan references Google Play Billing to be implemented later. The billing artifact (`com.android.billingclient:billing-ktx`) is distributed under Android SDK terms (not a standard OSI open-source license). Include it in release compliance once added.

## Disclaimer

This notice file is informational and not legal advice. For distribution, rely on exact lockfiles/artifacts in your release pipeline and include the full upstream license texts where required.
