# Third-Party Notices

This repository uses third-party software. This notice is based on the dependency manifests currently tracked in the repo and is intended as a release-facing summary, not a substitute for shipping the upstream license texts with distributed artifacts.

Manifest inputs reviewed on 2026-03-10:

- `backend/requirements.txt`
- `backend/requirements-dev.txt`
- `android-client/app/build.gradle.kts`
- `backend/Dockerfile`
- `ios-client/WakeFromFar.xcodeproj/project.pbxproj`

## Python Backend Dependencies (Direct)

- `fastapi==0.116.1` - MIT - <https://github.com/fastapi/fastapi>
- `uvicorn[standard]==0.35.0` - BSD-3-Clause - <https://github.com/encode/uvicorn>
- `PyJWT==2.10.1` - MIT - <https://github.com/jpadilla/pyjwt>
- `cryptography==44.0.1` - Apache-2.0 OR BSD-3-Clause - <https://github.com/pyca/cryptography>
- `httpx[http2]==0.28.1` - BSD-3-Clause - <https://github.com/encode/httpx>
- `passlib[bcrypt]==1.7.4` - BSD - <https://passlib.readthedocs.io/>
- `bcrypt==4.0.1` - Apache-2.0 - <https://github.com/pyca/bcrypt>
- `pydantic-settings==2.10.1` - MIT - <https://github.com/pydantic/pydantic-settings>
- `python-multipart==0.0.20` - Apache-2.0 - <https://github.com/Kludex/python-multipart>
- `redis==6.4.0` - MIT - <https://github.com/redis/redis-py>
- `cbor2==5.6.5` - MIT - <https://github.com/agronholm/cbor2>

## Python Development/Test Dependencies (Direct)

- `pytest==8.4.2` - MIT - <https://github.com/pytest-dev/pytest>

## Python Transitive Notes

- The `httpx[http2]` extra brings in HTTP/2 support dependencies such as `h2`, `hpack`, and `hyperframe`; validate the exact resolved versions in your release environment.
- The Python dependency tree also commonly includes packages such as `certifi`, `typing_extensions`, and `packaging`; verify the final lockfile or wheel set used for distribution.

## Android Dependencies (Direct)

Versions below are taken from `android-client/app/build.gradle.kts`.

### AndroidX / Jetpack Compose

- `androidx.core:core-ktx:1.15.0` - Apache-2.0
- `androidx.appcompat:appcompat:1.7.0` - Apache-2.0
- `androidx.activity:activity-compose:1.10.0` - Apache-2.0
- `androidx.lifecycle:lifecycle-runtime-ktx:2.8.7` - Apache-2.0
- `androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7` - Apache-2.0
- `androidx.compose:compose-bom:2025.01.00` and Compose artifacts managed by that BOM - Apache-2.0
- `androidx.security:security-crypto:1.1.0-alpha06` - Apache-2.0

### Kotlin and Networking

- `org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0` - Apache-2.0
- `org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.0` - Apache-2.0
- `com.squareup.okhttp3:okhttp:4.12.0` - Apache-2.0
- `com.squareup.okhttp3:logging-interceptor:4.12.0` - Apache-2.0

### Google SDK Terms

- `com.android.billingclient:billing-ktx:6.2.1` - distributed under Google Play / Android SDK terms, not a standard OSI license
- `com.google.android.play:integrity:1.6.0` - distributed under Google Play services / Android SDK terms, not a standard OSI license

### Android Test Dependencies

- `junit:junit:4.13.2` - EPL-1.0
- `com.squareup.okhttp3:mockwebserver:4.12.0` - Apache-2.0

## Fonts

The Android app uses Google Fonts provider support from Compose for:

- Outfit
- JetBrains Mono

Verify the final font metadata and license files included in release builds.

## iPhone Target Notes

The tracked iPhone target currently relies on Apple platform frameworks from Xcode rather than a checked-in third-party package manager lockfile. For public distribution:

- treat Apple framework usage under Apple's platform terms
- continue shipping repo-level notices for shared backend, Android, container, and project-level legal material
- re-run this review if Swift Package Manager, CocoaPods, or other vendored iOS dependencies are added

## Container / OS Packages

The backend container image is based on `python:3.12-slim` and installs Debian packages including:

- `iproute2`
- `libnss-mdns`

If you redistribute built images, verify the exact Debian package metadata and include any required notices or source-offer material for the shipped package set.

## Distribution Reminder

Official maintained binaries are the store-published releases from the project/publisher. Source builds, self-hosted deployments, and third-party redistributions should also review:

- `DISTRIBUTION.md`
- `TRADEMARKS.md`
- `LICENSE`

## Disclaimer

This file is informational and not legal advice. For release compliance, rely on the exact lockfiles, built artifacts, and upstream license texts that correspond to the binaries or images you ship.
