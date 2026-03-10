# Contributing

Thanks for contributing to WakeFromFar.

## Before you start

- Read [README.md](README.md) for the current product and deployment surface.
- Use [docs/local-reset-workflow.md](docs/local-reset-workflow.md) for disposable local backend resets.
- Review [SECURITY.md](SECURITY.md) before reporting vulnerabilities.

## Contribution scope

Good contributions include:

- bug fixes
- tests
- deployment and documentation improvements
- accessibility, localization, and UX polish
- focused feature work that matches the current product direction

Open an issue or discussion first for:

- large product changes
- new infrastructure dependencies
- licensing or distribution changes
- major API or data-model changes

## Development expectations

- Prefer small, reviewable pull requests.
- Keep docs aligned with behavior changes.
- Add or update tests when changing backend or app behavior.
- Do not commit secrets, signing keys, provisioning profiles, private credentials, or production configuration.

## Verification

Use repo-relative commands where possible.

Backend example:

```bash
.venv-test/bin/python -m pytest -q
```

Android example:

```bash
gradle -p android-client :app:testDebugUnitTest
```

iPhone example:

```bash
xcodebuild -project ios-client/WakeFromFar.xcodeproj \
  -scheme WakeFromFar \
  -destination 'platform=iOS Simulator,name=iPhone 17' \
  test CODE_SIGNING_ALLOWED=NO
```

## Pull requests

- Describe the user-visible change and the technical approach.
- List verification steps you ran.
- Call out any follow-up work or known limitations.
