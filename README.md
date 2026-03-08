# Self-hosted WoL Relay (Tailscale-only)

MVP-Monorepo mit:

- `backend/`: Dockerisiertes FastAPI-Backend für Auth, Gerätezugriff, Wake-on-LAN, Discovery, Shutdown-Requests und geplante Wake-Jobs
- `android-client/`: Kotlin/Compose Android-Client für Login, gruppierte Geräte, Favoriten, Wake, read-only Schedule-Hinweise und Admin-Aktivität
- `ios-client/`: Native SwiftUI iPhone-Client für Login, gruppierte Geräte, Favoriten, Wake, read-only Schedule-Hinweise, Admin-Aktivität und APNs

Release-Dokumente:

- `docs/ios-release-readiness.md` für den finalen iPhone/TestFlight/App-Store-Readiness-Status
- `docs/release-gates.md` für die allgemeinen Backend-/Release-Gates

Aktueller Repo-Status für den Clean-Slate-Refactor:

- `refactorplan.md` ist die aktuelle Quelle für die Refactor-Richtung.
- `implementationplan.md` ist nur noch historische Referenz und nicht mehr die aktive Umsetzungsgrundlage.
- Das aktuelle Backend-Testsystem ist als disposable Pre-Production-System zu behandeln.
- Der kanonische Reset-/Reseed-Ablauf steht in `docs/local-reset-workflow.md`.

## Aktueller Funktionsstand

- Device access läuft über `device_memberships`, nicht mehr über Assignments.
- `/me/devices` liefert Favoriten, Gruppierung, Berechtigungen und `scheduled_wake_summary`.
- Scheduled wakes sind im Backend und in der Admin UI verfügbar; Android und iPhone zeigen den Status read-only im Geräte-Listing.
- Die unterstützte Admin-API arbeitet über `/admin/devices`, `/admin/device-memberships` und `/admin/scheduled-wakes`.

## 1. Backend starten

Voraussetzungen:

- Docker + Docker Compose
- Host ist im Tailnet (Tailscale installiert)

Setup:

```bash
cp .env.example .env
# .env Werte setzen (APP_SECRET, ADMIN_PASS)
docker compose up -d --build
```

Minimal Docker setup (same backend, fewer compose knobs):

```bash
cp .env.example .env
# .env Werte setzen (APP_SECRET, ADMIN_PASS)
docker compose -f docker-compose.simple.yml up -d --build
```

Testing-Deployment (separate DB volume):

```bash
docker compose -f docker-compose.yml -f docker-compose.testing.yml up -d --build
```

Für den Clean-Slate-Refactor ist dies der bevorzugte lokale Stack, weil er ein eigenes resetbares Daten-Volume nutzt.

Production-Deployment (separate DB volume):

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

Diese Prod-Compose-Datei bleibt für Topologie-/Deployment-Referenz im Repo, ändert aber nichts an der aktuellen Sprint-0-Annahme: keine In-Place-Migrationen für bestehende Testdaten.

Production with global/distributed rate limits (shared Redis):

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.redis.yml up -d --build
```

Homelab betatesting deployment behind Traefik:

- Runbook: `docs/homelab-traefik-beta.md`
- Helper script: `./scripts/deploy_beta.sh`

Healthcheck:

```bash
curl http://localhost:8080/health
```

### Docker / Betrieb

- Default Docker setup now uses named volumes instead of bind mounts for `/data`, which avoids common UID/GID and local path friction.
- The container process already runs as a non-root user (`appuser`) in the image.
- `docker-compose.simple.yml` is the shortest supported Docker entrypoint in this repo.
- The compose variants currently map to distinct named volumes: `wakefromfar_wol-data`, `wakefromfar_wol-data-simple`, `wakefromfar_wol-data-testing`, `wakefromfar_wol-data-prod`.
- Shared Redis remains optional and is only needed for distributed/global rate limits.
- A prebuilt GHCR image is still future packaging work; the repository currently builds locally from `backend/`.

### Security / Netzwerk

- Kein Router Port-Forwarding.
- Zugriff nur über Tailnet-IPs (Default: `ENFORCE_IP_ALLOWLIST=true`, `100.64.0.0/10` + Tailscale IPv6).
- Zusätzlich hostseitige Firewall-Regel auf `tailscale0` empfohlen.
- Optional: Tailnet ACLs für Port `8080` auf den Server setzen.
- Docker ist auf `network_mode: host` ausgelegt, damit WoL-Broadcasts im LAN/NIC-Routing zuverlässig funktionieren.

### Multi-NIC + Reverse Proxy

- Pro Device `broadcast` (oder `subnet_cidr`) passend zum Zielnetz setzen.
- Optional `interface` (z.B. `eth0`) setzen, um ein NIC explizit zu wählen.
- Für Containerbetrieb und non-root Containerprozesse bevorzugt `source_ip` setzen (IP der passenden Host-NIC), da das stabil ohne zusätzliche Container-Caps funktioniert.
- `interface` kann in manchen Umgebungen zusätzliche Netz-Capabilities erfordern, weil dafür ein Device-Bind versucht wird.
- Hinter Reverse Proxy `TRUST_PROXY_HEADERS=true` und `TRUSTED_PROXY_CIDRS` auf die Proxy-IP/Netze setzen, damit Allowlist + Rate Limits die echte Client-IP nutzen.
- Für mehrere Backend-Instanzen `RATE_LIMIT_BACKEND=redis` setzen und eine gemeinsame Redis-Instanz über `RATE_LIMIT_REDIS_URL` verwenden.
- Sprint-4 Rate-Limits (per minute) are configurable via:
  - `SHUTDOWN_POKE_REQUEST_RATE_LIMIT_PER_MINUTE`
  - `SHUTDOWN_POKE_SEEN_RATE_LIMIT_PER_MINUTE`
  - `SHUTDOWN_POKE_RESOLVE_RATE_LIMIT_PER_MINUTE`

### Admin Activity Notifications (Backend-only)

- Android admin app reads compact wake activity from `GET /admin/mobile/events`.
- No Firebase setup is required for this flow.
- If the admin app is offline, events are shown (and surfaced as in-app notices) on next online refresh.

## 2. Admin Bootstrap und Datenpflege

Initialer Admin wird aus ENV angelegt (`ADMIN_USER`, `ADMIN_PASS`), falls User noch nicht existiert.

Für einen vollständigen lokalen Reset inklusive Neuaufbau von Admin, Test-Usern, Devices, Memberships und optionalen Wake-Zeitplänen siehe `docs/local-reset-workflow.md`.

### Admin Panel (Sprint 2)

- URL: `http://localhost:8080/admin/ui/login`
- Login mit Admin-User (`ADMIN_USER` / `ADMIN_PASS` oder API-angelegter Admin).
- User-Onboarding läuft manuell: Admin erstellt Benutzerkonten und übermittelt URL + Zugangsdaten sicher an Nutzer.
- Verfügbare Seiten:
  - Users CRUD
  - Devices CRUD inkl. "Test Power Check"
  - Device Access
  - Scheduled Wakes
  - Wake- und Power-Check-Logs mit Filtern
  - Discovery Wizard (Netzwerke scannen, Kandidaten validieren, in Devices importieren)
  - Diagnostics, Audit Logs, Metrics (Sprint 3)

### Hardening / Sprint 3

Zusätzliche Admin-APIs:

- `GET /admin/audit-logs`
- `GET /admin/metrics`
- `GET /admin/diagnostics/devices`
- Discovery:
  - `GET /admin/discovery/networks`
  - `GET/POST /admin/discovery/runs`
  - `GET /admin/discovery/runs/{id}`
  - `GET /admin/discovery/runs/{id}/candidates`
  - `POST /admin/discovery/runs/{id}/import-bulk`
  - `POST /admin/discovery/candidates/{id}/validate-wake`
  - `POST /admin/discovery/candidates/{id}/import`

Runbook/Release-Checklist:

- `docs/sprint3-runbook-checklist.md`
- `docs/deployment-guide.md` (Docker/non-Docker, with/without reverse proxy, multi-NIC WoL)
- `docs/release-gates.md` (strict pre-testing and pre-production gates)

### Hardening / Sprint 4

Metrics counters expected in `/admin/metrics`:

- `activity_events.created`
- `activity_feed.poll_requests`
- `activity_feed.poll_errors`
- `shutdown_pokes.open`
- `shutdown_pokes.resolved`

Shutdown poke verification flow:

1. Device member/admin calls `POST /me/devices/{id}/shutdown-poke` (expect `201`, `status=open`).
2. Admin sees item in `GET /admin/shutdown-pokes?status=open`.
3. Admin marks `POST /admin/shutdown-pokes/{id}/seen` (expect `200`, `status=seen`).
4. Admin marks `POST /admin/shutdown-pokes/{id}/resolve` (expect `200`, `status=resolved`).
5. Verify activity feed `GET /admin/mobile/events?type=poke&limit=20` contains requested/seen/resolved events for the poke id.
6. Verify `/admin/metrics` increments `shutdown_pokes.open`, `shutdown_pokes.resolved`, and `activity_events.created`.
### Device per Admin API anlegen

```bash
TOKEN=$(curl -s http://localhost:8080/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"YOUR_ADMIN_PASS"}' | jq -r .token)

curl -s http://localhost:8080/admin/devices \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name":"NAS",
    "mac":"AA:BB:CC:DD:EE:FF",
    "broadcast":"192.168.178.255",
    "source_ip":"192.168.178.2",
    "interface":"eth0",
    "udp_port":9,
    "check_method":"tcp",
    "check_target":"192.168.178.50",
    "check_port":80
}'
```

Power check fields (`check_method`, `check_target`, `check_port`) are required for the app to show whether a device is on or off. Only `tcp` is supported — set `check_target` to the device IP and `check_port` to any port that is open when the device is on (e.g. `80`, `443`, `445`, `22`). If left blank, power state will always show `unknown`.

### Alternativ per CLI

```bash
docker compose exec wol-backend python -m app.cli add-user alice supersecret --role user
docker compose exec wol-backend python -m app.cli add-host --name Proxmox --mac AA:BB:CC:DD:EE:FF --broadcast 192.168.178.255 --source-ip 192.168.178.2 --interface eth0
```

Hinweis: Die CLI deckt aktuell nur Basis-User-/Host-Erstellung ab. Für wiederholbares Reseeding mit Power-Check-Feldern, Device Access und Scheduled Wakes ist die Admin-API bzw. die Admin UI der verlässliche Weg.

## 3. API (MVP)

Aktiv für aktuelle Setup-/Test-Arbeit dokumentiert:

- `POST /auth/login`
- `GET /me/devices` (auth)
- `PATCH /me/devices/{id}/preferences` (auth)
- `POST /me/devices/{id}/wake` (auth)
- `POST /me/devices/{id}/power-check` (auth)
- `POST /me/devices/{id}/shutdown-poke` (auth; device member/admin)
- `POST /admin/users` (admin)
- `GET/POST/PATCH/DELETE /admin/users` (admin)
- `GET/POST/PATCH/DELETE /admin/devices` (admin)
- `GET/POST/PATCH/DELETE /admin/device-memberships` (admin)
- `GET/POST/PATCH/DELETE /admin/scheduled-wakes` (admin)
- `GET /admin/scheduled-wakes/runs` (admin)
- `GET /admin/wake-logs`, `GET /admin/power-check-logs` (admin)
- `GET /admin/mobile/events` (admin, compact mobile activity feed with optional `cursor`, `limit`, `type`)
- `GET /admin/shutdown-pokes`, `POST /admin/shutdown-pokes/{id}/seen`, `POST /admin/shutdown-pokes/{id}/resolve` (admin)
- `GET /admin/discovery/networks`, `GET/POST /admin/discovery/runs` (admin)
- `GET /admin/discovery/runs/{id}`, `GET /admin/discovery/runs/{id}/candidates` (admin)
- `POST /admin/discovery/runs/{id}/import-bulk` (admin)
- `POST /admin/discovery/candidates/{id}/validate-wake`, `POST /admin/discovery/candidates/{id}/import` (admin)

Nicht Teil der aktuellen API-Oberfläche:

- Die früheren Legacy-Pfade `/hosts` und `/admin/hosts` sind entfernt.
- `/me/scheduled-wakes` existiert bewusst noch nicht; Schedule-Management bleibt Admin-only.

Beispiel Login Body:

```json
{
  "username": "admin",
  "password": "..."
}
```

## 4. Android Client

`android-client/` in Android Studio öffnen, Gradle sync durchführen, auf Gerät/Emulator starten.

Sprint-2 Features:

- Login mit Username/Passwort
- Invite-Deep-Link handling (`wakefromfar://claim?...`)
- Onboarding-Claim Flow über Invite-Token
- Token + URL in `EncryptedSharedPreferences`
- "My Devices" (`/me/devices`) mit Power-State Badge, Favoriten, Gruppierung und Schedule-Hinweisen
- Wake mit `already_on`/`sent`/`failed` Messaging
- Admin activity polling (`/admin/mobile/events`) with in-app new-event notices
- Shutdown poke flow (`/me/devices/{id}/shutdown-poke`) with optional note
- Admin activity actions for shutdown pokes (`seen` / `resolved`)
- Activity feed pagination (cursor-based load more against `/admin/mobile/events`)
- Lifecycle-safe polling for admin activity (foreground start, background stop, single loop, silent transient poll failures)

Sprint-1 Admin-App Additions:

- Admin role detection in Android from JWT role claim.
- Admin tabbed home: `Devices` + `Activity`.
- Activity tab reads compact backend feed from `GET /admin/mobile/events` (wake + shutdown poke events).

Hinweis:

- Debug/Testing nutzt `usesCleartextTraffic=true`; Release-Builds setzen `usesCleartextTraffic=false`.
- Als Backend URL z.B. `http://wol-server:8080` (MagicDNS) oder `http://100.x.y.z:8080`.
- Release signing in CI/local build über Umgebungsvariablen:
  - `WFF_RELEASE_STORE_FILE`
  - `WFF_RELEASE_STORE_PASSWORD`
  - `WFF_RELEASE_KEY_ALIAS`
  - `WFF_RELEASE_KEY_PASSWORD`

Hinweis: Admin event notifications are backend-driven in-app messages; there is no Firebase dependency in the Android client.

Der iPhone-Client nutzt denselben `/me/devices`-Vertrag inklusive Favoriten, Gruppierung und read-only `scheduled_wake_summary`.

## 5. Backup und Restore (SQLite)

Backup erstellen:

```bash
python3 backend/scripts/backup_db.py
```

Restore aus Backup:

```bash
python3 backend/scripts/restore_db.py backups/<backup-file>.db --force
```

## 6. Lokale Backend-Entwicklung ohne Docker

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
APP_SECRET=dev-secret-please-change ADMIN_USER=admin ADMIN_PASS=admin123456 uvicorn app.main:app --reload --port 8080
```

## 7. Lokale Verifikation

Backend:

```bash
/Users/max/projekte/wakefromfar/backend/.venv/bin/pytest -q \
  backend/tests/test_api_smoke.py \
  backend/tests/test_admin_ui.py \
  backend/tests/test_sprint1_memberships.py \
  backend/tests/test_sprint1_membership_and_wake.py \
  backend/tests/test_shutdown_pokes_api.py \
  backend/tests/test_scheduled_wakes_api.py \
  backend/tests/test_scheduled_wakes_runner.py
```

iPhone:

```bash
xcodebuild -project /Users/max/projekte/wakefromfar/ios-client/WakeFromFar.xcodeproj \
  -scheme WakeFromFar \
  -destination 'platform=iOS Simulator,name=iPhone 17' \
  test CODE_SIGNING_ALLOWED=NO
```

Android:

```bash
export JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home'
/Users/max/.gradle/wrapper/dists/gradle-8.10.2-bin/a04bxjujx95o3nb99gddekhwo/gradle-8.10.2/bin/gradle \
  -p /Users/max/projekte/wakefromfar/android-client \
  :app:testDebugUnitTest
```

Hinweise:

- Das Android-Repo hat derzeit keinen `gradlew`-Wrapper. Mit installiertem Android Studio funktioniert die CLI-Verifikation trotzdem über die bereits gecachte Gradle-Distribution und das Android-Studio-JBR.
- `:app:testDebugUnitTest` kompiliert dabei die App (`compileDebugKotlin`) und führt die JVM-Tests für Device-Parsing und Presentation aus.
- Für manuelle API-/UI-Smokes bleiben `GET /admin/mobile/events`, `/admin/ui/device-memberships` und `/admin/ui/scheduled-wakes` die schnellsten Kontrollpunkte.
