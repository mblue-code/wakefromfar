# Self-hosted WoL Relay (Tailscale-only)

MVP-Monorepo mit:

- `backend/`: Dockerisiertes FastAPI-Backend für Auth, Gerätezugriff, Wake-on-LAN, Discovery, Shutdown-Requests und geplante Wake-Jobs
- `android-client/`: Kotlin/Compose Android-Client für Login, gruppierte Geräte, Favoriten, Wake, read-only Schedule-Hinweise und Admin-Aktivität
- `ios-client/`: Native SwiftUI iPhone-Client für Login, gruppierte Geräte, Favoriten, Wake, read-only Schedule-Hinweise, Admin-Aktivität und APNs

Release-Dokumente:

- `docs/ios-release-readiness.md` für den finalen iPhone/TestFlight/App-Store-Readiness-Status
- `docs/release-gates.md` für die allgemeinen Backend-/Release-Gates
- `docs/security-preproduction-checklist.md` für den ausführbaren Security-/Beta-Verifikationslauf vor externen Tests

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
# optional nur fuer lokale/manuale Unsafesets:
# ALLOW_UNSAFE_PUBLIC_EXPOSURE=true und ENFORCE_IP_ALLOWLIST=false
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

- Bottom line fuer Betreiber:
  - Reverse Proxy ist optional.
  - Eigene DNS-Aufloesung ist optional.
  - Fuer normalen Mobile-App-Betrieb braucht ihr aber praktisch einen vertrauenswuerdigen HTTPS-Endpunkt.
  - Wenn Clients direkt per IP zugreifen, muss das Zertifikat diese IP als SAN enthalten und auf den Geraeten vertraut werden.
  - Private-network-HTTP bleibt nur eine explizite Ausnahme fuer kontrollierte Setups und ist nicht der empfohlene Standardpfad fuer mobile Clients.
- Kein Router Port-Forwarding.
- Das Backend failt jetzt standardmaessig closed: `ENFORCE_IP_ALLOWLIST=true` ist der Code-Default.
- Zugriff bleibt private-network-first: Standard-Allowlist ist Tailscale + Loopback (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`, `127.0.0.1/32`, `::1/128`).
- Authentifizierung und bereits authentifizierter Traffic brauchen standardmaessig TLS: `REQUIRE_TLS_FOR_AUTH=true`.
- Unsicheres HTTP fuer Login, Bearer-Auth und Admin-UI-Sessions ist nur als private Ausnahme moeglich: `ALLOW_INSECURE_PRIVATE_HTTP=true` plus `PRIVATE_HTTP_ALLOWED_CIDRS`.
- Default fuer `PRIVATE_HTTP_ALLOWED_CIDRS`: `127.0.0.1/32`, `::1/128`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `fd7a:115c:a1e0::/48`.
- Die Admin-Plane ist jetzt separat eingegrenzt: `/admin/*` und `/admin/ui/*` verwenden zusaetzlich `ADMIN_IP_ALLOWLIST_CIDRS`.
- Default fuer `ADMIN_IP_ALLOWLIST_CIDRS`: `127.0.0.1/32`, `::1/128`, `100.64.0.0/10`, `fd7a:115c:a1e0::/48`.
- Empfehlung: `ADMIN_IP_ALLOWLIST_CIDRS` enger setzen als `IP_ALLOWLIST_CIDRS`, damit App-Clients nicht automatisch die Admin-Plane erreichen.
- `ADMIN_UI_ENABLED=true` schaltet die Browser-Admin-Oberflaeche unter `/admin/ui/*`; bei `false` liefern diese Pfade `404`, waehrend `/admin/*`-APIs weiterlaufen und nur ueber die Admin-Allowlist erreichbar bleiben.
- Browser-Admin-MFA ist jetzt verfuegbar: `ADMIN_MFA_REQUIRED=false` ist der sichere Upgrade-Default, damit bestehende Installationen nicht sofort ausgesperrt werden.
- `ADMIN_MFA_ISSUER=WakeFromFar` steuert den Issuer fuer Authenticator-Apps; `ADMIN_MFA_PENDING_EXPIRES_SECONDS=300` begrenzt Pending-Login-/Setup-Zustaende; `ADMIN_MFA_VERIFY_RATE_LIMIT_PER_MINUTE=10` begrenzt TOTP-Pruefversuche.
- Wenn `ADMIN_MFA_REQUIRED=false`, koennen nicht eingerichtete Browser-Admins weiter mit Passwort einloggen; bereits eingerichtete Admins muessen trotzdem TOTP bestaetigen.
- Wenn `ADMIN_MFA_REQUIRED=true`, erhalten nicht eingerichtete Browser-Admins keine volle `admin_session`, sondern nur den eingeschraenkten MFA-Setup-Flow bis zur erfolgreichen TOTP-Aktivierung.
- Sprint 6 hat die Mobile-App-Proof-Architektur als ADR festgelegt: `docs/mobile-app-proof-architecture.md`.
- Sprint 7 ist jetzt implementiert: mobile Bearer-Session-Issuance kann ueber Platform Attestation (`Play Integrity` auf Android, `App Attest` auf iOS) gestuft aktiviert werden.
- Rollout-Schalter: `APP_PROOF_MODE=disabled|report_only|soft_enforce|enforce_login`.
- `disabled`: altes Verhalten, keine App-Proof-Enforcement.
- `report_only`: Proof wird genutzt und protokolliert, fehlender/ungueltiger Proof blockiert Login noch nicht.
- `soft_enforce`: neue oder unbekannte Installationen brauchen Proof; bereits vertraute Installationen duerfen nur innerhalb von `APP_PROOF_DEGRADED_GRACE_SECONDS` degradiert weiter einloggen.
- `enforce_login`: mobile Bearer-Login ohne gueltigen Proof wird geblockt.
- Android-Operator-Konfig: `APP_PROOF_ANDROID_PACKAGE_NAME`, `APP_PROOF_ANDROID_ALLOWED_CERT_SHA256`, `APP_PROOF_ANDROID_CLOUD_PROJECT_NUMBER`, plus Service-Account-JSON fuer serverseitiges Google-Decode.
- iOS-Operator-Konfig: `APP_PROOF_IOS_TEAM_ID`, `APP_PROOF_IOS_BUNDLE_ID`; `DeviceCheck` bleibt nur report-only/telemetry und ist kein Enforcement-Ersatz.
- Mobile Sessions werden jetzt an Installationen gebunden (`aid`/`apm`/`asv` im JWT, `X-WFF-Installation-ID` auf Client-Requests); revokte oder stale Installationen verlieren neue Sessions und koennen gebundene Sessions invalidieren.
- Kleine Admin-API fuer Operatoren: `/admin/app-installations` und `/admin/app-installations/{installation_id}/revoke`.
- Sprint 8 macht die Hardening-Layer operator-faehig:
  - `GET /admin/security-status` liefert Hardening-Modus, Warnungen, Deferrals, App-Proof-Installationssummary und aktuelle Failure-Kategorien.
  - `GET /admin/metrics` enthaelt weiter Runtime-Counter und jetzt zusaetzlich den Security-Status-Snapshot.
  - `GET /admin/app-installations?platform=android|ios&status=...&limit=...` dient als read-only Installationsinspektion fuer Pre-Production/Beta.
- Es gibt bewusst keine Migrationsschritte fuer bestehende Nutzer oder Installationen, weil noch keine Produktionsnutzung existiert.
- Weiterhin explizit defert:
  - all-request proof-of-possession
  - mTLS
  - DeviceCheck als Enforcement
  - Admin-Bearer-Login-App-Proof als Default-Rollout
- Browser-Admin-MFA aus Sprint 5 bleibt unveraendert.
- Browserbasierte Admin-POSTs unter `/admin/ui/*` verlangen jetzt zusaetzlich einen serverseitig validierten CSRF-Token, auch fuer `/admin/ui/login`.
- Browserbasierte Admin-POSTs verlangen ausserdem Same-Origin-Requests: `Origin` muss zum aktuellen Admin-Ursprung passen; falls ein Browser keinen `Origin` sendet, wird nur ein strikt gleich-originiger `Referer` als Fallback akzeptiert.
- Das ist Defense-in-Depth auf `ADMIN_IP_ALLOWLIST_CIDRS`, TLS-/Transport-Checks und `SameSite=Strict`/`HttpOnly`-Cookies, ersetzt diese Kontrollen aber nicht.
- Public HTTP fuer `POST /auth/login`, Bearer-geschuetzte `/me/*`-/`/admin/*`-Requests und Admin-UI-Login/Sessions wird mit `403` blockiert.
- Admin-Bearer-Scope fuer Sprint 7 bleibt bewusst konservativ: Browser-Admin-UI/MFA bleibt wie bisher, und `APP_PROOF_REQUIRE_ON_ADMIN_BEARER_LOGIN=false` ist der Default, bis Telemetrie fuer mobile User-Logins stabil ist.
- Operatoren muessen entweder eine gueltige `IP_ALLOWLIST_CIDRS` setzen oder explizit `ALLOW_UNSAFE_PUBLIC_EXPOSURE=true` zusammen mit `ENFORCE_IP_ALLOWLIST=false` setzen.
- `ADMIN_IP_ALLOWLIST_CIDRS` muss ebenfalls gueltige CIDRs enthalten; leere oder fehlerhafte Werte stoppen den Start standardmaessig mit einer klaren Fehlermeldung.
- `ALLOW_UNSAFE_PUBLIC_EXPOSURE=true` ist nur als Escape Hatch fuer lokale Tests/manuelle Setups gedacht, unsicher und nicht empfohlen.
- Zusätzlich hostseitige Firewall-Regel auf `tailscale0` empfohlen.
- Optional: Tailnet ACLs für Port `8080` auf den Server setzen.
- Docker ist auf `network_mode: host` ausgelegt, damit WoL-Broadcasts im LAN/NIC-Routing zuverlässig funktionieren.
- Das macht Public-Internet-Exposure nicht zu einem supporteten Setup; das Produkt bleibt private-network-first.

### Multi-NIC + Reverse Proxy

- Pro Device `broadcast` (oder `subnet_cidr`) passend zum Zielnetz setzen.
- Optional `interface` (z.B. `eth0`) setzen, um ein NIC explizit zu wählen.
- Für Containerbetrieb und non-root Containerprozesse bevorzugt `source_ip` setzen (IP der passenden Host-NIC), da das stabil ohne zusätzliche Container-Caps funktioniert.
- `interface` kann in manchen Umgebungen zusätzliche Netz-Capabilities erfordern, weil dafür ein Device-Bind versucht wird.
- Hinter Reverse Proxy `TRUST_PROXY_HEADERS=true` und `TRUSTED_PROXY_CIDRS` auf die Proxy-IP/Netze setzen, damit Allowlist, TLS-Erkennung (`X-Forwarded-Proto=https`) und Rate Limits die echte Client-IP nutzen.
- Wenn Proxy-Header nicht vertraut werden, zaehlt `X-Forwarded-Proto=https` bewusst nicht als HTTPS-Nachweis.
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

- Lokales Direktbeispiel auf dem Server selbst: `http://localhost:8080/admin/ui/login`
- Fuer regulaeren entfernten Browser- oder Mobile-Zugriff sollte die sichtbare Backend-URL ein vertrauenswuerdiger HTTPS-Endpunkt sein.
- Login mit Admin-User (`ADMIN_USER` / `ADMIN_PASS` oder API-angelegter Admin).
- Browser-Admin ist jetzt hart abschaltbar ueber `ADMIN_UI_ENABLED=false`; dann liefern `/admin/ui`, `/admin/ui/login`, `/admin/ui/logout` und weitere `/admin/ui/*`-Pfade `404`.
- Admin-Plane meint in diesem Repo immer `/admin/*` plus `/admin/ui/*`; beide laufen hinter `ADMIN_IP_ALLOWLIST_CIDRS`.
- Alle browserseitigen Admin-Formulare tragen jetzt einen CSRF-Token; fehlende oder ungueltige Tokens liefern bei POSTs ein explizites `403 Invalid CSRF token`.
- Cross-Origin-Form-Posts in die Admin-UI werden serverseitig geblockt; erlaubt sind nur same-originige Browser-Requests zum aktuellen Admin-Ursprung.
- Browser-Admin-Login unterstuetzt jetzt TOTP-MFA. Die Einrichtung passiert in der UI ueber ein manuelles Secret plus `otpauth://`-URI; ein voller Browser-Admin-Login wird fuer eingerichtete Admins erst nach erfolgreicher TOTP-Pruefung ausgestellt.
- Recovery fuer self-hosted Break-Glass: `python -m app.cli admin-disable-mfa --username <adminname>`.
- Sprint-5-Scope bleibt bewusst begrenzt: `/auth/login` fuer Admin-Bearer-Tokens und mobile Admin-Clients bleiben vorerst unveraendert und noch ohne MFA-Challenge.
- Mobile/Admin-API-Features wie `GET /admin/mobile/events` bleiben auch bei deaktivierter Browser-UI verfuegbar, sofern Auth und Admin-Allowlist passen.
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
- `docs/security-preproduction-checklist.md` (praktischer Sprint-8-Verifikationslauf fuer private Beta/Public-Test-Vorbereitung)

### Hardening / Sprint 4

Browser-Admin-Defense-in-Depth:

- `/admin/ui/*`-POSTs sind jetzt CSRF-geschuetzt und an die aktuelle Browser-Session gebunden.
- `/admin/ui/*`-POSTs akzeptieren nur same-originige Browser-Requests (`Origin`, optional strenger `Referer`-Fallback).
- Die bestehende Produktposition bleibt unveraendert: private-network-first, keine supportete Public-Internet-Exposure.

### Hardening / Sprint 5

Browser-Admin-MFA:

- Browser-Admin-Accounts koennen jetzt TOTP-MFA einrichten und verwenden.
- Secrets werden nicht roh im SQLite-User-Datensatz abgelegt, sondern vor dem Speichern mit einem aus `APP_SECRET` abgeleiteten Schluessel verschluesselt.
- Login mit aktivierter MFA erstellt zuerst nur einen kurzlebigen Pending-State; die volle `admin_session` wird erst nach erfolgreicher TOTP-Pruefung gesetzt.
- Bei `ADMIN_MFA_REQUIRED=true` werden nicht eingerichtete Browser-Admins direkt in den eingeschraenkten Setup-Flow geleitet und kommen erst danach in die eigentliche Admin-Oberflaeche.
- Recovery bleibt shell-tauglich: `python -m app.cli admin-disable-mfa --username admin`.
- Absichtliche Restluecke der gestuften Einfuehrung: `/auth/login` fuer Admin-Bearer-Tokens ist noch nicht MFA-geschuetzt.

### Hardening / Sprint 7

Mobile App Proof:

- Backend-Endpunkte: `POST /auth/app-proof/challenge`, `POST /auth/app-proof/verify/android`, `POST /auth/app-proof/verify/ios`.
- Enforced wird nur Login-/Session-Issuance fuer mobile Bearer-Tokens, noch nicht jeder einzelne API-Request mit frischem Provider-Proof.
- Generische HTTP-Clients koennen in `enforce_login` ohne gueltigen mobilen Proof keine neuen User-Bearer-Sessions mehr holen.
- Observability: `/admin/metrics` zaehlt u.a. `app_proof.challenge_issued`, `app_proof.verify_success`, `app_proof.verify_failed`, `app_proof.degraded_allow`, `app_proof.enforcement_blocked`.
- Private-network-first bleibt unveraendert. App-Proof macht Public-Internet-Exposure nicht zu einem supporteten Betriebsmodell.
- Weiterhin explizit deferred: all-request proof-of-possession, mTLS, DeviceCheck als Enforcement-Surrogat und ein grosses Revocation-UI.

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

Hinweis: Die CLI deckt aktuell Basis-User-/Host-Erstellung plus MFA-Break-Glass-Recovery ab. Für wiederholbares Reseeding mit Power-Check-Feldern, Device Access und Scheduled Wakes ist die Admin-API bzw. die Admin UI der verlässliche Weg.
Break-Glass-Recovery: `python -m app.cli admin-disable-mfa --username <adminname>`.

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
- Fuer regulare App-Nutzung sollte die Backend-URL ein vertrauenswuerdiger HTTPS-Endpunkt sein, z.B. `https://wol-server.tailnet.ts.net:6500` oder `https://192.168.1.200:6500`.
- Wenn direkt per IP verbunden wird, muss das Zertifikat diese IP als SAN enthalten und vom Geraet vertraut werden.
- Plain HTTP auf privaten Netzen bleibt nur ein expliziter Betreiber-Override und ist nicht der empfohlene Standardpfad fuer Release-Clients.
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
