# Self-hosted WoL Relay (Tailscale-only)

MVP-Monorepo mit:

- `backend/`: Dockerisiertes FastAPI-Backend (Auth, Hosts, Wake-on-LAN)
- `android-client/`: Kotlin/Compose Android-Client (Login, Hostliste, Wake)

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

Healthcheck:

```bash
curl http://localhost:8080/health
```

### Security / Netzwerk

- Kein Router Port-Forwarding.
- Zugriff nur über Tailnet-IPs (Default: `ENFORCE_IP_ALLOWLIST=true`, `100.64.0.0/10` + Tailscale IPv6).
- Zusätzlich hostseitige Firewall-Regel auf `tailscale0` empfohlen.
- Optional: Tailnet ACLs für Port `8080` auf den Server setzen.
- Docker ist auf `network_mode: host` ausgelegt, damit WoL-Broadcasts im LAN/NIC-Routing zuverlässig funktionieren.

### Multi-NIC + Reverse Proxy

- Pro Device `broadcast` (oder `subnet_cidr`) passend zum Zielnetz setzen.
- Optional `interface` (z.B. `eth0`) setzen, um ein NIC explizit zu wählen.
- Für Containerbetrieb bevorzugt `source_ip` setzen (IP der passenden Host-NIC), da das stabil ohne zusätzliche Container-Caps funktioniert.
- Hinter Reverse Proxy `TRUST_PROXY_HEADERS=true` und `TRUSTED_PROXY_CIDRS` auf die Proxy-IP/Netze setzen, damit Allowlist + Rate Limits die echte Client-IP nutzen.

## 2. Admin Bootstrap und Datenpflege

Initialer Admin wird aus ENV angelegt (`ADMIN_USER`, `ADMIN_PASS`), falls User noch nicht existiert.

### Admin Panel (Sprint 2)

- URL: `http://localhost:8080/admin/ui/login`
- Login mit Admin-User (`ADMIN_USER` / `ADMIN_PASS` oder API-angelegter Admin).
- Verfügbare Seiten:
  - Users CRUD
  - Devices CRUD inkl. "Test Power Check"
  - Assignments
  - Invite-Generierung inkl. Deep-Link + QR
  - Wake- und Power-Check-Logs mit Filtern
  - Diagnostics, Audit Logs, Metrics, Pilot Metrics (Sprint 3)

### Hardening / Sprint 3

Zusätzliche Admin-APIs:

- `GET /admin/audit-logs`
- `GET /admin/metrics`
- `GET /admin/diagnostics/devices`
- `GET /admin/pilot-metrics`

Runbook/Release-Checklist:

- `docs/sprint3-runbook-checklist.md`
- `docs/deployment-guide.md` (Docker/non-Docker, with/without reverse proxy, multi-NIC WoL)
### Host per Admin API anlegen

```bash
TOKEN=$(curl -s http://localhost:8080/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"YOUR_ADMIN_PASS"}' | jq -r .token)

curl -s http://localhost:8080/admin/hosts \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name":"NAS",
    "mac":"AA:BB:CC:DD:EE:FF",
    "broadcast":"192.168.178.255",
    "source_ip":"192.168.178.2",
    "interface":"eth0",
    "udp_port":9
  }'
```

### Alternativ per CLI

```bash
docker compose exec wol-backend python -m app.cli add-user alice supersecret --role user
docker compose exec wol-backend python -m app.cli add-host --name Proxmox --mac AA:BB:CC:DD:EE:FF --broadcast 192.168.178.255 --source-ip 192.168.178.2 --interface eth0
```

## 3. API (MVP)

- `POST /auth/login`
- `POST /onboarding/claim`
- `GET /me/devices` (auth)
- `POST /me/devices/{id}/wake` (auth)
- `POST /me/devices/{id}/power-check` (auth)
- `POST /admin/users` (admin)
- `GET/POST/PATCH/DELETE /admin/users` (admin)
- `GET/POST/PATCH/DELETE /admin/devices` (admin)
- `GET/POST/DELETE /admin/assignments` (admin)
- `GET/POST /admin/invites` + `POST /admin/invites/{id}/revoke` (admin)
- `GET /admin/wake-logs`, `GET /admin/power-check-logs` (admin)
- Legacy (deprecated): `GET /hosts`, `POST /hosts/{id}/wake`, `POST /admin/hosts`

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
- "My Devices" (`/me/devices`) mit Power-State Badge
- Wake mit `already_on`/`sent`/`failed` Messaging

Hinweis:

- Für HTTP im Tailnet ist `usesCleartextTraffic=true` gesetzt.
- Als Backend URL z.B. `http://wol-server:8080` (MagicDNS) oder `http://100.x.y.z:8080`.

## 5. Lokale Backend-Entwicklung ohne Docker

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
APP_SECRET=dev-secret-please-change ADMIN_USER=admin ADMIN_PASS=admin123456 uvicorn app.main:app --reload --port 8080
```
