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

## 2. Admin Bootstrap und Datenpflege

Initialer Admin wird aus ENV angelegt (`ADMIN_USER`, `ADMIN_PASS`), falls User noch nicht existiert.

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
    "udp_port":9
  }'
```

### Alternativ per CLI

```bash
docker compose exec wol-backend python -m app.cli add-user alice supersecret --role user
docker compose exec wol-backend python -m app.cli add-host --name Proxmox --mac AA:BB:CC:DD:EE:FF --broadcast 192.168.178.255
```

## 3. API (MVP)

- `POST /auth/login`
- `GET /hosts` (auth)
- `POST /hosts/{id}/wake` (auth)
- `POST /admin/users` (admin)
- `POST /admin/hosts` (admin)

Beispiel Login Body:

```json
{
  "username": "admin",
  "password": "..."
}
```

## 4. Android Client

`android-client/` in Android Studio öffnen, Gradle sync durchführen, auf Gerät/Emulator starten.

MVP Features:

- Login mit Username/Passwort
- Backend URL konfigurierbar
- Token + URL in `EncryptedSharedPreferences`
- Hostliste laden
- Wake pro Host auslösen

Hinweis:

- Für HTTP im Tailnet ist `usesCleartextTraffic=true` gesetzt.
- Als Backend URL z.B. `http://wol-server:8080` (MagicDNS) oder `http://100.x.y.z:8080`.

## 5. Lokale Backend-Entwicklung ohne Docker

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
APP_SECRET=dev-secret ADMIN_USER=admin ADMIN_PASS=admin123 uvicorn app.main:app --reload --port 8080
```
