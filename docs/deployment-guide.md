# Deployment Guide (With and Without Reverse Proxy)

This guide covers production-style deployment of the WoL backend in these modes:

1. Docker, no reverse proxy
2. Docker, behind reverse proxy
3. No Docker, no reverse proxy
4. No Docker, behind reverse proxy

It also includes multi-network (multiple NIC) Wake-on-LAN setup.

## 1. Core Networking Model (Important)

When the server has multiple NICs/networks, each target device should use network-specific WoL settings:

- `broadcast`: broadcast address of the target LAN (for example `192.168.1.255` or `10.0.0.255`)
- `source_ip`: source IP bound on the sender side (IP of the NIC in that LAN)
- `interface` (optional): interface name such as `eth0`, `enp3s0`, `enx...`

Why `source_ip` and optional `interface`:

- Ensures packets leave through the correct NIC.
- Prevents wrong-route issues when policy routing or overlapping/private ranges exist.
- In containers, `source_ip` is usually the most reliable option.

Device examples:

- Device in network A: `broadcast=192.168.1.255`, `source_ip=192.168.1.10`
- Device in network B: `broadcast=10.0.0.255`, `source_ip=10.0.0.2`

## 2. Prerequisites

- Linux host with access to target LANs
- Docker + Docker Compose (for Docker deployments)
- Tailscale or your preferred secure access path
- Open TCP access to backend port (`8080`) only from trusted networks/proxy

Recommended validation commands on host:

```bash
ip -4 addr show
ip route
```

## 3. Environment Variables

Create `.env` from `.env.example`:

```bash
cp .env.example .env
```

Minimum required to change:

- `APP_SECRET`
- `ADMIN_PASS`

Proxy-related variables:

- `TRUST_PROXY_HEADERS=false` if clients connect directly to backend
- `TRUST_PROXY_HEADERS=true` if backend sits behind reverse proxy
- `TRUSTED_PROXY_CIDRS` must contain only proxy source networks

Examples:

- Proxy on same host: `TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128`
- Proxy in Docker bridge network: use that bridge subnet, for example `172.18.0.0/16`
- Dedicated proxy VLAN: for example `192.168.50.0/24`

## 4. Docker Deployment (No Reverse Proxy)

This repository uses `network_mode: host` for the backend, which is ideal for WoL broadcast traffic.

Steps:

```bash
cp .env.example .env
# edit .env:
# TRUST_PROXY_HEADERS=false
docker compose up -d --build
```

Check:

```bash
curl http://127.0.0.1:8080/health
```

Add devices (CLI example):

```bash
docker compose exec wol-backend python -m app.cli add-host \
  --name "NAS-A" \
  --mac "AA:BB:CC:DD:EE:01" \
  --broadcast "192.168.1.255" \
  --source-ip "192.168.1.10" \
  --interface "eth0"

docker compose exec wol-backend python -m app.cli add-host \
  --name "PC-B" \
  --mac "AA:BB:CC:DD:EE:02" \
  --broadcast "10.0.0.255" \
  --source-ip "10.0.0.2" \
  --interface "enx001122334455"
```

## 5. Docker Deployment Behind Reverse Proxy

### 5.1 Backend settings

In `.env`:

```env
TRUST_PROXY_HEADERS=true
TRUSTED_PROXY_CIDRS=<your-proxy-network>
```

Important:

- Never set overly broad proxy CIDRs.
- Only trust IP ranges where your reverse proxy actually runs.

### 5.2 Proxy header requirements

Proxy must forward:

- `X-Forwarded-For`
- `X-Real-IP`
- `X-Forwarded-Proto`
- `Host`

### 5.3 NGINX example

```nginx
server {
    listen 443 ssl http2;
    server_name wol.example.com;

    # tls config...

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_read_timeout 60s;
    }
}
```

### 5.4 Start

```bash
docker compose up -d --build
sudo nginx -t && sudo systemctl reload nginx
```

Validation:

- `https://wol.example.com/health` returns `{"ok":"true"}`
- Admin UI login works
- IP allowlist behaves correctly for real client IPs (not proxy IP)

## 6. Non-Docker Deployment (No Reverse Proxy)

### 6.1 App setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 6.2 Runtime env

```bash
export APP_SECRET='replace-me-with-a-long-random-secret'
export ADMIN_USER='admin'
export ADMIN_PASS='replace-me-with-a-strong-password'
export DATA_DIR='/opt/wakefromfar/data'
export DB_FILENAME='wol.db'
export TRUST_PROXY_HEADERS='false'
```

### 6.3 Start server

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

## 7. Non-Docker Deployment Behind Reverse Proxy

Use same backend setup as Section 6, but set:

```bash
export TRUST_PROXY_HEADERS='true'
export TRUSTED_PROXY_CIDRS='127.0.0.1/32,::1/128'
```

Put NGINX/Caddy/Traefik in front of `127.0.0.1:8080` and forward headers.

## 8. Optional systemd service (Non-Docker)

Example service file `/etc/systemd/system/wakefromfar.service`:

```ini
[Unit]
Description=WakeFromFar Backend
After=network-online.target
Wants=network-online.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/wakefromfar/backend
EnvironmentFile=/opt/wakefromfar/.env
ExecStart=/opt/wakefromfar/backend/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8080
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Activate:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wakefromfar
sudo systemctl status wakefromfar
```

## 9. Device Provisioning Checklist (Multi-NIC)

For each device:

1. Determine target LAN and broadcast IP.
2. Determine sender NIC IP in that LAN (`source_ip`).
3. Optionally set interface name for additional routing control.
4. Configure power check target/port (`check_target`, `check_port`).

If WoL fails:

- Verify sender host can reach the broadcast domain.
- Confirm `broadcast` is correct for that subnet.
- Confirm `source_ip` belongs to the intended NIC.
- If using `interface` binding inside container, ensure required permissions; prefer `source_ip`.

## 10. Reverse Proxy Security Checklist

- Backend not exposed publicly without auth and allowlist.
- `TRUST_PROXY_HEADERS=true` only when proxy is in front.
- `TRUSTED_PROXY_CIDRS` only includes proxy ranges.
- TLS terminated at proxy with valid certs.
- Access logs enabled on proxy for audit/debugging.

## 11. Smoke Test Flow

1. `GET /health`
2. Admin login
3. Create one device per network (A and B)
4. Assign device to test user
5. Trigger wake for both devices
6. Check `/admin/wake-logs` and verify `sent_to` network targets

## 12. Common Failure Patterns

- Docker daemon not running: start Docker engine/Desktop first.
- Wrong proxy CIDR: backend ignores forwarded headers and sees proxy source IP only.
- Wrong broadcast: packet sent successfully but target never wakes.
- Missing check target/port: wake may send, but power state remains `unknown`.
- Non-host Docker network for backend: broadcast can be dropped or routed incorrectly.
