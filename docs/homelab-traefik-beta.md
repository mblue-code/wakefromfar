# Homelab Beta Deployment (Traefik)

This project is deployed on this host with:

- Backend container from this repository (`/homelab/wakefromfar`)
- Traefik dynamic config in `/homelab/config/traefik/configs/wakefromfar.yml`
- Public hostname: `wakefromfar.bluecherlab1887.work`

## 1) Backend environment

Create `/homelab/wakefromfar/.env` with secure values and proxy trust enabled:

```env
APP_SECRET=<strong-random-secret>
ADMIN_USER=admin
ADMIN_PASS=<strong-random-password>
ENFORCE_IP_ALLOWLIST=false
TRUST_PROXY_HEADERS=true
TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128,172.18.0.0/16
```

Notes:

- `ENFORCE_IP_ALLOWLIST=false` is suitable for public beta testing.
- For private/Tailscale-only operation, set it back to `true` and restrict `IP_ALLOWLIST_CIDRS`.

## 2) Start backend

```bash
cd /homelab/wakefromfar
./scripts/deploy_beta.sh
```

This runs:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

## 3) Traefik route

Ensure this file exists:

- `/homelab/config/traefik/configs/wakefromfar.yml`

It routes:

- `Host(wakefromfar.bluecherlab1887.work)` -> `http://172.18.0.1:8080`

Traefik watches this directory and picks up changes automatically.

## 4) DNS

In Cloudflare DNS, create/update an `A` record:

- `wakefromfar.bluecherlab1887.work` -> this server public IP

## 5) Validation

```bash
curl -fsS http://127.0.0.1:8080/health
curl -k --resolve wakefromfar.bluecherlab1887.work:443:127.0.0.1 https://wakefromfar.bluecherlab1887.work/health
```
