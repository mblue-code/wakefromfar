# Homelab Beta Deployment (Traefik)

This is a sanitized example for a homelab-style Traefik deployment.

Example assumptions:

- Backend checkout path: `/opt/wakefromfar`
- Traefik dynamic config path: `/etc/traefik/dynamic/wakefromfar.yml`
- Public hostname: `wakefromfar.example.com`

## 1) Backend environment

Create `/opt/wakefromfar/.env` with secure values, Tailscale allowlisting, and proxy trust enabled:

```env
APP_SECRET=<strong-random-secret>
ADMIN_USER=admin
ADMIN_PASS=<strong-random-password>
ENFORCE_IP_ALLOWLIST=true
ALLOW_UNSAFE_PUBLIC_EXPOSURE=false
IP_ALLOWLIST_CIDRS=100.64.0.0/10,fd7a:115c:a1e0::/48,127.0.0.1/32,::1/128
ADMIN_IP_ALLOWLIST_CIDRS=100.64.0.0/10,fd7a:115c:a1e0::/48,127.0.0.1/32,::1/128
TRUST_PROXY_HEADERS=true
TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128,172.18.0.0/16
```

Notes:

- Keep `ENFORCE_IP_ALLOWLIST=true` for normal operation and keep `IP_ALLOWLIST_CIDRS`/`ADMIN_IP_ALLOWLIST_CIDRS` limited to trusted ranges.
- If you intentionally disable allowlisting for temporary local/manual testing, you must set `ALLOW_UNSAFE_PUBLIC_EXPOSURE=true`.
- `ALLOW_UNSAFE_PUBLIC_EXPOSURE=true` is an explicit unsafe override and is not recommended for internet-facing deployments.

## 2) Start backend

```bash
cd /opt/wakefromfar
./scripts/deploy_beta.sh
```

This runs:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

## 3) Traefik route

Ensure this file exists:

- `/etc/traefik/dynamic/wakefromfar.yml`

Example route:

- `Host(wakefromfar.example.com)` -> `http://172.18.0.1:8080`

Traefik watches this directory and picks up changes automatically.

## 4) DNS

In your DNS provider, create/update an `A` or equivalent record:

- `wakefromfar.example.com` -> this server public IP

## 5) Validation

```bash
curl -fsS http://127.0.0.1:8080/health
curl -k --resolve wakefromfar.example.com:443:127.0.0.1 https://wakefromfar.example.com/health
```

## 6) Device setup reminder (power state)

When creating devices, configure power-check fields as well:

- `check_method=tcp`
- `check_target=<device-ip-or-hostname>`
- `check_port=<open-tcp-port-when-device-is-on>` (for example `80`, `443`, `445`, `22`)

If `check_target` or `check_port` is missing, power state remains `unknown` and logs show `missing_check_target` or `missing_check_port`.

## 7) Troubleshooting `{"detail":"Client IP not allowed"}`

When this appears behind Traefik, verify what the backend sees:

```bash
docker compose -f /opt/wakefromfar/docker-compose.yml -f /opt/wakefromfar/docker-compose.prod.yml logs --tail=200 wol-backend | grep security.ip_allowlist.blocked
```

If blocked events show proxy IPs (for example `172.18.0.1`) instead of real client IPs:

- Keep `TRUST_PROXY_HEADERS=true`.
- Ensure `TRUSTED_PROXY_CIDRS` includes the actual proxy source network that reaches backend.
- If an upstream hop still collapses traffic to one proxy source IP, enforce client/network restrictions at Traefik (or upstream) and add that proxy IP/CIDR to backend allowlists as fallback.

Example fallback:

```env
IP_ALLOWLIST_CIDRS=100.64.0.0/10,fd7a:115c:a1e0::/48,127.0.0.1/32,::1/128,172.18.0.1/32
ADMIN_IP_ALLOWLIST_CIDRS=100.64.0.0/10,fd7a:115c:a1e0::/48,127.0.0.1/32,::1/128,172.18.0.1/32
```
