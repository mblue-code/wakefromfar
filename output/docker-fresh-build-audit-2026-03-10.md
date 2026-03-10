# Docker Fresh Build Audit

Date: 2026-03-10
Repo: `/Volumes/macminiExtern/wakefromfar`
Host: macOS with Docker Desktop 4.36.0 / Engine 27.3.1 / `desktop-linux` context / `darwin/arm64`

## Scope

Goal: re-run the fresh-install Docker audit after switching the default rate-limit backend to memory and clarifying the required local `.env` setup.

This audit used the documented testing stack:

```bash
cp .env.example .env
# set real values for APP_SECRET and ADMIN_PASS
docker compose -f docker-compose.yml -f docker-compose.testing.yml down -v --remove-orphans
docker compose -f docker-compose.yml -f docker-compose.testing.yml up -d --build
```

Temporary local audit values were written into `.env` only for the run and removed afterward.

## Commands Run

```bash
cp .env.example .env
docker compose -f docker-compose.yml -f docker-compose.testing.yml down -v --remove-orphans
docker compose -f docker-compose.yml -f docker-compose.testing.yml config
docker compose -f docker-compose.yml -f docker-compose.testing.yml up -d --build
docker inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}} {{.RestartCount}}' wol-backend
docker compose -f docker-compose.yml -f docker-compose.testing.yml ps
docker compose -f docker-compose.yml -f docker-compose.testing.yml logs --tail=120 wol-backend
python3 -u - <<'PY'
import time, urllib.request
for i in range(10):
    try:
        with urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2) as r:
            print(r.status)
            print(r.read().decode())
            break
    except Exception as e:
        print(f'attempt {i+1}: {e}')
        time.sleep(1)
PY
docker inspect -f 'network={{.HostConfig.NetworkMode}} ports={{json .NetworkSettings.Ports}}' wol-backend
```

## Current Outcome

### Fresh build and startup now work

Status: fixed

Observed behavior:

- `docker compose ... config` rendered successfully with valid local `.env`.
- The testing stack built and started cleanly.
- Container state after startup:

```text
running healthy 0
```

- `docker compose ps` reported:

```text
wol-backend   Up ... (healthy)
```

- Container logs showed normal startup:

```text
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8080
INFO:     127.0.0.1:57784 - "GET /health HTTP/1.1" 200 OK
```

Why this matters:

- The earlier Redis startup crash is gone.
- The default local/testing path is now bootstrappable from a standard `.env` with real secrets.

Relevant files:

- `backend/app/config.py`
- `docker-compose.yml`
- `docker-compose.simple.yml`
- `docker-compose.prod.yml`
- `.env.example`

### Local `.env` requirement is now explicit in the setup docs

Status: fixed

Observed behavior:

- The current docs now consistently instruct operators to create a local repo-root `.env` before Compose commands.
- The audit flow matched that documentation without needing undocumented steps.

Why this matters:

- The repo still intentionally requires `.env`.
- That is no longer a hidden first-install trap as long as the docs are followed.

Relevant files:

- `README.md`
- `docs/deployment-guide.md`
- `docs/local-reset-workflow.md`

## Remaining Issue

### On macOS Docker Desktop, the container is healthy but still unreachable from the Mac host

Severity: high

Observed behavior:

- The container health check passed internally.
- Container logs showed successful in-container `GET /health`.
- From the macOS host, repeated requests to `http://127.0.0.1:8080/health` still failed:

```text
attempt 1..10: <urlopen error [Errno 61] Connection refused>
```

- Container inspect output:

```text
network=host ports={}
```

Why this matters:

- The backend is running, but Docker Desktop host networking does not expose it to the Mac host the way a Linux operator would expect.
- This remains the main open issue for local macOS Docker use.

Relevant files:

- `docker-compose.yml`
- `backend/Dockerfile`

## Conclusion

For this audit, the earlier fresh-install blockers are fixed:

1. Redis is no longer required by default for local/testing startup.
2. The setup docs now clearly require a local `.env`.
3. A fresh testing-stack build now reaches healthy startup with zero restarts when `.env` contains real values.

The only issue reproduced in this rerun is the existing macOS Docker Desktop `network_mode: host` reachability problem.
