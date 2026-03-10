# Local Backend Reset Workflow

This repo currently treats the backend test environment as disposable.

For the current post-refactor system:

- reset local state by rebuilding the SQLite volume
- reseed the backend with representative users, devices, memberships, and optional scheduled wakes
- do not preserve old DB files or add migration work just to keep old local data alive

## Canonical local stack

Use the testing compose overlay as the default local refactor environment:

```bash
cp .env.example .env
# set APP_SECRET and ADMIN_PASS in the local repo-root .env before first startup
docker compose -f docker-compose.yml -f docker-compose.testing.yml up -d --build
```

With the current compose files, that stack stores backend state in the named Docker volume `wakefromfar_wol-data-testing`.

Why this stack:

- it keeps local refactor/test data separate from the default and prod-style volumes
- it matches the same backend service wiring as the main compose file
- it is the safest place to do repeated clean-slate rebuilds

## Reset strategy

The repo should stay bootstrappable from an empty database and rely on DB rebuilds instead of historical migration chains.

- Keep the current repo bootstrappable from an empty database.
- Prefer direct schema setup in `init_db()` over preserving old migration history.
- When schema changes land, reset the testing DB and reseed it instead of carrying forward old local SQLite files.

## Full reset and reseed sequence

Run from the repo root:

```bash
set -a
source .env
set +a

export API_BASE_URL="http://127.0.0.1:8080"
export COMPOSE_FILES="-f docker-compose.yml -f docker-compose.testing.yml"

docker compose $COMPOSE_FILES down -v --remove-orphans
docker compose $COMPOSE_FILES up -d --build

until curl -fsS "$API_BASE_URL/health" >/dev/null; do
  sleep 1
done
```

Admin bootstrap:

- the backend creates or updates the bootstrap admin from `ADMIN_USER` and `ADMIN_PASS` during startup
- the login call below is the verification step that the bootstrap admin exists in the fresh DB

```bash
TOKEN=$(
  curl -fsS "$API_BASE_URL/auth/login" \
    -H 'content-type: application/json' \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" |
  jq -r '.token'
)
```

Seed representative users:

```bash
ALICE_ID=$(
  curl -fsS "$API_BASE_URL/admin/users" \
    -H "authorization: Bearer $TOKEN" \
    -H 'content-type: application/json' \
    -d '{"username":"alice","password":"alicepass123","role":"user"}' |
  jq -r '.id'
)

BOB_ID=$(
  curl -fsS "$API_BASE_URL/admin/users" \
    -H "authorization: Bearer $TOKEN" \
    -H 'content-type: application/json' \
    -d '{"username":"bob","password":"bobpass1234","role":"user"}' |
  jq -r '.id'
)
```

Seed representative devices:

Replace the network fields before running this in a real lab. The example below keeps the sequence concrete while making the adjustable values obvious.

```bash
NAS_ID=$(
  curl -fsS "$API_BASE_URL/admin/devices" \
    -H "authorization: Bearer $TOKEN" \
    -H 'content-type: application/json' \
    -d '{
      "name":"nas",
      "display_name":"NAS",
      "mac":"AA:BB:CC:DD:EE:01",
      "group_name":"Core",
      "broadcast":"192.168.178.255",
      "source_ip":"192.168.178.2",
      "udp_port":9,
      "check_method":"tcp",
      "check_target":"192.168.178.50",
      "check_port":445
    }' |
  jq -r '.id'
)

WORKSTATION_ID=$(
  curl -fsS "$API_BASE_URL/admin/devices" \
    -H "authorization: Bearer $TOKEN" \
    -H 'content-type: application/json' \
    -d '{
      "name":"workstation",
      "display_name":"Office Workstation",
      "mac":"AA:BB:CC:DD:EE:02",
      "group_name":"Work",
      "broadcast":"192.168.178.255",
      "source_ip":"192.168.178.2",
      "udp_port":9,
      "check_method":"tcp",
      "check_target":"192.168.178.60",
      "check_port":22
    }' |
  jq -r '.id'
)

MEDIA_PC_ID=$(
  curl -fsS "$API_BASE_URL/admin/devices" \
    -H "authorization: Bearer $TOKEN" \
    -H 'content-type: application/json' \
    -d '{
      "name":"media-pc",
      "display_name":"Media PC",
      "mac":"AA:BB:CC:DD:EE:03",
      "group_name":"Home",
      "broadcast":"192.168.178.255",
      "source_ip":"192.168.178.2",
      "udp_port":9,
      "check_method":"tcp",
      "check_target":"192.168.178.70",
      "check_port":443
    }' |
  jq -r '.id'
)
```

Create representative device memberships:

```bash
curl -fsS "$API_BASE_URL/admin/device-memberships" \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d "{\"user_id\":${ALICE_ID},\"device_id\":\"${NAS_ID}\"}"

curl -fsS "$API_BASE_URL/admin/device-memberships" \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d "{\"user_id\":${ALICE_ID},\"device_id\":\"${MEDIA_PC_ID}\",\"is_favorite\":true,\"sort_order\":1}"

curl -fsS "$API_BASE_URL/admin/device-memberships" \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d "{\"user_id\":${BOB_ID},\"device_id\":\"${WORKSTATION_ID}\",\"can_request_shutdown\":0}"
```

Optional: seed one scheduled wake job so admin UI schedule pages and client schedule hints have real data:

```bash
curl -fsS "$API_BASE_URL/admin/scheduled-wakes" \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d "{
    \"device_id\":\"${MEDIA_PC_ID}\",
    \"label\":\"Weekday morning wake\",
    \"enabled\":true,
    \"timezone\":\"Europe/Berlin\",
    \"days_of_week\":[\"mon\",\"tue\",\"wed\",\"thu\",\"fri\"],
    \"local_time\":\"07:30\"
  }"
```

Quick verification:

```bash
curl -fsS "$API_BASE_URL/admin/users" \
  -H "authorization: Bearer $TOKEN"

curl -fsS "$API_BASE_URL/admin/devices" \
  -H "authorization: Bearer $TOKEN"

curl -fsS "$API_BASE_URL/admin/device-memberships" \
  -H "authorization: Bearer $TOKEN"

curl -fsS "$API_BASE_URL/admin/scheduled-wakes" \
  -H "authorization: Bearer $TOKEN"
```

## Other compose variants

These compose files also use their own named volumes:

- `docker-compose.yml` -> `wakefromfar_wol-data`
- `docker-compose.simple.yml` -> `wakefromfar_wol-data-simple`
- `docker-compose.yml` + `docker-compose.testing.yml` -> `wakefromfar_wol-data-testing`
- `docker-compose.yml` + `docker-compose.prod.yml` -> `wakefromfar_wol-data-prod`

For clean-slate refactor work, the testing overlay above is the one to reset and reseed repeatedly.
