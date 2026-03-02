# Admin Autodiscovery MVP Spec

## Goal

Add an admin-facing discovery wizard that:

1. Finds local sender NICs and reachable networks.
2. Finds candidate target machines (MAC + last IP + hostname best effort).
3. Suggests Wake-on-LAN routing values per target (`broadcast`, `source_ip`, optional `interface`).
4. Suggests power-check settings (`check_method=tcp`, `check_target`, `check_port`) when detectable.
5. Supports multi-NIC hosts explicitly by binding each discovered target to a sender network path.

This must be backward-compatible with the current production deployment.

## Non-Goals (MVP)

1. No automatic cross-subnet WOL relays.
2. No guaranteed detection of sleeping/offline devices.
3. No ICMP power check implementation in MVP (current backend already returns `icmp_not_implemented`).
4. No Android app changes required in MVP.

## Current Baseline (from existing code)

1. `hosts` already has WOL routing fields: `broadcast`, `subnet_cidr`, `interface`, `source_ip`.
2. `hosts` already has power-check fields: `check_method`, `check_target`, `check_port`.
3. Existing APIs/UI depend on `hosts` and must keep working:
   - `/admin/devices` CRUD
   - `/me/devices`
   - `/me/devices/{id}/wake`
4. DB migration framework exists via `schema_migrations`, current version is `4`.

## Data Model (MVP)

Use additive schema only.

### New table: `discovery_runs`

Purpose: track one discovery execution and status.

Columns:

1. `id TEXT PRIMARY KEY` (uuid)
2. `requested_by TEXT NOT NULL` (admin username)
3. `status TEXT NOT NULL CHECK(status IN ('queued','running','completed','failed','canceled'))`
4. `options_json TEXT NOT NULL` (networks selected, probe options, limits)
5. `summary_json TEXT` (counts and warnings)
6. `started_at TEXT`
7. `finished_at TEXT`
8. `created_at TEXT NOT NULL`

Indexes:

1. `idx_discovery_runs_created_at(created_at DESC)`
2. `idx_discovery_runs_status(status)`

### New table: `discovery_candidates`

Purpose: store discovered machine candidates tied to a run and source route.

Columns:

1. `id TEXT PRIMARY KEY` (uuid)
2. `run_id TEXT NOT NULL` (FK `discovery_runs.id`)
3. `hostname TEXT`
4. `mac TEXT` (normalized 12-hex lower; nullable if unknown)
5. `ip TEXT` (last seen IPv4)
6. `source_interface TEXT` (sender NIC name chosen for this observation)
7. `source_ip TEXT` (sender NIC IPv4)
8. `source_network_cidr TEXT` (network where candidate was seen)
9. `broadcast_ip TEXT` (derived from source network)
10. `wol_confidence TEXT NOT NULL CHECK(wol_confidence IN ('high','medium','low','unknown'))`
11. `power_check_method TEXT` (nullable; MVP uses `tcp`)
12. `power_check_target TEXT`
13. `power_check_port INTEGER`
14. `power_data_source TEXT NOT NULL DEFAULT 'inferred' CHECK(power_data_source IN ('none','inferred','agent','api'))`
15. `imported_host_id TEXT` (FK `hosts.id`, nullable)
16. `notes_json TEXT` (raw evidence/warnings)
17. `created_at TEXT NOT NULL`
18. `updated_at TEXT NOT NULL`

Indexes:

1. `idx_discovery_candidates_run_id(run_id)`
2. `idx_discovery_candidates_mac(mac)`
3. `idx_discovery_candidates_ip(ip)`
4. `idx_discovery_candidates_imported_host_id(imported_host_id)`

### New table: `discovery_events`

Purpose: audit and troubleshooting for discovery/validation actions.

Columns:

1. `id INTEGER PRIMARY KEY AUTOINCREMENT`
2. `run_id TEXT NOT NULL`
3. `candidate_id TEXT`
4. `event_type TEXT NOT NULL` (`probe`, `validation`, `import`, `warning`, `error`)
5. `detail TEXT NOT NULL`
6. `created_at TEXT NOT NULL`

Indexes:

1. `idx_discovery_events_run_id(run_id, id DESC)`

### Additive columns on `hosts`

Purpose: persist explicit sender-network binding and provenance without breaking old logic.

1. `source_network_cidr TEXT` (nullable)
2. `provisioning_source TEXT NOT NULL DEFAULT 'manual' CHECK(provisioning_source IN ('manual','discovery'))`
3. `discovery_confidence TEXT` (nullable: `high|medium|low|unknown`)
4. `last_discovered_at TEXT` (nullable)

`/me/devices` response does not need these fields in MVP.

## Migration Plan (Production-Safe)

### Migration `005_discovery_schema`

1. Create `discovery_runs`, `discovery_candidates`, `discovery_events`.
2. Add nullable/additive columns to `hosts`.
3. No destructive changes, no column renames, no dropped indexes.

### Backfill strategy

Run immediately after migration in the same startup phase:

1. `hosts.provisioning_source='manual'` where null.
2. `hosts.source_network_cidr`:
   - If `source_ip` belongs to `subnet_cidr`, set to `subnet_cidr`.
   - Else leave null (avoid incorrect assumptions).
3. `hosts.discovery_confidence` remains null.
4. `hosts.last_discovered_at` remains null.

### Rollback strategy

1. Keep old APIs untouched and code paths default to existing fields.
2. If discovery feature flag is disabled, app behavior equals pre-migration behavior.
3. In emergency, ignore new tables/columns; existing wake flow still works.

## API Contract (MVP)

All endpoints require admin auth.

### 1) Preview sender networks

`GET /admin/discovery/networks`

Returns:

1. interfaces (`name`, `ipv4`, `netmask`, `is_up`, `is_loopback`)
2. derived networks (`network_cidr`, `broadcast_ip`)
3. route candidates (best source interface/IP per network)
4. warnings (multiple interfaces on same subnet, missing broadcast, etc.)

### 2) Start discovery run

`POST /admin/discovery/runs`

Request:

1. `network_cidrs: string[]`
2. `source_bindings: [{ network_cidr, source_ip, interface? }]`
3. `host_probe: { enabled: bool, timeout_ms: int, max_hosts_per_network: int }`
4. `power_probe: { ports: int[], timeout_ms: int }`

Response: `202 Accepted` with `{ run_id, status }`.

### 3) Poll run status

`GET /admin/discovery/runs/{run_id}`

Returns run metadata + summary counts:

1. `candidate_count`
2. `with_mac_count`
3. `wol_high_confidence_count`
4. `imported_count`
5. `warnings`

### 4) List candidates

`GET /admin/discovery/runs/{run_id}/candidates`

Optional filters:

1. `only_unimported=true|false`
2. `wol_confidence=high|medium|low|unknown`
3. `source_network_cidr=...`

### 5) Validate wake for one candidate

`POST /admin/discovery/candidates/{candidate_id}/validate-wake`

Behavior:

1. Sends magic packet using candidate’s selected `source_ip`/`interface` + `broadcast_ip`.
2. If `power_check_target/port` available, polls for on-state up to a short timeout window.
3. Writes result to `discovery_events`.

Response:

1. `result: sent|validated|failed`
2. `detail`
3. `latency_ms` optional

### 6) Import candidate to existing device model

`POST /admin/discovery/candidates/{candidate_id}/import`

Modes:

1. `create_new`
2. `update_existing` (`target_host_id` required)

Mappings into `hosts`:

1. `mac` <- candidate `mac` (required for create)
2. `name` <- provided by admin (required for create)
3. `broadcast` <- candidate `broadcast_ip`
4. `source_ip` <- candidate `source_ip`
5. `interface` <- candidate `source_interface` (optional)
6. `source_network_cidr` <- candidate `source_network_cidr`
7. `check_method/target/port` <- candidate power probe suggestion if accepted
8. `provisioning_source='discovery'`
9. `discovery_confidence`, `last_discovered_at=now`

Response: imported `AdminDeviceOut` + import metadata.

## Discovery Engine Behavior

### Step 1: Build sender network map

1. Reuse existing interface discovery (`app/network.py`).
2. Add route inspection (preferred route per destination subnet).
3. Build candidate source bindings `{network_cidr, source_ip, interface, broadcast_ip}`.

### Step 2: Candidate collection

Per selected network:

1. Read neighbor cache (`ip neigh`/ARP) for fast passive discovery.
2. Optional lightweight probe sweep (bounded concurrency and host cap).
3. Reverse DNS lookup best-effort.
4. Produce candidate rows with evidence in `notes_json`.

### Step 3: WOL confidence scoring

`high`:

1. Valid MAC and network binding present.
2. Broadcast/source path resolved cleanly.

`medium`:

1. Valid MAC but incomplete hostname or uncertain route.

`low`:

1. Missing MAC, unstable observations, or conflicting source bindings.

`unknown`:

1. Not enough evidence.

### Step 4: Power-check suggestion

1. For online candidates, probe configurable TCP port list (default `[22,80,443,445]`).
2. First successful port becomes suggested `check_target/check_port`.
3. If no open port found, leave power-check suggestion empty.

## UI Flow (Admin)

1. New menu entry: `Discovery`.
2. Step A: pick networks + confirm source binding per network (critical for multi-NIC).
3. Step B: run scan, see progress and warnings.
4. Step C: review candidates table (MAC/IP/hostname/confidence/source network/power suggestion).
5. Step D: optional validate wake.
6. Step E: import selected candidates into `hosts`.

## Compatibility Rules

1. Existing `/admin/devices` forms remain valid and unchanged.
2. Existing wake logic keeps using `broadcast|subnet_cidr`, `source_ip`, `interface`.
3. New `source_network_cidr` is additive metadata; wake send path remains backward compatible.
4. Android client remains unaffected.

## Feature Flags

Add config flags (default safe):

1. `DISCOVERY_ENABLED=true`
2. `DISCOVERY_MAX_CONCURRENT_PROBES=128`
3. `DISCOVERY_DEFAULT_HOST_CAP=1024`
4. `DISCOVERY_DEFAULT_TCP_PORTS=22,80,443,445`
5. `DISCOVERY_RUN_TIMEOUT_SECONDS=120`

If disabled, hide endpoints/UI and keep old behavior.

## Security and Safety

1. Admin-only endpoints.
2. Reuse existing IP allowlist and auth middleware.
3. Add rate limit scope `discovery`.
4. Bound probe ranges and concurrency to prevent accidental LAN flooding.
5. Log discovery actions in admin audit trail (`target_type='discovery'`).

## Testing Plan

### Unit tests

1. Route/source binding selection in multi-NIC scenarios.
2. Confidence scoring edge cases.
3. Candidate import mapping into `hosts`.
4. Migration `005` on fresh and existing DBs.

### Integration tests

1. Start run -> poll -> list candidates.
2. Import candidate creates valid device with correct `source_ip/broadcast`.
3. Update existing host from candidate preserves untouched fields.
4. Feature flag off hides discovery routes.

### Regression tests

1. Existing tests for `/admin/devices`, `/me/devices`, wake flow remain green.
2. Existing DBs at migration `4` upgrade to `5` without data loss.

## Incremental Delivery

### Phase 1 (MVP backend)

1. Migration `005`.
2. Discovery APIs (`networks`, `runs`, `candidates`, `import`).
3. Basic candidate collection from interface + ARP/neigh + optional probes.

### Phase 2 (MVP UI)

1. Admin discovery page/workflow.
2. Candidate review/import UI.

### Phase 3 (Validation hardening)

1. Wake validation endpoint + event logs.
2. Better warning UX for subnet/firewall limitations.

## Open Decisions

1. Should import default to `create_new` always, or support MAC-based auto-merge by default?
2. Should `interface` be persisted only when explicitly selected, or auto-filled from route binding?
3. Should scans include VPN/tunnel interfaces by default, or require explicit opt-in?

