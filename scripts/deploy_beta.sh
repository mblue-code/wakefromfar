#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

if [[ ! -f .env ]]; then
  echo "ERROR: ${ROOT_DIR}/.env missing. Copy .env.example to .env and set secrets first." >&2
  exit 1
fi

# Pre-create data directories so Docker doesn't auto-create them as root,
# which would prevent the container's appuser (uid 1000) from writing.
mkdir -p "${ROOT_DIR}/data-prod"

# Build and start production profile (separate data volume) for betatesting.
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

echo "Backend deployed. Local health check:"
curl -fsS http://127.0.0.1:8080/health && echo
