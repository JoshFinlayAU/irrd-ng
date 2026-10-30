#!/usr/bin/env bash
# Stop the parity stack. Pass --volumes to drop the v4 database as well.
set -euo pipefail
cd "$(dirname "$0")"
docker compose down --remove-orphans "$@"
