#!/usr/bin/env bash
# Start the pinned IRRd v4 reference stack and wait until it answers !v.
set -euo pipefail
cd "$(dirname "$0")"
docker compose up -d --build --wait postgres redis mailpit
docker compose up -d irrd-v4
for _ in $(seq 1 90); do
  if v=$(./whois.sh 127.0.0.1 9043 '!v' 2>/dev/null) && [[ $v == *"version 4.5.4"* ]]; then
    printf '%s\n' "$v"
    exit 0
  fi
  sleep 2
done
echo "irrd-v4 did not answer !v within 180s" >&2
docker compose logs --tail 50 irrd-v4 >&2
exit 1
