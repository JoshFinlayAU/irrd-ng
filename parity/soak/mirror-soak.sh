#!/usr/bin/env bash
# Mirroring soak (PLAN.md Phase 4 exit): IRRd v4 4.5.4 and irrd-ng mirror the
# same public upstreams side by side for days; after every cycle their object
# sets and database_status are compared per source, and memory is recorded.
#
#   parity/soak/mirror-soak.sh up        build the irrd-ng image, write the
#                                        configs, start both mirrors
#   parity/soak/mirror-soak.sh cycle     one comparison (appends to the log)
#   parity/soak/mirror-soak.sh run [D]   cycle every INTERVAL seconds for D
#                                        days (default 7), in the foreground
#   parity/soak/mirror-soak.sh report    summary of the log so far
#   parity/soak/mirror-soak.sh down      stop and remove everything
#
# Meant for the parity VM; start it under tmux/nohup:
#   SOAK=/srv/irrd-mirror-soak IRRD_NG_BIN=./irrd-ng parity/soak/mirror-soak.sh up
#   nohup parity/soak/mirror-soak.sh run 7 > /srv/irrd-mirror-soak/run.out 2>&1 &
#
# Upstreams, all public, read-only and offered for mirroring:
#   RIPE-NONAUTH  NRTMv4 from nrtm.db.ripe.net (HTTPS, ES256 JWS). Deltas
#                 about every minute and periodic snapshots: the NRTMv4
#                 client's steady state, signature checks, hash checks and,
#                 when RIPE rotates or resets, its recovery paths. The key is
#                 RIPE's published nrtmv4_public_key.txt.
#   RADB          full imports over FTP (ftp.radb.net), gzipped, with
#                 RADB.CURRENTSERIAL, class-filtered to as-set, aut-num,
#                 route-set, route, route6 as on the reference server: the
#                 biggest source (about 1.4M objects), re-imported whenever the
#                 published serial moves, so it soaks the bulk import path,
#                 the spool and the single writer under load.
#   ARIN          full imports over HTTPS (ftp.arin.net) with
#                 ARIN.CURRENTSERIAL: rustls, the Mozilla roots built into the
#                 static binary, gzip.
#   ALTDB         full imports over FTP (ftp.altdb.net): a small second FTP
#                 server and a different dump producer.
# Nobody offers NRTMv3 to anonymous clients, so NRTMv3 is covered by the
# local differential (parity/mirror/run.sh) only.
#
# Both mirrors use v4's default timers (300 s for full imports, 60 s for
# NRTMv4), so each upstream sees two ordinary mirrors. Downloads identify as
# v4 does ("irrd/4.5.4"), with no contact details.
#
# Memory caps (the VM has 32 GB and other workloads): PostgreSQL 4 GB,
# Redis 1 GB, IRRd v4 6 GB, irrd-ng 6 GB, each export for a comparison 2 GB.
# Peak is about 19 GB.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
export SOAK=${SOAK:-$ROOT/parity/.work/soak}
BIN=${IRRD_NG_BIN:-$ROOT/target/x86_64-unknown-linux-musl/release/irrd-ng}
INTERVAL=${INTERVAL:-1800}
V4_IMAGE=irrd-ng-parity/irrd-v4:4.5.4
DC=(docker compose -f "$HERE/compose.yaml" --project-directory "$HERE")
LOG="$SOAK/soak.jsonl"

log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" >&2; }

RIPE_KEY_URL=https://ftp.ripe.net/ripe/dbase/nrtmv4/nrtmv4_public_key.txt

write_configs() {
  local key
  key=$(curl -fsS --max-time 30 -A "irrd/4.5.4" "$RIPE_KEY_URL")
  [[ $key == *"BEGIN PUBLIC KEY"* ]] || { echo "could not fetch RIPE's NRTMv4 key" >&2; exit 1; }
  mkdir -p "$SOAK/v4" "$SOAK/irrd-ng"
  local cfg="$SOAK/v4/irrd.yaml"
  cat > "$cfg" <<EOF
# Written by parity/soak/mirror-soak.sh. irrd-ng reads the same file.
irrd:
  database_url: postgresql://irrd:irrd@postgres/irrd
  redis_url: redis://redis
  piddir: /run/irrd
  server:
    http: {interface: 0.0.0.0, port: 8080, url: "http://localhost:8080/", workers: 1}
    whois: {interface: 0.0.0.0, port: 8043, max_connections: 3}
  auth: {gnupg_keyring: /var/lib/irrd/gnupg}
  email: {from: mirror-soak@parity.invalid, smtp: localhost}
  rpki: {roa_source: null}
  log: {level: INFO}
  sources:
    RIPE-NONAUTH:
      nrtm4_client_notification_file_url: https://nrtm.db.ripe.net/nrtmv4/RIPE-NONAUTH/update-notification-file.jose
      nrtm4_client_initial_public_key: |
$(printf '%s\n' "$key" | sed 's/^/        /')
    RADB:
      import_source: ftp://ftp.radb.net/radb/dbase/radb.db.gz
      import_serial_source: ftp://ftp.radb.net/radb/dbase/RADB.CURRENTSERIAL
      object_class_filter: [as-set, aut-num, route-set, route, route6]
    ARIN:
      import_source: https://ftp.arin.net/pub/rr/arin.db.gz
      import_serial_source: https://ftp.arin.net/pub/rr/ARIN.CURRENTSERIAL
    ALTDB:
      import_source: ftp://ftp.altdb.net/pub/altdb/altdb.db.gz
      import_serial_source: ftp://ftp.altdb.net/pub/altdb/ALTDB.CURRENTSERIAL
EOF
  cp "$cfg" "$SOAK/irrd-ng/irrd.yaml"
}

up() {
  [[ -x $BIN ]] && file "$BIN" | grep -q 'statically linked' \
    || { echo "need the static irrd-ng binary (IRRD_NG_BIN)" >&2; exit 1; }
  docker image inspect "$V4_IMAGE" >/dev/null 2>&1 \
    || { echo "build the v4 image first (parity/up.sh builds it)" >&2; exit 1; }
  mkdir -p "$SOAK/irrd-ng-image" "$SOAK/ng-out" "$SOAK/compare"
  chmod a+rwx "$SOAK/ng-out"
  cp "$BIN" "$SOAK/irrd-ng-image/irrd-ng"
  cp "$ROOT/parity/mirror/irrd-ng.Dockerfile" "$SOAK/irrd-ng-image/Dockerfile"
  write_configs
  "${DC[@]}" build irrd-ng
  "${DC[@]}" up -d
  log "soak started; first comparison after the initial imports (allow an hour for RADB)"
}

# Export both mirrors at (nearly) the same moment and compare per source.
# A source whose mirrors stand at different positions is "moving"; it is
# retried a few times before the cycle gives up on it.
cycle() {
  local ts out attempt res
  ts=$(date -u +%Y%m%dT%H%M%SZ)
  for attempt in 1 2 3 4 5; do
    out="$SOAK/compare/$ts-$attempt"
    mkdir -p "$out/v4" "$SOAK/ng-out/$ts-$attempt"
    docker run --rm --network irrd-mirror-soak_default --memory 2g --user root \
      --entrypoint /opt/irrd/bin/python -v "$ROOT/parity/tools:/tools:ro" -v "$out/v4:/out" "$V4_IMAGE" \
      /tools/export_v4.py postgresql://irrd:irrd@postgres/irrd /out > /dev/null &
    "${DC[@]}" exec -T irrd-ng /irrd-ng export-jsonl --config /etc/irrd/irrd.yaml \
      --table all --output-dir "/out/$ts-$attempt" &
    wait
    mv "$SOAK/ng-out/$ts-$attempt" "$out/irrd-ng"
    res=$(python3 "$HERE/soak_compare.py" "$out/v4" "$out/irrd-ng" || true)
    rm -rf "$out/v4" "$out/irrd-ng"
    if ! grep -q '"result": "moving"' <<<"$res" || [[ $attempt == 5 ]]; then
      break
    fi
    sleep 20
  done
  local mem
  mem=$(docker stats --no-stream --format '{{.Name}}={{.MemUsage}}' | grep irrd-mirror-soak | tr '\n' ' ')
  while IFS= read -r line; do
    [[ -n $line ]] && printf '{"time": "%s", "attempt": %s, "memory": "%s", "comparison": %s}\n' \
      "$ts" "$attempt" "$mem" "$line" >> "$LOG"
  done <<<"$res"
  printf '%s\n' "$res" | python3 -c '
import json, sys
for l in sys.stdin:
    if l.strip():
        r = json.loads(l)
        print("%-14s %-9s v4=%s irrd-ng=%s objects %s/%s" % (r["source"], r["result"], r["position_v4"], r["position_irrd_ng"], r["objects_v4"], r["objects_irrd_ng"]))
' >&2
  log "memory: $mem"
  if grep -q '"result": "DIFFERENT"' <<<"$res"; then
    "${DC[@]}" logs --no-color --since 2h irrd-v4 > "$SOAK/compare/$ts-v4.log" 2>&1 || true
    "${DC[@]}" logs --no-color --since 2h irrd-ng > "$SOAK/compare/$ts-irrd-ng.log" 2>&1 || true
    log "DIFFERENT: logs kept in $SOAK/compare/$ts-*.log"
    return 1
  fi
}

run() {
  local days=${1:-7} end
  end=$(( $(date +%s) + days * 86400 ))
  while (( $(date +%s) < end )); do
    cycle || true
    sleep "$INTERVAL"
  done
  report
}

report() {
  python3 - "$LOG" <<'EOF'
import collections, json, sys
counts = collections.defaultdict(collections.Counter)
first = last = None
for line in open(sys.argv[1], encoding="utf-8"):
    r = json.loads(line)
    first = first or r["time"]; last = r["time"]
    c = r["comparison"]
    counts[c["source"]][c["result"]] += 1
print(f"cycles from {first} to {last}")
for s, c in sorted(counts.items()):
    print(f"{s:14} " + ", ".join(f"{k} {v}" for k, v in sorted(c.items())))
EOF
}

down() { "${DC[@]}" down -v --remove-orphans; }

case ${1:-} in
  up) up ;;
  cycle) cycle ;;
  run) run "${2:-7}" ;;
  report) report ;;
  down) down ;;
  *) sed -n '2,15p' "$0"; exit 2 ;;
esac
