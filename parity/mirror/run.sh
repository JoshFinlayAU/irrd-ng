#!/usr/bin/env bash
# Mirroring differential: an IRRd v4 upstream, mirrored side by side by a
# second IRRd v4 and by irrd-ng, through a scripted series of upstream
# changes. After every step both mirrors' canonical exports and
# database_status are compared.
#
#   parity/mirror/run.sh [--keep]
#
# Environment:
#   IRRD_NG_BIN  the irrd-ng binary (default: the static x86_64 musl build)
#   DUMP         a cached public dump to cut test data from
#                (default: parity/.cache/ALTDB.db.gz)
#   WORK         scratch directory (default: parity/.work/mirror)
#
# Upstream sources:
#   UPA  NRTMv3 (whois -g) plus HTTP export and serial: the mirrors do a
#        full import over HTTP, then follow NRTMv3, with keep_journal.
#   UPB  NRTMv4 server; the mirrors are NRTMv4 clients over HTTPS, trusting
#        the harness's CA through REQUESTS_CA_BUNDLE.
#   UPC  export only, over FTP (gzipped), with an object_class_filter.
#   UPD  export only, read from local files (file://, gzipped).
#
# Steps: initial load; changes; force reload; changes after reload; NRTMv4
# key rotation (announce, then rotate); NRTMv4 session reset; a broken
# delta and its repair; an expired Update Notification File and recovery.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
export WORK=${WORK:-$ROOT/parity/.work/mirror}
BIN=${IRRD_NG_BIN:-$ROOT/target/x86_64-unknown-linux-musl/release/irrd-ng}
DUMP=${DUMP:-$ROOT/parity/.cache/ALTDB.db.gz}
KEEP=${1:-}
DC=(docker compose -f "$HERE/compose.yaml" --project-directory "$HERE")
V4_IMAGE=irrd-ng-parity/irrd-v4:4.5.4
NET=irrd-mirror-diff_default
SOURCES=(UPA UPB UPC UPD)
RESULTS=()
FAILED=0

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

# v4's NRTMv4 test keys (irrd/mirroring/nrtm4/tests/__init__.py).
KEY_A='-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGQrdALKHTVC4sVav
mKUjXaPB22CWZP3t5XSkLqKHMO2hRANCAAQ9U/aaZwLV4koey4Jvu9cRaxiXna9k
aQ3YwrPzZlwd5MQSZ59kfT2+LAbQmXbZg0NGzptqHoOK0YD3YVBjv4kc
-----END PRIVATE KEY-----'
PUB_A='-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPVP2mmcC1eJKHsuCb7vXEWsYl52v
ZGkN2MKz82ZcHeTEEmefZH09viwG0Jl22YNDRs6bah6DitGA92FQY7+JHA==
-----END PUBLIC KEY-----'
KEY_B='-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmHtbXrQ0uEcrzeZK
iaK8UnpD5c/YAmqdUHqoHLz997ShRANCAAQ18hSL1o3ynp1kLsfXgZBtlWSYwKvc
LT2qRj7QeJPxHA6X3XMk7eD6xbdeyNFnLXiKwNPFMPcwRLC6oLN81Fvb
-----END PRIVATE KEY-----'

indent() { sed 's/^/        /'; }

common_config() {
  cat <<EOF
  database_url: postgresql://irrd:irrd@postgres/$1
  redis_url: redis://$2
  piddir: /run/irrd
  server:
    http: {interface: 0.0.0.0, port: 8080, url: "http://localhost:8080/", workers: 1}
    whois: {interface: 0.0.0.0, port: 8043, max_connections: 3}
  access_lists:
    all: [0.0.0.0/0, "::/0"]
  auth:
    gnupg_keyring: /var/lib/irrd/gnupg
    override_password: \$1\$J6KycItM\$MbPaBU6iFSGFV299Rk7Di0
  email: {from: mirror-diff@parity.invalid, smtp: localhost}
  rpki: {roa_source: null}
  log: {level: INFO}
EOF
}

# write_upstream <current private key> [next private key]
write_upstream() {
  local next=""
  if [[ -n ${2:-} ]]; then
    next="      nrtm4_server_private_key_next: |
$(printf '%s\n' "$2" | indent)"
  fi
  mkdir -p "$WORK/upstream"
  cat > "$WORK/upstream/irrd.yaml.new" <<EOF
irrd:
$(common_config upstream redis-up)
  sources:
    UPA: {authoritative: true, keep_journal: true, nrtm_access_list: all, export_destination: /srv/exports, export_timer: 999999}
    UPB:
      authoritative: true
      keep_journal: true
      nrtm_access_list: all
      nrtm4_server_local_path: /srv/nrtm4/UPB
      nrtm4_server_private_key: |
$(printf '%s\n' "$1" | indent)
$next
    UPC: {authoritative: true, keep_journal: true, export_destination: /srv/exports, export_timer: 999999}
    UPD: {authoritative: true, keep_journal: true, export_destination: /srv/exports, export_timer: 999999}
EOF
  mv "$WORK/upstream/irrd.yaml.new" "$WORK/upstream/irrd.yaml"
}

write_mirror() {
  local dir=$1
  mkdir -p "$WORK/$dir"
  cat > "$WORK/$dir/irrd.yaml" <<EOF
irrd:
$(common_config mirror redis-mirror)
  sources:
    UPA:
      nrtm_host: upstream
      nrtm_port: 8043
      import_source: http://files/exports/upa.db.gz
      import_serial_source: http://files/exports/UPA.CURRENTSERIAL
      import_timer: 2
      keep_journal: true
    UPB:
      nrtm4_client_notification_file_url: https://files/nrtm4/UPB/update-notification-file.jose
      nrtm4_client_initial_public_key: |
$(printf '%s\n' "$PUB_A" | indent)
      import_timer: 2
    UPC:
      import_source:
        - ftp://files/exports/upc.db.gz
      import_serial_source: ftp://files/exports/UPC.CURRENTSERIAL
      import_timer: 2
      object_class_filter: [route, route6, aut-num, as-set, mntner]
    UPD:
      import_source: file:///exports/upd.db.gz
      import_serial_source: file:///exports/UPD.CURRENTSERIAL
      import_timer: 2
EOF
}

psql() { "${DC[@]}" exec -T postgres psql -U irrd -d "$1" -Atc "$2"; }

up_exec() { "${DC[@]}" exec -T upstream "$@"; }

export_upstream() {
  for s in "$@"; do
    up_exec /opt/irrd/bin/python -c "
import pydantic.main
from irrd.conf import config_init
config_init('/etc/irrd/irrd.yaml')
from irrd.mirroring.mirror_runners_export import SourceExportRunner
SourceExportRunner('$s').run()" >/dev/null
  done
}

# What each mirror should reach, from the upstream: per source,
# "serial_newest_mirror/nrtm4 session:version".
expected() {
  local a b c d
  a=$(psql upstream "select serial_newest_journal from database_status where source='UPA'")
  b=$(psql upstream "select nrtm4_server_session_id || ':' || nrtm4_server_version from database_status where source='UPB'")
  c=$(cat "$WORK/srv/exports/UPC.CURRENTSERIAL" 2>/dev/null || echo none)
  d=$(cat "$WORK/srv/exports/UPD.CURRENTSERIAL" 2>/dev/null || echo none)
  printf 'UPA=%s UPB=%s UPC=%s UPD=%s' "$a" "$b" "$c" "$d"
}

v4_state() {
  psql mirror "select string_agg(source || '=' || case when source = 'UPB' then coalesce(nrtm4_client_session_id::text, '') || ':' || coalesce(nrtm4_client_version::text, '') else coalesce(serial_newest_mirror::text, '') end, ' ' order by source) from database_status where source in ('UPA','UPB','UPC','UPD')"
}

ng_state() {
  "${DC[@]}" exec -T irrd-ng /irrd-ng export-jsonl --config /etc/irrd/irrd.yaml --table database_status \
    | python3 -c '
import json, sys
out = []
for line in sys.stdin:
    r = json.loads(line)
    if r["source"] not in ("UPA", "UPB", "UPC", "UPD"):
        continue
    if r["source"] == "UPB":
        v = "%s:%s" % (r["nrtm4_client_session_id"] or "", r["nrtm4_client_version"] if r["nrtm4_client_version"] is not None else "")
    else:
        v = str(r["serial_newest_mirror"]) if r["serial_newest_mirror"] is not None else ""
    out.append("%s=%s" % (r["source"], v))
print(" ".join(sorted(out)))'
}

wait_synced() {
  local want v4 ng
  want=$(expected)
  for _ in $(seq 1 90); do
    v4=$(v4_state); ng=$(ng_state)
    if [[ $v4 == "$want" && $ng == "$want" ]]; then
      log "synced: $want"
      return 0
    fi
    sleep 2
  done
  log "NOT synced after 180s: want [$want] v4 [$v4] irrd-ng [$ng]"
  return 1
}

compare() {
  local step=$1 out="$WORK/compare/$1"
  rm -rf "$out"; mkdir -p "$out/v4" "$WORK/ng-out/$step"
  docker run --rm --network "$NET" --user root --entrypoint /opt/irrd/bin/python \
    -v "$ROOT/parity/tools:/tools:ro" -v "$out/v4:/out" "$V4_IMAGE" \
    /tools/export_v4.py postgresql://irrd:irrd@postgres/mirror /out >/dev/null
  "${DC[@]}" exec -T irrd-ng /irrd-ng export-jsonl --config /etc/irrd/irrd.yaml --table all --output-dir "/out/$step"
  cp -r "$WORK/ng-out/$step" "$out/irrd-ng"
  local objs
  objs=$(wc -l < "$out/v4/rpsl_objects.jsonl")
  if python3 "$ROOT/parity/tools/compare_exports.py" "$out/v4" "$out/irrd-ng" \
      --exclude-file "$HERE/excluded-columns.tsv" --label-left v4 --label-right irrd-ng > "$out/diff.txt" 2>&1; then
    RESULTS+=("PASS  $step  ($objs objects)")
    log "PASS $step ($objs objects)"
  else
    RESULTS+=("FAIL  $step  (see $out/diff.txt)")
    FAILED=1
    log "FAIL $step"; head -40 "$out/diff.txt" >&2
  fi
}

update_upstream() {
  local round=$1; shift
  for s in "$@"; do
    python3 "$HERE/data.py" change "$WORK/data/$s.db" "$WORK/data/$s.pool" "$round" >&2
    up_exec irrd_update_database --config /etc/irrd/irrd.yaml --source "$s" "/data/$s.db" >&2
  done
}

# Both mirrors' log lines since a marker, matching a pattern.
count_logs() {
  local svc=$1 since=$2 pattern=$3
  "${DC[@]}" logs --no-color --since "$since" "$svc" 2>&1 | grep -c -- "$pattern" || true
}

check_both_logged() {
  local step=$1 since=$2 pattern=$3 n4 nng
  n4=$(count_logs mirror-v4 "$since" "$pattern"); nng=$(count_logs irrd-ng "$since" "$pattern")
  if (( n4 > 0 && nng > 0 )); then
    RESULTS+=("PASS  $step  both logged: $pattern (v4 $n4x, irrd-ng ${nng}x)")
  else
    RESULTS+=("FAIL  $step  log '$pattern': v4 $n4, irrd-ng $nng")
    FAILED=1
  fi
}

nrtm4_dir() { echo "$WORK/srv/nrtm4/UPB"; }
unf_version() { psql upstream "select nrtm4_server_version from database_status where source='UPB'"; }

cleanup() {
  if [[ $KEEP != --keep ]]; then
    "${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}

main() {
  [[ -x $BIN ]] || { echo "irrd-ng binary $BIN not found (build the musl target first)" >&2; exit 1; }
  file "$BIN" | grep -q 'statically linked' || { echo "$BIN is not statically linked" >&2; exit 1; }
  [[ -f $DUMP ]] || { echo "dump $DUMP not found (parity/fetch-dumps.sh)" >&2; exit 1; }
  "${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  # Containers write as root into the work directory.
  if [[ -d $WORK ]]; then
    docker run --rm --user root --entrypoint sh -v "$WORK:/w" "$V4_IMAGE" -c 'rm -rf /w/* /w/.[!.]*' 2>/dev/null || true
    rm -rf "$WORK" 2>/dev/null || true
  fi
  mkdir -p "$WORK"/{data,srv/exports,srv/nrtm4/UPB,overlay,ng-data,ng-out,irrd-ng-image,compare,logs,tls}
  chmod -R a+rwX "$WORK"
  docker run --rm --user "$(id -u)" --entrypoint /opt/irrd/bin/python -v "$HERE:/harness:ro" \
    -v "$WORK/tls:/tls" "$V4_IMAGE" /harness/make_cert.py /tls
  chmod a+r "$WORK"/tls/*
  trap cleanup EXIT

  cp "$BIN" "$WORK/irrd-ng-image/irrd-ng"
  cp "$HERE/irrd-ng.Dockerfile" "$WORK/irrd-ng-image/Dockerfile"
  python3 "$HERE/data.py" initial "$DUMP" "$WORK/data" "${SOURCES[@]}" --per-source 1500
  write_upstream "$KEY_A"
  write_mirror mirror-v4
  write_mirror irrd-ng

  log "starting upstream"
  "${DC[@]}" build irrd-ng >/dev/null
  "${DC[@]}" up -d --wait postgres redis-up redis-mirror files >/dev/null
  "${DC[@]}" up -d upstream >/dev/null
  for _ in $(seq 1 60); do
    "$ROOT/parity/whois.sh" 127.0.0.1 9643 '!v' 2>/dev/null | grep -q '4.5.4' && break
    sleep 2
  done
  for s in "${SOURCES[@]}"; do
    up_exec irrd_load_database --config /etc/irrd/irrd.yaml --source "$s" --serial 1000 "/data/$s.db" >&2
  done
  export_upstream UPA UPC UPD
  for _ in $(seq 1 60); do [[ -f $(nrtm4_dir)/update-notification-file.jose ]] && break; sleep 1; done

  log "step 01: initial import by both mirrors"
  "${DC[@]}" up -d mirror-v4 irrd-ng >/dev/null
  wait_synced || true
  compare 01-initial

  log "step 02: changes (NRTMv3, NRTMv4 deltas, new exports over FTP and file)"
  update_upstream 1 "${SOURCES[@]}"
  export_upstream UPA UPC UPD
  wait_synced || true
  compare 02-changes

  log "step 03: force reload of UPA and UPB on both mirrors"
  local out4 outng
  out4=$("${DC[@]}" exec -T mirror-v4 irrd_mirror_force_reload --config /etc/irrd/irrd.yaml UPB 2>&1; \
         "${DC[@]}" exec -T mirror-v4 irrd_mirror_force_reload --config /etc/irrd/irrd.yaml UPA 2>&1)
  outng=$("${DC[@]}" exec -T irrd-ng /irrd-ng irrd_mirror_force_reload --config /etc/irrd/irrd.yaml UPB 2>&1; \
          "${DC[@]}" exec -T irrd-ng /irrd-ng irrd_mirror_force_reload --config /etc/irrd/irrd.yaml UPA 2>&1)
  # The log lines carry timestamps and PIDs; compare the printed text.
  if [[ $(grep -v ' irrd\[' <<<"$out4") == "$(grep -v ' irrd\[' <<<"$outng")" ]]; then
    RESULTS+=("PASS  03-force-reload  irrd_mirror_force_reload output")
  else
    RESULTS+=("FAIL  03-force-reload  irrd_mirror_force_reload output differs"); FAILED=1
    printf 'v4:\n%s\nirrd-ng:\n%s\n' "$out4" "$outng" >&2
  fi
  sleep 1
  wait_synced || true
  compare 03-force-reload

  log "step 04: changes after the reload"
  update_upstream 2 UPA UPB
  wait_synced || true
  compare 04-changes-after-reload

  log "step 05: NRTMv4 key rotation announced (next_signing_key)"
  write_upstream "$KEY_A" "$KEY_B"
  "${DC[@]}" kill -s HUP upstream >/dev/null
  sleep 3
  update_upstream 3 UPB
  wait_synced || true
  compare 05-rotation-announced

  log "step 06: NRTMv4 key rotated"
  write_upstream "$KEY_B"
  "${DC[@]}" kill -s HUP upstream >/dev/null
  sleep 3
  local since
  since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  update_upstream 4 UPB
  wait_synced || true
  compare 06-rotated
  check_both_logged 06-rotated "$since" "signing key rotated from"

  log "step 07: NRTMv4 session reset upstream"
  local snap
  snap=$(psql upstream "select nrtm4_server_last_snapshot_filename from database_status where source='UPB'")
  rm -f "$(nrtm4_dir)/$snap"
  since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  sleep 3
  wait_synced || true
  compare 07-session-reset
  check_both_logged 07-session-reset "$since" "Session ID has changed"

  log "step 08: a broken delta"
  mkdir -p "$WORK/overlay/nrtm4/UPB"
  cp "$(nrtm4_dir)/update-notification-file.jose" "$WORK/overlay/nrtm4/UPB/"
  local before
  before=$(unf_version)
  update_upstream 5 UPB
  for _ in $(seq 1 30); do [[ $(unf_version) != "$before" ]] && break; sleep 1; done
  local delta
  delta=$(psql upstream "select d->>'filename' from database_status, jsonb_array_elements(nrtm4_server_previous_deltas) d where source='UPB' order by (d->>'version')::int desc limit 1")
  docker run --rm --user root --entrypoint /opt/irrd/bin/python -v "$HERE:/harness:ro" -v "$WORK:/work" "$V4_IMAGE" \
    /harness/tamper.py break-file "/work/srv/nrtm4/UPB/$delta" "/work/overlay/nrtm4/UPB/$delta"
  since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  rm -f "$WORK/overlay/nrtm4/UPB/update-notification-file.jose"
  sleep 12
  compare 08-broken-delta
  check_both_logged 08-broken-delta "$since" "Invalid hash in"

  log "step 09: the delta repaired"
  rm -f "$WORK/overlay/nrtm4/UPB/$delta"
  wait_synced || true
  compare 09-delta-repaired

  log "step 10: an expired Update Notification File"
  printf '%s\n' "$KEY_B" > "$WORK/overlay/key-b.pem"
  docker run --rm --user root --entrypoint /opt/irrd/bin/python -v "$HERE:/harness:ro" -v "$WORK:/work" "$V4_IMAGE" \
    /harness/tamper.py expire-unf /work/srv/nrtm4/UPB/update-notification-file.jose \
    /work/overlay/nrtm4/UPB/update-notification-file.jose /work/overlay/key-b.pem 25
  since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  sleep 10
  compare 10-expired-unf
  check_both_logged 10-expired-unf "$since" "older than 24 hours"
  rm -f "$WORK/overlay/nrtm4/UPB/update-notification-file.jose"

  log "step 11: recovery and a last round of changes everywhere"
  update_upstream 6 "${SOURCES[@]}"
  export_upstream UPA UPC UPD
  wait_synced || true
  compare 11-final

  "${DC[@]}" logs --no-color mirror-v4 > "$WORK/logs/mirror-v4.log" 2>&1 || true
  "${DC[@]}" logs --no-color irrd-ng > "$WORK/logs/irrd-ng.log" 2>&1 || true
  "${DC[@]}" logs --no-color upstream > "$WORK/logs/upstream.log" 2>&1 || true
  printf '\n%s\n' "${RESULTS[@]}"
  return $FAILED
}

main "$@"
