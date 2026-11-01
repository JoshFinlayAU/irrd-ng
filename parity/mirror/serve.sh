#!/usr/bin/env bash
# Serving differential: irrd-ng as an upstream. A v4 upstream and an
# irrd-ng upstream get the same data and the same changes, each with an
# IRRd v4 mirror following it over NRTMv3, NRTMv4, HTTP, FTP and file
# exports. After every step:
#
#   - the two v4 mirrors must hold the same objects, journal and status
#     (a v4 mirror cannot tell which upstream it follows);
#   - the two upstreams must hold the same objects, journal and status;
#   - the exports must be byte-identical (gzip MTIME and FNAME aside, which
#     differ between any two v4 runs too);
#   - the NRTMv4 repositories must serve the same snapshot and the same
#     changes (parity/tools/compare_nrtm4.py);
#   - NRTMv3 (-g, -q, !j) answers must be byte-identical
#     (parity/corpus/whois/nrtm.q through parity/tools/whois_diff.py).
#
#   parity/mirror/serve.sh [--keep]
#
# Environment: IRRD_NG_BIN, DUMP, WORK and ROUNDS (churn rounds, default 6).
# The irrd-ng-from-v4 direction is parity/mirror/run.sh.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
export WORK=${WORK:-$ROOT/parity/.work/serve}
BIN=${IRRD_NG_BIN:-$ROOT/target/x86_64-unknown-linux-musl/release/irrd-ng}
DUMP=${DUMP:-$ROOT/parity/.cache/ALTDB.db.gz}
ROUNDS=${ROUNDS:-6}
KEEP=${1:-}
DC=(docker compose -f "$HERE/compose.yaml" --project-directory "$HERE" --profile serve)
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

dummify_config() {
  cat <<'EOF'
      nrtm_dummified_object_classes: [mntner, person, role]
      nrtm_dummified_attributes:
        e-mail: unread@parity.invalid
        phone: "+0 000 0000"
        address: Dummy address for %s
        upd-to: unread@parity.invalid
      nrtm_dummified_remarks: |
        This object has been dummified.
        See the authoritative source.
EOF
}

# write_upstream <dir> <database> <redis> <current key> [next key]: the
# same file for both upstreams (irrd-ng ignores database_url/redis_url).
# authoritative_retain_last_modified keeps the two upstreams from stamping
# objects with their own wall clock times in last-modified.
write_upstream() {
  local dir=$1 db=$2 redis=$3 key=$4 next=""
  if [[ -n ${5:-} ]]; then
    next="      nrtm4_server_private_key_next: |
$(printf '%s\n' "$5" | indent)"
  fi
  mkdir -p "$WORK/$dir"
  cat > "$WORK/$dir/irrd.yaml.new" <<EOF
irrd:
$(common_config "$db" "$redis")
  sources:
    UPA:
      authoritative: true
      authoritative_retain_last_modified: true
      keep_journal: true
      nrtm_access_list: all
      export_destination: /srv/exports
      export_timer: 999999
$(dummify_config)
    UPB:
      authoritative: true
      authoritative_retain_last_modified: true
      keep_journal: true
      nrtm_access_list: all
      nrtm_query_serial_days_limit: 1
      nrtm4_server_local_path: /srv/nrtm4/UPB
      nrtm4_server_private_key: |
$(printf '%s\n' "$key" | indent)
$next
$(dummify_config)
    UPC:
      authoritative: true
      authoritative_retain_last_modified: true
      keep_journal: true
      export_destination: /srv/exports
      export_destination_unfiltered: /srv/exports-unfiltered
      export_timer: 999999
$(dummify_config)
    UPD:
      authoritative: true
      authoritative_retain_last_modified: true
      keep_journal: true
      nrtm_access_list: all
      nrtm_access_list_unfiltered: all
      nrtm_query_serial_range_limit: 10
      nrtm_response_header: |
        Serving differential
        second line
      export_destination: /srv/exports
      export_timer: 999999
EOF
  mv "$WORK/$dir/irrd.yaml.new" "$WORK/$dir/irrd.yaml"
}

# write_mirror <dir> <database> <redis> <whois host> <files prefix>
write_mirror() {
  local dir=$1 db=$2 redis=$3 host=$4 p=$5
  mkdir -p "$WORK/$dir"
  cat > "$WORK/$dir/irrd.yaml" <<EOF
irrd:
$(common_config "$db" "$redis")
  sources:
    UPA:
      nrtm_host: $host
      nrtm_port: 8043
      import_source: http://files/${p}exports/upa.db.gz
      import_serial_source: http://files/${p}exports/UPA.CURRENTSERIAL
      import_timer: 5
      keep_journal: true
    UPB:
      nrtm4_client_notification_file_url: https://files/${p}nrtm4/UPB/update-notification-file.jose
      nrtm4_client_initial_public_key: |
$(printf '%s\n' "$PUB_A" | indent)
      import_timer: 5
    UPC:
      import_source:
        - ftp://files/${p}exports-unfiltered/upc.db.gz
      import_serial_source: ftp://files/${p}exports-unfiltered/UPC.CURRENTSERIAL
      import_timer: 5
      object_class_filter: [route, route6, aut-num, as-set, mntner]
    UPD:
      import_source: file:///exports/upd.db.gz
      import_serial_source: file:///exports/UPD.CURRENTSERIAL
      import_timer: 5
EOF
}

psql() { "${DC[@]}" exec -T postgres psql -U irrd -d "$1" -Atc "$2"; }
v4up() { "${DC[@]}" exec -T upstream "$@"; }
ngup() { "${DC[@]}" exec -T ng-upstream /irrd-ng "$@"; }

export_upstreams() {
  for s in "$@"; do
    v4up /opt/irrd/bin/python -c "
import pydantic.main
from irrd.conf import config_init
config_init('/etc/irrd/irrd.yaml')
from irrd.mirroring.mirror_runners_export import SourceExportRunner
SourceExportRunner('$s').run()" >/dev/null
    ngup run-export --config /etc/irrd/irrd.yaml --source "$s" >/dev/null
  done
}

# One round of changes (parity/mirror/data.py), applied to both upstreams
# with at most one modification or deletion per irrd_update_database run
# (split_changes.py), so the journals do not depend on orders v4 leaves to
# chance.
update_upstreams() {
  local round=$1 s n i; shift
  for s in "$@"; do
    cp "$WORK/data/$s.db" "$WORK/data/$s.old"
    python3 "$HERE/data.py" change "$WORK/data/$s.db" "$WORK/data/$s.pool" "$round" --delete-rate 0.004 --modify-rate 0.008 >&2
    n=$(python3 "$HERE/split_changes.py" "$WORK/data/$s.old" "$WORK/data/$s.db" "$WORK/data/$s.step")
    for i in $(seq 0 $((n - 1))); do
      v4up irrd_update_database --config /etc/irrd/irrd.yaml --source "$s" "/data/$s.step.$i" >> "$WORK/logs/update-v4.log" 2>&1
      ngup irrd_update_database --config /etc/irrd/irrd.yaml --source "$s" "/data/$s.step.$i" >> "$WORK/logs/update-ng.log" 2>&1
    done
  done
}

ng_status_json() {
  ngup export-jsonl --config /etc/irrd/irrd.yaml --table database_status
}

# What each v4 mirror should reach from its upstream.
expected_v4() {
  local a b
  a=$(psql upstream "select serial_newest_seen from database_status where source='UPA'")
  b=$(psql upstream "select nrtm4_server_session_id || ':' || nrtm4_server_version from database_status where source='UPB'")
  printf 'UPA=%s UPB=%s UPC=%s UPD=%s' "$a" "$b" \
    "$(cat "$WORK/srv/exports-unfiltered/UPC.CURRENTSERIAL" 2>/dev/null || echo none)" \
    "$(cat "$WORK/srv/exports/UPD.CURRENTSERIAL" 2>/dev/null || echo none)"
}

expected_ng() {
  ng_status_json | python3 -c '
import json, sys
st = {r["source"]: r for r in map(json.loads, sys.stdin)}
a = st.get("UPA", {}).get("serial_newest_seen")
b = st.get("UPB", {})
print("UPA=%s UPB=%s:%s" % (a, b.get("nrtm4_server_session_id"), b.get("nrtm4_server_version")), end="")'
  printf ' UPC=%s UPD=%s' \
    "$(cat "$WORK/srv/ng/exports-unfiltered/UPC.CURRENTSERIAL" 2>/dev/null || echo none)" \
    "$(cat "$WORK/srv/ng/exports/UPD.CURRENTSERIAL" 2>/dev/null || echo none)"
}

mirror_state() {
  psql "$1" "select string_agg(source || '=' || case when source = 'UPB' then coalesce(nrtm4_client_session_id::text, '') || ':' || coalesce(nrtm4_client_version::text, '') else coalesce(serial_newest_mirror::text, '') end || case when force_reload then '*' else '' end, ' ' order by source) from database_status where source in ('UPA','UPB','UPC','UPD')"
}

wait_synced() {
  local w4 wng s4 sng
  for _ in $(seq 1 90); do
    w4=$(expected_v4); wng=$(expected_ng)
    s4=$(mirror_state mirror); sng=$(mirror_state mirrorng)
    if [[ $s4 == "$w4" && $sng == "$wng" ]]; then
      log "synced: v4 mirror [$s4], mirror of irrd-ng [$sng]"
      return 0
    fi
    sleep 2
  done
  log "NOT synced after 180s: v4 mirror want [$w4] have [$s4]; mirror of irrd-ng want [$wng] have [$sng]"
  RESULTS+=("FAIL  sync  mirrors did not catch up"); FAILED=1
  return 1
}

v4_export() {
  docker run --rm --network "$NET" --user root --entrypoint /opt/irrd/bin/python \
    -v "$ROOT/parity/tools:/tools:ro" -v "$2:/out" "$V4_IMAGE" \
    /tools/export_v4.py "postgresql://irrd:irrd@postgres/$1" /out >/dev/null
}

check() {
  local step=$1 what=$2 out=$3; shift 3
  if "$@" > "$out" 2>&1; then
    RESULTS+=("PASS  $step  $what")
    log "PASS $step $what"
  else
    RESULTS+=("FAIL  $step  $what (see $out)")
    FAILED=1
    log "FAIL $step $what"; head -30 "$out" >&2
  fi
}

# The NRTMv3 corpus bindings: each journal-keeping source's range.
nrtm_bindings() {
  psql upstream "select coalesce(json_agg(json_build_object('source', source, 'oldest', serial_oldest_journal, 'newest', serial_newest_journal, 'mid', (serial_oldest_journal + serial_newest_journal) / 2, 'next', serial_newest_journal + 1, 'after', serial_newest_journal + 2, 'before', serial_oldest_journal - 1) order by source), '[]') from database_status where serial_newest_journal is not null" \
    | python3 -c 'import json,sys; print(json.dumps({"nrtm": json.load(sys.stdin) or []}))'
}

compare_nrtm4() {
  local i
  for i in $(seq 1 10); do
    if python3 "$ROOT/parity/tools/compare_nrtm4.py" "$WORK/srv/nrtm4/UPB" "$WORK/srv/ng/nrtm4/UPB" \
        --label-left v4 --label-right irrd-ng; then
      return 0
    fi
    sleep 2
  done
  return 1
}

compare() {
  local step=$1 out="$WORK/compare/$1"
  rm -rf "$out"; mkdir -p "$out"/{m4,mng,up4,upng} "$WORK/ng-out/$step"

  # The two v4 mirrors.
  v4_export mirror "$out/m4"
  v4_export mirrorng "$out/mng"
  rm -f "$out"/m4/setting.jsonl "$out"/mng/setting.jsonl
  check "$step" "v4 mirror of v4 = v4 mirror of irrd-ng ($(wc -l < "$out/m4/rpsl_objects.jsonl") objects)" "$out/mirrors.txt" \
    python3 "$ROOT/parity/tools/compare_exports.py" "$out/m4" "$out/mng" \
      --exclude-file "$HERE/excluded-columns.tsv" --exclude-file "$HERE/serve-excluded-columns.tsv" \
      --label-left "mirror of v4" --label-right "mirror of irrd-ng"

  # The two upstreams.
  v4_export upstream "$out/up4"
  ngup export-jsonl --config /etc/irrd/irrd.yaml --table all --output-dir "/out/$step"
  cp -r "$WORK/ng-out/$step/." "$out/upng/"
  check "$step" "upstream objects, journal and status" "$out/upstreams.txt" \
    python3 "$ROOT/parity/tools/compare_exports.py" "$out/up4" "$out/upng" \
      --table rpsl_objects --table rpsl_database_journal --table database_status \
      --exclude-file "$HERE/excluded-columns.tsv" --exclude-file "$HERE/serve-excluded-columns.tsv" \
      --label-left v4 --label-right irrd-ng

  # Exports, byte for byte.
  check "$step" "exports byte-identical" "$out/exports.txt" \
    python3 "$ROOT/parity/tools/compare_gzip.py" "$WORK/srv/exports" "$WORK/srv/ng/exports" --label-left v4 --label-right irrd-ng
  check "$step" "unfiltered exports byte-identical" "$out/exports-unfiltered.txt" \
    python3 "$ROOT/parity/tools/compare_gzip.py" "$WORK/srv/exports-unfiltered" "$WORK/srv/ng/exports-unfiltered" --label-left v4 --label-right irrd-ng

  # NRTMv4 repositories; both servers run about every second, so give the
  # later one a moment to write its delta.
  local nrc=0
  compare_nrtm4 > "$out/nrtm4.txt" 2>&1 || nrc=1
  check "$step" "NRTMv4 repositories: $(tail -1 "$out/nrtm4.txt" | sed 's/^.*: //')" "$out/nrtm4.check" test "$nrc" = 0

  # NRTMv3 and friends over whois.
  nrtm_bindings > "$out/bindings.json"
  python3 "$ROOT/parity/tools/corpus_expand.py" --bindings "$out/bindings.json" --scale 4 \
    --out "$out/nrtm.corpus" "$ROOT/parity/corpus/whois/nrtm.q" 2>/dev/null
  check "$step" "NRTMv3 whois corpus ($(cut -f1 "$out/nrtm.corpus" | sort -u | wc -l) items)" "$out/whois.txt" \
    python3 "$ROOT/parity/tools/whois_diff.py" --suite whois --corpus "$out/nrtm.corpus" \
      --ref 127.0.0.1:9643 --test 127.0.0.1:9646 --out "$out/whois" --jobs 2 --timeout 60
}

# Run a command on both upstreams and compare what it prints and its exit code.
same_output() {
  local step=$1 what=$2; shift 2
  local a b
  a=$(v4up "$@" 2>&1; echo "rc=$?")
  b=$("${DC[@]}" exec -T ng-upstream /irrd-ng "$@" 2>&1; echo "rc=$?")
  if [[ $a == "$b" ]]; then
    RESULTS+=("PASS  $step  $what")
  else
    RESULTS+=("FAIL  $step  $what differs"); FAILED=1
    printf 'v4:\n%s\nirrd-ng:\n%s\n' "$a" "$b" >&2
  fi
}

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
  if [[ -d $WORK ]]; then
    docker run --rm --user root --entrypoint sh -v "$WORK:/w" "$V4_IMAGE" -c 'rm -rf /w/* /w/.[!.]*' 2>/dev/null || true
    rm -rf "$WORK" 2>/dev/null || true
  fi
  mkdir -p "$WORK"/{data,overlay,ng-out,ng-up-store,irrd-ng-image,compare,logs,tls} \
    "$WORK"/srv/{exports,exports-unfiltered,nrtm4/UPB} "$WORK"/srv/ng/{exports,exports-unfiltered,nrtm4/UPB}
  chmod -R a+rwX "$WORK"
  docker run --rm --user "$(id -u)" --entrypoint /opt/irrd/bin/python -v "$HERE:/harness:ro" \
    -v "$WORK/tls:/tls" "$V4_IMAGE" /harness/make_cert.py /tls
  chmod a+r "$WORK"/tls/*
  trap cleanup EXIT

  cp "$BIN" "$WORK/irrd-ng-image/irrd-ng"
  cp "$HERE/irrd-ng.Dockerfile" "$WORK/irrd-ng-image/Dockerfile"
  python3 "$HERE/data.py" initial "$DUMP" "$WORK/data" "${SOURCES[@]}" --per-source 1500
  write_upstream upstream upstream redis-up "$KEY_A"
  write_upstream ng-upstream upstream redis-up "$KEY_A"
  write_mirror mirror-v4 mirror redis-mirror upstream ""
  write_mirror mirror-ng-v4 mirrorng redis-mirror-ng ng-upstream "ng/"

  log "starting the upstreams"
  "${DC[@]}" build irrd-ng >/dev/null
  "${DC[@]}" up -d --wait postgres redis-up redis-mirror redis-mirror-ng files >/dev/null
  psql upstream "create database mirrorng owner irrd" >/dev/null
  "${DC[@]}" up -d upstream ng-upstream >/dev/null
  for port in 9643 9646; do
    for _ in $(seq 1 60); do
      "$ROOT/parity/whois.sh" 127.0.0.1 "$port" '!v' 2>/dev/null | grep -q '4.5.4' && break
      sleep 2
    done
  done
  for s in "${SOURCES[@]}"; do
    v4up irrd_load_database --config /etc/irrd/irrd.yaml --source "$s" --serial 1000 "/data/$s.db" >&2
    ngup irrd_load_database --config /etc/irrd/irrd.yaml --source "$s" --serial 1000 "/data/$s.db" >&2
  done
  export_upstreams UPA UPC UPD
  for d in "$WORK/srv/nrtm4/UPB" "$WORK/srv/ng/nrtm4/UPB"; do
    for _ in $(seq 1 60); do [[ -f $d/update-notification-file.jose ]] && break; sleep 1; done
  done

  log "step 01: initial load, both mirrors follow"
  "${DC[@]}" up -d mirror-v4 mirror-ng-v4 >/dev/null
  wait_synced || true
  compare 01-initial

  log "step 02: changes everywhere"
  update_upstreams 1 "${SOURCES[@]}"
  export_upstreams UPA UPC UPD
  wait_synced || true
  compare 02-changes

  log "step 03: force reload of UPA and UPB on both mirrors"
  for m in mirror-v4 mirror-ng-v4; do
    "${DC[@]}" exec -T "$m" irrd_mirror_force_reload --config /etc/irrd/irrd.yaml UPA >/dev/null 2>&1
    "${DC[@]}" exec -T "$m" irrd_mirror_force_reload --config /etc/irrd/irrd.yaml UPB >/dev/null 2>&1
  done
  sleep 1
  update_upstreams 2 UPA UPB
  export_upstreams UPA
  wait_synced || true
  compare 03-force-reload

  log "step 04: NRTMv4 key rotation announced on both upstreams"
  write_upstream upstream upstream redis-up "$KEY_A" "$KEY_B"
  write_upstream ng-upstream upstream redis-up "$KEY_A" "$KEY_B"
  "${DC[@]}" kill -s HUP upstream ng-upstream >/dev/null
  sleep 3
  same_output 04-rotation "irrdctl nrtm4 server-show-public-key" \
    irrdctl --config /etc/irrd/irrd.yaml nrtm4 server-show-public-key UPB
  update_upstreams 3 UPB
  wait_synced || true
  compare 04-rotation-announced

  log "step 05: NRTMv4 key rotated on both upstreams"
  write_upstream upstream upstream redis-up "$KEY_B"
  write_upstream ng-upstream upstream redis-up "$KEY_B"
  "${DC[@]}" kill -s HUP upstream ng-upstream >/dev/null
  sleep 3
  update_upstreams 4 UPB
  wait_synced || true
  compare 05-rotated

  local r
  for r in $(seq 1 "$ROUNDS"); do
    log "step churn-$r: a round of changes everywhere"
    update_upstreams $((10 + r)) "${SOURCES[@]}"
    export_upstreams UPA UPC UPD
    wait_synced || true
    compare "$(printf '06-churn-%02d' "$r")"
  done

  log "step 07: tools"
  same_output 07-tools "irrd_expire_journal, nothing to expire" \
    irrd_expire_journal --config /etc/irrd/irrd.yaml --source UPA --expire-before 2000-01-01 \
    --delete-this-history-irrevocably-without-confirmation
  same_output 07-tools "irrd_expire_journal, too recent" \
    irrd_expire_journal --config /etc/irrd/irrd.yaml --source UPA --expire-before 2999-01-01
  same_output 07-tools "irrd_expire_journal, bad date" \
    irrd_expire_journal --config /etc/irrd/irrd.yaml --source UPA --expire-before 2026-02-30

  "${DC[@]}" logs --no-color mirror-v4 > "$WORK/logs/mirror-v4.log" 2>&1 || true
  "${DC[@]}" logs --no-color mirror-ng-v4 > "$WORK/logs/mirror-ng-v4.log" 2>&1 || true
  "${DC[@]}" logs --no-color upstream > "$WORK/logs/upstream.log" 2>&1 || true
  "${DC[@]}" logs --no-color ng-upstream > "$WORK/logs/ng-upstream.log" 2>&1 || true
  printf '\n%s\n' "${RESULTS[@]}"
  return $FAILED
}

main "$@"
