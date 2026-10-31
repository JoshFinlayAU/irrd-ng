#!/usr/bin/env bash
# Status suite at full scale, on the parity VM: v4 4.5.4 and irrd-ng take
# the restored reference data through the same ROA import, scope filter and
# route preference changes, and every object's statuses, the journal
# entries the transitions produce, the ROAs and database_status are
# compared after each step (compact.py).
#
#   status/tier2.sh run|restore
#
# Works on the Tier 2 copies (tier2/README.md): v4 on the database
# $TIER2_V4_DB (a template copy of the reference) and irrd-ng on the store
# $TIER2_NG_STORE (imported from the reference). Both are changed by the
# run; `restore` puts them back (the v4 copy recreated from the template,
# the store re-imported, both only reading the reference) and restarts the
# Tier 2 irrd-ng if it was running. The reference database is only read.
#
# Sources keep a journal here (RADB, RIPE and APNIC are made authoritative)
# so status transitions are journalled; notify_invalid_enabled is false, so
# no mail is sent. Nothing leaves the VM: reports hold counts, keys of the
# first differing rows at most, and md5 sums.
#
# Env: TIER2_DIR (default /srv/irrd-ng/tier2), TIER2_PG_CONTAINER (required),
# TIER2_REF_DB (default irrd), TIER2_V4_DB (default irrd_v4),
# TIER2_NG_STORE (required), STATUS_DIR (work files, default
# /srv/irrd-ng/status), STATUS_NG_BIN (default $STATUS_DIR/bin/irrd-ng),
# STATUS_MEM (memory cap per job, default 6G).
set -euo pipefail
tier2=${TIER2_DIR:-/srv/irrd-ng/tier2}
pg=${TIER2_PG_CONTAINER:?set TIER2_PG_CONTAINER}
refdb=${TIER2_REF_DB:-irrd} v4db=${TIER2_V4_DB:-irrd_v4}
store=${TIER2_NG_STORE:?set TIER2_NG_STORE}
dir=${STATUS_DIR:-/srv/irrd-ng/status}
ngbin=${STATUS_NG_BIN:-$dir/bin/irrd-ng}
mem=${STATUS_MEM:-6G}
image=irrd-ng-parity/irrd-v4:4.5.4
redis_image=redis:8.0.2-alpine@sha256:48501c5ad00d5563bc30c075c7bcef41d7d98de3e9a1e6c752068c66f0a8463b
work=$dir/work
src=$(cd "$(dirname "$0")" && pwd)

psql_v4() { docker exec "$pg" psql -U irrd -d "$v4db" "$@"; }
capped() { systemd-run --scope -q -p MemoryMax="$mem" "$@"; }

config() { # roas, then the scope filter and preferences as JSON
  python3 -I - "$work/irrd.yaml" "$1" "$2" "$v4db" <<'PY'
import json, sys, yaml
out, roas, extra, db = sys.argv[1], sys.argv[2], json.loads(sys.argv[3]), sys.argv[4]
filt = ["as-set", "aut-num", "route-set", "route", "route6"]
sources = {
    "RADB": {"object_class_filter": filt, "authoritative": True, "keep_journal": True},
    "APNIC": {"authoritative": True, "keep_journal": True},
    "RIPE": {"authoritative": True, "keep_journal": True},
    "ARIN": {"object_class_filter": filt},
    "AFRINIC": {"object_class_filter": filt},
    "LACNIC": {"object_class_filter": filt},
}
for name in extra.get("scopefilter_excluded", []):
    sources[name]["scopefilter_excluded"] = True
for name, p in extra.get("preferences", {}).items():
    sources[name]["route_object_preference"] = p
irrd = {
    "database_url": f"postgresql://irrd:irrd@127.0.0.1:5432/{db}",
    "redis_url": "redis://127.0.0.1:9479",
    "piddir": "/tmp",
    "server": {"http": {"interface": "127.0.0.1", "port": 9180, "url": "http://localhost/"},
               "whois": {"interface": "127.0.0.1", "port": 9143}},
    "auth": {"gnupg_keyring": "/tmp/gnupg", "set_creation": {"COMMON": {"prefix_required": True}},
             "password_hashers": {"crypt-pw": "legacy", "md5-pw": "legacy", "bcrypt-pw": "enabled"}},
    "email": {"from": "irrd-tier2@parity.invalid", "smtp": "127.0.0.1:1"},
    "rpki": {"roa_source": f"file://{roas}", "roa_import_timer": 99999999999,
             "notify_invalid_enabled": False},
    "route_object_preference": {"update_timer": 99999999999},
    "log": {"level": "INFO"},
    "sources_default": ["RPKI", "RADB", "APNIC", "RIPE", "ARIN", "AFRINIC", "LACNIC"],
    "sources": sources,
}
if extra.get("scopefilter"):
    irrd["scopefilter"] = extra["scopefilter"]
open(out, "w").write(yaml.safe_dump({"irrd": irrd}, sort_keys=False))
PY
  chmod 644 "$work/irrd.yaml"
}

v4job() {
  docker run --rm --network host --memory "$mem" -v "$work:$work" -v "$work/irrd.yaml:/etc/irrd/irrd.yaml:ro" \
    --entrypoint python3 "$image" -c "
import logging, sys
logging.basicConfig(level=logging.INFO, stream=sys.stdout, format='%(levelname)s %(name)s: %(message)s')
from irrd.conf import config_init
config_init('/etc/irrd/irrd.yaml')
from irrd.mirroring.mirror_runners_import import $1
$1().run()
"
}
ngjob() { IRRD_NG_STORE_PATH=$store capped "$ngbin" run-job --config "$work/irrd.yaml" "$1"; }

snapshot() { # step
  local d=$work/$1
  rm -rf "$work"/[0-9]*/v4 "$work"/[0-9]*/ng
  mkdir -p "$d/v4" "$d/ng"
  for t in objects journal roas status; do
    psql_v4 -q -c "$(python3 -I "$src/compact.py" sql "$t")" > "$d/v4/$t.tsv"
  done
  for t in objects:rpsl_objects journal:rpsl_database_journal roas:roa_object status:database_status; do
    IRRD_NG_STORE_PATH=$store "$ngbin" export-jsonl --config "$work/irrd.yaml" --table "${t#*:}" \
      | python3 -I "$src/compact.py" ng "${t%%:*}" > "$d/ng/${t%%:*}.tsv"
  done
  echo "== $1"
  python3 -I "$src/compact.py" compare "$d/v4" "$d/ng" | tee "$d/compare.txt" | sed 's/^/  /' || failed=1
}

step() { # name, v4 runner, irrd-ng job
  mkdir -p "$work/$1"
  local t0=$SECONDS
  v4job "$2" > "$work/$1/v4.log" 2>&1 || true
  local t1=$SECONDS
  ngjob "$3" > "$work/$1/ng.log" 2>&1 || true
  local t2=$SECONDS
  echo "$1: v4 $((t1 - t0))s, irrd-ng $((t2 - t1))s" | tee "$work/$1/timing.txt"
  snapshot "$1"
}

run() {
  mkdir -p "$work"
  if [[ -f $tier2/run/ng/pid ]] && kill -0 "$(cat "$tier2/run/ng/pid")" 2>/dev/null; then
    echo "stopping the Tier 2 irrd-ng (restore starts it again)"
    kill "$(cat "$tier2/run/ng/pid")"; touch "$work/restart-ng"
    while kill -0 "$(cat "$tier2/run/ng/pid")" 2>/dev/null; do sleep 1; done
  fi
  echo "in use by the status suite since $(date -u +%FT%TZ); status/tier2.sh restore puts it back" > "$tier2/IN-USE-STATUS-SUITE"
  docker rm -f status-redis > /dev/null 2>&1 || true
  docker run -d --name status-redis -p 127.0.0.1:9479:6379 "$redis_image" > /dev/null

  echo "== ROAs from $v4db"
  psql_v4 -Atq -c "COPY (SELECT 'AS' || asn, prefix, max_length, trust_anchor FROM roa_object ORDER BY ip_version, prefix, asn, max_length, trust_anchor) TO STDOUT" \
    | python3 -I -c '
import json, sys
roas = []
for line in sys.stdin:
    a, p, m, t = line.rstrip("\n").split("\t")
    roas.append({"asn": a, "prefix": p, "maxLength": int(m), "ta": t})
json.dump({"roas": roas}, open(sys.argv[1], "w"))
print(len(roas), "ROAs")' "$work/roas-base.json"
  python3 -I "$src/roas.py" mutate "$work/roas-base.json" > "$work/roas-churn.json"

  failed=0
  config "$work/roas-churn.json" '{}'
  snapshot 00-start
  step 01-roa-churn ROAImportRunner roa-import
  SF='"scopefilter": {"prefixes": ["10.0.0.0/8", "100.64.0.0/10", "1.0.0.0/8", "fc00::/7", "2001:db8::/32", "2a00::/12"], "asns": [23456, "64496-131071", "4200000000-4294967295"]}, "scopefilter_excluded": ["ARIN"]'
  config "$work/roas-churn.json" "{$SF}"
  step 02-scopefilter ScopeFilterUpdateRunner scopefilter
  PREF='"preferences": {"RADB": 300, "RIPE": 800, "APNIC": 700, "ARIN": 500, "AFRINIC": 400, "LACNIC": 600}'
  config "$work/roas-churn.json" "{$SF, $PREF}"
  step 03-routepref RoutePreferenceUpdateRunner route-preference
  config "$work/roas-base.json" "{$SF, $PREF}"
  step 04-roa-back-with-filters ROAImportRunner roa-import
  docker rm -f status-redis > /dev/null 2>&1 || true
  echo "reports in $work/*/compare.txt"
  return $failed
}

restore() {
  echo "== restore: $v4db from the template $refdb, the store by re-import from $refdb"
  docker rm -f status-redis > /dev/null 2>&1 || true
  docker exec "$pg" psql -U irrd -d postgres -c "DROP DATABASE IF EXISTS $v4db" \
    -c "CREATE DATABASE $v4db TEMPLATE $refdb"
  capped "$ngbin" import --from-postgres "postgresql://irrd:irrd@127.0.0.1:5432/$refdb?sslmode=disable" \
    --store "$store" > "$work/restore-import.log" 2>&1 || { tail -5 "$work/restore-import.log"; exit 1; }
  tail -1 "$work/restore-import.log"
  rm -f "$tier2/IN-USE-STATUS-SUITE"
  if [[ -f $work/restart-ng ]]; then
    TIER2_NG_BIN=$tier2/bin/irrd-ng TIER2_NG_STORE=$store "$tier2/tier2/setup.sh" start-ng
    rm -f "$work/restart-ng"
  fi
}

case ${1:-} in
  run) run ;;
  restore) restore ;;
  *) echo "usage: status/tier2.sh run|restore" >&2; exit 2 ;;
esac
