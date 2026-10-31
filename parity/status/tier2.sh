#!/usr/bin/env bash
# Status parity at full scale, on the parity VM, without writing anything.
#
#   status/tier2.sh
#
# The reference database is a copy of production that may only be read,
# and the VM has no room for a writable copy of it, so this compares what
# each job would change instead of running it: v4's own validators on a
# read-only connection to the reference (v4_dryrun.py, in the v4 image) and
# `irrd-ng run-job --dry-run` on the Tier 2 store (imported from the same
# reference, opened read-only). Each prints one line per changed object (row
# UUID, new status, journal operation) and, for the ROA import, one line per
# RPKI pseudo-IRR object (key, sha256 of its text, scope filter status,
# addresses); the sorted outputs must be equal. Tier 1 (status/run.sh)
# checks that applying the same changes writes the same rows and journal.
#
# Scenarios: the reference's own ROAs (nothing may change, and the
# pseudo-IRR objects must come out as the reference has them), a churned
# ROA set (roas.py), a scope filter, and route preferences on every source.
#
# Env: TIER2_PG_CONTAINER (required), TIER2_REF_DB (default irrd),
# TIER2_NG_STORE (required), STATUS_DIR (default /srv/irrd-ng/status),
# STATUS_NG_BIN (default $STATUS_DIR/bin/irrd-ng), STATUS_MEM (memory cap
# per process, default 6G). Reports stay in $STATUS_DIR/work: counts, and at
# most the first few differing lines (row UUIDs and ROA keys, no object
# text).
set -euo pipefail
pg=${TIER2_PG_CONTAINER:?set TIER2_PG_CONTAINER}
refdb=${TIER2_REF_DB:-irrd}
store=${TIER2_NG_STORE:?set TIER2_NG_STORE}
dir=${STATUS_DIR:-/srv/irrd-ng/status}
ngbin=${STATUS_NG_BIN:-$dir/bin/irrd-ng}
mem=${STATUS_MEM:-6G}
image=irrd-ng-parity/irrd-v4:4.5.4
work=$dir/work
src=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$work"

config() { # roa file, then the scope filter and preferences as JSON
  python3 -I - "$work/irrd.yaml" "$1" "$2" "$refdb" <<'PY'
import json, sys, yaml
out, roas, extra, db = sys.argv[1], sys.argv[2], json.loads(sys.argv[3]), sys.argv[4]
filt = ["as-set", "aut-num", "route-set", "route", "route6"]
# The reference's shape (tier2/irrd-tier2.yaml), with journals on three
# sources so the dry runs report journal operations for them too.
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
    "redis_url": "redis://127.0.0.1:1",
    "piddir": "/tmp",
    "readonly_standby": False,
    "server": {"http": {"interface": "127.0.0.1", "port": 9180, "url": "http://localhost/"},
               "whois": {"interface": "127.0.0.1", "port": 9143}},
    "auth": {"gnupg_keyring": "/tmp/gnupg", "set_creation": {"COMMON": {"prefix_required": True}},
             "password_hashers": {"crypt-pw": "legacy", "md5-pw": "legacy", "bcrypt-pw": "enabled"}},
    "email": {"from": "irrd-tier2@parity.invalid", "smtp": "127.0.0.1:1"},
    "rpki": {"roa_source": f"file://{roas}", "roa_import_timer": 99999999999,
             "notify_invalid_enabled": False},
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

enough_memory() {
  local avail
  avail=$(awk '/MemAvailable/ {print int($2 / 1048576)}' /proc/meminfo)
  if (( avail < 10 )); then echo "only ${avail} GB available; not starting" >&2; exit 1; fi
}

v4dry() { # job [files...]
  enough_memory
  docker run --rm --network host --memory "$mem" -v "$work:$work:ro" -v "$src/v4_dryrun.py:/v4_dryrun.py:ro" \
    -v "$work/irrd.yaml:/etc/irrd/irrd.yaml:ro" --entrypoint python3 "$image" /v4_dryrun.py /etc/irrd/irrd.yaml "$@"
}
ngdry() { # job
  enough_memory
  IRRD_NG_STORE_PATH=$store systemd-run --scope -q -p MemoryMax="$mem" \
    "$ngbin" run-job --dry-run --config "$work/irrd.yaml" "$1"
}

failed=0
scenario() { # name, v4 job, irrd-ng job, v4 args...
  local name=$1 d=$work/$1
  mkdir -p "$d"
  local t0=$SECONDS
  v4dry "$2" "${@:4}" 2> "$d/v4.err" | LC_ALL=C sort > "$d/v4.tsv" || true
  local t1=$SECONDS
  ngdry "$3" 2> "$d/ng.err" | LC_ALL=C sort > "$d/ng.tsv" || true
  local t2=$SECONDS
  {
    echo "== $name (v4 $((t1 - t0))s, irrd-ng $((t2 - t1))s)"
    for side in v4 ng; do
      printf '  %s: %s lines;' "$side" "$(wc -l < "$d/$side.tsv")"
      cut -f1,3,4 "$d/$side.tsv" | sort | uniq -c | awk '{printf " %s %s/%s/%s", $1, $2, $3, $4}'
      echo
    done
    if cmp -s "$d/v4.tsv" "$d/ng.tsv"; then
      echo "  identical"
    else
      echo "  DIFFER: $(comm -3 "$d/v4.tsv" "$d/ng.tsv" | wc -l) lines on one side only"
      comm -23 "$d/v4.tsv" "$d/ng.tsv" | head -5 | cut -f1-3 | sed 's/^/    v4 only: /'
      comm -13 "$d/v4.tsv" "$d/ng.tsv" | head -5 | cut -f1-3 | sed 's/^/    ng only: /'
      failed=1
    fi
  } | tee "$d/summary.txt"
}

echo "== ROAs from $refdb (read-only)"
docker exec "$pg" psql -U irrd -d "$refdb" -Atq -c "COPY (SELECT 'AS' || asn, prefix, max_length, trust_anchor FROM roa_object ORDER BY ip_version, prefix, asn, max_length, trust_anchor) TO STDOUT" \
  | python3 -I -c '
import json, sys
roas = []
for line in sys.stdin:
    a, p, m, t = line.rstrip("\n").split("\t")
    roas.append({"asn": a, "prefix": p, "maxLength": int(m), "ta": t})
json.dump({"roas": roas}, open(sys.argv[1], "w"))
print(len(roas), "ROAs")' "$work/roas-base.json"
python3 -I "$src/roas.py" mutate "$work/roas-base.json" > "$work/roas-churn.json"

config "$work/roas-base.json" '{}'
scenario 1-roa-reference roa roa-import "$work/roas-base.json"
config "$work/roas-churn.json" '{}'
scenario 2-roa-churn roa roa-import "$work/roas-churn.json"
SF='"scopefilter": {"prefixes": ["10.0.0.0/8", "100.64.0.0/10", "1.0.0.0/8", "fc00::/7", "2001:db8::/32", "2a00::/12"], "asns": [23456, "64496-131071", "4200000000-4294967295"]}, "scopefilter_excluded": ["ARIN"]'
config "$work/roas-churn.json" "{$SF}"
scenario 3-scopefilter scopefilter scopefilter
PREF='"preferences": {"RADB": 300, "RIPE": 800, "APNIC": 700, "ARIN": 500, "AFRINIC": 400, "LACNIC": 600}'
config "$work/roas-churn.json" "{$PREF}"
scenario 4-routepref routepref route-preference
echo "reports: $work/*/summary.txt"
exit $failed
