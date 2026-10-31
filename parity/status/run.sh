#!/usr/bin/env bash
# Status suite: RPKI, scope filter and route preference, side by side.
#
#   parity/status/run.sh [--keep-going] [--queries]
#
# Loads the Tier 1 fixtures plus two synthetic sources (data/) into the
# pinned v4 with v4's own mirror import, copies that database into an
# irrd-ng store with `irrd-ng import`, and then takes both through the same
# steps: ROA imports (churned ROAs, a duplicate across trust anchors, SLURM),
# scope filter changes, route preference changes, and an
# irrd_update_database run that triggers route preference re-evaluation
# before commit. v4 runs each job through its own runner classes
# (ROAImportRunner, ScopeFilterUpdateRunner, RoutePreferenceUpdateRunner)
# in a one-off container; irrd-ng through `irrd-ng run-job`. After every
# step both databases are exported (tools/export_v4.py, irrd-ng
# export-jsonl) and compared (compare_status.py: every table, journal
# included), and the notification mails both sent are compared
# (mails.py, captured by Mailpit).
#
# --queries: afterwards, start both servers on the final state and run the
# whois and /v1/whois/ suites (parity/run.sh), whose answers then depend on
# all three statuses and the !f overrides.
#
# Uses the shared Tier 1 stack (compose.yaml): it replaces whatever
# parity/load.sh loaded, so run load.sh again before parity/run.sh.
# Env: PARITY_CACHE (fixtures), IRRD_NG (binary), PARITY_SMTP_PORT (Mailpit
# SMTP on the host, default 9026). Results: parity/out/status-<stamp>/.
set -euo pipefail
cd "$(dirname "$0")/.."
parity=$PWD
repo=$(cd .. && pwd)
export PARITY_CACHE=${PARITY_CACHE:-$parity/.cache}
IRRD_NG=${IRRD_NG:-$repo/target/release/irrd-ng}
work=${PARITY_WORK:-$parity/.work}/status
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=$parity/out/status-$stamp
keep_going=0 queries=0
while [[ $# -gt 0 ]]; do
  case $1 in
    --keep-going) keep_going=1; shift ;;
    --queries) queries=1; shift ;;
    -h|--help) sed -n '2,29p' "$0"; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done

fixtures=("$PARITY_CACHE"/fixtures/*.db)
[[ -e ${fixtures[0]} ]] || { echo "no fixtures in $PARITY_CACHE/fixtures" >&2; exit 2; }
[[ -x $IRRD_NG ]] || { echo "no irrd-ng binary at $IRRD_NG" >&2; exit 2; }

rm -rf "$work"
mkdir -p "$work/run" "$work/gnupg" "$out"
cp status/data/*.db status/slurm.json "$work/"
export PARITY_V4_CONFIG=$work/irrd-v4.yaml PARITY_TIER1_WORK=$work
export IRRD_NG_STORE_PATH=$work/store

step_config() { python3 -I status/config.py "$work" "$1"; }
DC=(docker compose)
v4run() {
  "${DC[@]}" run --rm -T --no-deps -v "$parity/tools:/tools:ro" -v "$out:/out" \
    --entrypoint "$1" irrd-v4 "${@:2}"
}
v4job() {
  v4run python3 -c "
import logging, sys
logging.basicConfig(level=logging.INFO, stream=sys.stdout, format='%(levelname)s %(name)s: %(message)s')
from irrd.conf import config_init
config_init('/etc/irrd/irrd.yaml')
from irrd.mirroring.mirror_runners_import import $1
$1().run()
"
}
ng() { "$IRRD_NG" "$@"; }
ngjob() { ng run-job --config "$work/irrd-ng.yaml" "$1"; }

# ---- ROA files ----
python3 -I tools/make_roas.py "${fixtures[@]}" corpus/whois/data/*.db \
  > "$work/roas-gen.json" 2> /dev/null
python3 -I -c '
import json, sys
a = json.load(open(sys.argv[1]))["roas"] + json.load(open(sys.argv[2]))["roas"]
json.dump({"roas": a}, open(sys.argv[3], "w"))' "$work/roas-gen.json" corpus/whois/data/roas-static.json "$work/roas-base.json"
python3 -I status/roas.py base "$work/roas-base.json" > "$work/roas1.json"
python3 -I status/roas.py mutate "$work/roas-base.json" > "$work/roas2.json"
python3 -I status/roas.py dup "$work/roas2.json" > "$work/roas-dup.json"

# ---- load ----
step_config '{"load": true, "roas": "roas1.json"}'
./up.sh > /dev/null
"${DC[@]}" stop irrd-v4 > /dev/null 2>&1
"${DC[@]}" exec -T postgres psql -q -U irrd -d irrd -c \
  "TRUNCATE rpsl_objects, rpsl_database_journal, database_status, roa_object, rpsl_objects_suspended CASCADE" > /dev/null
curl -s -X DELETE http://127.0.0.1:9025/api/v1/messages > /dev/null

serial=100000 spec=()
for f in "${fixtures[@]}"; do
  serial=$((serial + 11111)); spec+=("$(basename "$f" .db)=$serial=/cache/fixtures/$(basename "$f")")
done
serial=$((serial + 11111)); spec+=("EDGE96=$serial=/tier1/EDGE96.db")
cp corpus/whois/data/EDGE96.db "$work/"
for s in STATUSAUTH STATUSLOW; do
  serial=$((serial + 11111)); spec+=("$s=$serial=/tier1/$s.db")
done
echo "== load: v4 mirror import of ${#spec[@]} sources, then irrd-ng import"
v4run python3 - /etc/irrd/irrd.yaml "${spec[@]}" < tools/v4_mirror_load.py > "$out/v4-load.log" 2>&1 \
  || { tail -20 "$out/v4-load.log" >&2; exit 1; }
ng import --from-postgres "postgresql://irrd:irrd@127.0.0.1:${PARITY_PG_PORT:-9532}/irrd?sslmode=disable" \
  --store "$work/store" > "$out/ng-import.log" 2>&1 || { tail -20 "$out/ng-import.log" >&2; exit 1; }

failed=0
compare_step() {
  local name=$1 d=$out/$1
  mkdir -p "$d/v4" "$d/ng"
  chmod a+rwx "$d/v4"  # the v4 container writes as its own user
  v4run python3 /tools/export_v4.py postgresql://irrd:irrd@postgres/irrd "/out/$name/v4" > /dev/null
  ng export-jsonl --config "$work/irrd-ng.yaml" --table all --output-dir "$d/ng" > /dev/null
  echo "== $name"
  local ok=1
  python3 -I status/compare_status.py "$d/v4" "$d/ng" --exclude-file status/excluded-columns.tsv \
    | tee "$d/compare.txt" | sed 's/^/  /' || ok=0
  if [[ -f $d/v4-mails.json ]]; then
    python3 -I status/mails.py compare "$d/v4-mails.json" "$d/ng-mails.json" | sed 's/^/  /' || ok=0
  fi
  if [[ $ok == 0 ]]; then
    failed=1
    [[ $keep_going == 1 ]] || { echo "step $name differs; stopping (results in $d)"; exit 1; }
  fi
}
# Run the same job on both, capturing logs and mails.
both() {
  local name=$1 v4cmd=$2 ngcmd=$3
  mkdir -p "$out/$name"
  eval "$v4cmd" > "$out/$name/v4.log" 2>&1 || true
  python3 -I status/mails.py dump "$out/$name/v4-mails.json" > /dev/null
  eval "$ngcmd" > "$out/$name/ng.log" 2>&1 || true
  python3 -I status/mails.py dump "$out/$name/ng-mails.json" > /dev/null
  compare_step "$name"
}

compare_step 00-load

step_config '{"roas": "roas1.json"}'
both 01-roa-import 'v4job ROAImportRunner' 'ngjob roa-import'

step_config '{"roas": "roas2.json"}'
both 02-roa-churn 'v4job ROAImportRunner' 'ngjob roa-import'

# v4 fails on a ROA repeated under another trust anchor and keeps the
# previous state; so must irrd-ng.
step_config '{"roas": "roas-dup.json"}'
both 03-roa-duplicate 'v4job ROAImportRunner' 'ngjob roa-import'
for side in v4 ng; do
  grep -q 'rpsl_objects_rpsl_pk_source_class_unique' "$out/03-roa-duplicate/$side.log" \
    || { echo "  $side did not report the duplicate ROA"; failed=1; }
done

step_config '{"roas": "roas2.json", "slurm": "slurm.json"}'
both 04-slurm 'v4job ROAImportRunner' 'ngjob roa-import'

SF1='"scopefilter": {"prefixes": ["10.0.0.0/8", "100.64.0.0/10", "2001:db8:1::/48", "5.0.0.0/8"], "asns": [23456, "64496-64511", "4200000000-4294967295"]}'
step_config "{\"roas\": \"roas2.json\", \"slurm\": \"slurm.json\", $SF1}"
both 05-scopefilter 'v4job ScopeFilterUpdateRunner' 'ngjob scopefilter'

SF2='"scopefilter": {"prefixes": ["100.64.0.0/10", "2a00::/12", "45.0.0.0/8"], "asns": [23456, "64496-64511", "65010"]}, "scopefilter_excluded": ["RADB"]'
step_config "{\"roas\": \"roas2.json\", \"slurm\": \"slurm.json\", $SF2}"
both 06-scopefilter-change 'v4job ScopeFilterUpdateRunner' 'ngjob scopefilter'

P1='"preferences": {"STATUSAUTH": 900, "RADB": 500, "ALTDB": 300, "STATUSLOW": 100, "NTTCOM": 100}'
step_config "{\"roas\": \"roas2.json\", \"slurm\": \"slurm.json\", $SF2, $P1}"
both 07-routepref 'v4job RoutePreferenceUpdateRunner' 'ngjob route-preference'

P2='"preferences": {"STATUSLOW": 950, "STATUSAUTH": 300, "RADB": 200, "NTTCOM": 600, "APNIC": 0}'
step_config "{\"roas\": \"roas2.json\", \"slurm\": \"slurm.json\", $SF2, $P2}"
both 08-routepref-change 'v4job RoutePreferenceUpdateRunner' 'ngjob route-preference'

# A loader writing route objects: route preference is re-evaluated for the
# changed prefixes before commit.
both 09-update-hook \
  'v4run irrd_update_database --config /etc/irrd/irrd.yaml --source STATUSLOW /tier1/STATUSLOW-update.db' \
  'ng irrd_update_database --config "$work/irrd-ng.yaml" --source STATUSLOW "$work/STATUSLOW-update.db"'

# RPKI changes with scope filter and route preference active: journal
# entries depend on all three statuses, and route preference runs again
# for the prefixes whose visibility changed.
step_config "{\"roas\": \"roas1.json\", $SF2, $P2}"
both 10-roa-with-filters 'v4job ROAImportRunner' 'ngjob roa-import'

echo "results in $out"
if [[ $queries == 1 ]]; then
  echo "== whois and /v1/whois/ suites on the final state"
  python3 -I tools/corpus_bindings.py --out "$work/bindings.json" "${fixtures[@]}" corpus/whois/data/*.db \
    status/data/STATUSAUTH.db "$work/STATUSLOW-update.db" > /dev/null
  "${DC[@]}" up -d irrd-v4 > /dev/null
  ./up.sh > /dev/null
  IRRD_NG_STORE_PATH=$work/store nohup "$IRRD_NG" irrd --config "$work/irrd-ng.yaml" --foreground \
    > "$out/irrd-ng.log" 2>&1 &
  ngpid=$!
  for _ in $(seq 1 60); do
    [[ $(./whois.sh 127.0.0.1 "${NG_WHOIS_PORT:-8043}" '!v' 2>/dev/null) == A* ]] && break
    sleep 1
  done
  ./run.sh --suite all --test "127.0.0.1:${NG_WHOIS_PORT:-8043}" --http-test "127.0.0.1:${NG_HTTP_PORT:-8080}" \
    --bindings "$work/bindings.json" --out "$out/queries" || failed=1
  kill "$ngpid" 2>/dev/null || true
fi
exit $failed
