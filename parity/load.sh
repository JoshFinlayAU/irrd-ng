#!/usr/bin/env bash
# Load the same data into the v4 reference and into an irrd-ng store, for
# the whois and http suites (parity/run.sh).
#
#   parity/load.sh [--profile rpki|plain] [--ng import|none]
#
# Profiles: rpki (default) is v4/irrd-whois.yaml with rpki.roa_source set to
# synthetic ROAs (tools/make_roas.py over the fixtures, plus
# corpus/whois/data/roas-static.json), so answers carry rpki-ov-state lines,
# the RPKI pseudo-source exists and ROV filtering applies, as on a real
# mirror; plain is v4/irrd-whois.yaml unchanged (no RPKI).
#
# v4 side: switches the reference stack (parity/up.sh) to v4/irrd-whois.yaml
# and loads every Tier 1 fixture in $PARITY_CACHE/fixtures/ through v4's own
# mirror full-import runner (tools/v4_mirror_load.py), the way a public IRR
# mirror gets its data, with a fixed serial per source. Then restarts v4 so
# the preloaded route data is fresh.
#
# irrd-ng side (--ng, default import): `irrd-ng import --from-postgres` from
# v4's freshly loaded database, so both servers hold identical state down to
# serials and status timestamps (!j, !J) and only the query paths differ.
# (irrd-ng's own loader is checked against v4's by load-check.sh.)
#
# Also writes the corpus bindings for this data (tools/corpus_bindings.py).
# Everything lands in $PARITY_WORK/tier1 (default parity/.work/tier1).
#
# Env: PARITY_CACHE (dump cache, default parity/.cache), IRRD_NG (binary,
# default target/release/irrd-ng), PARITY_PG_PORT (v4's Postgres on the
# host, default 9532).
set -euo pipefail
cd "$(dirname "$0")"
parity=$PWD
repo=$(cd .. && pwd)
export PARITY_CACHE=${PARITY_CACHE:-$parity/.cache}
export PARITY_TIER1_WORK=${PARITY_WORK:-$parity/.work}/tier1
export PARITY_PG_PORT=${PARITY_PG_PORT:-9532}
IRRD_NG=${IRRD_NG:-$repo/target/release/irrd-ng}
work=${PARITY_WORK:-$parity/.work}/tier1
ng=import profile=rpki
while [[ $# -gt 0 ]]; do
  case $1 in
    --profile) profile=$2; shift 2 ;;
    --ng) ng=$2; shift 2 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done

fixtures=("$PARITY_CACHE"/fixtures/*.db)
[[ -e ${fixtures[0]} ]] || { echo "no fixtures in $PARITY_CACHE/fixtures (tools/cut_fixtures.py)" >&2; exit 2; }
mkdir -p "$work"
# The active v4 configuration for this load (ng.sh and run.sh use it too).
cp v4/irrd-whois.yaml "$work/irrd-v4.yaml"
if [[ $profile == rpki ]]; then
  python3 -I tools/make_roas.py "${fixtures[@]}" "$parity"/corpus/whois/data/*.db > "$work/roas-gen.json"
  python3 -I -c '
import json, sys
a = json.load(open(sys.argv[1]))["roas"] + json.load(open(sys.argv[2]))["roas"]
json.dump({"roas": a}, open(sys.argv[3], "w"))' "$work/roas-gen.json" corpus/whois/data/roas-static.json "$work/roas.json"
  python3 -I - "$work/irrd-v4.yaml" <<'PY'
import sys
p = sys.argv[1]
t = open(p).read()
# The import timer is past the Unix time so v4's scheduler never re-imports
# on its own (mid-run churn); load.sh runs the one import itself.
t = t.replace("  rpki:\n    roa_source: null\n", "  rpki:\n    roa_source: file:///tier1/roas.json\n    roa_import_timer: 99999999999\n    notify_invalid_enabled: false\n")
open(p, "w").write(t)
PY
  grep -q 'file:///tier1/roas.json' "$work/irrd-v4.yaml" || { echo "could not enable rpki in the config" >&2; exit 1; }
elif [[ $profile != plain ]]; then
  echo "--profile rpki|plain" >&2; exit 2
fi
echo "$profile" > "$work/profile"
export PARITY_V4_CONFIG=$work/irrd-v4.yaml

echo "== v4: reference stack with v4/irrd-whois.yaml"
./up.sh > /dev/null
v4() { docker compose exec -T irrd-v4 "$@"; }
# A clean database: drop every source the previous load left behind.
docker compose exec -T postgres psql -q -U irrd -d irrd -c \
  "TRUNCATE rpsl_objects, rpsl_database_journal, database_status, roa_object, rpsl_objects_suspended" 2>/dev/null || true

serial=100000
spec=()
: > "$work/v4-load.tsv"
for f in "${fixtures[@]}"; do
  src=$(basename "$f" .db)
  serial=$((serial + 11111))
  spec+=("$src=$serial=/cache/fixtures/$src.db")
  printf '%s\t%s\n' "$src" "$serial" >> "$work/v4-load.tsv"
done
for f in "$parity"/corpus/whois/data/*.db; do
  src=$(basename "$f" .db)
  serial=$((serial + 11111))
  spec+=("$src=$serial=/synthetic/$src.db")
  printf '%s\t%s\n' "$src" "$serial" >> "$work/v4-load.tsv"
done
# v4's mirror full-import path, not irrd_load_database (see tools/v4_mirror_load.py).
start=$SECONDS
v4 python3 - /etc/irrd/irrd.yaml "${spec[@]}" < "$parity/tools/v4_mirror_load.py" > "$work/v4-load.log" 2>&1 \
  || { tail -20 "$work/v4-load.log" >&2; exit 1; }
echo "v4 mirror import of ${#spec[@]} sources in $((SECONDS - start))s"
if [[ $profile == rpki ]]; then
  # v4's own ROA import and full revalidation (ROAImportRunner), run once.
  v4 python3 -c "
from irrd.conf import config_init
config_init('/etc/irrd/irrd.yaml')
from irrd.mirroring.mirror_runners_import import ROAImportRunner
ROAImportRunner().run()
" > "$work/v4-roa.log" 2>&1 || { tail -20 "$work/v4-roa.log" >&2; exit 1; }
  # ROAImportRunner logs its failures instead of raising.
  grep -q 'RPKI status updated for all routes' "$work/v4-roa.log" || { tail -20 "$work/v4-roa.log" >&2; exit 1; }
fi
since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
docker compose restart irrd-v4 > /dev/null
./up.sh > /dev/null

docker compose exec -T postgres psql -At -U irrd -d irrd -c \
  "SELECT source, count(*) FROM rpsl_objects GROUP BY 1 ORDER BY 1" | tr '|' '\t' > "$work/v4-objects.tsv"
docker compose exec -T postgres psql -At -U irrd -d irrd -c \
  "SELECT rpki_status, count(*) FROM rpsl_objects WHERE object_class IN ('route','route6') GROUP BY 1 ORDER BY 1" \
  | tr '|' '\t' > "$work/v4-rpki.tsv"
echo "route rpki status: $(tr '\t\n' '= ' < "$work/v4-rpki.tsv")"
echo "v4 objects: $(awk '{s+=$2} END {print s}' "$work/v4-objects.tsv") in $(wc -l < "$work/v4-objects.tsv") sources"

case $ng in
  import)
    echo "== irrd-ng: import from v4's database"
    rm -rf "$work/store"
    "$IRRD_NG" import --from-postgres "postgresql://irrd:irrd@127.0.0.1:$PARITY_PG_PORT/irrd?sslmode=disable" \
      --store "$work/store" > "$work/ng-import.log" 2>&1 || { tail -20 "$work/ng-import.log" >&2; exit 1; }
    tail -1 "$work/ng-import.log"
    ;;
  none) ;;
  *) echo "--ng import|none" >&2; exit 2 ;;
esac

echo "== corpus bindings"
python3 -I "$parity/tools/corpus_bindings.py" --out "$work/bindings.json" "${fixtures[@]}" "$parity"/corpus/whois/data/*.db
"$parity/ng.sh" stop > /dev/null 2>&1 || true
echo "loaded; next: parity/run.sh"
