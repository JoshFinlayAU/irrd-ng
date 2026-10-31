#!/usr/bin/env bash
# Load the same data into the v4 reference and into an irrd-ng store, for
# the whois and http suites (parity/run.sh).
#
#   parity/load.sh [--ng import|none]
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
export PARITY_V4_CONFIG=./v4/irrd-whois.yaml
export PARITY_PG_PORT=${PARITY_PG_PORT:-9532}
IRRD_NG=${IRRD_NG:-$repo/target/release/irrd-ng}
work=${PARITY_WORK:-$parity/.work}/tier1
ng=import
while [[ $# -gt 0 ]]; do
  case $1 in
    --ng) ng=$2; shift 2 ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done

fixtures=("$PARITY_CACHE"/fixtures/*.db)
[[ -e ${fixtures[0]} ]] || { echo "no fixtures in $PARITY_CACHE/fixtures (tools/cut_fixtures.py)" >&2; exit 2; }
mkdir -p "$work"

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
docker compose restart irrd-v4 > /dev/null
./up.sh > /dev/null
docker compose exec -T postgres psql -At -U irrd -d irrd -c \
  "SELECT source, count(*) FROM rpsl_objects GROUP BY 1 ORDER BY 1" | tr '|' '\t' > "$work/v4-objects.tsv"
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
