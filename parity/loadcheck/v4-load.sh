#!/bin/sh
# v4 side of the three-way load check. Runs inside the loadcheck v4
# container (see compose.yaml), so every tool is v4's own.
#
#   v4-load.sh <name> <SOURCE> <serial> <dump> [<dump>...]
#
# Creates a fresh database v4_<name>, brings it to v4's schema head with
# irrd_database_upgrade, loads the dump(s) with irrd_load_database, records
# wall time, peak RSS and PostgreSQL sizes, and exports the database to
# /work/<name>/v4/export/. Several dumps (APNIC publishes one per class) are
# concatenated first, because each irrd_load_database run replaces the whole
# source. Everything lands under /work/<name>/v4/.
set -eu
name=$1 source=$2 serial=$3
shift 3
out=/work/$name/v4
db=v4_$(echo "$name" | tr 'A-Z-' 'a-z_')
export PGHOST=postgres PGUSER=irrd PGPASSWORD=irrd
dsn="postgresql://irrd:irrd@postgres/$db"

rm -rf "$out" && mkdir -p "$out"
psql -q -d irrd -c "DROP DATABASE IF EXISTS $db" -c "CREATE DATABASE $db"

# Base config from parity/v4/irrd.yaml, pointed at this database, with the
# one non-authoritative source being loaded. Non-authoritative keeps v4
# from rewriting last-modified, so object text does not depend on the clock.
python3 - "$dsn" "$source" "$out/irrd.yaml" <<'PY'
import sys, yaml
dsn, source, path = sys.argv[1:]
cfg = yaml.safe_load(open("/v4/irrd.yaml"))
cfg["irrd"]["database_url"] = dsn
cfg["irrd"]["piddir"] = "/tmp"
cfg["irrd"]["sources_default"] = [source]
cfg["irrd"]["sources"] = {source: {"keep_journal": False}}
yaml.safe_dump(cfg, open(path, "w"), sort_keys=False)
PY

dump=$out/dump.db
: > "$dump"
for d in "$@"; do
  case $d in *.gz) zcat "$d" ;; *) cat "$d" ;; esac >> "$dump"
  printf '\n' >> "$dump"
done

irrd_database_upgrade --config "$out/irrd.yaml" > "$out/upgrade.log" 2>&1
set +e
python3 /tools/measure.py "$out/load.json" -- \
  irrd_load_database --config "$out/irrd.yaml" --source "$source" --serial "$serial" "$dump" \
  > "$out/load.log" 2>&1
rc=$?
set -e
echo "$rc" > "$out/load.exit"
rm -f "$dump"

psql -At -d "$db" > "$out/sizes.tsv" <<'SQL'
SELECT 'database', pg_database_size(current_database()), NULL, NULL
UNION ALL
SELECT 'table:' || c.relname, pg_total_relation_size(c.oid), pg_relation_size(c.oid), pg_indexes_size(c.oid)
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind = 'r'
ORDER BY 1;
SQL

python3 /tools/export_v4.py "$dsn" "$out/export" > "$out/export.json"
echo "v4 $name: exit $rc $(cat "$out/load.json")"
