#!/bin/sh
# v4 database with rows in every table, for the import check. Runs inside
# the loadcheck v4 container.
#
#   v4-seed.sh <name> <dump> <objects>
#
# Creates v4_<name>, seeds it through v4's own DatabaseHandler
# (tools/seed_v4_extras.py) and exports it to /work/<name>/v4/export/.
set -eu
name=$1 dump=$2 limit=$3
out=/work/$name/v4
db=v4_$(echo "$name" | tr 'A-Z-' 'a-z_')
export PGHOST=postgres PGUSER=irrd PGPASSWORD=irrd
dsn="postgresql://irrd:irrd@postgres/$db"

rm -rf "$out" && mkdir -p "$out"
psql -q -d irrd -c "DROP DATABASE IF EXISTS $db" -c "CREATE DATABASE $db"
python3 - "$dsn" "$out/irrd.yaml" <<'PY'
import sys, yaml
dsn, path = sys.argv[1:]
cfg = yaml.safe_load(open("/v4/irrd.yaml"))
cfg["irrd"]["database_url"] = dsn
cfg["irrd"]["piddir"] = "/tmp"
cfg["irrd"]["sources_default"] = ["TEST", "MIRROR"]
cfg["irrd"]["sources"] = {
    "TEST": {"authoritative": True, "keep_journal": True},
    "MIRROR": {
        "keep_journal": True,
        "nrtm_host": "nrtm.example.net",
        "nrtm_port": 43,
        "import_serial_source": "file:///nonexistent/MIRROR.CURRENTSERIAL",
        "import_source": "file:///nonexistent/mirror.db.gz",
    },
}
yaml.safe_dump(cfg, open(path, "w"), sort_keys=False)
PY
case $dump in *.gz) zcat "$dump" > "$out/dump.db" ;; *) cp "$dump" "$out/dump.db" ;; esac
irrd_database_upgrade --config "$out/irrd.yaml" > "$out/upgrade.log" 2>&1
python3 /tools/seed_v4_extras.py "$out/irrd.yaml" "$out/dump.db" "$limit" > "$out/seed.log" 2>&1 || { cat "$out/seed.log"; exit 1; }
rm -f "$out/dump.db"
python3 /tools/export_v4.py "$dsn" "$out/export" > "$out/export.json"
echo "v4 seed $name: $(tail -1 "$out/seed.log") $(cat "$out/export.json")"
