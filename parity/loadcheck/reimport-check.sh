#!/usr/bin/env bash
# Re-import check: a second `irrd-ng import` over an existing store must
# leave the store equal to the source, deletions included.
#
# Copies the seeded v4 database (v4-seed.sh: rows in every table) to a
# scratch database, imports it, then changes the source in several tables
# (deletes, inserts and modifications, including the first and last keys
# of the big tables and a whole status row), re-imports into the same store,
# and requires `irrd-ng export-jsonl` to equal v4's export of the changed
# database exactly. A third import of the unchanged source must delete and
# change nothing.
#
#   parity/loadcheck/reimport-check.sh
#
# Needs the loadcheck stack (parity/load-check.sh starts it) with the
# v4_seeded database, and IRRD_NG (default target/release/irrd-ng).
set -euo pipefail
cd "$(dirname "$0")/.."
parity=$PWD
work=${LOADCHECK_WORK:-$parity/.work}/reimport
IRRD_NG=${IRRD_NG:-$parity/../target/release/irrd-ng}
port=${LOADCHECK_PG_PORT:-9432}
db=v4_reimport
dsn="postgresql://irrd:irrd@127.0.0.1:$port/$db?sslmode=disable"
psql() { docker exec -i -e PGPASSWORD=irrd irrd-loadcheck-postgres-1 psql -q -v ON_ERROR_STOP=1 -U irrd "$@"; }

rm -rf "$work" && mkdir -p "$work"
psql -d irrd -c "DROP DATABASE IF EXISTS $db" -c "CREATE DATABASE $db TEMPLATE v4_seeded"
sed -e "s#piddir: /run/irrd#piddir: $work#" -e "s#gnupg_keyring: /var/lib/irrd/gnupg#gnupg_keyring: $work/gnupg#" \
  "$parity/v4/irrd.yaml" > "$work/irrd.yaml"

run_import() {
  "$IRRD_NG" import --from-postgres "$dsn" --store "$work/store" > "$work/import$1.out" 2> "$work/import$1.log"
}
ng_export() {
  rm -rf "$work/$1" && mkdir -p "$work/$1"
  IRRD_NG_STORE_PATH=$work/store "$IRRD_NG" export-jsonl --config "$work/irrd.yaml" --table all --output-dir "$work/$1"
}
v4_export() {
  docker exec irrd-loadcheck-v4-1 python3 /tools/export_v4.py \
    "postgresql://irrd:irrd@postgres/$db" "/work/reimport/$1" > /dev/null
}

run_import 1

# Change the source: every kind of change, in every table that has rows.
psql -d "$db" <<'SQL'
BEGIN;
-- rpsl_objects: the first and last keys, a few in between, a modification,
-- and new objects (one sorting before everything, one after).
CREATE TEMP VIEW deletable AS
  SELECT * FROM rpsl_objects WHERE pk NOT IN (SELECT rpsl_mntner_obj_id FROM auth_mntner);
DELETE FROM rpsl_objects WHERE pk IN (
  (SELECT pk FROM deletable ORDER BY source COLLATE "C", object_class COLLATE "C", rpsl_pk COLLATE "C" LIMIT 1),
  (SELECT pk FROM deletable ORDER BY source COLLATE "C" DESC, object_class COLLATE "C" DESC, rpsl_pk COLLATE "C" DESC LIMIT 1));
DELETE FROM rpsl_objects WHERE pk IN (
  SELECT pk FROM deletable WHERE object_class = 'route'
  ORDER BY rpsl_pk COLLATE "C" OFFSET 3 LIMIT 4);
UPDATE rpsl_objects SET object_text = object_text || 'remarks:        changed in the source' || chr(10),
  updated = updated + interval '1 day'
  WHERE pk IN (SELECT pk FROM rpsl_objects WHERE object_class = 'aut-num' ORDER BY rpsl_pk COLLATE "C" LIMIT 2);
INSERT INTO rpsl_objects (rpsl_pk, source, object_class, parsed_data, object_text, rpki_status, scopefilter_status,
  route_preference_status, created, updated)
  SELECT 'AAA-FIRST-' || rpsl_pk, 'AAA', object_class, parsed_data, object_text, rpki_status, scopefilter_status,
    route_preference_status, created, updated
  FROM rpsl_objects WHERE object_class = 'mntner' ORDER BY rpsl_pk COLLATE "C" LIMIT 1;
INSERT INTO rpsl_objects (rpsl_pk, source, object_class, parsed_data, object_text, rpki_status, scopefilter_status,
  route_preference_status, created, updated)
  SELECT 'ZZZ-LAST-' || rpsl_pk, 'ZZZ', object_class, parsed_data, object_text, rpki_status, scopefilter_status,
    route_preference_status, created, updated
  FROM rpsl_objects WHERE object_class = 'mntner' ORDER BY rpsl_pk COLLATE "C" LIMIT 1;
-- Journal: expire the oldest TEST entries, change one, add one.
DELETE FROM rpsl_database_journal WHERE source = 'TEST' AND serial_nrtm <= 5;
DELETE FROM rpsl_database_journal WHERE source = 'MIRROR' AND serial_nrtm IN (5100, 5101);
UPDATE rpsl_database_journal SET object_text = 'changed' || chr(10) WHERE source = 'MIRROR' AND serial_nrtm = 5200;
INSERT INTO rpsl_database_journal (rpsl_pk, source, origin, serial_nrtm, operation, object_class, object_text)
  VALUES ('AS-NEW', 'TEST', 'auth_change', 9000, 'delete', 'as-set', 'as-set: AS-NEW' || chr(10));
-- ROAs: one gone, one new, one with a changed key.
DELETE FROM roa_object WHERE prefix = '198.51.100.0/22';
INSERT INTO roa_object (prefix, asn, max_length, trust_anchor, ip_version) VALUES ('203.0.113.0/24', 64500, 24, NULL, 4);
UPDATE roa_object SET max_length = 64 WHERE prefix = '2001:db8::/32';
-- Small tables.
DELETE FROM rpsl_objects_suspended WHERE pk = (SELECT pk FROM rpsl_objects_suspended ORDER BY rpsl_pk LIMIT 1);
DELETE FROM protected_rpsl_name WHERE pk IN (SELECT pk FROM protected_rpsl_name ORDER BY protected_name LIMIT 2);
INSERT INTO protected_rpsl_name (rpsl_pk, source, object_class, protected_name) VALUES ('NEW-MNT', 'TEST', 'mntner', 'NEW-MNT');
DELETE FROM setting;
INSERT INTO setting (name, value) VALUES ('another', 'x');
DELETE FROM database_status WHERE source = 'MIRROR';
UPDATE database_status SET serial_last_export = 4242 WHERE source = 'TEST';
DELETE FROM change_log WHERE auth_change_descr IS NOT NULL;
DELETE FROM auth_permission WHERE user_management = false;
DELETE FROM auth_webauthn;
UPDATE auth_user SET name = 'Alice Renamed' WHERE email = 'alice@example.net';
INSERT INTO auth_api_token (name, creator_id, mntner_id, enabled_webapi, enabled_email)
  SELECT 'second', creator_id, mntner_id, false, true FROM auth_api_token LIMIT 1;
COMMIT;
SQL

run_import 2
ng_export ng2
v4_export v4
status=0
python3 -I "$parity/tools/compare_exports.py" "$work/v4" "$work/ng2" --label-left v4 --label-right reimport \
  > "$work/diff.txt" || status=1
echo "== re-import after source changes vs v4 (exact)"
cat "$work/diff.txt"
echo "== deleted per table (re-import)"
grep -P '\tdeleted [1-9]' "$work/import2.out" || true

# Nothing changed: a third run deletes and changes nothing.
run_import 3
ng_export ng3
python3 -I "$parity/tools/compare_exports.py" "$work/ng2" "$work/ng3" > "$work/diff-rerun.txt" || status=1
if grep -qP '\tdeleted [1-9]' "$work/import3.out"; then status=1; echo "unchanged re-run deleted rows"; fi
echo "== unchanged re-run: $(grep -c identical "$work/diff-rerun.txt") tables identical, nothing deleted"

# A failed import leaves the store marked: it refuses to open until it is
# imported again. A source row the store cannot hold (an ip_first with a
# mask) fails the import part way through.
psql -d "$db" -c "UPDATE rpsl_objects SET ip_first = '192.0.2.0/24' WHERE pk = (SELECT pk FROM rpsl_objects WHERE ip_first IS NOT NULL ORDER BY source COLLATE \"C\" DESC, object_class COLLATE \"C\" DESC, rpsl_pk COLLATE \"C\" DESC LIMIT 1)"
rm -rf "$work/store"
if run_import 4; then status=1; echo "import of a bad source succeeded"; fi
grep -q "is incomplete and will refuse to open" "$work/import4.log" || { status=1; echo "no incomplete-store message"; }
if IRRD_NG_STORE_PATH=$work/store "$IRRD_NG" export-jsonl --config "$work/irrd.yaml" --table setting > /dev/null 2> "$work/open4.log"; then
  status=1; echo "the partial store opened"
fi
grep -q "incomplete bulk load" "$work/open4.log" || { status=1; echo "partial store open did not report the incomplete load"; }
echo "== failed import: $(tail -2 "$work/import4.log" | head -c 300)"

# A source at another schema revision is refused before any store exists.
psql -d "$db" -c "UPDATE alembic_version SET version_num = 'a635d2217a48'"
rm -rf "$work/store"
if run_import 5; then status=1; echo "import of an old schema succeeded"; fi
[[ ! -e $work/store ]] || { status=1; echo "a store was created for a refused source"; }
echo "== old schema: $(tail -1 "$work/import5.log" | head -c 200)"

psql -d irrd -c "DROP DATABASE $db"
[[ $status == 0 ]] && echo "reimport-check: PASS" || echo "reimport-check: FAIL"
exit $status
