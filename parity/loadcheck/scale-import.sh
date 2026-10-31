#!/bin/sh
# Full-scale import of a v4 database copy (Tier 2: the production reference
# copy on the parity VM, PLAN.md D3). Run on that host. Rows never leave it;
# only timings, sizes, samples and the diff summaries are read back.
#
#   PG_CONTAINER=<name> scale-import.sh
#
# PG_CONTAINER is the Docker container running the source PostgreSQL,
# used for its database size.
#
# Expects in /srv/irrd-ng: bin/{irrd-ng,measure.py,export_v4.py,compare_exports.py}
# (static musl irrd-ng, scripts from parity/tools), irrd.yaml (parity/v4/irrd.yaml
# with host paths), the v4 image, and the source Postgres on 127.0.0.1:5432.
# Writes run/: import{1,2} and export timings, store sizes, per-minute I/O and
# thread samples, and the v4-vs-import and re-run diffs. Exports are deleted.
: "${PG_CONTAINER:?set PG_CONTAINER to the source PostgreSQL container}"
cd /srv/irrd-ng
rm -rf run && mkdir -p run
D="postgresql://irrd:irrd@127.0.0.1:5432/irrd?sslmode=disable"
# Every 60s: which irrd-ng step runs, its I/O counters and thread states.
( while [ ! -f run/all.done ]; do
    P=$(pgrep -x irrd-ng | head -1)
    if [ -n "$P" ]; then
      echo "$(date -u +%H:%M:%S) pid=$P $(tr '\0' ' ' < /proc/$P/cmdline | cut -c1-60)"
      grep -E "read_bytes|^write_bytes" /proc/$P/io | tr '\n' ' '; echo
      grep -E "RssAnon|RssFile" /proc/$P/status | tr '\n' ' '; echo
      for t in /proc/$P/task/*; do echo "  $(cat $t/comm) $(awk '{print $3, "utime="$14}' $t/stat) $(cat $t/wchan)"; done
    fi
    sleep 60
  done ) > run/samples.log 2>&1 &
for i in 1 2; do
  python3 bin/measure.py run/import$i.json -- bin/irrd-ng import --from-postgres "$D" --store run/store > run/import$i.out 2> run/import$i.log
  du -sb run/store/data.mdb | cut -f1 > run/store$i.bytes
  mkdir -p run/ng$i
  python3 bin/measure.py run/export-ng$i.json -- env IRRD_NG_STORE_PATH=run/store bin/irrd-ng export-jsonl --config irrd.yaml --table all --output-dir run/ng$i > run/export-ng$i.log 2>&1
done
python3 bin/measure.py run/export-v4.json -- docker run --rm --user 0 --network host --entrypoint python3 -v /srv/irrd-ng/bin:/tools:ro -v /srv/irrd-ng/run:/run-out irrd-ng-parity/irrd-v4:4.5.4 \
  /tools/export_v4.py "postgresql://irrd:irrd@127.0.0.1:5432/irrd" /run-out/v4 > run/export-v4.out 2> run/export-v4.log
docker exec "$PG_CONTAINER" psql -U irrd -d irrd -At -c "select pg_database_size(current_database())" > run/pg.bytes
python3 bin/compare_exports.py run/v4 run/ng1 --label-left v4 --label-right import > run/diff-v4-import.txt 2>&1; echo $? > run/diff-v4-import.exit
python3 bin/compare_exports.py run/ng1 run/ng2 > run/diff-rerun.txt 2>&1; echo $? > run/diff-rerun.exit
rm -rf run/v4 run/ng1 run/ng2
echo done > run/all.done
