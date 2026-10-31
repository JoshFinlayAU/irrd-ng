#!/usr/bin/env bash
# Tier 2 parity run on the VM (after tier2/setup.sh start): bindings from the
# reference data, the full corpus at --scale, the whois and http suites, and
# the bgpq4 sweep, all with --redact. Reports stay in $TIER2_DIR/out on the
# VM; only summary.txt and results.tsv are meant to be read from outside.
#
#   tier2/run-tier2.sh [--scale K] [--jobs N] [--skip-bgpq4]
set -euo pipefail
dir=${TIER2_DIR:-/srv/irrd-ng/tier2}
pg=${TIER2_PG_CONTAINER:?set TIER2_PG_CONTAINER}
v4db=${TIER2_V4_DB:-irrd_v4}
scale=4 jobs=4 bgpq4=1
while [[ $# -gt 0 ]]; do
  case $1 in
    --scale) scale=$2; shift 2 ;;
    --jobs) jobs=$2; shift 2 ;;
    --skip-bgpq4) bgpq4=0; shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
cd "$dir"
w=$dir/run/work && mkdir -p "$w"
if [[ ! -s $w/bindings.json ]]; then
  echo "== bindings from $v4db (object_text of the query classes only, streamed, not stored)"
  # Plain SELECT, not COPY: COPY's text format escapes the newlines inside
  # object_text. FETCH_COUNT keeps psql from buffering every row.
  docker exec "$pg" psql -U irrd -d "$v4db" -At -v FETCH_COUNT=20000 -c "SELECT object_text FROM rpsl_objects
      WHERE object_class IN ('as-set','route-set','aut-num','route','route6','mntner','as-block','filter-set',
      'peering-set','rtr-set','inet-rtr','key-cert','inetnum','inet6num','domain','irt','organisation')
      AND source <> 'RPKI'" \
    | systemd-run --scope -q -p MemoryMax=4G python3 -I tools/corpus_bindings.py --per 100 --rank 25 --out "$w/bindings.json" -
fi
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=$dir/out/$stamp && mkdir -p "$out"
python3 -I tools/corpus_expand.py --bindings "$w/bindings.json" --scale "$scale" --out "$w/corpus.tsv" corpus/whois/*.q
status=0
free -g | sed -n 2p
systemd-run --scope -q -p MemoryMax=12G python3 -I tools/whois_diff.py --suite whois --corpus "$w/corpus.tsv" --ref 127.0.0.1:9043 --test 127.0.0.1:8043 \
  --unordered corpus/whois/unordered.tsv --skip huge --redact --jobs "$jobs" --out "$out/whois" || status=1
systemd-run --scope -q -p MemoryMax=12G python3 -I tools/whois_diff.py --suite http --corpus "$w/corpus.tsv" --ref 127.0.0.1:9080 --test 127.0.0.1:8080 \
  --unordered corpus/whois/unordered.tsv --requests corpus/http/requests.tsv --skip huge --redact --jobs "$jobs" --out "$out/http" || status=1
if [[ $bgpq4 == 1 ]]; then
  ./bgpq4.sh --ref 127.0.0.1:9043 --test 127.0.0.1:8043 --bindings "$w/bindings.json" --sets 8 --redact --out "$out/bgpq4" || status=1
fi
echo "reports: $out"
exit $status
