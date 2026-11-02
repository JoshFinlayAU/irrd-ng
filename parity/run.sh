#!/usr/bin/env bash
# Differential parity run: replay the query corpus against v4 and irrd-ng
# and byte-diff every response (CLAUDE.md, "Differential parity testing").
#
#   parity/run.sh [--suite whois|http|graphql|api|events|events-live|all]
#                 [--test ng|v4-twin|HOST:PORT]
#                 [--http-test HOST:PORT] [--ref HOST:PORT] [--http-ref HOST:PORT]
#                 [--bindings FILE] [--scale K] [--only TAG,...] [--jobs N]
#                 [--timeout S] [--redact] [--save-responses] [--strict] [--out DIR]
#
# Suites: whois (TCP, single queries and keepalive sessions), http
# (/v1/whois/, single queries), graphql (/graphql/, corpus/graphql/*.gq),
# api (/v1/status/, /metrics/, the explorer and routing,
# corpus/http/api.gq) and events (the event stream WebSocket and its
# initial download, corpus/http/events.gq) and events-live (both streams
# while the same change is applied to both servers; it leaves their clocks'
# timestamps in the data, so it runs last and needs a fresh load.sh before
# the other suites run again). graphql, api and events run
# through tools/http_diff.py, which masks what differs between two
# servers by nature (times, host names) and accepts a permutation where
# v4's own order is not fixed. nrtm, submit and cli come with their phases.
#
# The rehearsal (rehearsal/run.sh) points the suites at other targets with
# --ref/--http-ref/--test/--http-test and these: PARITY_V4_SERVICE (the v4
# compose service to kick and to run v4 tools in, default irrd-v4),
# PARITY_NG_TOOL (the command that runs an irrd-ng tool on the store under
# test, default the host binary on $PARITY_WORK/tier1/store), PARITY_NG_CONFIG
# and PARITY_NG_FILES (its irrd.yaml and where it sees $work's files).
#
# Default targets are the Tier 1 setup from parity/load.sh: v4 on
# 127.0.0.1:9043/9080 and irrd-ng on 127.0.0.1:$NG_WHOIS_PORT/$NG_HTTP_PORT
# (8043/8080), started with parity/ng.sh if it is not answering.
# `--test v4-twin` instead compares v4 with a second v4 process on the same
# database (compose profile twin, 9243/9280), which validates the harness and
# shows where v4 itself is not deterministic.
#
# The corpus is parity/corpus/whois/*.q, expanded against the bindings for
# the loaded data (load.sh writes them; on Tier 2 tier2/run-tier2.sh does).
# Reports land in parity/out/<suite>-<timestamp>/ (summary.txt, diffs.txt,
# results.jsonl). Answers whose order v4 itself does not fix
# (corpus/whois/unordered.tsv) count as "equivalent" when they are a
# permutation of v4's; --strict counts them as differences. Exit 0 when
# nothing differs, 1 when anything does. A failing diff is fixed in irrd-ng or recorded in
# docs/divergences.md, never by editing expectations.
set -euo pipefail
cd "$(dirname "$0")"
parity=$PWD
work=${PARITY_WORK:-$parity/.work}/tier1
repo=$(cd .. && pwd)

suite=whois test=ng ref=127.0.0.1:9043 http_ref=127.0.0.1:9080 http_test=
bindings=$work/bindings.json scale=1 out= extra=()
v4_service=${PARITY_V4_SERVICE:-irrd-v4}
while [[ $# -gt 0 ]]; do
  case $1 in
    --suite) suite=$2; shift 2 ;;
    --test) test=$2; shift 2 ;;
    --ref) ref=$2; shift 2 ;;
    --http-ref) http_ref=$2; shift 2 ;;
    --http-test) http_test=$2; shift 2 ;;
    --bindings) bindings=$2; shift 2 ;;
    --scale) scale=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    --only|--skip|--rerun|--jobs|--timeout|--max-report) extra+=("$1" "$2"); shift 2 ;;
    --redact|--save-responses|--strict) extra+=("$1"); shift ;;
    -h|--help) sed -n '2,44p' "$0"; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done

case $test in
  ng)
    whois_test=127.0.0.1:${NG_WHOIS_PORT:-8043}
    http_test=${http_test:-127.0.0.1:${NG_HTTP_PORT:-8080}}
    if ! [[ $(./whois.sh 127.0.0.1 "${NG_WHOIS_PORT:-8043}" '!v' 2>/dev/null) == A* ]]; then
      ./ng.sh start
    fi
    ;;
  v4-twin)
    cfg=./v4/irrd-whois.yaml
    [[ -f $work/irrd-v4.yaml ]] && cfg=$work/irrd-v4.yaml
    export PARITY_V4_CONFIG=$cfg PARITY_TIER1_WORK=$work PARITY_CACHE=${PARITY_CACHE:-$parity/.cache}
    docker compose --profile twin up -d irrd-v4-twin > /dev/null 2>&1
    twin=${PARITY_TWIN_WHOIS_PORT:-9243}
    for _ in $(seq 1 90); do
      [[ $(./whois.sh 127.0.0.1 "$twin" '!v' 2>/dev/null) == A* ]] && break
      sleep 2
    done
    v4/preload-kick.sh irrd-v4-twin "${PARITY_TWIN_HTTP_PORT:-9280}"
    whois_test=127.0.0.1:$twin
    http_test=${http_test:-127.0.0.1:${PARITY_TWIN_HTTP_PORT:-9280}}
    ;;
  *) whois_test=$test ;;
esac

[[ -s $bindings ]] || { echo "no bindings at $bindings; run parity/load.sh first" >&2; exit 2; }
stamp=$(date -u +%Y%m%dT%H%M%SZ)
corpus=$work/corpus-whois.tsv
mkdir -p "$work"
python3 -I tools/corpus_expand.py --bindings "$bindings" --scale "$scale" --out "$corpus" corpus/whois/*.q

status=0
run_suite() {
  local s=$1 r=$2 t=$3
  local o=${out:-$parity/out/$s-$stamp}
  [[ -n $out && $suite == all ]] && o=$out/$s
  echo "== suite $s: v4 $r vs $t"
  python3 -I tools/whois_diff.py --suite "$s" --corpus "$corpus" --ref "$r" --test "$t" --out "$o" \
    --unordered corpus/whois/unordered.tsv --requests corpus/http/requests.tsv "${extra[@]}" \
    || status=1
}
run_api_suite() {
  local s=$1; shift
  local o=${out:-$parity/out/$s-$stamp}
  [[ -n $out && $suite == all ]] && o=$out/$s
  echo "== suite $s: v4 $http_ref vs $http_test"
  python3 -I tools/http_diff.py --suite "$s" --bindings "$bindings" --ref "$http_ref" --test "$http_test" \
    --out "$o" "$@" || status=1
}
kick() { v4/preload-kick.sh "$v4_service" "${http_ref##*:}"; }
graphql_suite() {
  kick
  run_api_suite graphql --corpus corpus/graphql/core.gq --corpus corpus/graphql/errors.gq --corpus corpus/graphql/edge.gq --corpus corpus/graphql/transport.gq
}
# One request at a time: v4 stalls when /v1/status/ requests overlap.
api_suite() { run_api_suite api --corpus corpus/http/api.gq --jobs 1; }
events_suite() { run_api_suite events --corpus corpus/http/events.gq; }
# Live: both streams while the same two irrd_update_database runs change
# the journaled source on each server. The pause between them is for
# irrd-ng, which notices a write by another process within two seconds
# (one event per source for everything written in that time). Each server
# stamps the change with its own clock, so afterwards the timestamps of
# EVSTREAM differ between them (!J, /v1/status/, the event stream): run it
# last, and run parity/load.sh again before the other suites.
events_live_suite() {
  local o=${out:-$parity/out/events-live-$stamp}
  cp events/EVSTREAM.live events/EVSTREAM.update "$work/"
  local ng_bin=${IRRD_NG:-$repo/target/release/irrd-ng}
  local ng=${PARITY_NG_TOOL:-IRRD_NG_STORE_PATH=$work/store $ng_bin}
  local ng_cfg=${PARITY_NG_CONFIG:-$work/irrd-ng.yaml} ng_files=${PARITY_NG_FILES:-$work}
  local upd="irrd_update_database --source EVSTREAM"
  local v4="docker compose --profile twin exec -T $v4_service"
  python3 -I tools/events_live.py --ref "$http_ref" --test "$http_test" --out "$o" \
    --v4-cmd "$v4 $upd --config /etc/irrd/irrd.yaml /tier1/EVSTREAM.live && sleep 3 && $v4 $upd --config /etc/irrd/irrd.yaml /tier1/EVSTREAM.update" \
    --ng-cmd "$ng $upd --config $ng_cfg $ng_files/EVSTREAM.live && sleep 3 && $ng $upd --config $ng_cfg $ng_files/EVSTREAM.update" \
    || status=1
}
case $suite in
  whois) run_suite whois "$ref" "$whois_test" ;;
  http) kick; run_suite http "$http_ref" "$http_test" ;;
  graphql) graphql_suite ;;
  api) api_suite ;;
  events) events_suite ;;
  events-live) events_live_suite ;;
  all)
    run_suite whois "$ref" "$whois_test"; kick; run_suite http "$http_ref" "$http_test"
    graphql_suite; api_suite; events_suite; events_live_suite ;;
  nrtm|submit|cli) echo "suite $suite is covered by parity/mirror/run.sh, parity/mirror/serve.sh and parity/submit/run.sh" >&2; exit 2 ;;
  *) echo "unknown suite $suite" >&2; exit 2 ;;
esac
exit $status
