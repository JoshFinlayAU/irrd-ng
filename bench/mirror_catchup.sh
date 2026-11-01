#!/usr/bin/env bash
# Mirror catch-up: v4 and irrd-ng mirror the same source from the same
# upstream, a full import and then one NRTMv3 catch-up of N changes, and
# both are timed.
#
#   bench/mirror_catchup.sh UPSTREAM_WORK [--source NAME] [--binary PATH]
#
# UPSTREAM_WORK is a work directory left by bench/large_txn.sh for the same
# source: a store whose journal holds 2N changes (every object rewritten,
# then rewritten back), with the dumps a.db and b.db beside it. That store
# is served as the upstream by irrd-ng (NRTMv3 on the Tier 1 Docker
# network's gateway, so v4's container reaches it too). Each mirror does a
# full import of b.db, the upstream's content after the first N changes,
# at serial N, and then catches up the last N changes over NRTMv3.
#   v4       RPSLMirrorImportUpdateRunner run twice in a one-off container
#            of the Tier 1 stack, on its database (the source is replaced):
#            the first run is the full import, the second the catch-up.
#   irrd-ng  the daemon on a fresh store, with the source's import_timer at
#            1 second; the full import and the catch-up are timed from the
#            daemon's start until !J shows each serial_newest_mirror.
# Needs the Tier 1 stack (parity/up.sh, parity/load.sh). Output under
# UPSTREAM_WORK/catchup/, one line per server and phase in summary.txt.
set -euo pipefail
here=$PWD
cd "$(dirname "$0")"
repo=$(cd .. && pwd)
up="" source=RADB bin=$repo/target/release/irrd-ng
while [[ $# -gt 0 ]]; do
  case $1 in
    --source) source=$2; shift 2 ;;
    --binary) bin=$2; shift 2 ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    -*) echo "unknown argument $1" >&2; exit 2 ;;
    *) up=$(cd "$here" && realpath "$1"); shift ;;
  esac
done
[[ -d $up/store && -f $up/b.db ]] || { echo "usage: bench/mirror_catchup.sh UPSTREAM_WORK (from bench/large_txn.sh)" >&2; exit 2; }
export PARITY_WORK=${PARITY_WORK:-$repo/parity/.work}
tier1=$PARITY_WORK/tier1
out=$up/catchup
rm -rf "$out" "$tier1/bench-mirror"
mkdir -p "$out/run" "$out/ng/run" "$out/ng/gnupg" "$tier1/bench-mirror"
gw=$(docker network inspect irrd-parity_default --format '{{(index .IPAM.Config 0).Gateway}}')
uport=18043 nport=18143

whois() { python3 -I - "$@" <<'PY'
import socket, sys
host, port, q = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.create_connection((host, port), timeout=30)
s.sendall(q.encode() + b"\n")
d = b""
while True:
    c = s.recv(65536)
    if not c:
        break
    d += c
print(d.decode(errors="replace"))
PY
}
# A serial field of the source in !J, or 0.
serial() { # host, port, field
  whois "$1" "$2" "!J$source" 2>/dev/null | python3 -I -c '
import json, sys
t = sys.stdin.read()
try:
    v = json.loads(t[t.index("{"):t.rindex("}") + 1])[sys.argv[1]][sys.argv[2]]
except (ValueError, KeyError):
    v = None
print(v or 0)' "$source" "$3"
}

# Configurations: irrd-ng's Tier 1 file with ports, paths and the source
# changed. `role` is upstream or mirror.
ng_config() { # role, out, whois interface, whois port, http port, rundir
  python3 -I - "$tier1/irrd-ng.yaml" "$@" "$source" "$gw" "$uport" "$tier1/bench-mirror" <<'PY'
import re, sys
src, role, out, wif, wport, hport, rundir, source, gw, uport, files = sys.argv[1:]
t = open(src).read()
t = re.sub(r"(?m)^  piddir: .*$", f"  piddir: {rundir}", t)
t = re.sub(r"(    whois:\n      interface: )[^\n]*\n      port: \d+", rf"\g<1>{wif}\n      port: {wport}", t)
t = re.sub(r"(    http:\n      interface: )[^\n]*\n      port: \d+", rf"\g<1>127.0.0.1\n      port: {hport}", t)
if role == "upstream":
    block = "      keep_journal: true\n      authoritative: true\n      nrtm_access_list: harness\n"
else:
    block = (f"      keep_journal: true\n      import_timer: 1\n      nrtm_host: {gw}\n      nrtm_port: {uport}\n"
             f"      import_source: file://{files}/b.db\n      import_serial_source: file://{files}/serial\n")
t, n = re.subn(rf"(?m)^    {re.escape(source)}:\n(      [^\n]*\n)*", f"    {source}:\n{block}", t, count=1)
assert n == 1, "source not in the configuration"
open(out, "w").write(t)
PY
}

ng_config upstream "$out/upstream.yaml" "$gw" "$uport" 18080 "$out/run"
IRRD_NG_STORE_PATH=$up/store "$bin" irrd --config "$out/upstream.yaml" --foreground > "$out/upstream.log" 2>&1 &
upid=$!
mpid=""
cleanup() { kill "$upid" ${mpid:+"$mpid"} 2>/dev/null || true; }
trap cleanup EXIT
for _ in $(seq 1 120); do [[ $(serial "$gw" "$uport" serial_newest_journal) != 0 ]] && break; sleep 1; done
first=$(serial "$gw" "$uport" serial_oldest_journal)
last=$(serial "$gw" "$uport" serial_newest_journal)
total=$((last - first + 1))
start=$((first - 1 + total / 2))
n=$((last - start))
cp "$up/b.db" "$tier1/bench-mirror/b.db"
echo "$start" > "$tier1/bench-mirror/serial"
echo "upstream $source journal $first-$last; mirrors import b.db at serial $start, then catch up $n changes" | tee "$out/summary.txt"

# v4
python3 -I - "$tier1/irrd-v4.yaml" "$tier1/bench-mirror/irrd-v4.yaml" "$source" "$gw" "$uport" <<'PY'
import re, sys
src, out, source, gw, uport = sys.argv[1:]
t = open(src).read()
block = (f"      keep_journal: true\n      nrtm_host: {gw}\n      nrtm_port: {uport}\n"
         f"      import_source: file:///tier1/bench-mirror/b.db\n      import_serial_source: file:///tier1/bench-mirror/serial\n")
t, n = re.subn(rf"(?m)^    {re.escape(source)}:\n(      [^\n]*\n)*", f"    {source}:\n{block}", t, count=1)
assert n == 1, "source not in the configuration"
open(out, "w").write(t)
PY
# Whatever parity/load.sh left for the source goes: the first run must be
# a full import, as on a new mirror.
(cd "$repo/parity" && docker compose exec -T postgres psql -q -U irrd -d irrd -c \
  "DELETE FROM rpsl_objects WHERE source = '$source'; DELETE FROM rpsl_database_journal WHERE source = '$source';
   DELETE FROM database_status WHERE source = '$source'")
(cd "$repo/parity" && PARITY_V4_CONFIG=$tier1/irrd-v4.yaml PARITY_TIER1_WORK=$tier1 \
  docker compose run --rm -T --no-deps --entrypoint python3 irrd-v4 -c "
import logging, sys, time
logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
from irrd.conf import config_init
config_init('/tier1/bench-mirror/irrd-v4.yaml')
from irrd.mirroring.mirror_runners_import import RPSLMirrorImportUpdateRunner
for phase in ('full import', 'nrtm catch-up'):
    t = time.time()
    RPSLMirrorImportUpdateRunner('$source').run()
    print(f'v4\t{phase}\t{time.time() - t:.1f} s', flush=True)
" 2> "$out/v4.log") | tee -a "$out/summary.txt"
v4serial=$(cd "$repo/parity" && docker compose exec -T postgres psql -At -U irrd -d irrd -c \
  "SELECT serial_newest_mirror FROM database_status WHERE source = '$source'")
echo "v4 serial_newest_mirror $v4serial (expected $last)" | tee -a "$out/summary.txt"

# irrd-ng
ng_config mirror "$out/mirror.yaml" 127.0.0.1 "$nport" 18180 "$out/ng/run"
t0=$(date +%s.%N)
IRRD_NG_STORE_PATH=$out/ng/store "$bin" irrd --config "$out/mirror.yaml" --foreground > "$out/ng.log" 2>&1 &
mpid=$!
full="" done=""
for _ in $(seq 1 36000); do
  s=$(serial 127.0.0.1 "$nport" serial_newest_mirror)
  now=$(date +%s.%N)
  [[ -z $full && $s -ge $start ]] && full=$now
  if [[ $s -ge $last ]]; then done=$now; break; fi
  sleep 0.1
done
printf 'irrd-ng\tfull import\t%.1f s (from daemon start)\n' "$(echo "$full - $t0" | bc)" | tee -a "$out/summary.txt"
printf 'irrd-ng\tnrtm catch-up\t%.1f s\n' "$(echo "${done:-$now} - $full" | bc)" | tee -a "$out/summary.txt"
echo "irrd-ng serial_newest_mirror $(serial 127.0.0.1 "$nport" serial_newest_mirror) (expected $last)" | tee -a "$out/summary.txt"
