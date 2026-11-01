#!/usr/bin/env bash
# Very large write transactions: memory, map growth and time of one source
# loaded and then rewritten in single transactions.
#
#   bench/large_txn.sh DUMP[.gz] [--source NAME] [--binary PATH] [--work DIR]
#
# Uses the Tier 1 irrd-ng configuration (parity/load.sh) for a store of its
# own under --work, with the source's journal kept, as a mirror keeps it:
#   1. irrd_load_database: the dump into an empty store (bulk load, one
#      transaction, no journal entries).
#   2. irrd_update_database with every object changed (a remarks line
#      added), one transaction that rewrites every row and journals every
#      object, as a large NRTM or mirror update would.
#   3. irrd_update_database with the original dump again: every object
#      changed back.
# For each step: wall time, CPU time (user and system: wall time on a
# busy disk varies a lot, CPU time much less), peak RSS and peak anonymous RSS (sampled every
# 0.1 s, so file-backed pages of the memory-mapped store are told apart
# from heap), and the store's map size and data file size afterwards
# (store-info).
set -euo pipefail
here=$PWD
cd "$(dirname "$0")"
repo=$(cd .. && pwd)
dump="" source=RADB bin=$repo/target/release/irrd-ng work=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --source) source=$2; shift 2 ;;
    --binary) bin=$2; shift 2 ;;
    --work) work=$2; shift 2 ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    -*) echo "unknown argument $1" >&2; exit 2 ;;
    *) dump=$1; shift ;;
  esac
done
[[ -n $dump ]] || { echo "usage: bench/large_txn.sh DUMP[.gz]" >&2; exit 2; }
dump=$(cd "$here" && realpath "$dump")
[[ -z $work ]] || work=$(cd "$here" && realpath -m "$work")
tier1=${PARITY_WORK:-$repo/parity/.work}/tier1
[[ -f $tier1/irrd-ng.yaml ]] || { echo "no $tier1/irrd-ng.yaml: run parity/load.sh and parity/ng.sh config" >&2; exit 2; }
work=${work:-$repo/bench/out/large-txn-$(date -u +%Y%m%dT%H%M%SZ)}
rm -rf "$work/store"
mkdir -p "$work"

case $dump in
  *.gz) gzip -dc "$dump" > "$work/a.db" ;;
  *) cp "$dump" "$work/a.db" ;;
esac
# Every object changed: one remarks line added before its source line.
python3 -I - "$work/a.db" "$work/b.db" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8", errors="surrogateescape").read()
out = re.sub(r"(?m)^(source:)", "remarks:        large transaction bench\n\\1", text)
open(sys.argv[2], "w", encoding="utf-8", errors="surrogateescape").write(out)
PY

python3 -I - "$tier1/irrd-ng.yaml" "$work/irrd.yaml" "$source" <<'PY'
import sys
src, out, source = sys.argv[1:]
t = open(src).read()
# keep_journal needs an authoritative or mirrored source; authoritative
# also lets irrd_load_database and irrd_update_database run on it.
t = t.replace(f"    {source}:\n      keep_journal: false\n",
              f"    {source}:\n      keep_journal: true\n      authoritative: true\n")
open(out, "w").write(t)
PY

export IRRD_NG_STORE_PATH=$work/store
run() { # label, command...
  local label=$1; shift
  python3 -I - "$label" "$@" <<'PY' | tee -a "$work/summary.txt"
import subprocess, sys, time
label, cmd = sys.argv[1], sys.argv[2:]
t = time.time()
p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=open(f"{label}.log", "w"))
rss = anon = 0
while p.poll() is None:
    try:
        for line in open(f"/proc/{p.pid}/status"):
            if line.startswith("VmRSS:"):
                rss = max(rss, int(line.split()[1]))
            elif line.startswith("RssAnon:"):
                anon = max(anon, int(line.split()[1]))
    except OSError:
        pass
    time.sleep(0.1)
import resource
ru = resource.getrusage(resource.RUSAGE_CHILDREN)
print(f"{label}\texit {p.returncode}\t{time.time() - t:.1f} s\tcpu {ru.ru_utime + ru.ru_stime:.1f} s\tpeak rss {rss // 1024} MiB\tpeak anon {anon // 1024} MiB")
PY
  "$bin" store-info --config "$work/irrd.yaml" 2>/dev/null | grep -iE 'map|used|size' | sed 's/^/    /' | tee -a "$work/summary.txt" || true
}
cd "$work"
echo "$(grep -c '^source:' a.db) objects in $dump, binary $bin" | tee "$work/summary.txt"
run load "$bin" irrd_load_database --config "$work/irrd.yaml" --source "$source" "$work/a.db"
run update-all "$bin" irrd_update_database --config "$work/irrd.yaml" --source "$source" "$work/b.db"
run update-back "$bin" irrd_update_database --config "$work/irrd.yaml" --source "$source" "$work/a.db"
ls -la "$work/store"
