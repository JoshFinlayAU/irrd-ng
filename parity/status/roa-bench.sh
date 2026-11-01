#!/usr/bin/env bash
# ROA import at production size: time and peak memory of v4's
# ROAImportRunner and `irrd-ng run-job roa-import` on the same data.
#
#   parity/status/roa-bench.sh [N]     # N synthetic ROAs, default 1,000,000
#
# irrd-ng's figure is reported twice: maxrss (as v4's) and the peak of its
# anonymous memory, without the store's page cache.
#
# Runs after parity/status/run.sh, on the state it left: the Tier 1
# fixtures plus the status suite's sources, about 37,000 objects, in v4's
# database and in irrd-ng's store. The ROAs are invented (consecutive /24s
# and /48s, private-use origins), so roughly the size of today's global
# RPKI, without real data. Each server runs the same import twice: the
# first replaces the suite's ROAs, the second replaces its own, which is
# the steady state of an hourly import. Then both databases are compared as
# the suite compares them.
set -euo pipefail
cd "$(dirname "$0")/.."
parity=$PWD
repo=$(cd .. && pwd)
IRRD_NG=${IRRD_NG:-$repo/target/release/irrd-ng}
work=${PARITY_WORK:-$parity/.work}/status
n=${1:-1000000}
[[ -f $work/irrd-v4.yaml ]] || { echo "run parity/status/run.sh first" >&2; exit 2; }
out=$parity/out/roa-bench-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$out"
export PARITY_V4_CONFIG=$work/irrd-v4.yaml PARITY_TIER1_WORK=$work IRRD_NG_STORE_PATH=$work/store

python3 -I - "$n" "$work/roas-bench.json" <<'PY'
import json, sys
n, path = int(sys.argv[1]), sys.argv[2]
tas = ["apnic", "arin", "ripe", "afrinic", "lacnic"]
roas = []
for i in range(n):
    if i % 4:
        a, b, c = 11 + (i >> 16), (i >> 8) & 255, i & 255
        roas.append({"asn": f"AS{64512 + i % 1000}", "prefix": f"{a}.{b}.{c}.0/24", "maxLength": 24, "ta": tas[i % 5]})
    else:
        roas.append({"asn": f"AS{4200000000 + i % 1000}", "prefix": f"2001:db8:{(i >> 16) & 0xffff:x}:{i & 0xffff:x}::/64",
                     "maxLength": 64, "ta": tas[i % 5]})
json.dump({"roas": roas}, open(path, "w"))
PY
python3 -I status/config.py "$work" '{"roas": "roas-bench.json"}'

v4job() {
  docker compose run --rm -T --no-deps --entrypoint python3 irrd-v4 -c "
import logging, resource, sys, time
logging.basicConfig(level=logging.INFO, stream=sys.stdout, format='%(levelname)s %(name)s: %(message)s')
from irrd.conf import config_init
config_init('/etc/irrd/irrd.yaml')
from irrd.mirroring.mirror_runners_import import ROAImportRunner
t = time.time()
ROAImportRunner().run()
print(f'BENCH seconds {time.time() - t:.1f} maxrss_kb {resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}')
"
}
ngjob() {
  # maxrss counts the pages of the memory-mapped store the job touched
  # (page cache, reclaimable), which v4's figure leaves out: its database
  # is in another process. So irrd-ng's anonymous memory is sampled too.
  python3 -I -c '
import resource, subprocess, sys, time
t = time.time()
p = subprocess.Popen(sys.argv[1:])
anon = 0
while p.poll() is None:
    try:
        for line in open(f"/proc/{p.pid}/status"):
            if line.startswith("RssAnon:"):
                anon = max(anon, int(line.split()[1]))
    except OSError:
        pass
    time.sleep(0.1)
print(f"BENCH seconds {time.time() - t:.1f} maxrss_kb {resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss} anon_peak_kb {anon}")
' "$IRRD_NG" run-job --config "$work/irrd-ng.yaml" roa-import
}
for round in 1 2; do
  v4job > "$out/v4-$round.log" 2>&1
  ngjob > "$out/ng-$round.log" 2>&1
  echo "round $round ($n ROAs): v4 $(grep -o 'BENCH.*' "$out/v4-$round.log"), irrd-ng $(grep -o 'BENCH.*' "$out/ng-$round.log")" | tee -a "$out/summary.txt"
done
mkdir -p "$out/v4" "$out/ng"
chmod a+rwx "$out/v4"
docker compose run --rm -T --no-deps -v "$parity/tools:/tools:ro" -v "$out:/out" --entrypoint python3 irrd-v4 \
  /tools/export_v4.py postgresql://irrd:irrd@postgres/irrd /out/v4 > /dev/null
"$IRRD_NG" export-jsonl --config "$work/irrd-ng.yaml" --table all --output-dir "$out/ng" > /dev/null
python3 -I status/compare_status.py "$out/v4" "$out/ng" --exclude-file status/excluded-columns.tsv | tee -a "$out/summary.txt"
