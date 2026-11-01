#!/usr/bin/env bash
# Load bench on the Tier 1 stack: whois, REST and GraphQL QPS, p50/p99,
# slow answers and server memory for v4 and irrd-ng on the same data with
# the same mixes. The Tier 2 version (production-size data) is load.sh;
# this one runs wherever the Tier 1 stack runs.
#
#   bench/tier1_load.sh [--concurrency "4 16 64"] [--duration S] [--warmup S]
#                       [--servers "v4 ng"] [--out DIR]
#
# Needs parity/up.sh and parity/load.sh (the store and the corpus bindings)
# and irrd-ng running on them (parity/ng.sh start). Three mixes:
#   whois    bench/mix.py over the bindings, AS-set members expanded on v4
#   rest     the /v1/whois/, /v1/status/ and /metrics/ entries of
#            bench/http_mix.py
#   graphql  the GraphQL entries of bench/http_mix.py
# Each server and mix: one unmeasured warm-up run, then one measured run per
# concurrency level, servers one after the other. Memory is sampled every
# second during the runs: irrd-ng's RSS and anonymous RSS from /proc; for
# v4 the memory of its three containers (irrd-v4, Redis, PostgreSQL) from
# docker stats, which counts page cache the containers touched as well.
# Output: bench/out/tier1-<stamp>/{*.tsv,*.json}, summary.tsv.
set -euo pipefail
cd "$(dirname "$0")"
bench=$PWD
repo=$(cd .. && pwd)
conc="4 16 64" duration=30 warmup=5 servers="v4 ng" out=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --concurrency) conc=$2; shift 2 ;;
    --duration) duration=$2; shift 2 ;;
    --warmup) warmup=$2; shift 2 ;;
    --servers) servers=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    -h|--help) sed -n '2,21p' "$0"; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
work=${PARITY_WORK:-$repo/parity/.work}/tier1
bindings=$work/bindings.json
[[ -f $bindings ]] || { echo "no $bindings: run parity/load.sh" >&2; exit 2; }
lg=${LOADGEN:-$repo/target/release/loadgen}
[[ -x $lg ]] || (cd "$repo" && cargo build --release -p loadgen)
out=${out:-$bench/out/tier1-$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$out"

python3 -I "$bench/mix.py" --bindings "$bindings" --expand 127.0.0.1:9043 > "$out/mix-whois.tsv"
python3 -I "$bench/http_mix.py" --bindings "$bindings" > "$out/mix-http.tsv"
grep -P '\tgql_' "$out/mix-http.tsv" > "$out/mix-graphql.tsv"
grep -vP '\tgql_' "$out/mix-http.tsv" > "$out/mix-rest.tsv"

target() { # server mix
  case $1-$2 in
    v4-whois) echo 127.0.0.1:9043 ;; v4-*) echo 127.0.0.1:9080 ;;
    ng-whois) echo 127.0.0.1:8043 ;; ng-*) echo 127.0.0.1:8080 ;;
  esac
}
ng_pid() { ss -ltnp "sport = :8043" | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2; }
mem() { # server -> "total_kib anon_kib"
  case $1 in
    ng) awk '/^VmRSS:/ {r=$2} /^RssAnon:/ {a=$2} END {print r, a}' "/proc/$(ng_pid)/status" ;;
    v4) docker stats --no-stream --format '{{.Name}} {{.MemUsage}}' \
          | awk '/irrd-parity-(irrd-v4|redis|postgres)-1/ {v=$2; u=1; if (v ~ /GiB/) u=1048576; else if (v ~ /MiB/) u=1024; sub(/[A-Za-z]+/, "", v); s+=v*u} END {printf "%d 0\n", s}' ;;
  esac
}

printf 'server\tmix\tconcurrency\tqps\tp50_us\tp99_us\tmax_us\tover_500ms\terrors\tmem_peak_kib\tanon_peak_kib\n' > "$out/summary.tsv"
for s in $servers; do
  echo "$s idle: $(mem "$s")" >> "$out/mem-idle.txt"
  for m in whois rest graphql; do
    t=$(target "$s" "$m")
    "$lg" --target "$t" --mix "$out/mix-$m.tsv" --concurrency 8 --duration "$warmup" --warmup 0 > /dev/null
    for c in $conc; do
      : > "$out/mem-$s-$m-c$c.tsv"
      ( while sleep 1; do mem "$s" >> "$out/mem-$s-$m-c$c.tsv"; done ) & sampler=$!
      "$lg" --target "$t" --mix "$out/mix-$m.tsv" --concurrency "$c" --duration "$duration" --warmup "$warmup" \
        > "$out/$s-$m-c$c.json"
      kill "$sampler" 2>/dev/null || true
      wait "$sampler" 2>/dev/null || true
      python3 -I - "$out/$s-$m-c$c.json" "$out/mem-$s-$m-c$c.tsv" "$s" "$m" "$c" >> "$out/summary.tsv" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))["total"]
rows = [l.split() for l in open(sys.argv[2]) if l.strip()]
tot = max((int(x[0]) for x in rows), default=0)
anon = max((int(x[1]) for x in rows), default=0)
print(f"{sys.argv[3]}\t{sys.argv[4]}\t{sys.argv[5]}\t{r['qps']:.0f}\t{r['p50_us']}\t{r['p99_us']}\t{r['max_us']}\t{r.get('over_500ms', '')}\t{r['errors']}\t{tot}\t{anon}")
PY
    done
  done
done
column -t "$out/summary.tsv"
