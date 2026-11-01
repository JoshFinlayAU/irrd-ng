#!/usr/bin/env bash
# HTTP API load bench: GraphQL, /v1/whois/, /v1/status/ and /metrics/ QPS,
# latency and server memory for v4 and irrd-ng on the same data and mix
# (bench/http_mix.py). Runs against the Tier 1 stack (parity/load.sh), or
# any pair of servers given with --v4 and --ng.
#
#   bench/http_load.sh [--concurrency "4 16"] [--duration S] [--warmup S]
#                      [--v4 HOST:PORT] [--ng HOST:PORT] [--bindings FILE]
#
# The servers are measured one after the other. Memory is sampled during
# each run: irrd-ng's RSS; for v4, the RSS of every process in its
# container plus its Redis and Postgres containers (docker stats).
# Output: bench/out/http-<stamp>/{mix.tsv,<server>-c<N>.json,summary.tsv}
set -euo pipefail
cd "$(dirname "$0")"
bench=$PWD
repo=$(cd .. && pwd)
conc="4 16" duration=30 warmup=5 v4=127.0.0.1:9080 ng=127.0.0.1:8080
bindings=${PARITY_WORK:-$repo/parity/.work}/tier1/bindings.json
while [[ $# -gt 0 ]]; do
  case $1 in
    --concurrency) conc=$2; shift 2 ;;
    --duration) duration=$2; shift 2 ;;
    --warmup) warmup=$2; shift 2 ;;
    --v4) v4=$2; shift 2 ;;
    --ng) ng=$2; shift 2 ;;
    --bindings) bindings=$2; shift 2 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
lg=${LOADGEN:-$repo/target/release/loadgen}
[[ -x $lg ]] || (cd "$repo" && cargo build --release -p loadgen)
out=$bench/out/http-$(date -u +%Y%m%dT%H%M%SZ) && mkdir -p "$out"
python3 -I "$bench/http_mix.py" --bindings "$bindings" > "$out/mix.tsv"

ng_pid() { ss -ltnp "sport = :${ng##*:}" | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2; }
mem() {
  case $1 in
    ng) awk '/^VmRSS:/ {print $2}' "/proc/$(ng_pid)/status" ;;
    v4) docker stats --no-stream --format '{{.Name}} {{.MemUsage}}' \
          | awk '/irrd-parity-(irrd-v4|redis|postgres)-1/ {v=$2; u=1; if (v ~ /GiB/) u=1048576; else if (v ~ /MiB/) u=1024; sub(/[A-Za-z]+/, "", v); s+=v*u} END {printf "%d\n", s}' ;;
  esac
}

printf 'server\tconcurrency\tqps\tp50_us\tp99_us\terrors\tmax_mem_kib\n' > "$out/summary.tsv"
for server in v4 ng; do
  target=${!server}
  "$lg" --target "$target" --mix "$out/mix.tsv" --concurrency 4 --duration "$warmup" --warmup 0 > /dev/null
  for c in $conc; do
    : > "$out/mem-$server-c$c.tsv"
    ( while sleep 2; do mem "$server" >> "$out/mem-$server-c$c.tsv"; done ) & sampler=$!
    "$lg" --target "$target" --mix "$out/mix.tsv" --concurrency "$c" --duration "$duration" --warmup "$warmup" \
      > "$out/$server-c$c.json"
    kill "$sampler" 2>/dev/null || true
    python3 -I - "$out/$server-c$c.json" "$out/mem-$server-c$c.tsv" "$server" "$c" >> "$out/summary.tsv" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))["total"]
mem = [int(x) for x in open(sys.argv[2]).read().split() if x.isdigit()]
print(f"{sys.argv[3]}\t{sys.argv[4]}\t{r['qps']:.0f}\t{r['p50_us']}\t{r['p99_us']}\t{r['errors']}\t{max(mem) if mem else 0}")
PY
  done
done
column -t "$out/summary.tsv"
