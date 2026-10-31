#!/usr/bin/env bash
# First load bench: whois QPS, p50/p99 latency and server memory for v4 and
# irrd-ng on the same data and the same query mix (PLAN.md Phase 3, item 5).
# Runs on the Tier 2 VM after parity/tier2/setup.sh; see bench/README.md.
#
#   bench/load.sh [--concurrency "4 10"] [--duration S] [--warmup S] [--servers "v4 ng"]
#                 [--big-set AS-SET ...]
#
# Each --big-set is also timed alone, unloaded: !a4, !a6 and !i<set>,1 over
# one keepalive connection (5 runs each, median), and `bgpq4 -4` end to end.
#
# Per server, one at a time (the other is stopped, so they never share the
# page cache or CPU): start it, run the mix once unmeasured to warm caches,
# then one measured run per concurrency level while sampling memory every
# 2 s, plus one run of the light classes alone at concurrency 10. Memory:
#   v4      sum of RSS and of PSS over the irrd processes (tier2-v4), Redis,
#           and the Postgres backends (PSS shares shared_buffers fairly)
#   irrd-ng RSS of the one process, split into anonymous and file-backed
#           (the mmap'd store, reclaimable page cache)
# Output: $TIER2_DIR/out/bench-<stamp>/{mix.tsv,<server>-c<N>.json,mem-*.tsv,summary.tsv}
set -euo pipefail
dir=${TIER2_DIR:-/srv/irrd-ng/tier2}
pg=${TIER2_PG_CONTAINER:?set TIER2_PG_CONTAINER}
conc="4 10" duration=60 warmup=20 servers="v4 ng" big=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --concurrency) conc=$2; shift 2 ;;
    --duration) duration=$2; shift 2 ;;
    --warmup) warmup=$2; shift 2 ;;
    --servers) servers=$2; shift 2 ;;
    --big-set) big+=("$2"); shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
cd "$dir"
out=$dir/out/bench-$(date -u +%Y%m%dT%H%M%SZ) && mkdir -p "$out"
lg=$dir/bin/loadgen

kib() { awk -v k="$1" '$1 == k":" {print $2}' "$2" 2>/dev/null || echo 0; }
pss() { awk '/^Pss:/ {print $2}' "/proc/$1/smaps_rollup" 2>/dev/null || echo 0; }
mem_sample() { # server -> "rss_kib pss_kib anon_kib file_kib"
  local rss=0 p=0 anon=0 file=0 pid
  if [[ $1 == v4 ]]; then
    for pid in $(docker top tier2-v4 -eo pid | tail -n +2) $(docker top tier2-redis -eo pid | tail -n +2) \
               $(docker top "$pg" -eo pid | tail -n +2); do
      rss=$((rss + $(kib VmRSS /proc/$pid/status))); p=$((p + $(pss "$pid")))
    done
  else
    pid=$(cat "$dir/run/ng/pid")
    rss=$(kib VmRSS /proc/$pid/status); p=$(pss "$pid")
    anon=$(kib RssAnon /proc/$pid/status); file=$(kib RssFile /proc/$pid/status)
  fi
  echo "$rss $p $anon $file"
}

port() { [[ $1 == v4 ]] && echo 9043 || echo 8043; }

# The mix comes from the Tier 2 bindings, expanded against v4 (same answers).
tier2/setup.sh start-v4 > /dev/null
bigargs=()
for b in "${big[@]}"; do bigargs+=(--big-set "$b"); done
python3 -I bench/mix.py --bindings "$dir/run/work/bindings.json" --expand 127.0.0.1:9043 --sets 5 "${bigargs[@]}" > "$out/mix.tsv"
printf 'server\tset\tcommand\tmedian_ms\tmin_ms\tmax_ms\n' > "$out/big.tsv"
printf 'server\tconcurrency\tqps\tp50_us\tp99_us\terrors\tmem_rss_peak_kib\tmem_pss_peak_kib\tng_anon_peak_kib\tng_file_peak_kib\n' > "$out/summary.tsv"
for s in $servers; do
  if [[ $s == v4 ]]; then tier2/setup.sh stop-ng; tier2/setup.sh start-v4; else tier2/setup.sh stop-v4; tier2/setup.sh start-ng; fi
  sync; echo "$s: idle $(mem_sample "$s")" | tee -a "$out/mem-idle.tsv"
  "$lg" --target "127.0.0.1:$(port "$s")" --mix "$out/mix.tsv" --concurrency 8 --duration "$warmup" --warmup 0 > "$out/$s-warmup.json"
  for b in "${big[@]}"; do
    for cmd in "!a4$b" "!a6$b" "!i$b,1"; do
      printf '1\tbig\tkeepalive\t%s\n' "$cmd" > "$out/one.tsv"
      ms=()
      for _ in 1 2 3 4 5; do
        ms+=("$("$lg" --target "127.0.0.1:$(port "$s")" --mix "$out/one.tsv" --concurrency 1 --count 1 --warmup 0 \
          | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["total"]["max_us"]/1000)')")
      done
      printf '%s\t%s\t%s\t%s\n' "$s" "$b" "$cmd" "$(printf '%s\n' "${ms[@]}" | sort -n | awk '{a[NR]=$1} END {print a[3]"\t"a[1]"\t"a[5]}')" >> "$out/big.tsv"
    done
    ms=()
    for _ in 1 2 3; do
      t0=$(date +%s%N); bgpq4 -h "127.0.0.1:$(port "$s")" -4 "$b" > /dev/null; ms+=($(( ($(date +%s%N) - t0) / 1000000 )))
    done
    printf '%s\t%s\tbgpq4 -4\t%s\n' "$s" "$b" "$(printf '%s\n' "${ms[@]}" | sort -n | awk '{a[NR]=$1} END {print a[2]"\t"a[1]"\t"a[3]}')" >> "$out/big.tsv"
  done
  # The light classes alone (single lookups, !g/!6, per-member !g/!6): the
  # mixed run is dominated by the multi-second large-set answers.
  awk -F'\t' '$2 == "lookup" || $2 == "origin" || $2 == "setmembers"' "$out/mix.tsv" > "$out/mix-light.tsv"
  ( while :; do echo "$(date +%s) $(mem_sample "$s")"; sleep 2; done ) > "$out/mem-$s-light.tsv" &
  sampler=$!
  "$lg" --target "127.0.0.1:$(port "$s")" --mix "$out/mix-light.tsv" --concurrency 10 --duration "$duration" --warmup 5 > "$out/$s-light-c10.json"
  kill "$sampler"
  python3 -I - "$out/$s-light-c10.json" "$out/mem-$s-light.tsv" "$s" light-c10 >> "$out/summary.tsv" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))["total"]
m = [list(map(int, l.split()[1:])) for l in open(sys.argv[2]) if len(l.split()) == 5]
peak = [max(x[i] for x in m) if m else 0 for i in range(4)]
print("\t".join(map(str, [sys.argv[3], sys.argv[4], r["qps"], r["p50_us"], r["p99_us"], r["errors"], *peak])))
PY
  for c in $conc; do
    ( while :; do echo "$(date +%s) $(mem_sample "$s")"; sleep 2; done ) > "$out/mem-$s-c$c.tsv" &
    sampler=$!
    "$lg" --target "127.0.0.1:$(port "$s")" --mix "$out/mix.tsv" --concurrency "$c" --duration "$duration" --warmup 5 > "$out/$s-c$c.json"
    kill "$sampler"
    python3 -I - "$out/$s-c$c.json" "$out/mem-$s-c$c.tsv" "$s" "$c" >> "$out/summary.tsv" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))["total"]
m = [list(map(int, l.split()[1:])) for l in open(sys.argv[2]) if len(l.split()) == 5]
peak = [max(x[i] for x in m) if m else 0 for i in range(4)]
print("\t".join(map(str, [sys.argv[3], sys.argv[4], r["qps"], r["p50_us"], r["p99_us"], r["errors"], *peak])))
PY
  done
done
tier2/setup.sh start > /dev/null
column -t "$out/summary.tsv"
column -t -s $'\t' "$out/big.tsv"
echo "results: $out"
