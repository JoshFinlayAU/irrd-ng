#!/usr/bin/env bash
# Real-client check: run bgpq4 (and peval, when installed) against v4 and
# irrd-ng with common flag sets over the largest and deepest sets in the
# data, and diff their output and exit codes.
#
#   parity/bgpq4.sh [--ref HOST:PORT] [--test HOST:PORT] [--bindings FILE]
#                   [--sets N] [--targets "SET ..."] [--out DIR] [--redact]
#
# Defaults are the Tier 1 targets (v4 127.0.0.1:9043, irrd-ng
# 127.0.0.1:$NG_WHOIS_PORT) and the bindings parity/load.sh wrote. Targets:
# the N (default 5) largest AS-sets, the deepest AS-sets and route-sets,
# and the busiest origins. bgpq4 sorts and aggregates what it receives, so
# its output is deterministic even where v4's answer order is not (P-13):
# every difference here is a real one. --redact keeps generated filters out
# of the report (Tier 2). Exit 0 when every run matches.
set -euo pipefail
cd "$(dirname "$0")"
parity=$PWD
ref=127.0.0.1:9043 test=127.0.0.1:${NG_WHOIS_PORT:-8043}
bindings=${PARITY_WORK:-$parity/.work}/tier1/bindings.json n=5 out= redact=0 targets_arg=
while [[ $# -gt 0 ]]; do
  case $1 in
    --ref) ref=$2; shift 2 ;;
    --test) test=$2; shift 2 ;;
    --bindings) bindings=$2; shift 2 ;;
    --sets) n=$2; shift 2 ;;
    --targets) targets_arg=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    --redact) redact=1; shift ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
command -v bgpq4 > /dev/null || { echo "bgpq4 not installed (apt install bgpq4)" >&2; exit 2; }
out=${out:-$parity/out/bgpq4-$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$out/v4" "$out/ng"

# Targets and the two sources -S uses, from the bindings.
mapfile -t targets < <(python3 -I - "$bindings" "$n" <<'PY'
import json, sys
b = json.load(open(sys.argv[1])); n = int(sys.argv[2])
seen = []
for key, k in (("as_set_large", n), ("as_set_deep", 3), ("route_set_deep", 2), ("origin_many4", 2), ("origin_many6", 1)):
    for v in b.get(key, [])[:k]:
        if v not in seen:
            seen.append(v)
print("\n".join(seen))
PY
)
if [[ -n $targets_arg ]]; then read -ra targets <<< "$targets_arg"; fi
srcs=$(python3 -I -c "import json,sys; print(','.join(json.load(open(sys.argv[1]))['source'][:2]))" "$bindings")

flagsets=(
  "-4"
  "-6"
  "-4 -A"
  "-6 -A"
  "-4 -S $srcs"
  "-4 -J -l parity"
  "-6 -j"
  "-4 -F %n/%l\n"
  "-4 -m 24 -A"
  "-6 -R 48"
  "-4 -E"
  "-3 -f 64496"
  "-G 64496"
  "-H 64496"
  "-4 -L 2"
)

run() { # host:port flags target outfile
  local hp=$1 flags=$2 target=$3 file=$4 rc=0
  # shellcheck disable=SC2086
  timeout 900 bgpq4 -h "$hp" $flags "$target" > "$file" 2> "$file.err" || rc=$?
  echo "$rc" > "$file.rc"
}

total=0 same=0
: > "$out/results.tsv"
for target in "${targets[@]}"; do
  for flags in "${flagsets[@]}"; do
    # Single ASNs only make sense for prefix lists.
    if [[ $target =~ ^AS[0-9]+$ && $flags =~ -[fGHL3] ]]; then continue; fi
    key=$(printf '%s %s' "$flags" "$target" | tr -c 'A-Za-z0-9.-' '_')
    run "$ref" "$flags" "$target" "$out/v4/$key" &
    run "$test" "$flags" "$target" "$out/ng/$key" &
    wait
    total=$((total + 1))
    if cmp -s "$out/v4/$key" "$out/ng/$key" && cmp -s "$out/v4/$key.rc" "$out/ng/$key.rc"; then
      same=$((same + 1)); verdict=same
    else
      verdict=DIFFER
    fi
    printf '%s\t%s\t%s\t%s/%s\t%s/%s\n' "$verdict" "$flags" "$target" \
      "$(cat "$out/v4/$key.rc")" "$(cat "$out/ng/$key.rc")" \
      "$(wc -l < "$out/v4/$key")" "$(wc -l < "$out/ng/$key")" >> "$out/results.tsv"
    if [[ $verdict == DIFFER && $redact == 0 ]]; then
      { echo "=== bgpq4 $flags $target (exit v4 $(cat "$out/v4/$key.rc"), irrd-ng $(cat "$out/ng/$key.rc"))"
        diff "$out/v4/$key" "$out/ng/$key" | head -20; echo; } >> "$out/diffs.txt"
    fi
  done
done

# peval (IRRToolSet, built from source; no Debian package), if on PATH:
# the same targets as filter expressions, IPv4 and IPv6.
if command -v peval > /dev/null; then
  for target in "${targets[@]}"; do
    for expr in "$target" "afi ipv6.unicast $target"; do
      key=peval_$(printf '%s' "$expr" | tr -c 'A-Za-z0-9.-' '_')
      for side in v4 ng; do
        hp=$ref; [[ $side == ng ]] && hp=$test
        rc=0
        timeout 900 peval -h "${hp%:*}" -p "${hp#*:}" "$expr" > "$out/$side/$key" 2> "$out/$side/$key.err" || rc=$?
        echo "$rc" > "$out/$side/$key.rc"
      done
      total=$((total + 1))
      if cmp -s "$out/v4/$key" "$out/ng/$key" && cmp -s "$out/v4/$key.rc" "$out/ng/$key.rc"; then
        same=$((same + 1)); verdict=same
      else verdict=DIFFER; fi
      printf '%s\tpeval\t%s\t%s/%s\t%s/%s\n' "$verdict" "$expr" "$(cat "$out/v4/$key.rc")" "$(cat "$out/ng/$key.rc")" \
        "$(wc -l < "$out/v4/$key")" "$(wc -l < "$out/ng/$key")" >> "$out/results.tsv"
    done
  done
else
  echo "peval not installed; skipped" > "$out/peval-skipped"
fi

if [[ $redact == 1 ]]; then rm -rf "$out/v4" "$out/ng"; fi
echo "bgpq4/peval: $total runs, $same identical, $((total - same)) differ (v4 $ref, irrd-ng $test); $out/results.tsv"
[[ $same == "$total" ]]
