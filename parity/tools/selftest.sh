#!/usr/bin/env bash
# Prove the whois harness against v4 alone, before irrd-ng serves anything:
#
#  1. v4 vs the same v4: every item must be identical (harness determinism).
#  2. v4 vs v4 through a transparent proxy: identical (the proxy is honest).
#  3. v4 vs v4 through a proxy that injects differences: the run must fail,
#     and each injected kind must be reported.
#
# Needs the Tier 1 stack loaded (parity/load.sh). Uses ports 9343-9346.
set -euo pipefail
cd "$(dirname "$0")/.."
out=${PARITY_WORK:-$PWD/.work}/selftest
rm -rf "$out" && mkdir -p "$out"
pids=()
trap 'kill "${pids[@]}" 2>/dev/null || true' EXIT
proxy() { python3 -I tools/fault_proxy.py --listen "127.0.0.1:$1" --target 127.0.0.1:9043 "${@:2}" & pids+=($!); }

proxy 9343
# A one-byte change inside object text, an extra byte after an IRRd frame
# (keepalive framing), a wrong A<len>, and a changed error string.
proxy 9344 --sub 'route:  ' 'route:x '
proxy 9345 --sub '\nC\n' '\nC\n\n'
proxy 9346 --sub '^A([0-9])' 'A9\1' --sub 'F Missing' 'F missing'
sleep 1

fail=0
check() {
  local name=$1 want=$2 test=$3
  if ./run.sh --test "$test" --out "$out/$name" > "$out/$name.log" 2>&1; then got=pass; else got=fail; fi
  printf '%-12s expect %-4s got %-4s  %s\n' "$name" "$want" "$got" "$(head -1 "$out/$name/summary.txt")"
  [[ $got == "$want" ]] || fail=1
}
check same pass 127.0.0.1:9043
check proxy pass 127.0.0.1:9343
check obj-byte fail 127.0.0.1:9344
check frame fail 127.0.0.1:9345
check len-err fail 127.0.0.1:9346
grep -h '^differences by reason' "$out"/*/summary.txt | sed 's/^/  /'
exit $fail
