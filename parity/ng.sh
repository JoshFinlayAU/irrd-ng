#!/usr/bin/env bash
# Run irrd-ng for the Tier 1 suites on the store parity/load.sh built.
#
#   parity/ng.sh start|stop|status|config
#
# Uses v4/irrd-whois.yaml with only what has to differ on the host changed:
# listen on 127.0.0.1, ports NG_WHOIS_PORT (default 8043) and NG_HTTP_PORT
# (default 8080), piddir and keyring under $PARITY_WORK/tier1. The store is
# $PARITY_WORK/tier1/store (IRRD_NG_STORE_PATH). Logs go to irrd-ng.log there.
set -euo pipefail
cd "$(dirname "$0")"
parity=$PWD
repo=$(cd .. && pwd)
IRRD_NG=${IRRD_NG:-$repo/target/release/irrd-ng}
work=${PARITY_WORK:-$parity/.work}/tier1
wport=${NG_WHOIS_PORT:-8043} hport=${NG_HTTP_PORT:-8080}
pidfile=$work/irrd-ng.harness.pid

config() {
  mkdir -p "$work/gnupg" "$work/run"
  python3 -I - "$parity/v4/irrd-whois.yaml" "$work/irrd-ng.yaml" "$work" "$wport" "$hport" <<'PY'
import sys
src, out, work, wport, hport = sys.argv[1:]
t = open(src).read()
t = t.replace("piddir: /run/irrd", f"piddir: {work}/run")
t = t.replace("gnupg_keyring: /var/lib/irrd/gnupg", f"gnupg_keyring: {work}/gnupg")
t = t.replace("      interface: 0.0.0.0\n      port: 8080", f"      interface: 127.0.0.1\n      port: {hport}")
t = t.replace("      interface: 0.0.0.0\n      port: 8043", f"      interface: 127.0.0.1\n      port: {wport}")
open(out, "w").write(t)
PY
}

answering() { [[ $(./whois.sh 127.0.0.1 "$wport" '!v' 2>/dev/null) == A* ]]; }

case ${1:-status} in
  config) config ;;
  start)
    if answering; then echo "irrd-ng already answering on $wport"; exit 0; fi
    [[ -d $work/store ]] || { echo "no store at $work/store; run parity/load.sh" >&2; exit 2; }
    config
    IRRD_NG_STORE_PATH=$work/store nohup "$IRRD_NG" irrd --config "$work/irrd-ng.yaml" --foreground \
      > "$work/irrd-ng.log" 2>&1 &
    echo $! > "$pidfile"
    for _ in $(seq 1 60); do
      if answering; then echo "irrd-ng answering on 127.0.0.1:$wport (pid $(cat "$pidfile"))"; exit 0; fi
      kill -0 "$(cat "$pidfile")" 2>/dev/null || break
      sleep 1
    done
    echo "irrd-ng did not answer !v on $wport; log:" >&2
    tail -20 "$work/irrd-ng.log" >&2
    exit 1
    ;;
  stop)
    if [[ -f $pidfile ]] && kill "$(cat "$pidfile")" 2>/dev/null; then
      for _ in $(seq 1 20); do kill -0 "$(cat "$pidfile")" 2>/dev/null || break; sleep 0.5; done
      echo "irrd-ng stopped"
    fi
    rm -f "$pidfile"
    ;;
  status)
    if answering; then ./whois.sh 127.0.0.1 "$wport" '!v'; else echo "irrd-ng not answering on $wport"; exit 1; fi ;;
  *) echo "usage: ng.sh start|stop|status|config" >&2; exit 2 ;;
esac
