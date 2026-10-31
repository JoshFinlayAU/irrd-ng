#!/usr/bin/env bash
# Tier 2 on the parity VM: a frozen v4 4.5.4 and irrd-ng over the same
# restored production reference database. Runs on the VM, from a copy of
# parity/ at $TIER2_DIR (default /srv/irrd-ng/tier2).
#
#   tier2/setup.sh start|stop|status
#
# Env (all have defaults matching the VM layout):
#   TIER2_PG_CONTAINER  the reference Postgres container (required)
#   TIER2_REF_DB        reference database, never written (default irrd)
#   TIER2_V4_DB         v4's own copy, made with CREATE DATABASE ... TEMPLATE
#                       on first start (default irrd_v4)
#   TIER2_NG_STORE      irrd-ng store imported from the reference (required)
#   TIER2_NG_BIN        irrd-ng binary (default $TIER2_DIR/bin/irrd-ng)
#   TIER2_MAX_CONN      server.whois.max_connections for both (default 10, v4's
#                       default; every v4 worker is a process holding the whole
#                       preload, so more workers do not fit in 16 GB)
# Ports: v4 whois 9043 / http 9080, irrd-ng 8043 / 8080, v4's Redis 9379,
# all on 127.0.0.1. Nothing here leaves the VM.
#
# v4 never touches the reference database: it runs on a template copy, with
# no mirroring and the ROA importer disabled (irrd-tier2.yaml), so its
# objects, ROAs and statuses stay those the irrd-ng store was imported from.
set -euo pipefail
dir=${TIER2_DIR:-/srv/irrd-ng/tier2}
pg=${TIER2_PG_CONTAINER:?set TIER2_PG_CONTAINER}
refdb=${TIER2_REF_DB:-irrd} v4db=${TIER2_V4_DB:-irrd_v4}
store=${TIER2_NG_STORE:?set TIER2_NG_STORE}
ngbin=${TIER2_NG_BIN:-$dir/bin/irrd-ng}
maxconn=${TIER2_MAX_CONN:-10}
run=$dir/run
image=irrd-ng-parity/irrd-v4:4.5.4
redis_image=redis:8.0.2-alpine@sha256:48501c5ad00d5563bc30c075c7bcef41d7d98de3e9a1e6c752068c66f0a8463b
mkdir -p "$run/v4" "$run/ng/gnupg"

render() { # out db_url redis_url piddir http whois
  sed -e "s#@DATABASE_URL@#$2#; s#@REDIS_URL@#$3#; s#@PIDDIR@#$4#g; s#@HTTP_PORT@#$5#; s#@WHOIS_PORT@#$6#; s#@MAX_CONNECTIONS@#$maxconn#" \
    "$dir/tier2/irrd-tier2.yaml" > "$1"
}
answers() { [[ $(timeout 10 "$dir/whois.sh" 127.0.0.1 "$1" '!v' 2>/dev/null) == A* ]]; }

start_v4() {
  if ! docker exec "$pg" psql -U irrd -d postgres -Atc "SELECT 1 FROM pg_database WHERE datname='$v4db'" | grep -q 1; then
    echo "copying $refdb to $v4db (template copy; $refdb is only read)"
    docker exec "$pg" psql -U irrd -d postgres -c "CREATE DATABASE $v4db TEMPLATE $refdb"
  fi
  docker rm -f tier2-redis tier2-v4 > /dev/null 2>&1 || true
  docker run -d --name tier2-redis -p 127.0.0.1:9379:6379 "$redis_image" > /dev/null
  render "$run/v4/irrd.yaml" "postgresql://irrd:irrd@127.0.0.1:5432/$v4db" redis://127.0.0.1:9379 /tmp 9080 9043
  chmod 644 "$run/v4/irrd.yaml"
  docker run -d --name tier2-v4 --network host -v "$run/v4/irrd.yaml:/etc/irrd/irrd.yaml:ro" \
    --entrypoint irrd "$image" --foreground --config /etc/irrd/irrd.yaml > /dev/null
  for _ in $(seq 1 180); do answers 9043 && break; sleep 2; done
  answers 9043 || { docker logs --tail 30 tier2-v4 >&2; exit 1; }
  # The HTTP preload race (parity/v4/preload-kick.sh), and wait for !g to answer.
  for _ in $(seq 1 60); do
    [[ $(curl -s -m 5 -H 'Host: localhost' 'http://127.0.0.1:9080/v1/whois/?q=!v') == IRRd* ]] && break; sleep 2
  done
  docker exec tier2-v4 python3 -c "
from irrd.conf import config_init
config_init('/etc/irrd/irrd.yaml')
from irrd.storage.preload import Preloader
Preloader(enable_queries=False).signal_reload()"
  for _ in $(seq 1 120); do
    code=$(curl -s -m 30 -o /dev/null -w '%{http_code}' -H 'Host: localhost' 'http://127.0.0.1:9080/v1/whois/?q=!gAS0' || true)
    [[ $code == 200 || $code == 204 ]] && break; sleep 2
  done
  echo "v4: $(timeout 10 "$dir/whois.sh" 127.0.0.1 9043 '!v' | sed -n 2p) on 9043/9080"
}

start_ng() {
  if [[ -f $run/ng/pid ]] && kill -0 "$(cat "$run/ng/pid")" 2>/dev/null && answers 8043; then
    echo "irrd-ng: already running, pid $(cat "$run/ng/pid")"; return
  fi
  render "$run/ng/irrd.yaml" postgresql://unused/irrd redis://unused "$run/ng" 8080 8043
  IRRD_NG_STORE_PATH=$store nohup "$ngbin" irrd --config "$run/ng/irrd.yaml" --foreground > "$run/ng/irrd-ng.log" 2>&1 &
  echo $! > "$run/ng/pid"
  for _ in $(seq 1 120); do answers 8043 && break; sleep 1; done
  answers 8043 || { tail -20 "$run/ng/irrd-ng.log" >&2; exit 1; }
  echo "irrd-ng: pid $(cat "$run/ng/pid") on 8043/8080"
}

case ${1:-status} in
  start) start_v4; start_ng ;;
  start-v4) start_v4 ;;
  start-ng) start_ng ;;
  stop-v4) docker rm -f tier2-v4 tier2-redis > /dev/null 2>&1 || true ;;
  stop-ng) [[ -f $run/ng/pid ]] && kill "$(cat "$run/ng/pid")" 2>/dev/null || true ;;
  stop) "$0" stop-v4; "$0" stop-ng ;;
  status)
    answers 9043 && echo "v4 up" || echo "v4 down"
    answers 8043 && echo "irrd-ng up" || echo "irrd-ng down" ;;
  *) echo "usage: setup.sh start|stop|status|start-v4|start-ng|stop-v4|stop-ng" >&2; exit 2 ;;
esac
