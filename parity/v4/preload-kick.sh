#!/usr/bin/env bash
# Work around a v4 startup race: a worker's Preloader only loads the route
# and set preload data when it receives a reload message, and v4 sends one
# when its first preload completes. HTTP workers that subscribe after that
# (uvicorn starts them a few seconds later) block every !g, !6, !a and !i
# answer until the next database change. This waits for HTTP to answer and
# then publishes one reload, the same message a database commit sends.
#
#   v4/preload-kick.sh <compose service> <host http port>
set -euo pipefail
cd "$(dirname "$0")/.."
service=$1 port=$2
for _ in $(seq 1 60); do
  [[ $(curl -s -m 5 -H 'Host: localhost' "http://127.0.0.1:$port/v1/whois/?q=!v" 2>/dev/null) == IRRd* ]] && break
  sleep 1
done
docker compose --profile twin exec -T "$service" python3 -c "
from irrd.conf import config_init
config_init('/etc/irrd/irrd.yaml')
from irrd.storage.preload import Preloader
Preloader(enable_queries=False).signal_reload()
"
for _ in $(seq 1 60); do
  code=$(curl -s -m 5 -o /dev/null -w '%{http_code}' -H 'Host: localhost' "http://127.0.0.1:$port/v1/whois/?q=!gAS0" || true)
  [[ $code == 204 ]] && exit 0
  sleep 1
done
echo "v4 ($service) HTTP preload still not answering !gAS0" >&2
exit 1
