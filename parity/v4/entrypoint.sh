#!/bin/sh
# Bring the schema to head, then run IRRd in the foreground.
set -e
until pg_isready -q -h postgres -U irrd; do sleep 1; done
irrd_database_upgrade --config /etc/irrd/irrd.yaml
exec irrd --foreground --config /etc/irrd/irrd.yaml
