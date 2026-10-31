# Tier 2: the full corpus at production scale

A frozen IRRd v4 4.5.4 and irrd-ng, both serving the same restored
production reference database on the parity VM, replayed with the whole
corpus. Host names and addresses are not kept here; the scripts take them
from the environment.

Layout on the VM (`$TIER2_DIR`, default `/srv/irrd-ng/tier2`): a copy of
`whois.sh`, `bgpq4.sh`, `tools/`, `corpus/whois/`, `tier2/`, `bench/`, and
`bin/irrd-ng`, `bin/loadgen`.

- **Reference database** (`TIER2_REF_DB`, default `irrd`) in the Postgres
  container `TIER2_PG_CONTAINER`. Only ever read: by the irrd-ng import and
  as the template for v4's copy.
- **v4** (`setup.sh start-v4`): container `tier2-v4`, host network, whois
  127.0.0.1:9043, HTTP :9080, on its own copy `irrd_v4` (`CREATE DATABASE
  ... TEMPLATE`, made once) and its own Redis (`tier2-redis`, :9379).
  Frozen by `irrd-tier2.yaml`: no import_source or nrtm_host anywhere, and
  `rpki.roa_import_timer` past the Unix time so the ROA importer never runs,
  while `roa_source` stays set so v4 is RPKI-aware exactly as the reference.
  The HTTP preload race is worked around (see `../v4/preload-kick.sh`).
- **irrd-ng** (`setup.sh start-ng`): whois 127.0.0.1:8043, HTTP :8080, on a
  store imported from the reference with `irrd-ng import --from-postgres`
  (`TIER2_NG_STORE`).
- Both use `server.whois.max_connections: 10` (v4's default). Each v4 worker
  is a process holding the whole preload; 32 of them exhausted 16 GB.

```sh
export TIER2_PG_CONTAINER=<pg container> TIER2_NG_STORE=<store>
tier2/setup.sh start
tier2/run-tier2.sh --scale 4      # whois + http suites, bgpq4/peval sweep, all --redact
bench/load.sh                     # the load bench (bench/README.md)
```

The database holds production auth tables and personal data. Reports stay on
the VM under `out/`, are written with `--redact` (no response bytes, only
offsets, lengths and hashes), and only `summary.txt` and `results.tsv`
counts are read from outside. Nothing from the database or a response is
copied off the VM or into git.
