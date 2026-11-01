# Load bench

`bench/load.sh` measures whois throughput, latency and server memory for v4
and irrd-ng on the same data with the same query mix. It runs on the Tier 2
parity VM (production-scale reference data, `parity/tier2/`), one server at
a time so they never share CPU or page cache.

- `loadgen/` is a std-only Rust closed-loop load generator: N worker threads,
  each sending one query and reading the whole answer before the next, with
  per-class p50/p90/p99/max latency and QPS. Single queries use a new
  connection each (the server closes after the answer); keepalive classes
  keep one `!!` connection per worker and read answers by v4's framing.
- `mix.py` builds the mix from the corpus bindings: 40% single lookups
  (`!m`, `-x`, `!r...,o`, free text, `!i`), 20% single `!g`/`!6`, 20%
  keepalive `!g`+`!6` for every member AS of the five largest AS-sets (the
  members come from v4's `!i<set>,1`, the way `bgpq4 -L` style clients
  work), 5% `!a4`/`!a6` and 5% `!i<set>,1` on those sets, 10% bgpq4's
  `!s-lc`/`!a4`/`!s` sequence.
- Memory: v4 is the sum over its processes, Redis and the Postgres backends
  (RSS, and PSS so shared memory counts once); irrd-ng is its one process,
  split into anonymous memory and file-backed pages of the mmap'd store
  (page cache the kernel can reclaim).

```sh
# on the VM, after parity/tier2/setup.sh and run-tier2.sh (for the bindings)
TIER2_PG_CONTAINER=<pg container> TIER2_NG_STORE=<store> bench/load.sh --concurrency "4 10" --duration 60
```

`cargo bench -p query` (criterion micro-benchmarks) is separate and not yet
written.

## HTTP API

`bench/http_load.sh` does the same for the HTTP side: GraphQL lookups of the kinds irrexplorer sends (`rpslObjects` by prefix and origin, `asnPrefixes`, primary keys with `mntByObjs`), set expansion over GraphQL, `/v1/whois/`, `/v1/status/` and `/metrics/`, mixed by `bench/http_mix.py` from the corpus bindings. `loadgen` sends them in its `http` mode (one request per connection). It runs against the Tier 1 stack by default (v4 on 9080, irrd-ng on 8080), one server after the other, sampling irrd-ng's RSS and the memory of v4's containers (v4, Redis, PostgreSQL).

```sh
parity/load.sh && parity/ng.sh start
bench/http_load.sh --concurrency "4 16" --duration 30
```

## Tier 1

`bench/tier1_load.sh` runs the whois mix (`mix.py`), the REST part and the GraphQL part of the HTTP mix (`http_mix.py`) against both servers on the Tier 1 stack, one server and one mix at a time, at several concurrency levels. It reports QPS, p50, p99, the slowest answer and how many answers took 500 ms or more, and samples memory every second (irrd-ng's RSS and anonymous RSS; for v4 its three containers). This is the bench that runs on a development box; the numbers and how they were taken are in `bench/RESULTS.md`.

```sh
parity/up.sh && parity/load.sh && parity/ng.sh start
bench/tier1_load.sh --concurrency "4 16 64" --duration 20
```

## Large write transactions

`bench/large_txn.sh DUMP` loads one dump into a store of its own with `irrd_load_database` and then rewrites every object twice with `irrd_update_database` (each one transaction, journalled), reporting wall time, CPU time, peak RSS, peak anonymous RSS and the map and data file size after each step.

```sh
bench/large_txn.sh parity/.cache/RADB.db.gz
```
