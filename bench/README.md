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
TIER2_PG_CONTAINER=<pg container> TIER2_NG_STORE=<store> bench/load.sh --concurrency "8 32" --duration 60
```

`cargo bench -p query` (criterion micro-benchmarks) is separate and not yet
written.
