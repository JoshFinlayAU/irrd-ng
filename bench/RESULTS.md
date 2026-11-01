# Load bench results

Numbers from the Phase 10 performance work, irrd-ng against IRRd v4.5.4 on the same data. Every figure here was measured with the scripts in `bench/` and `parity/status/roa-bench.sh`; how each was taken is described next to it. The production-size bench on the Tier 2 VM (`bench/load.sh`) was not run this time, because the VM was busy with the soak test.

## Machine and method

- One development box: 16 vCPUs (Intel Xeon Gold 6140, 2.3 GHz, a VM), 31 GB RAM, Debian with kernel 6.12, a virtio disk shared with several other workloads. Other builds and test runs were going on at the same time, so absolute numbers move between runs; comparisons were taken close together and repeated where they looked odd.
- v4: the pinned 4.5.4 reference stack from `parity/compose.yaml` (v4 in Docker with its PostgreSQL 18.6 and Redis 8.0.2), whois `max_connections: 10`, four HTTP workers, as the parity harness runs it.
- irrd-ng: the release build (fat LTO, mimalloc), started by `parity/ng.sh` with the same `irrd.yaml` and the same `max_connections: 10`, logging to a file as v4 does.
- Data: the Tier 1 data set, `parity/load.sh --profile rpki` (37,257 objects in 13 sources, 12,077 ROAs; irrd-ng's store is imported from v4's database, so both hold the same rows).
- Disk: wall times of anything that writes to disk (imports, loads, the ROA job) vary by a factor of several on this box, because the disk is shared and fsync latency follows whatever else is running. Where that matters, CPU time is given as well.

## Queries: whois, REST and GraphQL

`bench/tier1_load.sh --concurrency "4 16 64" --duration 20 --warmup 5`: a closed-loop load generator (`bench/loadgen`) with N clients, each sending one query and reading the whole answer before the next. The whois mix is `bench/mix.py` (lookups, `!g`/`!6`, keepalive set expansion as bgpq4 does it, `!a`, `!i`, bgpq4 sessions); the REST mix is the `/v1/whois/`, `/v1/status/` and `/metrics/` part of `bench/http_mix.py`, and the GraphQL mix the GraphQL part (lookups by prefix, origin and key, `asnPrefixes`, set expansion). Servers ran one after the other. Memory is the peak while the run lasted: irrd-ng's RSS from `/proc` (anonymous memory in brackets, the rest is the memory-mapped store in the page cache); for v4 the sum over its three containers from `docker stats` (irrd-v4, Redis, PostgreSQL), which includes page cache they touched.

| mix | clients | v4 QPS | irrd-ng QPS | v4 p50 / p99 ms | irrd-ng p50 / p99 ms | v4 slowest ms | irrd-ng slowest ms (answers over 500 ms) | v4 memory | irrd-ng memory (anonymous) |
|---|---|---|---|---|---|---|---|---|---|
| whois | 4 | 882 | 3,259 | 3.4 / 22.4 | 0.2 / 16.5 | 150 | 48.8 (0) | 2,526 MiB | 214 MiB (173 MiB) |
| whois | 16 | 2,067 | 10,508 | 8.7 / 21.8 | 0.6 / 14.4 | 45.7 | 42.6 (0) | 2,528 MiB | 316 MiB (276 MiB) |
| whois | 64 | 1,828 | 5,719 | 47.7 / 72.9 | 6.6 / 19.1 | 102 | 9,458 (64) | 2,529 MiB | 347 MiB (307 MiB) |
| rest | 4 | 347 | 7,952 | 9.5 / 64.6 | 0.3 / 4.5 | 179 | 3,762 (4) | 2,539 MiB | 210 MiB (158 MiB) |
| rest | 16 | 1,071 | 27,473 | 12.6 / 72.3 | 0.4 / 3.9 | 207 | 15.4 (0) | 2,553 MiB | 149 MiB (97 MiB) |
| rest | 64 | 1,078 | 26,366 | 55.6 / 122 | 1.5 / 8.4 | 263 | 6,520 (64) | 2,568 MiB | 586 MiB (533 MiB) |
| graphql | 4 | 285 | 4,157 | 13.1 / 32.4 | 0.7 / 9.1 | 183 | 42.9 (0) | 2,573 MiB | 618 MiB (564 MiB) |
| graphql | 16 | 404 | 16,494 | 37.5 / 91.7 | 0.7 / 6.1 | 220 | 55.3 (0) | 2,580 MiB | 617 MiB (563 MiB) |
| graphql | 64 | 390 | 19,645 | 163 / 307 | 2.4 / 13.7 | 361 | 68.6 (0) | 2,589 MiB | 659 MiB (605 MiB) |

What the columns show: QPS over the 20 s, latency percentiles in milliseconds, the slowest single answer, and how many answers took 500 ms or more.

irrd-ng is ahead on every row: 3.1 to 5.1 times v4's whois QPS, 23 to 26 times on REST and 15 to 50 times on GraphQL, with a lower p50 and p99 throughout, in 6% to 26% of v4's memory. The three irrd-ng rows with multi-second answers (whois and REST at 64 clients, REST at 4) are the log file, not the queries: in those runs the log on this shared disk was written more slowly than the server produced records (the kernel throttled the writes; the box's I/O pressure stall figure was around 6%), the log writer's queue filled, and every thread waited for it, which shows as a gap with no records at all in the log's timestamps. With the same binary and the log on `/dev/null`, right after: whois at 64 clients 9,755 QPS, slowest answer 49 ms; REST at 64 clients 31,186 QPS, slowest 30 ms; no answer over 500 ms. An operator logging every query at INFO level on a slow disk will see the same; v4 logs the same lines and has the same exposure per worker process.

Before and after this work, irrd-ng alone, same bench (the "before" run is the branch point, 878318c):

| mix | clients | QPS before | QPS after | p99 ms before | p99 ms after | slowest ms before (over 500 ms) | slowest ms after (over 500 ms) |
|---|---|---|---|---|---|---|---|
| whois | 4 | 3,096 | 3,259 | 17.6 | 16.5 | 321 (0) | 48.8 (0) |
| whois | 16 | 6,320 | 10,508 | 21.1 | 14.4 | 927 (16) | 42.6 (0) |
| whois | 64 | 5,899 | 5,719 | 30.7 | 19.1 | 1,040 (129) | 9,458 (64) |
| rest | 4 | 9,567 | 7,952 | 3.7 | 4.5 | 244 (0) | 3,762 (4) |
| rest | 16 | 16,065 | 27,473 | 5.4 | 3.9 | 556 (16) | 15.4 (0) |
| rest | 64 | 21,220 | 26,366 | 11.0 | 8.4 | 687 (64) | 6,520 (64) |
| graphql | 4 | 3,461 | 4,157 | 6.7 | 9.1 | 6,599 (4) | 42.9 (0) |
| graphql | 16 | 9,473 | 16,494 | 9.2 | 6.1 | 749 (16) | 55.3 (0) |
| graphql | 64 | 13,243 | 19,645 | 21.4 | 13.7 | 91.8 (0) | 68.6 (0) |

The rows where "after" looks no better (whois and REST at 64 clients, REST at 4) are the runs the log file held up, as described above; an earlier run of the same changes, before the log writer's queue was enlarged, gave whois at 64 clients 9,548 QPS and REST at 64 clients 26,950 QPS, and the `/dev/null` control above gives 9,755 and 31,186.

### The stalls at maximum load

Phase 8 saw occasional answers taking 0.5 to 3.6 s at maximum load. The load generator's slow-answer count showed their shape: exactly one slow answer per client in a run, all about 0.9 s, so every worker stalled at the same moment. Two causes:

1. **Synchronous logging.** Every log record was written to the log file by the thread that logged it, under the handler's lock, and whois logs a line per answer. A write that the shared disk held up for a moment stopped every thread that logged meanwhile, which is every query. With the same binary logging to `/dev/null` the stalls were gone (max 60 ms). v4 does not see this as badly because each of its worker processes writes its own records. The daemon now hands records to a log-writer thread through a bounded queue; the text and order of the log are unchanged.
2. **The whois accept queue.** v4's listener keeps a queue of 50 pending connections. With 64 clients opening a connection per query it overflowed (the kernel's `ListenOverflows` counter rose), and a client whose connection was dropped retried after a second. irrd-ng now keeps a queue of 1024. v4 shows the same effect at 64 clients in the table above.

After both, whois at 16 clients went from a 927 ms worst answer to 43 ms. The log writer's queue holds 262,144 records (some 64 MiB at most), several seconds of logging at these rates; a log that stays slower than the incoming records for longer still holds the server back once the queue is full (see above), since dropping log lines is not an option. The very long answers v4 gives on the REST mix (up to 22 s) are v4's own: `/v1/status/` requests that overlap stall in v4, which `parity/run.sh` already works around by sending them one at a time.

### Profile

`perf` on the whois mix at 16 clients (a release build with symbols): about 40% of the server's CPU is LMDB B-tree search, mostly the origin index lookups set expansion makes for every member AS in every source; 9% was SipHash and hash table inserts on the sets of names set expansion builds, and about 4% growing a Vec per origin lookup. The last two are gone (foldhash for those sets, a callback instead of a Vec). On the GraphQL mix the largest single item is allocation inside the GraphQL executor, spread over many call sites, with no single hot spot. A further step for set expansion would be one cursor walking the origin index across all member ASes of a source instead of one search per AS; heed does not expose cursor seeks, so that needs the raw LMDB API and was left for later.

## ROA import

`parity/status/roa-bench.sh` (1,000,000 synthetic ROAs, after `parity/status/run.sh`, so on the status suite's 37,000 objects). Both servers import the same file twice: the first run replaces the suite's ROAs, the second its own, which is the steady state of an hourly import. maxrss is the peak resident set; for irrd-ng that includes pages of the memory-mapped store the job read, which v4's figure leaves out (its data is in PostgreSQL, a separate process), so irrd-ng's peak anonymous memory is given too.

| | time | maxrss | irrd-ng anonymous peak |
|---|---|---|---|
| v4, run 1 / run 2 | 617 s / 587 s | 2.34 GB / 2.34 GB | |
| irrd-ng before, run 1 / run 2 | 30.8 s / 57.8 s | 3.10 GB / 3.72 GB | 2.13 GB / 2.03 GB |
| irrd-ng after, run 1 / run 2 | 46.2 s / 50.5 s | 2.45 GB / 2.45 GB | 0.76 GB / 0.76 GB |

After each pair of runs the two databases were exported and compared: `roa_object` 1,000,000 rows identical, `rpsl_objects` 1,025,175 rows identical, the journal equivalent (P-21). The status suite (`parity/status/run.sh`) passed every step with identical tables and mails.

What changed: the ROA file is no longer parsed into a tree of JSON values (each entry borrows its text and is converted one at a time); repeated ROAs are found on numeric keys instead of key strings; the pseudo-IRR objects are rendered one at a time inside the write instead of all before it; and the `roa_object` rows are written in batches instead of being held until commit. The rest of irrd-ng's figure is mostly the store's pages the job reads (the old pseudo-IRR objects it deletes, the routes it re-validates), which is page cache rather than memory the job owns. On a full-size store the re-validation reads every route object, so the maxrss there will be higher than here while the anonymous part stays about the same; that is the figure to check on the Tier 2 VM.

## Large write transactions

`bench/large_txn.sh` with full RADB (1,373,035 objects): `irrd_load_database` into an empty store, then `irrd_update_database` with every object changed (a remarks line added), then with the original file again. Each step is one transaction; the source keeps its journal, so the updates journal every object.

| step | peak anonymous memory before | after | store used / map size after |
|---|---|---|---|
| `irrd_load_database` | 2,365 MiB | 846 MiB | 1.9 GB / 3.9 GB |
| `irrd_update_database`, all changed | 3,765 MiB | 3,345 MiB | 5.2 GB / 10.4 GB |
| `irrd_update_database`, changed back | 3,638 MiB | 3,208 MiB | 6.6 GB / 13.1 GB |

- `irrd_load_database` kept the whole file, every paragraph and every parsed object in memory so it could write them in key order. It now parses a batch at a time into a spool file and replays the spool in key order, as the mirror runner's full import already did. `parity/load-check.sh --tier fixtures` (v4's loader against irrd-ng's on all nine fixtures, including one v4 rejects) agrees on every one.
- `irrd_update_database` no longer copies every stored row's text to compare it. It still holds the parsed file whole, as v4 does; that is most of what is left.
- Map growth behaved: the map was grown ahead of each transaction, with no failed attempt. The data file grows by about the size of the source with each full rewrite while journalling, because LMDB cannot reuse pages freed in the same transaction; the next transactions reuse them.
- Wall times were left out of the table: the same load took 38 s in one run and 253 s in another on this disk.

## Mirror catch-up

`bench/mirror_catchup.sh` on the first 200,000 objects of RADB: an irrd-ng upstream holds a journal of 400,000 changes (every object rewritten, then rewritten back). Each mirror starts empty, does a full import of the upstream's content at serial 200,000, then catches up the last 200,000 changes over NRTMv3 in one run. v4 runs its `RPSLMirrorImportUpdateRunner` twice in a one-off container of the Tier 1 stack; irrd-ng runs as the daemon with the source's `import_timer` at 1 s, timed until `!J` shows each serial.

| | full import, 200,000 objects | NRTMv3 catch-up, 200,000 changes |
|---|---|---|
| v4 | 142.9 s | 1,452.3 s (138 changes/s) |
| irrd-ng | 10.4 s (from daemon start) | 75.4 s (2,650 changes/s) |

Both ended at serial 400,000. irrd-ng's catch-up time includes waiting for the scheduler's next run after the full import (about 11 s).

## Import from v4

`irrd-ng import --from-postgres` of the Tier 1 database (49,423 rows) took 30.8 s in the final `parity/load.sh` run and 1.1 s in a run with the store on tmpfs: the difference is the final sync on this disk. v4's own mirror import of the same 9 sources in that `load.sh` run took 170 s.

## Standby snapshots

A standby snapshot holds one LMDB read transaction while the standby receives every row, and LMDB can only grow its map with no read transaction open in the process. Before, a write on the active that needed a bigger map during a snapshot waited for the snapshot to finish, and while it waited every new query waited too, because the resize held new readers back. Now long reads (standby snapshots, exports, NRTMv4 snapshot files, the event stream's initial download) are registered as long readers: a resize waits for them without holding back queries, so only the write that needed the space waits. A snapshot also grows the map before it starts by as much as the store already uses, so on a store that is not doubling during one snapshot no write waits at all. `crates/store/tests/map_growth.rs` checks that a query is answered while a resize waits behind a long reader and that the resize completes once the reader ends.
