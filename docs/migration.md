# Moving from IRRd v4 to irrd-ng

This is the runbook for replacing an IRRd 4.5 installation with irrd-ng on the same host, keeping the same `irrd.yaml`, the same ports and the same NRTM serials, so that neither query clients nor downstream mirrors notice. It also covers a standby, checking the result, and going back to v4.

The examples assume v4's documented layout: the configuration in `/etc/irrd.yaml`, v4 running as root under systemd as `irrd.service` and dropping to an `irrd` user and group, and irrd-ng installed from its Debian package, which puts the binaries in `/usr/bin`. Where a release tarball is used instead, the binaries are wherever you copied them, `/usr/local/bin` in the examples. Adjust paths to match your installation.

`irrd-ng migrate-check` does most of the checking in this runbook for you. It reads `/etc/irrd.yaml` (or `--config`) and reports whether v4 is still running, whether the irrd-ng store already holds an import, how large v4's database is, how much disk space the import needs and whether there is enough, and then prints the remaining steps with the exact commands for this host. The Debian package runs it after every install and upgrade, and starts irrd-ng only when it passes. Run it again after each step below:

```sh
sudo irrd-ng migrate-check
```

Its exit code says where things stand: 0 ready to start, 10 IRRd v4 (or another program on its ports) is running, 11 the store is not imported, 12 not enough disk space for the import, 13 the configuration is missing or invalid. `--json` prints the findings as JSON and `--quiet` prints nothing.

## What changes and what does not

irrd-ng reads the same `irrd.yaml`, answers on the same whois and HTTP ports, writes the same PID file in `piddir`, drops to the same `user` and `group`, writes the same exports and NRTMv4 files, sends the same mails through the same SMTP server and reloads on SIGHUP the way v4 does. The command line tools keep their names, flags and exit codes.

What goes away is PostgreSQL, Redis and the Python virtualenv. irrd-ng keeps everything in one embedded store, a directory set by the environment variable `IRRD_NG_STORE_PATH` (default `/var/lib/irrd-ng`). There is deliberately no `irrd.yaml` key for it, so the file stays valid for v4 as well, which is what makes rollback simple.

These settings are accepted and checked exactly as v4 checks them, but irrd-ng does not use them:

- `database_url` and `redis_url`. They are still required, because v4 requires them and irrd-ng validates the file the same way. irrd-ng logs one notice at startup saying they are ignored.
- `auth.gnupg_keyring`. Still required, but irrd-ng keeps its PGP keyring in the store instead of a GnuPG home directory, and does not need a `gpg` binary.

A few settings behave slightly differently, each listed in `docs/divergences.md`: `log.logging_config_path` is read as data and supports the common handlers (P-49), `server.http.workers` sizes a thread pool rather than starting processes, and SIGHUP reloads the HTTP server in place instead of restarting its workers (P-52).

## Prerequisites

- IRRd 4.5.x with its database at the 4.5 schema revision. The import checks the Alembic revision and refuses anything else. If v4 was upgraded recently, make sure `irrd_database_upgrade` has been run.
- Network access from the irrd-ng host to v4's PostgreSQL with the credentials in `database_url`. The import only reads.
- Disk space for the store (see the next section) on the filesystem that holds `IRRD_NG_STORE_PATH`.
- The irrd-ng Debian package for your architecture (amd64 or arm64; one package for every Debian and Ubuntu release), or the release tarball. Both contain the static musl build, which has no runtime dependencies at all.
- A maintenance window long enough for the import. irrd-ng serves nothing until the import has finished, and v4 should not accept changes while it runs.

## Sizing the store

The store holds the same data as v4's PostgreSQL database, in a more compact form. `irrd-ng migrate-check` estimates it for you: it connects to `database_url` read-only, with short timeouts, counts the rows of `rpsl_objects`, `rpsl_database_journal` and `roa_object`, and allows 1.45 KB per row. That figure comes from measured imports: a full RADB mirror of 1.37 million objects built a 1,839 MB store, and a production database of 6,444,813 rows a 7.7 GB store. For the free space the import needs, it doubles the estimate, because LMDB writes changed pages to new places and only frees the old ones when a transaction commits, so a full import can briefly need about twice the final size, and adds 1 GiB for the next step of map growth. It compares that with the free space on the filesystem that holds the store and says ENOUGH or NOT ENOUGH.

To estimate by hand instead, count what v4 holds:

```sh
psql "$DSN" -Atc "select count(*) from rpsl_objects"
psql "$DSN" -Atc "select count(*) from rpsl_database_journal"
psql "$DSN" -Atc "select pg_size_pretty(pg_database_size(current_database()))"
```

A full RADB mirror of about 1.4 million objects takes a little under 2 GB. The store is an LMDB memory map: it grows on its own whenever less than a quarter of the map is free, roughly doubling each time, so keep free disk space of at least the store's own size again. Memory needs are modest because the store is read through the operating system's page cache; the more of the store fits in RAM, the faster queries are, but nothing has to fit.

`irrd-ng store-info` prints the schema version, map size and the size of each table once the store exists. The map size is not shown in `/v1/status/`, because v4 shows nothing like it there (P-39).

## Before the cutover

1. Install irrd-ng beside v4. With the Debian package (see the README for adding the APT repository instead):

   ```sh
   sudo apt install ./irrd-ng_${version}_$(dpkg --print-architecture).deb
   ```

   The package sees that v4 is running and does not start irrd-ng. It creates the `irrd` user and group only if they do not exist, and the store directory `/var/lib/irrd-ng` owned by `irrd`, and then prints the migration check: what is still running, the size of v4's database and whether there is enough disk space for the import.

   With a release tarball instead, extract it and copy the binaries and their symlinks:

   ```sh
   tar -xzf irrd-ng-$version-$target.tar.gz
   sudo cp -a irrd-ng-$version-$target/bin/. /usr/local/bin/
   ```

   If v4's tools are also on the `PATH`, call irrd-ng's by their full path (`/usr/bin/irrd` from the package, `/usr/local/bin/irrd` from the tarball) until v4 is gone.

2. The store directory must belong to the user irrd-ng will run as. That is the `user` and `group` from `irrd.yaml`, since irrd-ng opens the store only after dropping privileges. The package creates it for the `irrd` user; with a tarball, or if `irrd.yaml` names another user, create or change it yourself (`irrd-ng migrate-check` points out a mismatch):

   ```sh
   sudo install -d -o irrd -g irrd -m 0750 /var/lib/irrd-ng
   ```

3. Check that irrd-ng accepts your configuration. A file v4 accepts is one irrd-ng accepts, with the same error messages if it does not. Any tool that takes `--config` validates the file first; `irrd_database_upgrade` pointed at a throwaway store is a harmless way to run that check, and prints v4's errors and exits 1 if the file is invalid:

   ```sh
   scratch=$(sudo -u irrd mktemp -d)
   sudo -u irrd env IRRD_NG_STORE_PATH=$scratch /usr/bin/irrd_database_upgrade --config /etc/irrd.yaml
   sudo rm -rf "$scratch"
   ```

4. Optionally rehearse the import. The import never writes to the source, so it can be run against the live v4 database at any time to measure how long it takes and how large the store will be. It reads in one long repeatable-read transaction, so pick a quiet time on a busy database. Use a scratch store directory (`--store /some/scratch/dir`) and delete it afterwards.

5. Record what clients currently see, so you can compare after the cutover:

   ```sh
   whois -h localhost '!j-*' > before-serials.txt
   whois -h localhost '!J-*' > before-status.txt
   curl -s http://localhost:8000/v1/status/ > before-status.html
   ```

   Use the whois and HTTP addresses from your `irrd.yaml` (v4's default HTTP port is 8000, and `/v1/status/` answers only addresses in `server.http.status_access_list`), and add a `Host` header matching `server.http.url` if v4 is behind a proxy.

## The cutover

1. Stop v4 and keep it from starting again:

   ```sh
   sudo systemctl stop irrd
   sudo systemctl disable irrd
   ```

   PostgreSQL must stay up for the import. Redis can be stopped. `sudo irrd-ng migrate-check` should now report v4 as not running; if it still sees something on v4's ports or a live PID in v4's PID file, deal with that first.

2. Import the v4 database. Run it as the irrd user so the store's files belong to that user. The connection string can be v4's `database_url` exactly as it appears in `irrd.yaml`, including the `postgresql+psycopg2://` form, or any libpq URL or `key=value` string:

   ```sh
   sudo -u irrd env IRRD_NG_STORE_PATH=/var/lib/irrd-ng \
     irrd-ng import --from-postgres 'postgresql://irrd@localhost/irrd'
   ```

   `irrd-ng migrate-check` prints this command with your own `database_url`, its password masked.

   The import reads every table in one consistent, read-only snapshot: RPSL objects, the journal with its serials, `database_status` including NRTMv4 client and server state, ROAs, suppressed objects, protected names, settings and the web UI tables (users, permissions, API keys, WebAuthn, change log). It prints a line per table and a summary. `sslmode` and `sslrootcert` follow libpq: the verifying modes check against `sslrootcert`, by default `~/.postgresql/root.crt`, and refuse to connect when that file is missing; `require` checks the chain too when the file exists. `sslrootcert=system` uses the Mozilla roots built into the binary and requires `verify-full`.

   By default the import also rebuilds the PGP keyring from every `key-cert` object, so PGP signed submissions keep working as they did on v4. Pass `--no-load-pgp-keys` to leave the keyring empty instead, which is what a v4 installation moved to a new host would see; `irrd_load_pgp_keys` can then fill it per source.

   The import is safe to run again: a second run over the same store changes nothing and duplicates nothing. If an import is interrupted, the store refuses to open until an import completes, so it can never serve partial data.

3. Start irrd-ng. Check first that `sudo irrd-ng migrate-check` says READY. `piddir` in `irrd.yaml` must match the unit's `PIDFile`, which is `/run/irrd/irrd.pid` as shipped; the check warns if it does not. If your `piddir` is elsewhere (v4's guide uses `/home/irrd`), override `PIDFile` with `sudo systemctl edit irrd-ng`, or change `piddir` in the file.

   The Debian package has already installed the unit, so:

   ```sh
   sudo systemctl enable --now irrd-ng
   ```

   With a tarball, install the unit from it first, changing `/usr/local/bin` in `ExecStart` if you put the binaries elsewhere:

   ```sh
   sudo install -m 0644 irrd-ng-$version-$target/systemd/irrd-ng.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now irrd-ng
   ```

   From now on the package's upgrades, including unattended ones, restart irrd-ng when it was running before the upgrade.

   The unit starts `irrd --foreground --config /etc/irrd.yaml` as root, exactly as v4's documented unit does. irrd-ng writes `irrd.pid` in `piddir`, binds the whois port, switches to `user` and `group`, and then opens the store and binds the HTTP port. Its log goes where `irrd.yaml` says, in v4's format.

4. Point anything that called v4's tools by their virtualenv path at the new ones. The usual one is the mail server's pipe to `irrd_submit_email`, for example `/home/irrd/irrd-venv/bin/irrd_submit_email` becomes `/usr/bin/irrd_submit_email` (or `/usr/local/bin/irrd_submit_email` with a tarball). Cron jobs that run `irrd_expire_journal` or `irrd_load_database` need the same change. The tools read the store from `IRRD_NG_STORE_PATH`, so set it in their environment if you do not use the default.

## Checking the result

The first log lines are v4's (`IRRd 4.5.4 starting, PID ..., PID file in ...`) followed by the notice about `database_url` and `redis_url`. Then compare what clients see with what you recorded:

```sh
whois -h localhost '!v'
whois -h localhost '!j-*' | diff before-serials.txt -
whois -h localhost '!J-*' | diff before-status.txt -
curl -s http://localhost:8000/v1/status/ | diff before-status.html -
```

`!v` answers with IRRd's version, 4.5.4, as v4 did. `!j-*` and `!J-*` must be identical to v4's, because they report the serials and status the import carried over. `/v1/status/` lists the same sources with the same serials; expect only times that depend on when the process started to differ. A few spot queries your users rely on (`!gAS...`, `!iAS-...,1`, `-x` on a prefix) and a `bgpq4` run against an AS-set you know are a good final check.

Send `SIGHUP` (`systemctl reload irrd-ng`) and check the log for `Configuration successfully (re)loaded from /etc/irrd.yaml`.

## NRTM serials and downstream mirrors

The import keeps every source's serials and journal exactly as they were in v4, and irrd-ng serves NRTMv3 (`-g`) from that journal. A downstream mirror that last saw serial N from v4 asks irrd-ng for N+1 onwards and gets the same entries v4 would have sent, so no mirror needs a full reload. Keep `keep_journal` and the NRTM access lists unchanged.

For NRTMv4, the import carries over each source's server session ID and version, and irrd-ng keeps writing snapshots, deltas and the signed Update Notification File to `nrtm4_server_local_path`, using the same keys from `irrd.yaml`. Your web server goes on publishing that directory unchanged, and NRTMv4 clients see the next version of the same session.

Exports (`export_destination`) carry on with the next serial on the next `export_timer` run.

Sources that irrd-ng itself mirrors carry on from the serial v4 had reached, over NRTMv3, NRTMv4 or a full import, as configured.

## A standby

In v4, a standby is a PostgreSQL streaming replica with `readonly_standby: true`. irrd-ng has no PostgreSQL to stream, so it replicates its own store over an authenticated TCP connection. This needs one setting v4 does not have, `ng_replication` (DIV-006), and that is the only change to `irrd.yaml` in this whole runbook.

On the active, add a listener:

```yaml
irrd:
  ng_replication:
    secret: <at least 16 characters, the same on both ends>
    interface: "::0"
    port: 8044
```

On the standby, keep `readonly_standby: true` and point it at the active:

```yaml
irrd:
  readonly_standby: true
  ng_replication:
    secret: <the same secret>
    active_host: irrd-active.example.net
    active_port: 8044
```

The secret can instead come from the environment as `IRRD_NG_REPLICATION_SECRET`, which keeps it out of the file. Start the standby with an empty store directory: it fetches a full snapshot from the active, then follows every committed change, reconnecting and resuming on its own after restarts or network problems. There is no import to run on the standby, and the old PostgreSQL replica is no longer needed.

The two ends prove they share the secret without sending it, and every message is authenticated, but the stream is not encrypted. Run it over a private network or a tunnel.

As in v4, the standby answers queries but writes nothing: no mirroring, exports, NRTMv4 files or RPKI jobs, and the command line tools that write refuse to run. To promote it, set `readonly_standby` to false (and remove `active_host` and `active_port`) and send SIGHUP or restart it.

## Rolling back to v4

The import never writes to v4's database, so v4's data is exactly as it was when you stopped it, and the same `irrd.yaml` is still valid for v4 as long as you have not added `ng_replication`.

```sh
sudo systemctl disable --now irrd-ng
sudo systemctl enable --now irrd
```

Remove `ng_replication` from `irrd.yaml` first if you added it, because v4 refuses a file that contains it. Point the mail server and cron jobs back at v4's tools.

What v4 does not have is anything that changed while irrd-ng was running:

- Sources v4 mirrors catch up on their own, from the serial v4 had reached.
- Changes to authoritative sources (submissions by mail or HTTP, `irrd_update_database`) exist only in irrd-ng's store. If there were none, rollback is clean. If there were, v4 would hand out the same serials again with different content, and downstream mirrors that already followed irrd-ng would diverge. Either replay those changes into v4 before it serves NRTM again, or ask the affected mirrors to do a full reload.

For that reason, a cautious cutover keeps the window between starting irrd-ng and taking the first authoritative change short, or checks everything before re-enabling submissions.

Once you are satisfied with irrd-ng, PostgreSQL, Redis, the v4 virtualenv and the GnuPG keyring directory can be removed. Keep a final `pg_dump` of the v4 database for a while.

If you also remove the irrd-ng package, `apt remove` keeps the store and `apt purge` removes the package's configuration and the `irrd` user if the package created it; neither deletes `/var/lib/irrd-ng`.
