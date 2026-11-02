# irrd-ng

irrd-ng is a drop-in replacement for [IRRd](https://github.com/irrdnet/irrd) 4.5, the Internet Routing Registry daemon, written in Rust. An operator running IRRd 4.5.4 should be able to stop `irrd`, run a one-shot import of the v4 database, start irrd-ng with the same `irrd.yaml`, and have no client notice the change.

It is one static binary with an embedded LMDB store. There is no PostgreSQL, no Redis and no Python runtime to install, run or upgrade.

## Status

irrd-ng 1.0.0 is the first release. Every surface listed below is implemented and tested against IRRd 4.5.4 by the differential harness in `parity/`, and every known difference from v4 is listed in `docs/divergences.md`. As with any replacement, run it beside v4 first, and keep v4's database until you are happy (see `docs/migration.md`).

The v4 web UI (user accounts, two-factor authentication, mntner migration) is not part of irrd-ng yet. Its data is carried through the import untouched so that a later version can serve it.

## Performance

IRRd v4 is mature, well-engineered software, and its design (Python workers in front of PostgreSQL and Redis) makes good sense for a project that values flexibility and a familiar stack. irrd-ng takes a different route, with one compiled process reading from an embedded, memory-mapped store, and that route turns out to be quick. On the same data, with the same configuration and query mix:

| | IRRd 4.5.4 | irrd-ng 1.0.0 |
|---|---|---|
| whois queries per second (16 clients) | 2,067 | 10,508 |
| REST (`/v1/whois/`, status) requests per second (16 clients) | 1,071 | 27,473 |
| GraphQL requests per second (16 clients) | 404 | 16,494 |
| Memory while serving (v4 includes PostgreSQL and Redis) | about 2.5 GiB | 150 to 660 MiB |
| Mirror catching up on 200,000 NRTMv3 changes | 1,452 s | 75 s |
| ROA import of 1,000,000 ROAs | 587 to 617 s | 46 to 51 s |

Latency is lower too, at the median and the 99th percentile, at every concurrency we measured. These figures come from a shared development machine and a test data set of about 37,000 objects, so treat them as a comparison rather than a promise for your hardware. A production-sized run is still to come. [`bench/RESULTS.md`](bench/RESULTS.md) has every number, the machine, the method and the scripts to reproduce them.

## The compatibility promise

irrd-ng behaves exactly like IRRd 4.5.4 on everything a client or an operator can see:

- whois on port 43, in both IRRd style (`!g`, `!i`, `!r` and the rest, including multi-command mode) and RIPE style (`-i`, `-l`, `-M`, `-g` and the rest), byte for byte, including framing and error text
- NRTMv3 serving and mirroring, NRTMv4 client and server (the files v4 writes for a web server to publish), and exports
- email submissions through `irrd_submit_email` and the reply and notification mails
- the HTTP APIs: `/v1/whois/`, `/v1/submit/`, `/v1/status/`, `/v1/suspension/`, `/graphql` with v4's schema and error shapes, the event stream WebSocket and its initial download, and `/metrics/`
- `irrd.yaml`: the same keys, defaults, validation errors and SIGHUP reload behaviour
- the twelve command line tools v4 installs, with the same names, flags, output and exit codes
- RPSL validation and authentication, RPKI route validation, the scope filter, route object preference, suppression and set expansion

The deliberate differences are all listed in [`docs/divergences.md`](docs/divergences.md), each with what v4 does, what irrd-ng does instead, who can see it and why. Any difference from v4 that is not on that list is a bug, and we would like to hear about it.

How irrd-ng is built inside, and why it looks the way it does, is in [`docs/architecture.md`](docs/architecture.md).

## Debian and Ubuntu

Each release has a Debian package for amd64 and for arm64. It is built from the static musl binary, so the same package installs on every Debian and Ubuntu release; each one is tested on Debian 12 and 13 and Ubuntu 22.04 and 24.04 before it is published. Install it from the latest release:

```sh
version=$(curl -fsSL https://api.github.com/repos/JoshFinlayAU/irrd-ng/releases/latest | sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p')
arch=$(dpkg --print-architecture)
curl -LO https://github.com/JoshFinlayAU/irrd-ng/releases/download/v$version/irrd-ng_${version}_$arch.deb
sudo apt install ./irrd-ng_${version}_$arch.deb
```

or add the APT repository and its signing key, and install from there:

```sh
sudo curl -fsSLo /usr/share/keyrings/irrd-ng-archive-keyring.gpg https://joshfinlayau.github.io/irrd-ng/apt/irrd-ng-archive-keyring.gpg
sudo curl -fsSLo /etc/apt/sources.list.d/irrd-ng.sources https://joshfinlayau.github.io/irrd-ng/apt/irrd-ng.sources
sudo apt update && sudo apt install irrd-ng
```

The repository is signed with the key `8F07 C3D3 B0DE A2A6 3644  FE36 EC45 6733 FAF7 9C2A`.

The package installs `irrd-ng` and the twelve v4 tool names in `/usr/bin`, the systemd unit `irrd-ng.service`, the documentation and a man page. It creates the `irrd` user and group if they do not exist yet (v4's documented deployment already has them) and the store directory `/var/lib/irrd-ng`. It does not ship an `irrd.yaml`: irrd-ng reads v4's `/etc/irrd.yaml`.

Installing the package never stops IRRd v4 and never starts irrd-ng too early. After installing, it runs `irrd-ng migrate-check`, and starts irrd-ng only if that check passes. If IRRd v4 is still running (its systemd unit, its PID file, or anything else on the configured whois and HTTP ports), if the v4 database has not been imported yet, or if there is no `/etc/irrd.yaml`, the service is left alone and the check's findings and the remaining steps are printed instead: how to stop v4, the exact import command (with the password from `database_url` masked), how much disk space the import needs and whether the store's filesystem has enough, how to start and check irrd-ng, and how to go back to v4. Run the check yourself at any time:

```sh
sudo irrd-ng migrate-check
```

It exits 0 when irrd-ng is ready to start, 10 while IRRd v4 (or another program on its ports) is running, 11 before the import, 12 when there is not enough disk space for the import and 13 for a missing or invalid `irrd.yaml`. `--json` prints the findings as JSON and `--quiet` only sets the exit code. [`docs/migration.md`](docs/migration.md) walks through the whole move.

### Automatic upgrades

Both ways of installing leave the APT repository configured in `/etc/apt/sources.list.d/irrd-ng.sources`, and the package adds `/etc/apt/apt.conf.d/52irrd-ng-unattended-upgrades`, which lets unattended-upgrades install new irrd-ng releases from it (unattended-upgrades itself has to be enabled, as it is by default on Ubuntu). After an upgrade, whether by hand or unattended, the package restarts irrd-ng if it was running before, and leaves it stopped otherwise. It also tells needrestart to leave irrd-ng to the package.

To opt out of automatic upgrades, delete `/etc/apt/apt.conf.d/52irrd-ng-unattended-upgrades` (dpkg keeps it deleted on later upgrades), or hold the package with `sudo apt-mark hold irrd-ng`. To stop using the repository altogether, set `Enabled: no` in `/etc/apt/sources.list.d/irrd-ng.sources`.

`sudo apt remove irrd-ng` stops irrd-ng and removes the program, and keeps the store and the repository configuration. `sudo apt purge irrd-ng` also removes the repository configuration, and the `irrd` user and group if the package created them. The store in `/var/lib/irrd-ng` is never deleted by the package.

## Install from a release

Each release has four tarballs: static musl builds for x86_64 and aarch64, which run on any Linux, and glibc builds for both (glibc 2.36 or newer). The musl builds are the recommended ones.

```sh
version=0.1.0
target=x86_64-unknown-linux-musl
curl -LO https://github.com/JoshFinlayAU/irrd-ng/releases/download/v$version/irrd-ng-$version-$target.tar.gz
curl -LO https://github.com/JoshFinlayAU/irrd-ng/releases/download/v$version/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf irrd-ng-$version-$target.tar.gz
sudo cp -a irrd-ng-$version-$target/bin/. /usr/local/bin/
```

The `bin` directory holds the `irrd-ng` binary and a symlink to it under each of v4's tool names (`irrd`, `irrdctl`, `irrd_submit_email`, `irrd_load_database` and so on). The binary looks at the name it was started as and becomes that tool, so scripts, cron jobs and mail server pipes that call the v4 names keep working once they point at the new path. `irrd-ng <tool> ...` works too.

The tarball also contains a systemd unit (`systemd/irrd-ng.service`), this README, the documentation and the licences.

## Quick start

irrd-ng reads the same `irrd.yaml` as v4. The one thing v4's file has no key for is where the store lives, so that comes from the environment variable `IRRD_NG_STORE_PATH`, which defaults to `/var/lib/irrd-ng`.

To move an existing v4 installation, follow [`docs/migration.md`](docs/migration.md). In short:

```sh
sudo systemctl stop irrd
sudo install -d -o irrd -g irrd -m 0750 /var/lib/irrd-ng
sudo -u irrd irrd-ng import --from-postgres 'postgresql://irrd@localhost/irrd'
sudo install -m 0644 irrd-ng-$version-$target/systemd/irrd-ng.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now irrd-ng
whois -h localhost '!v'
```

For a new installation, write an `irrd.yaml` as you would for v4 (`database_url` and `redis_url` are still required by the validation v4 does, and are ignored), load your sources with `irrd_load_database` or let the mirroring client fetch them, and start `irrd`:

```sh
export IRRD_NG_STORE_PATH=/var/lib/irrd-ng
irrd_load_database --config /etc/irrd.yaml --source EXAMPLE example.db
irrd --config /etc/irrd.yaml --foreground
```

## Building from source

You need the Rust toolchain named in `rust-toolchain.toml` (rustup installs it automatically). A plain build for the machine you are on:

```sh
cargo build --release
ln -sf irrd-ng target/release/irrd
```

The release artefacts are cross-built with [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild) and zig:

```sh
cargo zigbuild --release --target x86_64-unknown-linux-musl
cargo zigbuild --release --target aarch64-unknown-linux-musl
cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.36
cargo zigbuild --release --target aarch64-unknown-linux-gnu.2.36
file target/x86_64-unknown-linux-musl/release/irrd-ng    # "statically linked"
dist/package.sh x86_64-unknown-linux-musl 0.1.0 dist/out
dist/debian/build-deb.sh target/x86_64-unknown-linux-musl/release/irrd-ng amd64 0.1.0 dist/out
```

`dist/debian/install-test.sh` install-tests a package inside a throwaway Debian or Ubuntu container, as the release workflow does.

The source builds without the `vendor/irrd-v4` git submodule. The submodule (IRRd 4.5.4 at its release tag) is only needed for the parity harness and for one test that checks irrd-ng's copies of v4's GraphiQL files against it.

irrd-ng runs on Linux only.

## Testing

The checks every change has to pass:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace
cargo test --doc --workspace
cargo deny check
```

Parity with v4 is proven by running the same inputs through a pinned IRRd 4.5.4 and through irrd-ng and comparing the results byte for byte. The harness in `parity/` needs Docker and the submodule, and fetches public IRR dumps into a local cache that is never committed:

```sh
git submodule update --init
parity/fetch-dumps.sh
python3 -I parity/tools/cut_fixtures.py parity/.cache
parity/up.sh
parity/load.sh
parity/run.sh --suite all
parity/down.sh
```

The slower differentials (mirroring, serving, submissions and the full drop-in rehearsal) are `parity/mirror/run.sh`, `parity/mirror/serve.sh`, `parity/submit/run.sh` and `parity/rehearsal/run.sh`. CI runs the fast suites on every push and the slow ones nightly.

## Licence

irrd-ng is licensed under the GNU Lesser General Public License, version 2.1 or (at your option) any later version. See `LICENSE`.

irrd-ng is a reimplementation of IRRd v4 and ports a good deal of its behaviour, messages and tests, so v4's BSD-2-Clause notice and the notices of the code v4 itself includes are kept in `NOTICE`. The binary also contains the GraphiQL explorer files v4 serves (GraphiQL, React and the GraphiQL explorer plugin, all MIT licensed). Their origins and licence texts are in `crates/http/assets/graphiql/`, and in `licenses/` in each release tarball.

irrd-ng is an independent project, separate from IRRd itself.
