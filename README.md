# irrd-ng

irrd-ng is a drop-in replacement for [IRRd](https://github.com/irrdnet/irrd) 4.5, the Internet Routing Registry daemon, written in Rust. An operator running IRRd 4.5.4 should be able to stop `irrd`, run a one-shot import of the v4 database, start irrd-ng with the same `irrd.yaml`, and have no client notice the change.

It is one static binary with an embedded LMDB store. There is no PostgreSQL, no Redis and no Python runtime to install, run or upgrade.

## Status

irrd-ng is in its release phase and has not had a tagged release yet. Every surface listed below is implemented and tested against IRRd 4.5.4 by the differential harness in `parity/`. Treat it as pre-release software: run it beside v4 first, and keep v4's database until you are happy (see `docs/migration.md`).

The v4 web UI (user accounts, two-factor authentication, mntner migration) is not part of irrd-ng yet. Its data is carried through the import untouched so that a later version can serve it.

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
```

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
