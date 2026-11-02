#!/usr/bin/env bash
# Install-test the irrd-ng package in a throwaway Debian or Ubuntu container.
#
#   dist/debian/install-test.sh DEB
#
# Run as root inside a container, never on a real host: it replaces
# systemctl and policy-rc.d with stand-ins and installs and purges packages.
# Containers have no systemd, so a stub systemctl records what the
# maintainer scripts ask for, and the test checks those decisions:
#
#   1. no /etc/irrd.yaml: installs, exits 0, prints the guidance, does not
#      start irrd-ng; the irrd user and the store directory are created
#   2. irrd.yaml and a fake IRRd v4 holding the whois port and its PID file:
#      reinstalls, exits 0, says v4 is running and how to stop it, does
#      not start irrd-ng
#   3. a small store loaded with irrd_load_database: migrate-check says
#      ready; after a purge and a fresh install the service is started
#   4. upgrade (reinstall of the same version) while running: restarted;
#      while stopped: left stopped
#   5. remove: stopped, store and user kept; purge: the user this package
#      created is removed, the store is kept
#   6. a pre-existing irrd user (v4's deployment) survives a purge
#
# Example:
#   docker run --rm -v "$PWD:/src:ro" -v "$PWD/dist/out:/debs:ro" debian:13 \
#     bash /src/dist/debian/install-test.sh /debs/irrd-ng_1.0.0_amd64.deb
set -euo pipefail
[[ $# -eq 1 ]] || { sed -n '2,25p' "$0" >&2; exit 2; }
deb=$(readlink -f "$1")
[[ -r $deb ]] || { echo "no package at $1" >&2; exit 2; }
[[ -e /.dockerenv || -n ${container:-} || -n ${CI_CONTAINER:-} ]] ||
  { echo "refusing to run outside a container" >&2; exit 2; }

export DEBIAN_FRONTEND=noninteractive
step() { printf '\n===== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
contains() { grep -qF -- "$2" <<<"$1" || { printf '%s\n' "$1"; fail "output lacks: $2"; }; }
lacks() { if grep -qF -- "$2" <<<"$1"; then printf '%s\n' "$1"; fail "output has: $2"; fi; }
calls() { cat /var/log/systemctl-stub.log 2>/dev/null || true; }
reset_calls() { : >/var/log/systemctl-stub.log; }
expect_rc() {
  local want=$1 rc=0
  shift
  "$@" >/dev/null 2>&1 || rc=$?
  [[ $rc -eq $want ]] || fail "$* exited $rc, expected $want"
}
apt_install() { apt-get install -y --no-install-recommends "$@" 2>&1; }

step "setup: $(grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2- | tr -d '"'), $(dpkg --print-architecture)"
apt-get update -qq
# Docker's images forbid service starts; the stub below decides instead.
printf '#!/bin/sh\nexit 0\n' >/usr/sbin/policy-rc.d
chmod 0755 /usr/sbin/policy-rc.d
mkdir -p /run/systemd/system /run/stub-systemd
! command -v systemctl >/dev/null || fail "this container has a real systemctl"
cat >/usr/bin/systemctl <<'EOF'
#!/bin/sh
# Stand-in for systemctl: records each call and keeps unit state in files.
echo "systemctl $*" >>/var/log/systemctl-stub.log
action=
unit=
for a in "$@"; do
  case $a in
  -*) ;;
  *) if [ -z "$action" ]; then action=$a; else unit=$a; fi ;;
  esac
done
case $action in
is-active) [ -e "/run/stub-systemd/$unit" ] ;;
is-enabled)
  if [ -e "/etc/systemd/system/multi-user.target.wants/$unit" ]; then echo enabled; else echo disabled; exit 1; fi ;;
enable | preset | reenable)
  mkdir -p /etc/systemd/system/multi-user.target.wants
  ln -sf "/usr/lib/systemd/system/$unit" "/etc/systemd/system/multi-user.target.wants/$unit" ;;
disable) rm -f "/etc/systemd/system/multi-user.target.wants/$unit" ;;
start | restart) : >"/run/stub-systemd/$unit" ;;
stop) rm -f "/run/stub-systemd/$unit" ;;
*) exit 0 ;;
esac
EOF
chmod 0755 /usr/bin/systemctl
hash -r
pkg_version=$(dpkg-deb -f "$deb" Version)

step "1. install without /etc/irrd.yaml"
rm -f /etc/irrd.yaml
reset_calls
out=$(apt_install "$deb") || { printf '%s\n' "$out"; fail "apt-get install failed"; }
printf '%s\n' "$out"
contains "$out" "irrd-ng: created system user irrd"
contains "$out" "installed, but not starting irrd-ng.service"
contains "$out" "/etc/irrd.yaml does not exist"
contains "$out" "Result: NOT READY, because irrd.yaml is missing or not valid."
contains "$out" "Put the irrd.yaml of your IRRd v4 installation at /etc/irrd.yaml"
lacks "$(calls)" " start "
[[ $(stat -c '%U:%G %a' /var/lib/irrd-ng) == "irrd:irrd 750" ]] || fail "store directory: $(stat -c '%U:%G %a' /var/lib/irrd-ng)"
[[ $(readlink /usr/bin/irrd) == irrd-ng ]] || fail "/usr/bin/irrd is not a symlink to irrd-ng"
[[ $(find /usr/bin -lname irrd-ng | wc -l) -eq 12 ]] || fail "expected 12 tool symlinks"
irrd --help >/dev/null || fail "irrd --help"
irrd_load_database --help >/dev/null || fail "irrd_load_database --help"
expect_rc 13 irrd-ng migrate-check --quiet
json=$(irrd-ng migrate-check --json) || true
contains "$json" '"verdict":"config_problem"'
# Not the man page or docs: Ubuntu's minimal images exclude them from installs.
for f in /etc/apt/sources.list.d/irrd-ng.sources /etc/apt/apt.conf.d/52irrd-ng-unattended-upgrades \
  /etc/needrestart/conf.d/irrd-ng.conf /usr/share/keyrings/irrd-ng-archive-keyring.gpg \
  /usr/lib/systemd/system/irrd-ng.service /usr/share/doc/irrd-ng/copyright; do
  [[ -s $f ]] || fail "missing $f"
done
grep -q '^ExecStart=/usr/bin/irrd --foreground --config /etc/irrd.yaml$' /usr/lib/systemd/system/irrd-ng.service ||
  fail "unit ExecStart"
apt-config dump | grep -q 'origin=irrd-ng' || fail "Unattended-Upgrade::Origins-Pattern not set"

step "2. irrd.yaml and a fake IRRd v4 on the whois port"
mkdir -p /run/irrd
cat >/etc/irrd.yaml <<'EOF'
irrd:
  database_url: postgresql://irrd:not-the-password@127.0.0.1:1/irrd
  redis_url: redis://localhost
  piddir: /run/irrd
  user: irrd
  group: irrd
  email:
    from: irrd@example.net
    smtp: localhost
  auth:
    gnupg_keyring: /tmp
  rpki:
    roa_source: null
  server:
    http:
      url: http://localhost/
  sources:
    TEST:
      authoritative: true
EOF
chmod 0640 /etc/irrd.yaml
chgrp irrd /etc/irrd.yaml
# Named like v4's whois listener, as setproctitle names it.
perl -MSocket -e '$0 = "irrd-whois-server-listener";
  socket(my $s, PF_INET6, SOCK_STREAM, 0) or die "socket: $!";
  setsockopt($s, SOL_SOCKET, SO_REUSEADDR, 1);
  bind($s, pack_sockaddr_in6(43, "\0" x 16)) or die "bind: $!";
  listen($s, 5) or die "listen: $!"; sleep 900' &
fake_v4=$!
echo "$fake_v4" >/run/irrd/irrd.pid
for _ in $(seq 50); do grep -q ':002B .* 0A ' /proc/net/tcp6 && break; sleep 0.2; done
reset_calls
out=$(apt_install --reinstall "$deb") || { printf '%s\n' "$out"; fail "reinstall failed"; }
printf '%s\n' "$out"
contains "$out" "installed, but not starting irrd-ng.service"
contains "$out" "IRRd v4:      RUNNING"
contains "$out" "port 43 (whois) is held by"
contains "$out" "Result: NOT READY, because IRRd v4 (or another program on its ports) is still running."
contains "$out" "sudo systemctl stop irrd"
contains "$out" "irrd-ng import --from-postgres 'postgresql://irrd:****@127.0.0.1:1/irrd'"
contains "$out" "Disk space:"
lacks "$out" "not-the-password"
lacks "$(calls)" " start "
lacks "$(calls)" " restart "
expect_rc 10 irrd-ng migrate-check --quiet
kill "$fake_v4"
wait "$fake_v4" 2>/dev/null || true
rm -f /run/irrd/irrd.pid

step "3. a loaded store: ready, and started on a fresh install"
printf 'route: 192.0.2.0/24\ndescr: test\norigin: AS64496\nmnt-by: TEST-MNT\nsource: TEST\n\n' >/tmp/test.db
chmod 0644 /tmp/test.db
runuser -u irrd -- env IRRD_NG_STORE_PATH=/var/lib/irrd-ng \
  irrd_load_database --config /etc/irrd.yaml --source TEST /tmp/test.db
irrd-ng migrate-check || fail "migrate-check is not ready with a loaded store"
out=$(apt-get purge -y irrd-ng 2>&1) || { printf '%s\n' "$out"; fail "purge failed"; }
printf '%s\n' "$out"
[[ -e /var/lib/irrd-ng/data.mdb ]] || fail "purge removed the store"
reset_calls
out=$(apt_install "$deb") || { printf '%s\n' "$out"; fail "install failed"; }
printf '%s\n' "$out"
contains "$out" "ready: starting irrd-ng.service"
contains "$(calls)" "start irrd-ng.service"
[[ -L /etc/systemd/system/multi-user.target.wants/irrd-ng.service ]] || fail "unit not enabled"

step "4. upgrade while running: restarted; while stopped: left stopped"
reset_calls
out=$(apt_install --reinstall "$deb") || { printf '%s\n' "$out"; fail "upgrade failed"; }
printf '%s\n' "$out"
contains "$out" "ready: restarting irrd-ng.service after the upgrade"
contains "$(calls)" "restart irrd-ng.service"
[[ ! -e /run/irrd-ng.dpkg-was-running ]] || fail "restart flag left behind"
systemctl stop irrd-ng.service
reset_calls
out=$(apt_install --reinstall "$deb") || { printf '%s\n' "$out"; fail "upgrade failed"; }
printf '%s\n' "$out"
contains "$out" "was not running before the upgrade, so it is left stopped"
lacks "$(calls)" " start "
lacks "$(calls)" " restart "
dpkg -s irrd-ng | grep -q "^Version: $pkg_version\$" || fail "version"

step "5. remove, then purge"
systemctl start irrd-ng.service
reset_calls
out=$(apt-get remove -y irrd-ng 2>&1) || { printf '%s\n' "$out"; fail "remove failed"; }
printf '%s\n' "$out"
contains "$(calls)" "stop irrd-ng.service"
contains "$out" "the store at /var/lib/irrd-ng was kept"
[[ -e /var/lib/irrd-ng/data.mdb ]] || fail "remove deleted the store"
getent passwd irrd >/dev/null || fail "remove deleted the user"
[[ -e /etc/apt/sources.list.d/irrd-ng.sources ]] || fail "remove deleted a conffile"
out=$(apt-get purge -y irrd-ng 2>&1) || { printf '%s\n' "$out"; fail "purge failed"; }
printf '%s\n' "$out"
contains "$out" "removed the system user irrd, which this package created"
contains "$out" "the store at /var/lib/irrd-ng was kept"
! getent passwd irrd >/dev/null || fail "purge kept the user it created"
[[ -e /var/lib/irrd-ng/data.mdb ]] || fail "purge deleted the store"
[[ ! -e /etc/apt/sources.list.d/irrd-ng.sources ]] || fail "purge kept the APT source"
[[ ! -e /var/lib/irrd-ng-package ]] || fail "purge kept the package state"

step "6. an existing irrd user survives a purge"
rm -rf /var/lib/irrd-ng
groupadd --system irrd 2>/dev/null || true
useradd --system --gid irrd --home-dir /home/irrd --shell /usr/sbin/nologin irrd
out=$(apt_install "$deb") || { printf '%s\n' "$out"; fail "install failed"; }
printf '%s\n' "$out"
lacks "$out" "created system user"
[[ $(stat -c '%U:%G %a' /var/lib/irrd-ng) == "irrd:irrd 750" ]] || fail "store directory owner"
out=$(apt-get purge -y irrd-ng 2>&1) || { printf '%s\n' "$out"; fail "purge failed"; }
printf '%s\n' "$out"
getent passwd irrd >/dev/null || fail "purge removed a user the package did not create"

step "all install tests passed"
