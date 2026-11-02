#!/bin/sh
# Install exact versions of Debian packages in a CI container.
#
#   dist/debian/apt-pinned.sh SNAPSHOT PACKAGE=VERSION...
#
# Run as root in the pinned debian:13 image the workflows use. Tries the
# normal Debian mirror first; when a pinned version has been superseded
# there, falls back to snapshot.debian.org at SNAPSHOT (a timestamp such
# as 20261015T000000Z), which keeps every version. Either way exactly the
# pinned versions are installed, or the script fails.
set -eu
[ $# -ge 2 ] || { sed -n '2,10p' "$0" >&2; exit 2; }
snapshot=$1
shift
export DEBIAN_FRONTEND=noninteractive
retries='-o Acquire::Retries=5'

# shellcheck disable=SC2086
apt-get $retries update -qq
# shellcheck disable=SC2086
if ! apt-get $retries install -y -qq --no-install-recommends "$@" >/dev/null; then
	echo "pinned versions not on the Debian mirror, using snapshot.debian.org/$snapshot"
	# shellcheck source=/dev/null
	. /etc/os-release
	cat >/etc/apt/sources.list.d/snapshot.sources <<EOF
Types: deb
URIs: http://snapshot.debian.org/archive/debian/$snapshot
Suites: $VERSION_CODENAME
Components: main
Check-Valid-Until: no
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF
	# shellcheck disable=SC2086
	apt-get $retries update -qq
	# shellcheck disable=SC2086
	apt-get $retries install -y -qq --no-install-recommends "$@" >/dev/null
fi
for p in "$@"; do
	name=${p%%=*}
	want=${p#*=}
	have=$(dpkg-query -W -f '${Version}' "$name")
	[ "$have" = "$want" ] || { echo "$name is $have, not $want" >&2; exit 1; }
	echo "$name $have"
done
