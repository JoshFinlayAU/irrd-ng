#!/usr/bin/env bash
# Build the irrd-ng Debian package from a static musl release binary.
#
#   dist/debian/build-deb.sh BINARY ARCH VERSION OUTDIR
#
# BINARY is a static musl build of irrd-ng (target/<target>/release/irrd-ng)
# and ARCH its Debian architecture, amd64 or arm64. Writes
# OUTDIR/irrd-ng_VERSION_ARCH.deb, one package for every Debian and Ubuntu
# release. Needs dpkg-deb, gzip and base64.
#
# The package holds:
#   /usr/bin/irrd-ng and a symlink to it under each of the 12 IRRd v4 tool
#     names, which the binary dispatches on
#   /usr/lib/systemd/system/irrd-ng.service, from dist/irrd-ng.service
#   /etc/apt/sources.list.d/irrd-ng.sources and the archive keyring in
#     /usr/share/keyrings, so apt keeps irrd-ng up to date
#   /etc/apt/apt.conf.d/52irrd-ng-unattended-upgrades and a needrestart
#     snippet
#   the documentation, a man page, the copyright file and a changelog
#
# The package is reproducible for a given commit: files are owned by root,
# dated from SOURCE_DATE_EPOCH (default: the HEAD commit time) and archived
# in a fixed order.
set -euo pipefail
[[ $# -eq 4 ]] || { sed -n '2,22p' "$0" >&2; exit 2; }
binary=$1 arch=$2 version=$3 outdir=$4
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

case $arch in
  amd64) elf='x86-64' ;;
  arm64) elf='ARM aarch64' ;;
  *) echo "unsupported architecture $arch (amd64 or arm64)" >&2; exit 2 ;;
esac
[[ -x $binary ]] || { echo "no binary at $binary" >&2; exit 1; }
if command -v file >/dev/null; then
  desc=$(file -b "$binary")
  [[ $desc == *"$elf"* ]] || { echo "$binary is not an $arch binary: $desc" >&2; exit 1; }
  [[ $desc == *"statically linked"* || $desc == *"static-pie linked"* ]] ||
    { echo "$binary is not statically linked: $desc" >&2; exit 1; }
fi
[[ $version =~ ^[0-9][0-9A-Za-z.+~-]*$ ]] || { echo "bad version $version" >&2; exit 2; }

# The console scripts IRRd 4.5.4 installs; the same list as dist/package.sh.
tools=(
  irrd irrdctl irrd_submit_email irrd_database_upgrade irrd_database_downgrade
  irrd_load_database irrd_update_database irrd_set_last_modified_auth
  irrd_expire_journal irrd_mirror_force_reload irr_rpsl_submit irrd_load_pgp_keys
)

epoch=${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}
export SOURCE_DATE_EPOCH=$epoch
mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
pkg=$stage/irrd-ng
umask 022

doc=$pkg/usr/share/doc/irrd-ng
install -d "$pkg/DEBIAN" "$pkg/usr/bin" "$pkg/usr/lib/systemd/system" "$doc/docs" \
  "$pkg/usr/share/keyrings" "$pkg/usr/share/man/man1" "$pkg/usr/share/lintian/overrides" \
  "$pkg/etc/apt/sources.list.d" "$pkg/etc/apt/apt.conf.d" "$pkg/etc/needrestart/conf.d"

install -m 0755 "$binary" "$pkg/usr/bin/irrd-ng"
for t in "${tools[@]}"; do
  ln -s irrd-ng "$pkg/usr/bin/$t"
done

# The unit: dist/irrd-ng.service with the binaries in /usr/bin, under a
# header for the packaged copy.
{
  cat <<'EOF'
# systemd unit for irrd-ng, the drop-in replacement for IRRd 4.5, as
# installed by the irrd-ng package. Change it with "systemctl edit irrd-ng"
# rather than editing this file.
#
# It runs irrd-ng the way IRRd v4's documented unit runs v4: started as
# root, in the foreground, with the same /etc/irrd.yaml. irrd-ng writes
# irrd.pid in `piddir`, binds the whois port, switches to the `user` and
# `group` from irrd.yaml, and only then opens the store and binds the HTTP
# port. `piddir` should be /run/irrd to match PIDFile below.
#
# The package does not start it while IRRd v4 is running or before the v4
# database is imported. "irrd-ng migrate-check" says what is left to do.

EOF
  sed -n '/^\[Unit\]/,$p' "$root/dist/irrd-ng.service" | sed 's|/usr/local/bin/|/usr/bin/|g'
} > "$pkg/usr/lib/systemd/system/irrd-ng.service"
grep -q '^ExecStart=/usr/bin/irrd ' "$pkg/usr/lib/systemd/system/irrd-ng.service" ||
  { echo "unexpected ExecStart in dist/irrd-ng.service" >&2; exit 1; }
grep -q '^Conflicts=irrd.service' "$pkg/usr/lib/systemd/system/irrd-ng.service" ||
  { echo "dist/irrd-ng.service lost Conflicts=irrd.service" >&2; exit 1; }

# The archive key, dearmoured: the base64 body of the armoured key, without
# its headers and checksum line.
awk '/^-----BEGIN/ {body = 0; next} /^$/ && !body {body = 1; next}
     /^=/ || /^-----END/ {body = 0; next} body' "$root/dist/apt/irrd-ng-archive-keyring.asc" |
  base64 -d > "$pkg/usr/share/keyrings/irrd-ng-archive-keyring.gpg"
[[ -s $pkg/usr/share/keyrings/irrd-ng-archive-keyring.gpg ]] || { echo "could not dearmour the archive key" >&2; exit 1; }
chmod 0644 "$pkg/usr/share/keyrings/irrd-ng-archive-keyring.gpg"

install -m 0644 "$here/irrd-ng.sources" "$pkg/etc/apt/sources.list.d/irrd-ng.sources"
install -m 0644 "$here/52irrd-ng-unattended-upgrades" "$pkg/etc/apt/apt.conf.d/52irrd-ng-unattended-upgrades"
install -m 0644 "$here/needrestart.conf" "$pkg/etc/needrestart/conf.d/irrd-ng.conf"
install -m 0644 "$here/lintian-overrides" "$pkg/usr/share/lintian/overrides/irrd-ng"

install -m 0644 "$root/README.md" "$root/NOTICE" "$doc/"
install -m 0644 "$root"/docs/*.md "$doc/docs/"
install -m 0644 "$here/copyright" "$doc/copyright"
date=$(date -u -R -d "@$epoch")
{
  printf 'irrd-ng (%s) stable; urgency=medium\n\n' "$version"
  printf '  * irrd-ng %s. Release notes:\n' "$version"
  printf '    https://github.com/JoshFinlayAU/irrd-ng/releases/tag/v%s\n\n' "$version"
  printf ' -- %s  %s\n' "$(sed -n 's/^Maintainer: //p' "$here/control.in")" "$date"
} | gzip -9n > "$doc/changelog.gz"

gzip -9n < "$here/irrd-ng.1" > "$pkg/usr/share/man/man1/irrd-ng.1.gz"
for t in "${tools[@]}"; do
  ln -s irrd-ng.1.gz "$pkg/usr/share/man/man1/$t.1.gz"
done

for s in preinst postinst prerm postrm; do
  install -m 0755 "$here/$s" "$pkg/DEBIAN/$s"
done
( cd "$pkg" && find etc -type f | sort | sed 's|^|/|' ) > "$pkg/DEBIAN/conffiles"
( cd "$pkg" && find usr -type f | LC_ALL=C sort | xargs md5sum ) > "$pkg/DEBIAN/md5sums"
size=$(du -sk --apparent-size --exclude=DEBIAN "$pkg" | cut -f1)
sed -e "s/@VERSION@/$version/" -e "s/@ARCH@/$arch/" -e "s/@SIZE@/$size/" \
  "$here/control.in" > "$pkg/DEBIAN/control"
chmod 0644 "$pkg/DEBIAN/control" "$pkg/DEBIAN/conffiles" "$pkg/DEBIAN/md5sums"

find "$pkg" -exec touch -h -d "@$epoch" {} +
deb=$outdir/irrd-ng_${version}_${arch}.deb
dpkg-deb --root-owner-group -Zxz --build "$pkg" "$deb" >/dev/null
echo "$deb"
