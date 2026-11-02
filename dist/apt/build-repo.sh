#!/bin/sh
# Build the signed irrd-ng APT repository.
#
#   APT_GPG_PRIVATE_KEY=... dist/apt/build-repo.sh DEBDIR SITEDIR
#
# Takes every irrd-ng_*.deb in DEBDIR and writes SITEDIR/apt:
#
#   pool/main/i/irrd-ng/*.deb
#   dists/stable/main/binary-{amd64,arm64}/Packages{,.gz}
#   dists/stable/{Release,InRelease,Release.gpg}
#   irrd-ng-archive-keyring.{asc,gpg}, irrd-ng.sources, index.html
#
# plus a SITEDIR/index.html pointing at it. Release says Origin and Label
# irrd-ng, Suite and Codename stable, which is what the package's
# unattended-upgrades snippet matches.
#
# The private key comes from the environment (ASCII armoured, without
# passphrase) and only ever lives in a throwaway GNUPGHOME. It must belong
# to the public key in dist/apt/irrd-ng-archive-keyring.asc (or
# APT_PUBLIC_KEY), and both signatures are checked against that public key
# alone before the script succeeds. Needs apt-ftparchive (apt-utils), gpg,
# gpg-agent and gpgv; the workflows run it in a pinned Debian container.
set -eu
[ $# -eq 2 ] || { sed -n '2,23p' "$0" >&2; exit 2; }
debdir=$1
site=$2
here=$(cd "$(dirname "$0")" && pwd)
public=${APT_PUBLIC_KEY:-$here/irrd-ng-archive-keyring.asc}
sources=$here/../debian/irrd-ng.sources
fail() {
	echo "build-repo: $*" >&2
	exit 1
}

[ -n "${APT_GPG_PRIVATE_KEY:-}" ] || fail "APT_GPG_PRIVATE_KEY is not set"
set -- "$debdir"/irrd-ng_*.deb
[ -e "$1" ] || fail "no irrd-ng_*.deb in $debdir"

GNUPGHOME=$(mktemp -d)
export GNUPGHOME
cleanup() {
	gpgconf --kill all 2>/dev/null || true
	rm -rf "$GNUPGHOME"
}
trap cleanup EXIT INT TERM

# The trust anchor is the committed public key.
gpg --batch --quiet --dearmor <"$public" >"$GNUPGHOME/public.gpg"
fpr=$(gpg --batch --with-colons --show-keys "$public" | awk -F: '$1 == "fpr" {print $10; exit}')
[ -n "$fpr" ] || fail "no key in $public"
printf '%s\n' "$APT_GPG_PRIVATE_KEY" | gpg --batch --quiet --import 2>/dev/null ||
	fail "APT_GPG_PRIVATE_KEY could not be imported"
gpg --batch --with-colons --list-secret-keys "$fpr" >/dev/null 2>&1 ||
	fail "APT_GPG_PRIVATE_KEY is not the secret key of $fpr"

repo=$site/apt
rm -rf "$repo"
mkdir -p "$repo/pool/main/i/irrd-ng"
for deb in "$@"; do
	cp "$deb" "$repo/pool/main/i/irrd-ng/"
done

cd "$repo"
for arch in amd64 arm64; do
	dir=dists/stable/main/binary-$arch
	mkdir -p "$dir"
	apt-ftparchive --arch "$arch" packages pool/main >"$dir/Packages"
	gzip -9n <"$dir/Packages" >"$dir/Packages.gz"
done
apt-ftparchive \
	-o APT::FTPArchive::Release::Origin=irrd-ng \
	-o APT::FTPArchive::Release::Label=irrd-ng \
	-o APT::FTPArchive::Release::Suite=stable \
	-o APT::FTPArchive::Release::Codename=stable \
	-o APT::FTPArchive::Release::Architectures="amd64 arm64" \
	-o APT::FTPArchive::Release::Components=main \
	-o APT::FTPArchive::Release::Description="irrd-ng, a drop-in replacement for IRRd 4.5" \
	release dists/stable >"$GNUPGHOME/Release"
mv "$GNUPGHOME/Release" dists/stable/Release

sign() {
	gpg --batch --yes --quiet --pinentry-mode loopback --local-user "$fpr!" \
		--digest-algo SHA512 "$@"
}
sign --clearsign --output dists/stable/InRelease dists/stable/Release
sign --armor --detach-sign --output dists/stable/Release.gpg dists/stable/Release
gpgv --quiet --keyring "$GNUPGHOME/public.gpg" dists/stable/InRelease 2>/dev/null ||
	fail "InRelease does not verify against $public"
gpgv --quiet --keyring "$GNUPGHOME/public.gpg" dists/stable/Release.gpg dists/stable/Release 2>/dev/null ||
	fail "Release.gpg does not verify against $public"

cp "$public" irrd-ng-archive-keyring.asc
cp "$GNUPGHOME/public.gpg" irrd-ng-archive-keyring.gpg
cp "$sources" irrd-ng.sources
chmod 0644 irrd-ng-archive-keyring.asc irrd-ng-archive-keyring.gpg irrd-ng.sources

packages=$(cd pool/main/i/irrd-ng && for f in *.deb; do
	printf '      <li><a href="pool/main/i/irrd-ng/%s">%s</a></li>\n' "$f" "$f"
done)
cat >index.html <<EOF
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>irrd-ng APT repository</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 46rem; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
  pre { background: #f4f4f4; padding: 0.75rem; overflow-x: auto; }
  @media (prefers-color-scheme: dark) { body { background: #111; color: #ddd; } pre { background: #222; } a { color: #8ab4f8; } }
</style>
</head>
<body>
<h1>irrd-ng APT repository</h1>
<p>Debian and Ubuntu packages of <a href="https://github.com/JoshFinlayAU/irrd-ng">irrd-ng</a>, a drop-in replacement for IRRd 4.5. One package per architecture (amd64, arm64) works on every Debian and Ubuntu release, because the binary is statically linked.</p>
<h2>Install</h2>
<p>Add the repository and its signing key, then install the package:</p>
<pre>sudo curl -fsSLo /usr/share/keyrings/irrd-ng-archive-keyring.gpg https://joshfinlayau.github.io/irrd-ng/apt/irrd-ng-archive-keyring.gpg
sudo curl -fsSLo /etc/apt/sources.list.d/irrd-ng.sources https://joshfinlayau.github.io/irrd-ng/apt/irrd-ng.sources
sudo apt update
sudo apt install irrd-ng</pre>
<p>The package installs the same two files, so apt and unattended-upgrades keep irrd-ng up to date from here on. The key's fingerprint is <code>$fpr</code>.</p>
<p>The package does not start irrd-ng while IRRd v4 is running or before its database has been imported. Run <code>sudo irrd-ng migrate-check</code> for what is left to do, and read the <a href="https://github.com/JoshFinlayAU/irrd-ng/blob/main/docs/migration.md">migration guide</a>.</p>
<h2>Packages</h2>
<ul>
$packages
</ul>
</body>
</html>
EOF
cat >"$site/index.html" <<'EOF'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>irrd-ng</title>
<meta http-equiv="refresh" content="0; url=apt/">
</head>
<body>
<p><a href="apt/">The irrd-ng APT repository</a>. The project is at <a href="https://github.com/JoshFinlayAU/irrd-ng">github.com/JoshFinlayAU/irrd-ng</a>.</p>
</body>
</html>
EOF
echo "build-repo: $# packages, signed by $fpr"
find . -type f | sort
