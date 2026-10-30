#!/usr/bin/env bash
# Generate synthetic PGP test keys for the irrd-ng RPSL corpus.
set -euo pipefail
out=$1
mkdir -p "$out"
export GNUPGHOME=$(mktemp -d)
chmod 700 "$GNUPGHOME"
g() { gpg --batch --pinentry-mode loopback --passphrase '' "$@"; }

# 1. ed25519, single uid
g --quick-gen-key 'Corpus Ed25519 <ed25519@example.net>' ed25519 sign 0
fp=$(gpg --list-keys --with-colons 'ed25519@example.net' | awk -F: '/^fpr/{print $10; exit}')
gpg --armor --export "$fp" > "$out/ed25519.asc"

# 2. RSA 2048 with three uids, the second marked primary
g --quick-gen-key 'Corpus Multi One <one@example.net>' rsa2048 sign 0
fp2=$(gpg --list-keys --with-colons 'one@example.net' | awk -F: '/^fpr/{print $10; exit}')
g --quick-add-uid "$fp2" 'Corpus Multi Two <two@example.net>'
g --quick-add-uid "$fp2" 'Corpus Multi Three: colon \ backslash <three@example.net>'
g --quick-set-primary-uid "$fp2" 'Corpus Multi Two <two@example.net>'
gpg --armor --export "$fp2" > "$out/multi.asc"

# 3. A key with a revoked uid
g --quick-gen-key 'Corpus Revoked Keep <keep@example.net>' ed25519 sign 0
fp3=$(gpg --list-keys --with-colons 'keep@example.net' | awk -F: '/^fpr/{print $10; exit}')
g --quick-add-uid "$fp3" 'Corpus Revoked Gone <gone@example.net>'
g --quick-revoke-uid "$fp3" 'Corpus Revoked Gone <gone@example.net>'
gpg --armor --export "$fp3" > "$out/revoked-uid.asc"

# 4. An expired key (created in 2015, expired in 2016)
g --faked-system-time 20150101T000000 --quick-gen-key 'Corpus Expired <expired@example.net>' rsa2048 sign 2016-01-01
fp4=$(gpg --list-keys --with-colons 'expired@example.net' | awk -F: '/^fpr/{print $10; exit}')
gpg --armor --export "$fp4" > "$out/expired.asc"

# 5. Non-ASCII uid (UTF-8), to check python-gnupg's Latin-1 decoding
g --quick-gen-key 'Corpus Ünïcødé Ñame <unicode@example.net>' ed25519 sign 0
fp5=$(gpg --list-keys --with-colons 'unicode@example.net' | awk -F: '/^fpr/{print $10; exit}')
gpg --armor --export "$fp5" > "$out/unicode.asc"

# 6. A uid containing a U+0085 byte sequence (C3 85 is "Å")
g --quick-gen-key 'Corpus Åse <ase@example.net>' ed25519 sign 0
fp6=$(gpg --list-keys --with-colons 'ase@example.net' | awk -F: '/^fpr/{print $10; exit}')
gpg --armor --export "$fp6" > "$out/a-ring.asc"

# 7. RSA key with an encryption subkey
g --quick-gen-key 'Corpus Subkey <subkey@example.net>' rsa2048 default 0
fp7=$(gpg --list-keys --with-colons 'subkey@example.net' | awk -F: '/^fpr/{print $10; exit}')
gpg --armor --export "$fp7" > "$out/subkey.asc"

# 8. DSA key
g --quick-gen-key 'Corpus DSA <dsa@example.net>' dsa2048 sign 0
fp8=$(gpg --list-keys --with-colons 'dsa@example.net' | awk -F: '/^fpr/{print $10; exit}')
gpg --armor --export "$fp8" > "$out/dsa.asc"

# 9. Same key as 2 but exported with only one uid, for keyring merge tests
gpg --armor --export-filter keep-uid='uid =~ one@example.net' --export "$fp2" > "$out/multi-one-uid.asc"

for f in "$out"/*.asc; do echo "$f $(grep -c '' "$f")"; done
gpg --list-keys --with-colons | grep -E '^(fpr|uid)' | head -40
rm -rf "$GNUPGHOME"
