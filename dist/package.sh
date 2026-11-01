#!/usr/bin/env bash
# Package one release build as a tarball.
#
#   dist/package.sh TARGET VERSION OUTDIR
#
# Takes target/TARGET/release/irrd-ng and writes
# OUTDIR/irrd-ng-VERSION-TARGET.tar.gz holding:
#
#   bin/irrd-ng              the multicall binary
#   bin/<tool>               symlinks to it under the 12 IRRd v4 tool names
#   systemd/irrd-ng.service  the systemd unit
#   docs/                    the operator documentation
#   licenses/                licences of third-party files built into the binary
#   LICENSE NOTICE README.md
#
# The archive is reproducible for a given commit: entries are sorted, owned
# by 0:0 and dated from SOURCE_DATE_EPOCH (default: the HEAD commit time).
set -euo pipefail
[[ $# -eq 3 ]] || { sed -n '2,16p' "$0" >&2; exit 2; }
target=$1 version=$2 outdir=$3
root=$(cd "$(dirname "$0")/.." && pwd)
bin=$root/target/$target/release/irrd-ng
[[ -x $bin ]] || { echo "no binary at $bin" >&2; exit 1; }

# The console scripts IRRd 4.5.4 installs (its pyproject.toml), which the
# binary dispatches on (crates/cli/src/tools.rs).
tools=(
  irrd irrdctl irrd_submit_email irrd_database_upgrade irrd_database_downgrade
  irrd_load_database irrd_update_database irrd_set_last_modified_auth
  irrd_expire_journal irrd_mirror_force_reload irr_rpsl_submit irrd_load_pgp_keys
)

# Where the binary runs here, check it answers to every name packaged.
if usage=$("$bin" 2>&1 >/dev/null; true) && [[ $usage == usage:* ]]; then
  for t in "${tools[@]}"; do
    [[ $usage == *" $t,"* || $usage == *" $t" ]] || { echo "binary does not list tool $t" >&2; exit 1; }
  done
fi

name=irrd-ng-$version-$target
mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
dir=$stage/$name
mkdir -p "$dir/bin" "$dir/systemd" "$dir/docs" "$dir/licenses/graphiql"
install -m 0755 "$bin" "$dir/bin/irrd-ng"
for t in "${tools[@]}"; do
  ln -s irrd-ng "$dir/bin/$t"
done
install -m 0644 "$root/dist/irrd-ng.service" "$dir/systemd/"
install -m 0644 "$root"/docs/*.md "$dir/docs/"
install -m 0644 "$root/LICENSE" "$root/NOTICE" "$root/README.md" "$dir/"
install -m 0644 "$root/crates/http/assets/graphiql/README.md" "$root"/crates/http/assets/graphiql/licenses/*.txt \
  "$dir/licenses/graphiql/"

epoch=${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
  --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
  -C "$stage" -cf - "$name" | gzip -9n > "$outdir/$name.tar.gz"
echo "$outdir/$name.tar.gz"
