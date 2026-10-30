#!/usr/bin/env bash
# Fail if vendor/irrd-v4 is not checked out at the commit in BASELINE, or has
# local edits. The v4 checkout is read-only reference material.
set -euo pipefail
cd "$(dirname "$0")/.."
want=$(sed -n 's/^irrd_commit=//p' parity/BASELINE)
have=$(git -C vendor/irrd-v4 rev-parse HEAD)
[[ $have == "$want" ]] || { echo "vendor/irrd-v4 is at $have, BASELINE says $want" >&2; exit 1; }
[[ -z $(git -C vendor/irrd-v4 status --porcelain) ]] || { echo "vendor/irrd-v4 has local changes" >&2; exit 1; }
echo "vendor/irrd-v4 matches BASELINE ($want)"
