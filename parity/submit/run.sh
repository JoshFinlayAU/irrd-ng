#!/usr/bin/env bash
# Submission differential (Phase 7): identical submissions by e-mail, HTTP
# and the CLI tools to IRRd v4 and irrd-ng from the same starting data,
# then compare responses, mails (Mailpit), the NRTMv3 journal and the
# canonical exports.
#
#   parity/submit/run.sh [--keep]
#
# Environment:
#   WORK  scratch directory (default: parity/.work/submit)
#
# irrd-ng is built here (release without LTO, in target/harness) and run in
# the pinned v4 image. Mail only goes to the two Mailpit containers.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
export WORK=${WORK:-$ROOT/parity/.work/submit}
export PATH=$HOME/.cargo/bin:$HOME/.local/bin:$PATH
KEEP=${1:-}

mkdir -p "$WORK/bin"
(cd "$ROOT" && CARGO_TARGET_DIR="$ROOT/target/harness" CARGO_PROFILE_RELEASE_LTO=false \
  CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 cargo build --release -p cli --bin irrd-ng -q)
install -m 755 "$ROOT/target/harness/release/irrd-ng" "$WORK/bin/irrd-ng"

DC=(docker compose -f "$HERE/compose.yaml" --project-directory "$HERE")
cleanup() {
  if [[ $KEEP != --keep ]]; then
    WORK=$WORK "${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

python3 "$HERE/scenario.py" "$WORK"
python3 "$HERE/compare.py" "$WORK" "${@:2}"
