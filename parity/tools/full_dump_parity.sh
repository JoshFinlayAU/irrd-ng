#!/usr/bin/env bash
# Phase 1 exit check: every paragraph of every cached dump against the v4
# oracle, not just the Tier 1 fixtures. Needs the v4 image and about 15 GB
# free; everything goes under parity/.cache/full/ (git-ignored).
#   parity/tools/full_dump_parity.sh [jobs]
set -euo pipefail
cd "$(dirname "$0")/../.."
jobs=${1:-12}
work=parity/.cache/full
rm -rf "$work" && mkdir -p "$work/chunks" "$work/oracle"
for d in parity/.cache/*.db.gz; do
  python3 -I parity/tools/split_dump.py "$d" "$work/chunks" "$(basename "$d" .db.gz)" 50000
done
ls "$work/chunks"/*.db | xargs -P "$jobs" -I{} sh -c \
  'out=parity/.cache/full/oracle/$(basename {} .db).rpsl.jsonl; parity/oracle/run.sh rpsl {} > "$out.part" && mv "$out.part" "$out"'
IRRD_NG_ORACLE_DIR=$PWD/$work/oracle IRRD_NG_FIXTURE_DIR=$PWD/$work/chunks \
  cargo nextest run -p rpsl --test oracle --no-capture --release
