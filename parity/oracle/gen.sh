#!/usr/bin/env bash
# Generate v4 oracle output for every Tier 1 fixture into parity/.cache/oracle/.
# Real-data oracle output is never committed; synthetic corpora under
# parity/corpus/ commit their expected output next to the inputs.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .cache/oracle
for f in .cache/fixtures/*.db; do
  out=.cache/oracle/$(basename "$f" .db).rpsl.jsonl
  oracle/run.sh rpsl "$f" > "$out.part" && mv "$out.part" "$out"
  echo "$(wc -l < "$out") paragraphs  $out"
done
