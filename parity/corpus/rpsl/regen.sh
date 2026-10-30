#!/usr/bin/env bash
# Regenerate the v4 oracle output for the synthetic RPSL corpus.
#   parity/corpus/rpsl/regen.sh
# Needs the pinned v4 image (parity/up.sh builds it). Rewrites every
# expected.*.jsonl here; review the diff like any other change, since
# expected output must never be edited to make a test pass.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
oracle=$(cd "$here/../../oracle" && pwd)
python3 -I "$here/make_corpus.py"
for db in "$here"/*.db; do
  name=$(basename "$db" .db)
  "$oracle/run.sh" rpsl "$db" > "$here/expected.$name.jsonl"
done
docker run --rm -i --network none --entrypoint python \
  -v "$oracle:/oracle:ro" -v "$here:/corpus:ro" -v "$here/../../v4/irrd.yaml:/etc/irrd/irrd.yaml:ro" \
  irrd-ng-parity/irrd-v4:4.5.4 /corpus/samples_oracle.py > "$here/expected.samples.jsonl" \
  2> >(grep -v 'gnupg#WARNING' >&2)
wc -l "$here"/expected.*.jsonl
