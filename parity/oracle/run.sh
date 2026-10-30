#!/usr/bin/env bash
# Run a v4 oracle script inside the pinned v4 image against local files.
#   parity/oracle/run.sh rpsl <input.db> > out.jsonl
#   parity/oracle/run.sh config <dir-of-yaml-files> > out.jsonl
# Needs only the image (parity/up.sh builds it), not the running stack.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
kind=$1 input=$(realpath "$2")
if [[ -d $input ]]; then mount=$input target=/input; else mount=$(dirname "$input") target=/input/$(basename "$input"); fi
exec docker run --rm -i --network none --entrypoint python \
  -v "$here:/oracle:ro" -v "$mount:/input:ro" -v "$here/../v4/irrd.yaml:/etc/irrd/irrd.yaml:ro" \
  irrd-ng-parity/irrd-v4:4.5.4 "/oracle/${kind}_oracle.py" "$target" 2> >(grep -v 'gnupg#WARNING' >&2)
