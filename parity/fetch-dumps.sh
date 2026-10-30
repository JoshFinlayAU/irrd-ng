#!/usr/bin/env bash
# Fetch the public IRR dumps listed in dumps.tsv into parity/.cache/.
# Real registry data is never committed. A dump already cached and younger
# than MAX_AGE_DAYS (default 7) is kept, so reruns and CI caches are cheap.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p .cache
max_age=${MAX_AGE_DAYS:-7}
ua="irrd-ng-parity/0.0 (+https://github.com/JoshFinlayAU/irrd-ng)"
status=0
while IFS=$'\t' read -r source url _; do
  [[ -z $source || $source == \#* ]] && continue
  out=".cache/$source.db.gz"
  if [[ -s $out ]] && [[ -n $(find "$out" -mtime -"$max_age") ]]; then
    echo "cached  $source"
    continue
  fi
  if curl -sSfL --retry 3 --connect-timeout 20 -A "$ua" -o "$out.part" "$url" && gzip -t "$out.part"; then
    mv "$out.part" "$out"
    echo "fetched $source $(du -h "$out" | cut -f1)"
  else
    rm -f "$out.part"
    echo "FAILED  $source $url" >&2
    status=1
  fi
done < dumps.tsv
exit $status
