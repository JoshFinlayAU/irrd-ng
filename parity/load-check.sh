#!/usr/bin/env bash
# Three-way load check (PLAN.md, "Testing and parity strategy").
#
# For each dump: load it into v4 with v4's irrd_load_database and export
# v4's database; load the same dump with irrd-ng's irrd_load_database into a
# fresh store and export it; import v4's database into another fresh store
# with `irrd-ng import --from-postgres` and export that; run the import a
# second time over the imported store and check nothing changed; then diff:
#
#   v4      vs import   every column, exactly (the import preserves all)
#   v4      vs load     minus the columns in loadcheck/excluded-columns.tsv
#   load    vs import   minus the same columns
#
# Wall time, peak RSS, PostgreSQL sizes and store sizes go to
# parity/.work/<dump>/ and one summary line per dump to
# parity/.work/load-check.tsv.
#
#   parity/load-check.sh [--tier fixtures|full|all] [--phases v4,load,import,diff]
#                        [--reuse-v4] [dump-name...]
#
# Dumps are read from LOADCHECK_CACHE (default parity/.cache). IRRD_NG is
# the irrd-ng binary (default target/release/irrd-ng). Uses its own compose
# project, irrd-loadcheck, with PostgreSQL on 127.0.0.1:${LOADCHECK_PG_PORT:-9432}.
set -euo pipefail
cd "$(dirname "$0")"
parity=$PWD
repo=$(cd .. && pwd)

export LOADCHECK_CACHE=${LOADCHECK_CACHE:-$parity/.cache}
export LOADCHECK_WORK=${LOADCHECK_WORK:-$parity/.work}
export LOADCHECK_PG_PORT=${LOADCHECK_PG_PORT:-9432}
export LOADCHECK_UID=${LOADCHECK_UID:-$(id -u)} LOADCHECK_GID=${LOADCHECK_GID:-$(id -g)}
IRRD_NG=${IRRD_NG:-$repo/target/release/irrd-ng}
SERIAL=${LOADCHECK_SERIAL:-1000}
work=$LOADCHECK_WORK
compose=(docker compose -f "$parity/loadcheck/compose.yaml")
v4=irrd-loadcheck-v4-1

tier=fixtures phases=v4,load,import,diff reuse_v4=0 only=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --tier) tier=$2; shift 2 ;;
    --phases) phases=$2; shift 2 ;;
    --reuse-v4) reuse_v4=1; shift ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) only+=("$1"); shift ;;
  esac
done
has_phase() { [[ ,$phases, == *,$1,* ]]; }

# name<TAB>source<TAB>dump paths inside the v4 container (/cache/...).
# Every dump runs twice: as published (v4's loader stops at the first object
# it rejects, and irrd-ng's must fail the same way), and as <name>-clean,
# the subset v4 accepts (tools/v4_clean_dump.py), which both load in full.
dumps() {
  raw_dumps | while IFS=$'\t' read -r name source files; do
    printf '%s\t%s\t%s\n' "$name" "$source" "$files"
    printf '%s-clean\t%s\t%s\n' "$name" "$source" "$files"
  done
}

raw_dumps() {
  if [[ $tier == fixtures || $tier == all ]]; then
    for f in "$LOADCHECK_CACHE"/fixtures/*.db; do
      s=$(basename "$f" .db)
      printf 'fixture-%s\t%s\t/cache/fixtures/%s.db\n' "$s" "$s" "$s"
    done
  fi
  if [[ $tier == full || $tier == all ]]; then
    local apnic=()
    for f in "$LOADCHECK_CACHE"/*.db.gz; do
      s=$(basename "$f" .db.gz)
      case $s in
        APNIC-*) apnic+=("/cache/$s.db.gz") ;;
        *) printf 'full-%s\t%s\t/cache/%s.db.gz\n' "$s" "$s" "$s" ;;
      esac
    done
    # APNIC publishes one file per class; v4 replaces the whole source on
    # every irrd_load_database run, so they are loaded as one dump.
    [[ ${#apnic[@]} -gt 0 ]] && printf 'full-APNIC\tAPNIC\t%s\n' "${apnic[*]}"
  fi
}

host_path() {
  case $1 in
    /work/*) printf '%s' "$work/${1#/work/}" ;;
    *) printf '%s' "$LOADCHECK_CACHE/${1#/cache/}" ;;
  esac
}

ensure_stack() {
  if ! docker inspect -f '{{.State.Running}}' "$v4" 2>/dev/null | grep -q true; then
    "${compose[@]}" up -d --wait
  fi
}

db_name() { printf 'v4_%s' "$(tr 'A-Z-' 'a-z_' <<< "$1")"; }
dsn_for() { printf 'postgresql://irrd:irrd@127.0.0.1:%s/%s?sslmode=disable' "$LOADCHECK_PG_PORT" "$(db_name "$1")"; }

# irrd-ng side. Each takes the dump name and writes under $work/<name>/<phase>/.
ng_config() {
  local name=$1 source=$2 out=$3
  python3 -I - "$parity/v4/irrd.yaml" "$source" "$out" <<'PY'
import sys
src, source, out = sys.argv[1:]
text = open(src).read()
# Same base config as v4's run, with the one source being loaded.
head = text.split("  sources_default:")[0]
# Host paths instead of the container's.
d = out.rsplit("/", 1)[0]
head = head.replace("piddir: /run/irrd", f"piddir: {d}")
head = head.replace("gnupg_keyring: /var/lib/irrd/gnupg", f"gnupg_keyring: {d}/gnupg")
open(out, "w").write(
    head
    + f"  sources_default:\n    - {source}\n  sources:\n    {source}:\n      keep_journal: false\n"
)
PY
}

ng_load() {
  local name=$1 source=$2; shift 2
  local out=$work/$name/ng-load
  rm -rf "$out" && mkdir -p "$out"
  ng_config "$name" "$source" "$out/irrd.yaml"
  local files=() f
  for f in "$@"; do files+=("$(host_path "$f")"); done
  local dump=$out/dump.db
  : > "$dump"
  for f in "${files[@]}"; do
    case $f in *.gz) zcat "$f" ;; *) cat "$f" ;; esac >> "$dump"
    printf '\n' >> "$dump"
  done
  set +e
  IRRD_NG_STORE_PATH=$out/store python3 -I "$parity/tools/measure.py" "$out/load.json" -- \
    "$IRRD_NG" irrd_load_database --config "$out/irrd.yaml" --source "$source" --serial "$SERIAL" "$dump" \
    > "$out/load.log" 2>&1
  echo $? > "$out/load.exit"
  set -e
  rm -f "$dump"
  du -sb "$out/store" 2>/dev/null | cut -f1 > "$out/store.bytes" || true
  ng_export "$out/store" "$out/export" "$out/irrd.yaml"
}

ng_import() {
  local name=$1 run=$2 source=$3
  local out=$work/$name/ng-import
  if [[ $run == 1 ]]; then
    rm -rf "$out" && mkdir -p "$out"
    ng_config "$name" "$source" "$out/irrd.yaml"
  fi
  set +e
  python3 -I "$parity/tools/measure.py" "$out/import$run.json" -- \
    "$IRRD_NG" import --from-postgres "$(dsn_for "$name")" --store "$out/store" \
    > "$out/import$run.log" 2>&1
  echo $? > "$out/import$run.exit"
  set -e
  du -sb "$out/store" 2>/dev/null | cut -f1 > "$out/store$run.bytes" || true
  ng_export "$out/store" "$out/export$run" "$out/irrd.yaml"
}

# The store's canonical export (crates/store/src/export.rs): <dir>/<table>.jsonl.
ng_export() {
  rm -rf "$2" && mkdir -p "$2"
  IRRD_NG_STORE_PATH=$1 "$IRRD_NG" export-jsonl --config "$3" --table all --output-dir "$2" \
    > "$2.log" 2>&1 || { cat "$2.log" >&2; return 1; }
}

compare() {
  local name=$1 d=$work/$1 rc=0
  local ex=$parity/loadcheck/excluded-columns.tsv
  {
    echo "== v4 vs import (exact)"
    python3 -I "$parity/tools/compare_exports.py" "$d/v4/export" "$d/ng-import/export1" \
      --label-left v4 --label-right import || rc=1
    echo "== import run 1 vs run 2 (idempotent re-run)"
    python3 -I "$parity/tools/compare_exports.py" "$d/ng-import/export1" "$d/ng-import/export2" \
      --label-left run1 --label-right run2 || rc=1
    echo "== v4 vs load (minus excluded columns)"
    python3 -I "$parity/tools/compare_exports.py" "$d/v4/export" "$d/ng-load/export" \
      --exclude-file "$ex" --label-left v4 --label-right load || rc=1
    echo "== load vs import (minus excluded columns)"
    python3 -I "$parity/tools/compare_exports.py" "$d/ng-load/export" "$d/ng-import/export1" \
      --exclude-file "$ex" --label-left load --label-right import || rc=1
  } > "$d/diff.txt" 2>&1
  return $rc
}

summary() {
  local name=$1 d=$work/$1 verdict=$2
  python3 -I - "$d" "$name" "$verdict" >> "$work/load-check.tsv" <<'PY'
import json, os, sys
d, name, verdict = sys.argv[1:]
def j(p):
    try:
        return json.load(open(os.path.join(d, p)))
    except Exception:
        return {}
def t(p):
    try:
        return open(os.path.join(d, p)).read().strip()
    except Exception:
        return ""
sizes = {}
for line in t("v4/sizes.tsv").splitlines():
    k, total, *_ = line.split("|")
    sizes[k] = int(total)
rows = j("v4/export.json").get("rows", {})
v4l, ngl, imp1, imp2 = j("v4/load.json"), j("ng-load/load.json"), j("ng-import/import1.json"), j("ng-import/import2.json")
print("\t".join(str(x) for x in [
    name, rows.get("rpsl_objects", ""),
    v4l.get("wall_s", ""), v4l.get("maxrss_kib", ""), sizes.get("database", ""),
    ngl.get("wall_s", ""), ngl.get("maxrss_kib", ""), t("ng-load/store.bytes"),
    imp1.get("wall_s", ""), imp1.get("maxrss_kib", ""), t("ng-import/store1.bytes"),
    imp2.get("wall_s", ""), t("ng-import/store2.bytes"),
    verdict,
]))
PY
}

mkdir -p "$work"
[[ -f $work/load-check.tsv ]] || printf 'dump\tobjects\tv4_load_s\tv4_load_rss_kib\tv4_pg_bytes\tng_load_s\tng_load_rss_kib\tng_load_store_bytes\timport_s\timport_rss_kib\timport_store_bytes\treimport_s\treimport_store_bytes\tresult\n' > "$work/load-check.tsv"
ensure_stack

status=0
while IFS=$'\t' read -r name source files; do
  if [[ ${#only[@]} -gt 0 ]]; then
    match=0
    for o in "${only[@]}"; do [[ $o == "$name" ]] && match=1; done
    [[ $match == 1 ]] || continue
  fi
  read -ra paths <<< "$files"
  echo "### $name ($source)"
  if [[ $name == *-clean ]]; then
    mkdir -p "$work/$name"
    if has_phase v4 || [[ ! -s $work/$name/input.db ]]; then
      docker exec "$v4" python3 /tools/v4_clean_dump.py "/work/$name/input.db" "$source" "${paths[@]}" \
        | tee "$work/$name/clean.txt"
    fi
    paths=("/work/$name/input.db")
  fi
  if has_phase v4 && ! { [[ $reuse_v4 == 1 ]] && [[ -s $work/$name/v4/export.json ]]; }; then
    docker exec "$v4" /loadcheck/v4-load.sh "$name" "$source" "$SERIAL" "${paths[@]}"
  fi
  if [[ $(cat "$work/$name/v4/load.exit" 2>/dev/null) != 0 ]]; then
    echo "v4 failed to load $name:"; tail -5 "$work/$name/v4/load.log"
  fi
  has_phase load && ng_load "$name" "$source" "${paths[@]}"
  if has_phase import; then
    ng_import "$name" 1 "$source"
    ng_import "$name" 2 "$source"
  fi
  if has_phase diff; then
    if compare "$name"; then verdict=AGREE; else verdict=DIFFER; status=1; fi
    echo "$name: $verdict (details in $work/$name/diff.txt)"
    summary "$name" "$verdict"
  fi
done < <(dumps)
exit $status
