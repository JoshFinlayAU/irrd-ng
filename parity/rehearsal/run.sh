#!/usr/bin/env bash
# The drop-in rehearsal (PLAN.md Phase 9 exit): replace a loaded v4 with
# irrd-ng the way an operator would, then prove no client can tell.
#
#   parity/rehearsal/run.sh [--skip-load] [--keep] [--suite SUITE]
#
# 1. Load the Tier 1 stack (parity/load.sh --profile rpki --ng none), so
#    v4 serves the fixtures on 127.0.0.1:9043 (whois) and :9080 (HTTP).
# 2. Record what an NRTMv3 client of v4 has seen (rehearsal/nrtm_client.py)
#    and v4's !j-* and !J-*.
# 3. Stop v4. Run `irrd-ng import --from-postgres` against v4's database,
#    inside v4's container image as v4's user, with the DSN host v4 uses.
# 4. Start irrd-ng in v4's place: v4's image, v4's user, the same
#    /etc/irrd/irrd.yaml file unchanged, the same mounts and the same ports
#    (compose service irrd-ng-rehearsal). Check !j-* and !J-* are unchanged, the PID
#    file is where v4 keeps it, and a SIGHUP reloads.
# 5. Start a second v4 on the untouched database (compose profile twin, on
#    9243/9280) as the reference, and run every suite against the two
#    (parity/run.sh --suite all, then bgpq4.sh), with irrd-ng's tools run
#    inside its container.
# 6. Follow EVSTREAM's journal across the cutover: the NRTMv3 client asks
#    irrd-ng for its last serial + 1 onwards and gets what v4 gives.
# 7. Stop irrd-ng (SIGTERM, checking it exits cleanly) and the twin, and
#    start v4 again, unless --keep. The events-live suite changes the
#    data: run parity/load.sh before the regular suites again.
#
# --skip-load uses the stack as load.sh left it. --suite limits run.sh to
# one suite (default all). Reports go to parity/out/rehearsal-<stamp>/
# (summary.txt). Exit 0 when every step passes with no unexplained
# difference.
#
# Env: PARITY_CACHE (dump cache), IRRD_NG (the binary to rehearse; it runs
# in v4's Debian image, so a glibc or static musl Linux build of the host
# architecture), PARITY_WORK.
set -euo pipefail
cd "$(dirname "$0")/.."
parity=$PWD
repo=$(cd .. && pwd)
export PARITY_CACHE=${PARITY_CACHE:-$parity/.cache}
work=${PARITY_WORK:-$parity/.work}/tier1
rwork=${PARITY_WORK:-$parity/.work}/rehearsal
IRRD_NG=${IRRD_NG:-$repo/target/release/irrd-ng}
export PARITY_TIER1_WORK=$work PARITY_V4_CONFIG=$work/irrd-v4.yaml PARITY_REHEARSAL_BIN=$rwork/bin
load=1 keep=0 suite=all
while [[ $# -gt 0 ]]; do
  case $1 in
    --skip-load) load=0; shift ;;
    --keep) keep=1; shift ;;
    --suite) suite=$2; shift 2 ;;
    -h|--help) sed -n '2,36p' "$0"; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=$parity/out/rehearsal-$stamp
mkdir -p "$out" "$rwork"
summary=$out/summary.txt
failed=0
note() { printf '%s\n' "$*" | tee -a "$summary"; }
step() { note ""; note "== $*"; }
check() { # check NAME COMMAND...
  local name=$1; shift
  if "$@" >> "$out/checks.log" 2>&1; then note "ok   $name"; else note "FAIL $name"; failed=1; fi
}
dc() { docker compose --profile twin --profile rehearsal "$@"; }
ng_exec() { dc exec -T irrd-ng-rehearsal "$@"; }
answers() { [[ $(./whois.sh 127.0.0.1 "$1" '!v' 2>/dev/null) == *"version 4.5.4"* ]]; }
wait_for() { # wait_for PORT WHAT
  for _ in $(seq 1 120); do answers "$1" && return 0; sleep 1; done
  note "FAIL $2 did not answer !v on $1"; return 1
}

step "1. Tier 1 v4 with the fixtures"
if [[ $load == 1 ]]; then
  ./load.sh --profile rpki --ng none | tee "$out/load.log"
fi
./up.sh > /dev/null
wait_for 9043 "v4"
note "v4: $(./whois.sh 127.0.0.1 9043 '!v' | sed -n 2p)"
note "irrd.yaml: $work/irrd-v4.yaml, sha256 $(sha256sum "$work/irrd-v4.yaml" | cut -c1-16)"

step "2. what v4's clients have seen"
{ ./whois.sh 127.0.0.1 9043 '!j-*'; ./whois.sh 127.0.0.1 9043 '!J-*'; } > "$out/v4-serials.txt"
python3 -I rehearsal/nrtm_client.py record --addr 127.0.0.1:9043 --source EVSTREAM --state "$rwork/nrtm.json" | tee -a "$summary"

step "3. stop v4, import its database"
rm -rf "$rwork/bin" && mkdir -p "$rwork/bin"
cp "$IRRD_NG" "$rwork/bin/irrd-ng"
for t in irrd irrd_submit_email irrd_load_database irrd_update_database irrd_mirror_force_reload \
  irrd_set_last_modified_auth irrd_expire_journal irrdctl irr_rpsl_submit irrd_load_pgp_keys \
  irrd_database_upgrade irrd_database_downgrade; do
  ln -s irrd-ng "$rwork/bin/$t"
done
t0=$SECONDS
dc stop irrd-v4 > /dev/null 2>&1
note "v4 stopped in $((SECONDS - t0))s"
dc rm -sf irrd-ng-rehearsal > /dev/null 2>&1 || true
docker volume rm -f irrd-parity_rehearsal-home > /dev/null
t0=$SECONDS
if dc run --rm --no-deps -T --entrypoint /opt/irrd-ng/irrd-ng irrd-ng-rehearsal \
  import --from-postgres "postgresql://irrd:irrd@postgres/irrd?sslmode=disable" \
  --store /var/lib/irrd/irrd-ng > "$out/import.log" 2>&1; then
  note "ok   import in $((SECONDS - t0))s: $(tail -1 "$out/import.log")"
else
  note "FAIL import"; tail -20 "$out/import.log" | tee -a "$summary"; exit 1
fi

step "4. irrd-ng in v4's place"
t0=$SECONDS
dc up -d irrd-ng-rehearsal > /dev/null 2>&1
wait_for 9043 "irrd-ng" || { dc logs --tail 30 irrd-ng-rehearsal | tee -a "$summary"; exit 1; }
note "irrd-ng answering on v4's port 9043 after $((SECONDS - t0))s: $(./whois.sh 127.0.0.1 9043 '!v' | sed -n 2p)"
{ ./whois.sh 127.0.0.1 9043 '!j-*'; ./whois.sh 127.0.0.1 9043 '!J-*'; } > "$out/ng-serials.txt"
check "!j-* and !J-* (every source's serials and status) identical to v4's before the cutover" cmp "$out/v4-serials.txt" "$out/ng-serials.txt"
check "runs as v4's user" bash -c "[[ \$(docker compose --profile rehearsal exec -T irrd-ng-rehearsal id -un) == irrd ]]"
ngpid=$(ng_exec cat /run/irrd/irrd.pid | tr -d '\r\n' || true)
check "PID file /run/irrd/irrd.pid (piddir) names the daemon" bash -c "[[ -n '$ngpid' ]] && docker compose --profile rehearsal logs irrd-ng-rehearsal | grep -q 'IRRd 4.5.4 starting, PID $ngpid, PID file in /run/irrd'"
dc kill -s HUP irrd-ng-rehearsal > /dev/null
sleep 2
check "SIGHUP reloads the configuration" bash -c "docker compose --profile rehearsal logs irrd-ng-rehearsal | grep -q 'Configuration successfully (re)loaded from /etc/irrd/irrd.yaml in PID $ngpid'"

step "5. every suite against v4 on the untouched database"
dc up -d irrd-v4-twin > /dev/null 2>&1
wait_for 9243 "the v4 twin"
v4/preload-kick.sh irrd-v4-twin 9280 > /dev/null
export PARITY_V4_SERVICE=irrd-v4-twin
export PARITY_NG_TOOL="docker compose --profile rehearsal exec -T irrd-ng-rehearsal /opt/irrd-ng/irrd-ng"
export PARITY_NG_CONFIG=/etc/irrd/irrd.yaml PARITY_NG_FILES=/tier1
targets=(--ref 127.0.0.1:9243 --http-ref 127.0.0.1:9280 --test 127.0.0.1:9043 --http-test 127.0.0.1:9080)
# bgpq4 first: events-live (last in run.sh's "all") changes the data.
if ./bgpq4.sh --ref 127.0.0.1:9243 --test 127.0.0.1:9043 --out "$out/bgpq4" > "$out/bgpq4.log" 2>&1; then
  note "ok   bgpq4.sh: $(tail -1 "$out/bgpq4.log")"
else
  note "FAIL bgpq4.sh: $(tail -1 "$out/bgpq4.log")"; failed=1
fi
if ./run.sh --suite "$suite" "${targets[@]}" --out "$out/suites" > "$out/suites.log" 2>&1; then
  note "ok   run.sh --suite $suite"
else
  note "FAIL run.sh --suite $suite"; failed=1
fi
for f in "$out"/suites/*/summary.txt "$out"/suites/summary.txt; do
  [[ -f $f ]] && { note "-- ${f#$out/}"; sed 's/^/   /' "$f" | tee -a "$summary" > /dev/null; }
done

step "6. an NRTMv3 client carries on across the cutover"
if [[ $suite != all && $suite != events-live ]]; then
  # Without events-live nothing changed since the cutover: make the same
  # change on both.
  cp events/EVSTREAM.live "$work/"
  dc exec -T irrd-v4-twin irrd_update_database --config /etc/irrd/irrd.yaml --source EVSTREAM /tier1/EVSTREAM.live > /dev/null
  ng_exec /opt/irrd-ng/irrd_update_database --config /etc/irrd/irrd.yaml --source EVSTREAM /tier1/EVSTREAM.live > /dev/null
fi
if python3 -I rehearsal/nrtm_client.py follow --addr 127.0.0.1:9043 --ref 127.0.0.1:9243 \
  --state "$rwork/nrtm.json" > "$out/nrtm.log" 2>&1; then :; else failed=1; fi
sed 's/^/     /' "$out/nrtm.log" | tee -a "$summary" > /dev/null

if [[ $keep == 0 ]]; then
  step "7. stop irrd-ng, restore v4"
  t0=$SECONDS
  dc stop -t 30 irrd-ng-rehearsal > /dev/null 2>&1
  code=$(docker inspect -f '{{.State.ExitCode}}' "$(dc ps -aq irrd-ng-rehearsal)")
  note "irrd-ng stopped by SIGTERM in $((SECONDS - t0))s, exit code $code"
  check "clean SIGTERM shutdown" bash -c "[[ $code == 0 ]] && docker compose --profile rehearsal logs irrd-ng-rehearsal | tail -3 | grep -q 'Main process exiting'"
  dc logs --no-log-prefix irrd-ng-rehearsal > "$out/irrd-ng.log" 2>&1
  dc stop irrd-v4-twin > /dev/null 2>&1
  dc rm -sf irrd-ng-rehearsal irrd-v4-twin > /dev/null 2>&1
  dc up -d irrd-v4 > /dev/null 2>&1
  note "v4 restarted (run parity/load.sh before the regular suites)"
fi

step "result"
if [[ $failed == 0 ]]; then note "PASS: drop-in rehearsal, report in $out"; else note "FAIL: see $out"; fi
exit $failed
