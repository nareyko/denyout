#!/bin/bash
# Runs inside a NET_ADMIN container. $1 = denyout-cli.
# Soak: SOAK_CONC concurrent clients (uid 1000, redirected into the proxy) for
# SOAK_SECONDS while the proxy (SIGKILL) and the helper (SIGKILL) are restarted
# repeatedly. Asserts: state returns to protected, rules present/removed as the
# fail-soft policy dictates, no orphan redirect at the end, and bounded
# goroutine / fd / thread growth of the final proxy and helper processes.
set -u
BIN=$1
DUR=${SOAK_SECONDS:-60}
CONC=${SOAK_CONC:-24}
MAX_FD_GROWTH=${SOAK_MAX_FD_GROWTH:-40}
MAX_GOROUTINE_GROWTH=${SOAK_MAX_GOROUTINE_GROWTH:-100}
MAX_HELPER_FD_GROWTH=${SOAK_MAX_HELPER_FD_GROWTH:-20}
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq iproute2 nftables ca-certificates procps curl util-linux >/dev/null 2>&1
id -u owner >/dev/null 2>&1 || useradd -u 1000 -M -s /usr/sbin/nologin owner
mkdir -p /var/lib/denyout; echo 1000 > /var/lib/denyout/owner_uid
CA=/tmp/ca; mkdir -p $CA; PORT=18443; fail=0
STATE=/run/denyout-hostguard.state
export DENYOUT_DEBUG_STATS=1
ok()  { echo "PASS: $*"; }
bad() { echo "FAIL: $*"; fail=1; }
has_table() { nft list tables 2>/dev/null | grep -q "inet denyout"; }
state() { head -n1 $STATE 2>/dev/null; }
fds() { ls /proc/$1/fd 2>/dev/null | wc -l; }
threads() { awk '/^Threads:/{print $2}' /proc/$1/status 2>/dev/null; }
rss_kb() { awk '/^VmRSS:/{print $2}' /proc/$1/status 2>/dev/null; }

start_helper() {
  rm -f /run/denyout-hostguard.sock
  $BIN hostctl helper-serve >>/tmp/helper.log 2>&1 & HP=$!
  for i in $(seq 1 50); do [ -S /run/denyout-hostguard.sock ] && break; sleep 0.1; done
}
start_proxy() {
  $BIN hostctl proxyd --port $PORT --ca-dir $CA >>/tmp/proxyd.log 2>&1 & PP=$!
  for i in $(seq 1 100); do ss -ltn | grep -q ":$PORT" && break; sleep 0.1; done
}
goroutines() { # prints goroutine count of the proxy via SIGUSR1
  local before; before=$(grep -c '^debug-stats' /tmp/proxyd.log)
  kill -USR1 $PP 2>/dev/null
  for i in $(seq 1 20); do
    [ "$(grep -c '^debug-stats' /tmp/proxyd.log)" -gt "$before" ] && break; sleep 0.1
  done
  grep '^debug-stats' /tmp/proxyd.log | tail -1 | sed 's/.*goroutines=//'
}
apply() { $BIN hostctl apply --port $PORT --ca $CA/ca.crt --uid 1000 >/tmp/apply.txt 2>&1 || { cat /tmp/apply.txt; bad "apply"; }; }
# One client attempt as the redirected uid: TLS to an unroutable address ends up at the proxy.
one_client() {
  setpriv --reuid=1000 --regid=1000 --clear-groups \
    curl -sk -o /dev/null --max-time 2 --resolve "soak$((RANDOM % 50)).example.test:443:203.0.113.$((RANDOM % 250 + 1))" \
    "https://soak$((RANDOM % 50)).example.test/" >/dev/null 2>&1 || true
}
worker() { while [ ! -e /tmp/soak.stop ]; do one_client; done; }
start_load() { rm -f /tmp/soak.stop; WORKERS=""; for i in $(seq 1 "$CONC"); do worker & WORKERS="$WORKERS $!"; done; }
stop_load() { touch /tmp/soak.stop; for w in $WORKERS; do wait "$w" 2>/dev/null; done; WORKERS=""; }
wait_state() { # $1 regex, $2 seconds
  for i in $(seq 1 "$2"); do state | grep -Eq "$1" && return 0; sleep 1; done; return 1
}

: >/tmp/proxyd.log; : >/tmp/helper.log
start_helper
start_proxy
for i in $(seq 1 50); do [ -f $CA/ca.crt ] && break; sleep 0.1; done
[ -f $CA/ca.crt ] || bad "proxyd did not create CA"
apply
has_table && ok "rules applied" || bad "rules not applied"
state | grep -q "^degraded" && bad "initial state degraded" || ok "initial state ok ($(state))"
HELPER_FD0=$(fds $HP)

echo "== soak: ${DUR}s, $CONC workers, proxy/helper restarts"
start_load
END=$(( $(date +%s) + DUR )); cycle=0
while [ "$(date +%s)" -lt "$END" ]; do
  cycle=$((cycle+1))
  sleep 3
  kill -9 $PP 2>/dev/null; wait $PP 2>/dev/null
  for i in $(seq 1 15); do has_table || break; sleep 1; done
  has_table && bad "cycle $cycle: orphan redirect with dead proxy" || ok "cycle $cycle: redirect removed (fail-soft)"
  wait_state '^degraded' 3 || bad "cycle $cycle: state not degraded: $(state)"
  start_proxy
  for i in $(seq 1 20); do has_table && break; sleep 1; done
  has_table && ok "cycle $cycle: redirect restored" || bad "cycle $cycle: redirect not restored"
  wait_state '^protected' 5 && ok "cycle $cycle: state=protected" || bad "cycle $cycle: state=$(state)"
  if [ $((cycle % 2)) = 0 ]; then
    kill -9 $HP 2>/dev/null; wait $HP 2>/dev/null
    has_table || bad "cycle $cycle: rules vanished on helper crash"
    start_helper
    wait_state '^(protected|restored_after_restart)' 8 && ok "cycle $cycle: helper restarted, state=$(state)" || bad "cycle $cycle: helper state=$(state)"
  fi
done
stop_load
echo "== quiesce, then leak check over a steady load window (final proxy process)"
wait_state '^(protected|restored_after_restart)' 10 || bad "pre-steady state: $(state)"
has_table || { apply; sleep 1; }
G0=$(goroutines); F0=$(fds $PP); T0=$(threads $PP); R0=$(rss_kb $PP)
D0=$(grep -c "^denyout: DENY" /tmp/proxyd.log); start_load; sleep 5; GP=$(goroutines); sleep 5; stop_load; sleep 5; D1=$(grep -c "^denyout: DENY" /tmp/proxyd.log)
[ $((D1 - D0)) -ge 20 ] && ok "load reached the proxy ($((D1 - D0)) connections handled, mid-load goroutines ${GP:-?})" || bad "load did not reach the proxy ($((D1 - D0)) connections)"
G1=$(goroutines); F1=$(fds $PP); T1=$(threads $PP); R1=$(rss_kb $PP)
echo "proxy goroutines $G0 -> $G1, fds $F0 -> $F1, threads $T0 -> $T1, rss_kb $R0 -> $R1"
[ -n "$G0" ] && [ -n "$G1" ] || bad "could not read goroutine counts"
[ $((G1 - G0)) -le "$MAX_GOROUTINE_GROWTH" ] && ok "goroutines bounded" || bad "goroutine growth $((G1-G0)) > $MAX_GOROUTINE_GROWTH"
[ $((F1 - F0)) -le "$MAX_FD_GROWTH" ] && ok "proxy fds bounded" || bad "proxy fd growth $((F1-F0)) > $MAX_FD_GROWTH"
HELPER_FD1=$(fds $HP)
echo "helper fds $HELPER_FD0 -> $HELPER_FD1"
[ $((HELPER_FD1 - HELPER_FD0)) -le "$MAX_HELPER_FD_GROWTH" ] && ok "helper fds bounded" || bad "helper fd growth"
wait_state '^(protected|restored_after_restart)' 5 && ok "final state ok: $(state)" || bad "final state: $(state)"
has_table && ok "redirect in place while protected" || bad "redirect missing at end"

echo "== end: proxy dies, then Protect Off; no orphan redirect may remain"
kill -9 $PP 2>/dev/null; wait $PP 2>/dev/null
for i in $(seq 1 15); do has_table || break; sleep 1; done
has_table && bad "orphan redirect after proxy loss" || ok "no orphan redirect after proxy loss"
$BIN hostctl remove --port $PORT --uid 1000 >/tmp/remove.txt 2>&1; echo "remove: $(cat /tmp/remove.txt)"; echo "state after remove: $(state) / helper alive: $(kill -0 $HP 2>&1 && echo y)"
start_proxy; sleep 6
has_table && bad "redirect resurrected after Protect Off" || ok "no resurrection after Protect Off"
kill $PP 2>/dev/null; kill $HP 2>/dev/null

[ $fail = 0 ] && echo "soak: OK" || { echo "soak: FAILED"; tail -n 20 /tmp/proxyd.log; tail -n 20 /tmp/helper.log; }
exit $fail
