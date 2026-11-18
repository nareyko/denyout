#!/bin/bash
# Runs inside a NET_ADMIN container. $1 = denyout-cli. Checks helper watchdog + IPv6 listener.
set -u
BIN=$1
apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq iproute2 nftables ca-certificates procps >/dev/null 2>&1
id -u owner >/dev/null 2>&1 || useradd -u 1000 -M -s /usr/sbin/nologin owner
mkdir -p /var/lib/denyout; echo 1000 > /var/lib/denyout/owner_uid
CA=/tmp/ca; mkdir -p $CA; PORT=18443; fail=0
ok()  { echo "PASS: $*"; }
bad() { echo "FAIL: $*"; fail=1; }
$BIN hostctl helper-serve >/tmp/helper.log 2>&1 &
for i in $(seq 1 50); do [ -S /run/denyout-hostguard.sock ] && break; sleep 0.1; done
start_proxy() { $BIN hostctl proxyd --port $PORT --ca-dir $CA >/tmp/proxyd.log 2>&1 & PP=$!; for i in $(seq 1 50); do ss -ltn | grep -q ":$PORT" && break; sleep 0.1; done; }
has_table() { nft list tables 2>/dev/null | grep -q "inet denyout"; }
has_redirect() { nft list ruleset 2>/dev/null | grep -q "redirect"; }
STATE=/run/denyout-hostguard.state
state() { head -n1 $STATE 2>/dev/null; }
wait_state() { for i in $(seq 1 "$2"); do state | grep -Eq "$1" && return 0; sleep 1; done; return 1; }
wait_gone() { for i in $(seq 1 "$1"); do has_table || return 0; sleep 1; done; return 1; }
wait_table() { for i in $(seq 1 "$1"); do has_table && return 0; sleep 1; done; return 1; }
fstatus() { $BIN hostctl fail-policy status 2>&1; }
start_helper() { rm -f /run/denyout-hostguard.sock; "$@" $BIN hostctl helper-serve >>/tmp/helper.log 2>&1 & for i in $(seq 1 50); do [ -S /run/denyout-hostguard.sock ] && break; sleep 0.1; done; }
start_proxy
for i in $(seq 1 50); do [ -f $CA/ca.crt ] && break; sleep 0.1; done
[ -f $CA/ca.crt ] || bad "proxyd did not create CA"
$BIN hostctl apply --port $PORT --ca $CA/ca.crt --uid 1000 >/tmp/apply.txt 2>&1 || { cat /tmp/apply.txt; bad "apply"; }
has_table && ok "rules applied" || bad "rules not applied"
ss -ltn | grep -q "\[::1\]:$PORT" && ok "proxy also listens on [::1]:$PORT (IPv6 redirect target)" || bad "no IPv6 listener"
nft list ruleset | grep -q "ip6 daddr" && ok "ruleset has IPv6 redirect" || bad "no IPv6 redirect rule"

echo "== proxy dies: expect degrade (rules removed) within ~10s"
kill $PP; wait $PP 2>/dev/null
for i in $(seq 1 12); do has_table || break; sleep 1; done
has_table && bad "rules still present with dead proxy (orphan blackhole)" || ok "rules removed after proxy death"
grep -q degraded /run/denyout-hostguard.state 2>/dev/null && ok "state=degraded" || bad "state file not degraded"

echo "== proxy returns: expect rules re-applied"
start_proxy
for i in $(seq 1 25); do has_table && break; sleep 1; done
has_table && ok "rules re-applied after recovery" || bad "rules not restored"
grep -q protected /run/denyout-hostguard.state 2>/dev/null && ok "state=protected" || bad "state not protected"

echo "== fail policy: default is open, reported with its source"
fstatus | grep -q "policy=open source=default" && ok "status: open (default)" || bad "default status: $(fstatus)"

echo "== fail policy closed (live, via fail-policy verb): rules stay and block while the proxy is down"
$BIN hostctl fail-policy closed | grep -q "policy=closed source=setting" && ok "set closed -> effective closed (setting)" || bad "set closed: $($BIN hostctl fail-policy status 2>&1)"
grep -q '"fail_policy":"closed"' /var/lib/denyout/helper_state.json && ok "closed persisted in helper_state.json" || bad "fail_policy not persisted"
kill $PP; wait $PP 2>/dev/null
wait_state '^blocked' 14 && ok "state=blocked with dead proxy (closed)" || bad "state not blocked: $(state)"
sleep 3
has_table && has_redirect && ok "closed: redirect kept, web traffic blocked (no orphan removal)" || bad "closed: rules were removed"

echo "== live switch closed -> open while the proxy is still down: redirect removed without restart"
$BIN hostctl fail-policy open | grep -q "policy=open source=setting" && ok "switched to open" || bad "switch to open"
wait_gone 14 && ok "open: rules removed within ~14s" || bad "open: rules still present"
wait_state '^degraded' 5 && ok "state=degraded" || bad "state not degraded: $(state)"

echo "== live switch open -> closed while degraded: rules are put back at once"
$BIN hostctl fail-policy closed >/dev/null
wait_table 8 && ok "closed: rules restored immediately (tightening)" || bad "rules not restored on tighten"
wait_state '^blocked' 8 && ok "state=blocked" || bad "state not blocked after tighten: $(state)"

echo "== proxy returns under closed: state back to protected, rules unchanged"
start_proxy
wait_state '^protected' 12 && ok "state=protected after recovery (closed)" || bad "state after recovery: $(state)"
has_table && ok "rules in place" || bad "rules lost on recovery"

echo "== env overrides the setting and is reported (DENYOUT_FAIL_POLICY, then DENYOUT_FAIL_CLOSED)"
pkill -9 -f "hostctl helper-serve"; sleep 0.5
start_helper env DENYOUT_FAIL_POLICY=open
sleep 1
fstatus | grep -q "policy=open source=env:DENYOUT_FAIL_POLICY configured=closed" && ok "env open overrides persisted closed (configured=closed kept)" || bad "env override status: $(fstatus)"
pkill -9 -f "hostctl helper-serve"; sleep 0.5
start_helper env DENYOUT_FAIL_POLICY=open DENYOUT_FAIL_CLOSED=1
sleep 1
fstatus | grep -q "policy=closed source=env:DENYOUT_FAIL_CLOSED" && ok "DENYOUT_FAIL_CLOSED=1 beats DENYOUT_FAIL_POLICY" || bad "legacy precedence: $(fstatus)"

echo "== persisted closed survives helper kill -9 and restart (no env), still enforced"
pkill -9 -f "hostctl helper-serve"; sleep 0.5
start_helper env
sleep 1
fstatus | grep -q "policy=closed source=setting" && ok "closed restored from helper_state.json after restart" || bad "policy lost on restart: $(fstatus)"
kill $PP; wait $PP 2>/dev/null
sleep 12
has_table && ok "closed after restart: rules kept with dead proxy" || bad "closed not enforced after restart"
$BIN hostctl fail-policy open >/dev/null
wait_gone 14 && ok "back to open: rules removed" || bad "open after restart not enforced"
start_proxy
wait_table 25 && ok "rules re-applied after recovery (open)" || bad "no recovery under open"

echo "== Protect Off: watchdog must not resurrect rules"
# Helper-routed remove (the path the desktop uses; no --no-elevate), as in soak.sh.
$BIN hostctl remove --port $PORT --uid 1000 >/tmp/remove.txt 2>&1 || { cat /tmp/remove.txt; bad "helper remove failed"; }
has_table && bad "rules still present after remove" || ok "rules removed by the helper remove verb"
[ -e /var/lib/denyout/helper_state.json ] && bad "helper_state.json kept after Protect Off" || ok "persisted state cleared by Protect Off"
kill $PP 2>/dev/null; wait $PP 2>/dev/null; sleep 1; start_proxy; sleep 6
has_table && bad "watchdog re-applied rules after Protect Off" || ok "no resurrection after Protect Off"
echo "== helper crash (kill -9): intent restored from disk, watchdog active again"
kill $PP 2>/dev/null; wait $PP 2>/dev/null; start_proxy
$BIN hostctl apply --port $PORT --ca $CA/ca.crt --uid 1000 --fail-policy closed >/dev/null 2>&1
has_table && ok "re-applied before crash" || bad "apply before crash failed"
fstatus | grep -q "policy=closed source=setting" && ok "apply carried fail=closed to the helper" || bad "apply did not carry the policy: $(fstatus)"
[ -s /var/lib/denyout/helper_state.json ] && ok "helper_state.json persisted" || bad "no persisted state"
[ "$(stat -c %a /var/lib/denyout/helper_state.json 2>/dev/null)" = 600 ] && ok "state file mode 600" || bad "state file mode not 600"
pkill -9 -f "hostctl helper-serve"; sleep 0.5; rm -f /run/denyout-hostguard.sock
has_table && ok "rules survive helper crash (as in production)" || bad "rules vanished"
$BIN hostctl helper-serve >/tmp/helper3.log 2>&1 &
for i in $(seq 1 50); do [ -S /run/denyout-hostguard.sock ] && break; sleep 0.1; done
sleep 1
grep -q restored /run/denyout-hostguard.state 2>/dev/null && ok "state=restored_after_restart" || bad "no reconcile after restart"
fstatus | grep -q "policy=closed source=setting" && ok "policy persisted across kill -9" || bad "policy lost after crash: $(fstatus)"
kill $PP; wait $PP 2>/dev/null
sleep 12
has_table && ok "watchdog active after restart: closed keeps rules with dead proxy" || bad "closed not enforced after helper crash"
$BIN hostctl fail-policy open >/dev/null
wait_gone 14 && ok "watchdog active after restart: open removes rules with dead proxy" || bad "watchdog inactive after restart (orphan redirect)"

echo "== reboot-like: state present but rules gone -> must NOT re-apply"
pkill -9 -f "hostctl helper-serve"; sleep 0.5; rm -f /run/denyout-hostguard.sock
nft flush ruleset; printf '%s' '{"version":1,"spec":{"ProxyPort":18443,"UID":1000,"CACert":"'$CA'/ca.crt"}}' > /var/lib/denyout/helper_state.json
$BIN hostctl helper-serve >/tmp/helper4.log 2>&1 &
for i in $(seq 1 50); do [ -S /run/denyout-hostguard.sock ] && break; sleep 0.1; done; sleep 1
has_table && bad "boot silently re-enabled protection" || ok "no silent re-enable when rules are gone"

[ $fail = 0 ] && echo "watchdog-e2e: OK" || echo "watchdog-e2e: FAILED"
exit $fail
