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
for i in $(seq 1 12); do has_table && break; sleep 1; done
has_table && ok "rules re-applied after recovery" || bad "rules not restored"
grep -q protected /run/denyout-hostguard.state 2>/dev/null && ok "state=protected" || bad "state not protected"

echo "== Protect Off: watchdog must not resurrect rules"
$BIN hostctl remove --port $PORT --uid 1000 --no-elevate >/dev/null 2>&1
has_table && bad "rules still present after remove" || ok "rules removed by remove"
kill $PP 2>/dev/null; wait $PP 2>/dev/null; sleep 1; start_proxy; sleep 6
has_table && bad "watchdog re-applied rules after Protect Off" || ok "no resurrection after Protect Off"
echo "== helper crash (kill -9): intent restored from disk, watchdog active again"
kill $PP 2>/dev/null; wait $PP 2>/dev/null; start_proxy
$BIN hostctl apply --port $PORT --ca $CA/ca.crt --uid 1000 >/dev/null 2>&1
has_table && ok "re-applied before crash" || bad "apply before crash failed"
[ -s /var/lib/denyout/helper_state.json ] && ok "helper_state.json persisted" || bad "no persisted state"
[ "$(stat -c %a /var/lib/denyout/helper_state.json 2>/dev/null)" = 600 ] && ok "state file mode 600" || bad "state file mode not 600"
pkill -9 -f "hostctl helper-serve"; sleep 0.5; rm -f /run/denyout-hostguard.sock
has_table && ok "rules survive helper crash (as in production)" || bad "rules vanished"
$BIN hostctl helper-serve >/tmp/helper3.log 2>&1 &
for i in $(seq 1 50); do [ -S /run/denyout-hostguard.sock ] && break; sleep 0.1; done
sleep 1
grep -q restored /run/denyout-hostguard.state 2>/dev/null && ok "state=restored_after_restart" || bad "no reconcile after restart"
kill $PP; wait $PP 2>/dev/null
for i in $(seq 1 12); do has_table || break; sleep 1; done
has_table && bad "watchdog inactive after restart (orphan redirect)" || ok "watchdog active after restart: rules removed with dead proxy"

echo "== reboot-like: state present but rules gone -> must NOT re-apply"
pkill -9 -f "hostctl helper-serve"; sleep 0.5; rm -f /run/denyout-hostguard.sock
nft flush ruleset; printf '%s' '{"version":1,"spec":{"ProxyPort":18443,"UID":1000,"CACert":"'$CA'/ca.crt"}}' > /var/lib/denyout/helper_state.json
$BIN hostctl helper-serve >/tmp/helper4.log 2>&1 &
for i in $(seq 1 50); do [ -S /run/denyout-hostguard.sock ] && break; sleep 0.1; done; sleep 1
has_table && bad "boot silently re-enabled protection" || ok "no silent re-enable when rules are gone"

[ $fail = 0 ] && echo "watchdog-e2e: OK" || echo "watchdog-e2e: FAILED"
exit $fail
