#!/bin/bash
# Runs inside a NET_ADMIN container (see ../upgrade-docker-test.sh).
set -u
export DEBIAN_FRONTEND=noninteractive
pass=0; fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; shift; [ $# -gt 0 ] && echo "$*" | sed 's/^/     | /' | tail -15; fail=$((fail+1)); }
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq curl ca-certificates iproute2 nftables procps util-linux >/dev/null 2>&1
getent passwd 1000 >/dev/null || useradd -u 1000 -m -s /bin/bash owner
OWNER=$(getent passwd 1000 | cut -d: -f1)
mkdir -p /var/lib/denyout; echo 1000 > /var/lib/denyout/owner_uid
BIN=/usr/local/bin/denyout-cli; CA=/tmp/ca; PORT=18443; mkdir -p $CA
cp /install.sh /tmp/install.sh
install_rel() { DENYOUT_VERSION=$1 DENYOUT_INSTALL_DIR=/usr/local/bin sh /tmp/install.sh --server 2>&1 </dev/null; }
has_table() { nft list tables 2>/dev/null | grep -q "inet denyout"; }
as_owner() { su "$OWNER" -s /bin/bash -c "$1"; }
start_helper() { rm -f /run/denyout-hostguard.sock; $BIN hostctl helper-serve >>/tmp/helper.log 2>&1 & for i in $(seq 1 50); do [ -S /run/denyout-hostguard.sock ] && break; sleep 0.1; done; }
start_proxy() { DENYOUT_POLICY_PROFILE=browse $BIN hostctl proxyd --port $PORT --ca-dir $CA >>/tmp/proxyd.log 2>&1 & for i in $(seq 1 80); do ss -ltn | grep -q ":$PORT" && break; sleep 0.1; done; }
canary='https://example.com/pixel.png?api_key=DENYOUT_CANARY_UPGRADE'
CAFILE_TRUST=""   # apply installs the session CA into the system trust store

echo "== install OLD $OLD_TAG and turn Protect On"
first=$(install_rel "$OLD_TAG"); echo "$first" | grep -E "checksum ok|error|FAIL" | head -3
echo "$first" | grep -q "Protect this computer was On" && bad "first install printed the Protect-was-On hint (Protect was not on)" || ok "first install: no Protect hint"
v=$($BIN version 2>&1); echo "$v" | grep -q "${OLD_TAG#v}" && ok "old version installed: $v" || { bad "old version" "$v"; exit 1; }
start_helper; start_proxy
$BIN hostctl apply --port $PORT --ca $CA/ca.crt --uid 1000 >/tmp/apply.txt 2>&1 && has_table && ok "old: Protect On (rules present)" || { bad "old: apply failed" "$(cat /tmp/apply.txt)"; exit 1; }
code=$(as_owner "curl -sS -m 20 $CAFILE_TRUST -o /dev/null -w '%{http_code}' https://example.com/ 2>&1")
[ "$code" = 200 ] && ok "old: HTTPS through the proxy works (200)" || bad "old: HTTPS via proxy: $code"

echo "== upgrade: install.sh overwrites the binaries while the OLD helper and proxy still run (what a user does)"
out=$(install_rel "$NEW_TAG"); echo "$out" | grep -q "checksum ok" && ok "installer finished over a running install"
echo "$out" | grep -q "Protect this computer was On and the upgrade stopped it" && ok "upgrade told the user Protect was stopped" || bad "no Protect hint on upgrade" "$(echo "$out" | tail -8)"
echo "$out" | grep -q "Turn Protect on again" && ok "hint says how to turn Protect on again" || bad "hint has no remedy" || bad "upgrade install" "$out"
v=$($BIN version 2>&1); echo "$v" | grep -q "${NEW_TAG#v}" && ok "binary is now: $v" || bad "binary not upgraded" "$v"
has_table && ok "rules still present after the binary swap (no teardown on upgrade)" || bad "rules vanished on upgrade"
# install.sh stops the running proxyd on purpose (install.sh: pkill ... hostctl proxyd) so the
# binary can be replaced. The redirect rules stay until the helper watchdog notices (~10 s):
# a short outage, then the fail policy applies (default open = rules removed, web works
# unprotected; closed = blocked on purpose). It must never stay a permanent blackhole.
echo "     (proxyd running after the swap: $(pgrep -f 'hostctl proxyd' >/dev/null && echo yes || echo no, stopped by the installer))"
rec=no; for i in $(seq 1 25); do code=$(as_owner "curl -sS -m 3 -o /dev/null -w '%{http_code}' https://example.com/ 2>&1"); [ "$code" = 200 ] && { rec=yes; break; }; sleep 1; done
[ "$rec" = yes ] && ok "after the swap the web recovers within 25 s (watchdog, fail policy open): no permanent blackhole (${i}s)" || bad "still no HTTPS 25 s after the swap" "$(nft list ruleset | grep -c redirect) redirect rules, proxy: $(pgrep -af 'hostctl proxyd' | head -1)"
has_table && echo "     (rules still present after recovery: protected again)" || echo "     (rules removed by the watchdog: web works UNPROTECTED until Protect is turned on again)"

echo "== restart helper and proxy with the NEW binary (reboot / re-login)"
pkill -9 -f "hostctl helper-serve"; pkill -f "hostctl proxyd"; sleep 1
start_helper; start_proxy; sleep 6
st=$(head -n1 /run/denyout-hostguard.state 2>/dev/null)
echo "state after new helper: ${st:-none}; rules present: $(has_table && echo yes || echo no)"
if has_table; then
  ok "Protect state kept across the upgrade (rules present, state=${st:-none})"
  code=$(as_owner "curl -sS -m 20 $CAFILE_TRUST -o /dev/null -w '%{http_code}' https://example.com/ 2>&1")
  [ "$code" = 200 ] && ok "new proxy serves HTTPS under the kept rules" || bad "kept rules but HTTPS fails: $code (blackhole?)"
else
  ok "Protect reset cleanly by the upgrade (no rules, state=${st:-none})"
  code=$(as_owner "curl -sS -m 20 -o /dev/null -w '%{http_code}' https://example.com/ 2>&1")
  [ "$code" = 200 ] && ok "no rules and direct HTTPS works: no blackhole" || bad "no rules but HTTPS fails: $code"
  $BIN hostctl apply --port $PORT --ca $CA/ca.crt --uid 1000 >/dev/null 2>&1
fi

echo "== NEW binary enforces: canary denied without a hang"
if has_table; then
  res=$(as_owner "curl -sS -m 20 $CAFILE_TRUST -o /dev/null -w '%{http_code}' '$canary' 2>&1")
  [ "$res" = 403 ] && ok "canary denied with 403 (no hang)" || bad "canary after upgrade: $res"
fi

echo "== Protect Off and teardown leave a clean system"
$BIN hostctl remove --port $PORT --uid 1000 >/dev/null 2>&1
has_table && bad "rules after remove" || ok "rules removed"
sleep 5; has_table && bad "rules resurrected" || ok "no resurrection"
code=$(as_owner "curl -sS -m 20 -o /dev/null -w '%{http_code}' https://example.com/ 2>&1")
[ "$code" = 200 ] && ok "direct HTTPS works after Off" || bad "direct HTTPS after Off: $code"
$BIN hostctl teardown >/dev/null 2>&1 && ok "teardown exit 0" || bad "teardown failed"

echo "== upgrade $OLD_TAG -> $NEW_TAG: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
