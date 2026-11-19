#!/bin/bash
# Runs inside a NET_ADMIN container (see ../desktop-protect-docker-test.sh).
set -u
export DEBIAN_FRONTEND=noninteractive
pass=0; fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; shift; [ $# -gt 0 ] && echo "$*" | sed 's/^/     | /' | tail -20; fail=$((fail+1)); }

apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq curl ca-certificates iproute2 nftables procps util-linux openssl >/dev/null 2>&1
getent passwd 1000 >/dev/null || useradd -u 1000 -m -s /bin/bash owner   # ubuntu images already have uid 1000 ("ubuntu")
OWNER=$(getent passwd 1000 | cut -d: -f1)
mkdir -p /var/lib/denyout; echo 1000 > /var/lib/denyout/owner_uid

echo "== D6 prerequisite: install the PUBLISHED release $DENYOUT_VERSION (server mode, to /usr/local/bin)"
cp /install.sh /tmp/install.sh
out=$(DENYOUT_INSTALL_DIR=/usr/local/bin sh /tmp/install.sh --server 2>&1 </dev/null) && ok "release installed" || { bad "install failed" "$out"; exit 1; }
BIN=/usr/local/bin/denyout-cli
[ -f /local-bin ] && { install -m 755 /local-bin $BIN; echo "NOTE: installed binary replaced by a local build (PROTECT_TEST_BIN)"; }
if [ -f /local-bin ]; then ok "local build under test: $("$BIN" version)"; else "$BIN" version | grep -q "${DENYOUT_VERSION#v}" && ok "binary is the release: $("$BIN" version)" || bad "version mismatch" "$("$BIN" version)"; fi

CA=/tmp/ca; PORT=18443; mkdir -p $CA
has_table() { nft list tables 2>/dev/null | grep -q "inet denyout"; }
as_owner() { su "$OWNER" -s /bin/bash -c "$1"; }

$BIN hostctl helper-serve >/tmp/helper.log 2>&1 &
for i in $(seq 1 50); do [ -S /run/denyout-hostguard.sock ] && break; sleep 0.1; done
# Safe desktop = the "browse" profile (the desktop default); the bare proxyd default is the strict agent allowlist.
DENYOUT_POLICY_PROFILE=browse $BIN hostctl proxyd --port $PORT --ca-dir $CA >/tmp/proxyd.log 2>&1 &
for i in $(seq 1 80); do [ -f $CA/ca.crt ] && ss -ltn | grep -q ":$PORT" && break; sleep 0.1; done
[ -f $CA/ca.crt ] && ok "proxyd up, session CA created" || { bad "proxyd did not start" "$(cat /tmp/proxyd.log)"; exit 1; }

echo "== baseline: Protect Off, no rules, direct HTTPS works and is NOT intercepted"
has_table && bad "nft table present before Protect On" || ok "no nft table before Protect On"
net=$(as_owner "curl -sS -m 20 -o /dev/null -w '%{http_code}' https://example.com/ 2>&1")
[ "$net" = 200 ] && ok "baseline direct HTTPS 200" || { echo "SKIP-ALL: no outbound internet from the container ($net)"; exit 2; }
iss=$(as_owner "curl -sSv -m 20 -o /dev/null https://example.com/ 2>&1" | grep -i "issuer:")
echo "$iss" | grep -qi denyout && bad "baseline already intercepted" "$iss" || ok "baseline issuer is the real CA"

echo "== D5: Protect On"
ap=$($BIN hostctl apply --port $PORT --ca $CA/ca.crt --uid 1000 2>&1) && ok "apply (Protect On) exit 0" || bad "apply failed" "$ap"
has_table && ok "nft table inet denyout present" || bad "no nft table after apply"
nft list ruleset | grep -q "redirect" && ok "IPv4 redirect rule" || bad "no redirect rule"
nft list ruleset | grep -q "ip6 daddr" && ok "IPv6 rule present" || bad "no IPv6 rule"

iss=$(as_owner "curl -sSv -m 20 -o /dev/null https://example.com/ 2>&1" | grep -i "issuer:")
echo "$iss" | grep -qi denyout && ok "owner's HTTPS is intercepted (issuer: session CA)" || bad "owner's HTTPS not intercepted" "$iss" "proxyd.log:" "$(tail -8 /tmp/proxyd.log)" "helper.log:" "$(tail -5 /tmp/helper.log)"
code=$(as_owner "curl -sS -m 20 -o /dev/null -w '%{http_code}' https://example.com/ 2>&1")
[ "$code" = 200 ] && ok "clean request allowed through the proxy (200)" || bad "clean request via proxy: $code"

canary='https://example.com/pixel.png?api_key=DENYOUT_CANARY_PROTECT_E2E'
res=$(as_owner "curl -sS -m 20 -o /tmp/body.txt -w '%{http_code}' '$canary' 2>&1")
[ "$res" = 403 ] && ok "canary URL denied with 403" || bad "canary URL not denied: $res" "$(as_owner "curl -sv -m 8 -o /dev/null '$canary' 2>&1" | grep -E '^< |^\* (Closing|Operation|Connection)' | head -12)"
grep -q DENYOUT_CANARY_PROTECT_E2E /tmp/body.txt 2>/dev/null && bad "deny body leaks the secret" || ok "deny body does not echo the secret"

rootcode=$(curl -sS -m 20 -o /dev/null -w '%{http_code}' "$canary" 2>&1)
[ "$rootcode" != 403 ] && ok "root (not the owner uid) is not redirected: $rootcode" || bad "root traffic was intercepted"

echo "== D5: helper audit trail has the apply"
$BIN hostctl audit-tail 5 2>&1 | grep -qi apply && ok "audit-tail shows apply" || bad "audit-tail has no apply" "$($BIN hostctl audit-tail 5 2>&1)"

echo "== D5: Protect Off"
rm=$($BIN hostctl remove --port $PORT --uid 1000 2>&1) && ok "remove (Protect Off) exit 0" || bad "remove failed" "$rm"
has_table && bad "nft table still present after Off" || ok "nft table gone after Off"
res=$(as_owner "curl -sS -m 20 -o /dev/null -w '%{http_code}' '$canary' 2>&1")
[ "$res" != 403 ] && ok "after Off the canary URL is no longer denied by DenyOut ($res)" || bad "still denied after Off"
iss=$(as_owner "curl -sSv -m 20 -o /dev/null https://example.com/ 2>&1" | grep -i "issuer:")
echo "$iss" | grep -qi denyout && bad "still intercepted after Off" "$iss" || ok "after Off the issuer is the real CA again"
sleep 6
has_table && bad "watchdog resurrected rules after Off" || ok "no resurrection after Off"

echo "== D5: teardown (what uninstall calls)"
td=$($BIN hostctl teardown 2>&1); trc=$?; [ $trc -eq 0 ] && ok "teardown exit 0" || bad "teardown exit $trc" "$td"
has_table && bad "table after teardown" || ok "clean after teardown"

echo "== protect: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
