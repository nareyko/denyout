#!/bin/sh
# G6 Docker lab dogfood: TCP HTTPS via TUN, QUIC sight, QuicMITM lab H3, teardown invariants.
# Does NOT touch host Chrome/Cursor/Protect. Requires Docker + /dev/net/tun.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
IMAGE="${DENYOUT_DOGFOOD_IMAGE:-debian:bookworm-slim}"
CLI_BIN="${DENYOUT_BIN:-/tmp/denyout-cli-g6}"
LAB_BIN="${DENYOUT_G6LAB_BIN:-/tmp/denyout-g6lab}"

if [ ! -e /dev/net/tun ]; then
  echo "closed-loop-tun-g6-docker-dogfood: /dev/net/tun missing" >&2
  exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "closed-loop-tun-g6-docker-dogfood: docker required" >&2
  exit 2
fi

echo "== build host binaries =="
(cd "$ROOT" && go build -buildvcs=false -o "$CLI_BIN" ./cmd/denyout-cli)
(cd "$ROOT" && go build -buildvcs=false -o "$LAB_BIN" ./cmd/denyout-g6lab)

echo "== g6 docker lab image=$IMAGE =="
docker run --rm --privileged \
  --device=/dev/net/tun \
  -v "$CLI_BIN:/usr/local/bin/denyout-cli:ro" \
  -v "$LAB_BIN:/usr/local/bin/denyout-g6lab:ro" \
  -e DENYOUT_TUN_E2E=1 \
  -e DEBIAN_FRONTEND=noninteractive \
  "$IMAGE" bash -ec '
    set -euo pipefail
    apt-get update -qq
    apt-get install -y -qq iproute2 nftables ca-certificates curl util-linux >/dev/null
    echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
    echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter

    # Lab origin in a netns so 198.18.0.10 is NOT a local address (local delivery
    # bypasses fwmark→denyout0 even when nft counters fire).
    LAB_IP=198.18.0.10
    HOST_IP=198.18.0.1
    ip netns del g6lab 2>/dev/null || true
    ip link del veth-g6 2>/dev/null || true
    ip netns add g6lab
    ip link add veth-g6 type veth peer name veth-lab
    ip link set veth-lab netns g6lab
    ip addr add "$HOST_IP/24" dev veth-g6
    ip link set veth-g6 up
    ip netns exec g6lab ip addr add "$LAB_IP/24" dev veth-lab
    ip netns exec g6lab ip link set veth-lab up
    ip netns exec g6lab ip link set lo up
    ip netns exec g6lab ip route add default via "$HOST_IP"
    echo "$LAB_IP lab.denyout.test" >> /etc/hosts
    id -u dogfood >/dev/null 2>&1 || useradd -u 1000 -M -s /usr/sbin/nologin dogfood

    CA_DIR=/tmp/denyout-g6-ca
    mkdir -p "$CA_DIR"
    PROXY_PORT=18443
    TEST_UID=1000
    export DENYOUT_LAB_IP="$LAB_IP"

    echo "== lab origins (netns g6lab) =="
    ip netns exec g6lab env DENYOUT_LAB_IP="$LAB_IP" denyout-g6lab serve >/tmp/g6lab.log 2>&1 &
    LABPID=$!
    for i in $(seq 1 50); do
      grep -q READY /tmp/g6lab.log 2>/dev/null && break
      sleep 0.1
    done
    grep -q READY /tmp/g6lab.log

    echo "== helper-serve + proxyd =="
    mkdir -p /var/lib/denyout && echo "${TEST_UID:-1000}" > /var/lib/denyout/owner_uid
    DENYOUT_TLS_INSECURE_UPSTREAM=1 denyout-cli hostctl helper-serve >/tmp/helper.log 2>&1 &
    HP=$!
    for i in $(seq 1 50); do
      [ -S /run/denyout-hostguard.sock ] && break
      sleep 0.1
    done
    test -S /run/denyout-hostguard.sock

    DENYOUT_ALWAYS_ALLOW=lab.denyout.test DENYOUT_ALLOW_PRIVATE=1 DENYOUT_TLS_INSECURE_UPSTREAM=1 \
      denyout-cli hostctl proxyd --port "$PROXY_PORT" --ca-dir "$CA_DIR" >/tmp/proxyd.log 2>&1 &
    PP=$!
    for i in $(seq 1 50); do
      [ -f "$CA_DIR/ca.crt" ] && break
      sleep 0.1
    done
    test -f "$CA_DIR/ca.crt"
    # dogfood client (uid 1000) must read the CA for TLS trust
    chmod 644 "$CA_DIR/ca.crt"

    cleanup() {
      denyout-cli hostctl tun-stop --real --uid "$TEST_UID" >/dev/null 2>&1 || true
      denyout-cli hostctl teardown --port "$PROXY_PORT" --uid "$TEST_UID" --no-elevate >/dev/null 2>&1 || true
      kill "$PP" "$HP" "$LABPID" 2>/dev/null || true
      ip link del veth-g6 2>/dev/null || true
      ip netns del g6lab 2>/dev/null || true
    }
    trap cleanup EXIT

    echo "== hostctl apply (via helper) =="
    denyout-cli hostctl apply --port "$PROXY_PORT" --ca "$CA_DIR/ca.crt" --uid "$TEST_UID"

    echo "== tun-start --real (TCP, MITM off) =="
    denyout-cli hostctl tun-start --real --uid "$TEST_UID"
    echo 0 > /proc/sys/net/ipv4/conf/denyout0/rp_filter || true
    ip link show denyout0 >/dev/null
    denyout-cli hostctl tun-stats --real --uid "$TEST_UID" | tee /tmp/stats1.txt
    grep -q "present=true" /tmp/stats1.txt

    echo "== TCP HTTPS via TUN → proxyd =="
    setpriv --reuid=1000 --regid=1000 --clear-groups \
      curl -fsS --http1.1 --cacert "$CA_DIR/ca.crt" --max-time 10 \
      "https://lab.denyout.test/" | tee /tmp/https.txt
    grep -q "g6-lab-ok" /tmp/https.txt

    echo "== QUIC sight (inject) =="
    setpriv --reuid=1000 --regid=1000 --clear-groups \
      env DENYOUT_LAB_IP="$LAB_IP" denyout-g6lab quic-inject
    sleep 0.3
    denyout-cli hostctl tun-stats --real --uid "$TEST_UID" | tee /tmp/stats2.txt
    grep -q "sightings=" /tmp/stats2.txt
    grep -q "last_sni=lab.denyout.test" /tmp/stats2.txt

    echo "== Cursor SNI: no MITM action =="
    setpriv --reuid=1000 --regid=1000 --clear-groups \
      env DENYOUT_LAB_IP="$LAB_IP" DENYOUT_SNI=api.cursor.sh denyout-g6lab quic-inject
    sleep 0.2
    denyout-cli hostctl tun-stats --real --uid "$TEST_UID" | tee /tmp/stats3.txt
    grep -q "last_sni=api.cursor.sh" /tmp/stats3.txt

    echo "== QuicMITM restart =="
    denyout-cli hostctl tun-stop --real --uid "$TEST_UID"
    denyout-cli hostctl tun-start --real --mitm --uid "$TEST_UID"
    echo 0 > /proc/sys/net/ipv4/conf/denyout0/rp_filter || true
    sleep 0.2

    echo "== HTTP/3 via TUN MITM =="
    setpriv --reuid=1000 --regid=1000 --clear-groups \
      env DENYOUT_CACERT="$CA_DIR/ca.crt" DENYOUT_LAB_IP="$LAB_IP" denyout-g6lab h3-get | tee /tmp/h3.txt
    grep -q "status=200" /tmp/h3.txt

    echo "== Protect Off teardown invariants =="
    denyout-cli hostctl tun-stop --real --uid "$TEST_UID"
    if ip link show denyout0 >/dev/null 2>&1; then
      echo "denyout0 still present" >&2
      exit 1
    fi
    if ip rule show | grep -q "fwmark 0x64756e"; then
      echo "fwmark steer rule still present" >&2
      exit 1
    fi
    if nft list tables 2>/dev/null | grep -q "denyout-tun"; then
      echo "denyout-tun nft table still present" >&2
      exit 1
    fi
    denyout-cli hostctl teardown --port "$PROXY_PORT" --uid "$TEST_UID"
    echo "teardown ok"
  '

echo "closed-loop-tun-g6-docker-dogfood OK"
