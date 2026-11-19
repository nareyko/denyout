#!/bin/sh
# Docker test for install.sh integrity gates (offline, file:// release; never touches the host).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
docker run --rm -v "$ROOT/install.sh:/install.sh:ro" debian:bookworm-slim sh -ec '
apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq curl ca-certificates >/dev/null 2>&1
arch=$(dpkg --print-architecture); case $arch in amd64) a=amd64;; arm64) a=arm64;; *) a=$arch;; esac
mkdir -p /rel /w/denyout-cli_0.0.1_linux_$a && cd /w
printf "#!/bin/sh\necho denyout-cli 0.0.1\n" > denyout-cli_0.0.1_linux_$a/denyout-cli; chmod +x denyout-cli_0.0.1_linux_$a/denyout-cli
cp denyout-cli_0.0.1_linux_$a/denyout-cli .
tar -czf /rel/denyout-cli_0.0.1_linux_$a.tar.gz denyout-cli
(cd /rel && sha256sum denyout-cli_0.0.1_linux_$a.tar.gz > SHA256SUMS)
run() { env HOME=/h DENYOUT_INSTALL_DIR=/h/bin DENYOUT_INSTALL_MODE=server DENYOUT_VERSION=v0.0.1 DENYOUT_BASE_URL=file:///rel DENYOUT_FETCH_RETRIES=1 "$@" sh /install.sh 2>&1; }
mkdir -p /h
echo "== auto, no cosign: installs with an honest note"
run DENYOUT_VERIFY_SIG=auto | grep -E "signature not verified|checksum ok"
echo "== require, no signature: must fail"
if run DENYOUT_VERIFY_SIG=require | grep -q "signature required"; then echo "PASS require fails"; else echo "FAIL require"; exit 1; fi
echo "== bad mode rejected"
run DENYOUT_VERIFY_SIG=bogus | grep -q "must be auto|require|skip" && echo "PASS bad mode"
echo "== missing GUI archive must not be retried (it is optional): fast, quiet, installs the CLI"
rm -f /rel/denyout_v0.0.1_linux_$a.tar.gz /h/bin/denyout
t0=$(date +%s)
out=$(run DENYOUT_VERIFY_SIG=skip DENYOUT_FETCH_RETRIES=6 DENYOUT_FETCH_RETRY_SECS=10)
t1=$(date +%s)
[ $((t1 - t0)) -le 8 ] && echo "$out" | grep -q "checksum ok" && ! echo "$out" | grep -q "download failed" && echo "PASS missing GUI not retried ($((t1 - t0))s)" || { echo "FAIL missing GUI retried or slow ($((t1 - t0))s): $out"; exit 1; }
echo "== GUI archive: auto without cosign installs with a note (require already fails at the CLI stage)"
printf "#!/bin/sh\necho gui\n" > denyout; chmod +x denyout; tar -czf /rel/denyout_v0.0.1_linux_$a.tar.gz denyout
rm -f /h/bin/denyout
out=$(run DENYOUT_VERIFY_SIG=auto)
echo "$out" | grep -q "denyout_v0.0.1_linux_$a.tar.gz signature not verified" && [ -e /h/bin/denyout ] && echo "PASS GUI auto note"
echo "== GUI .sha256 present and correct: installed, checksum ok"
(cd /rel && sha256sum denyout_v0.0.1_linux_$a.tar.gz > denyout_v0.0.1_linux_$a.tar.gz.sha256)
rm -f /h/bin/denyout
out=$(run DENYOUT_VERIFY_SIG=skip)
echo "$out" | grep -q "GUI checksum ok" && [ -e /h/bin/denyout ] && echo "PASS GUI checksum ok"
echo "== GUI tampered (.sha256 does not match): must NOT be installed"
rm -f /h/bin/denyout; cp /rel/denyout_v0.0.1_linux_$a.tar.gz /w/gui.bak
echo evil >> /rel/denyout_v0.0.1_linux_$a.tar.gz
out=$(run DENYOUT_VERIFY_SIG=skip)
echo "$out" | grep -q "SHA256 mismatch for denyout_v0.0.1" && [ ! -e /h/bin/denyout ] && echo "$out" | grep -q "checksum ok" && echo "PASS tampered GUI rejected, CLI still installed" || { echo "FAIL tampered GUI: $out"; exit 1; }
cp /w/gui.bak /rel/denyout_v0.0.1_linux_$a.tar.gz; rm -f /rel/denyout_v0.0.1_linux_$a.tar.gz.sha256
echo "== tampered archive: checksum mismatch"
echo evil >> /rel/denyout-cli_0.0.1_linux_$a.tar.gz
run DENYOUT_VERIFY_SIG=skip | grep -q "SHA256 mismatch" && echo "PASS tamper detected"
echo "== http BASE_URL rejected"
env HOME=/h DENYOUT_VERSION=v0.0.1 DENYOUT_BASE_URL=http://evil.example sh /install.sh 2>&1 | grep -q "must be https" && echo "PASS http base rejected"
echo "== path-injection tag rejected"
env HOME=/h DENYOUT_VERSION="../x" sh /install.sh 2>&1 | grep -q "invalid version" && echo "PASS bad tag rejected"
echo install-verify-test: OK
' 2>&1 | grep -v "^debconf"
