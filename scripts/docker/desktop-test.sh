#!/bin/bash
# Runs inside the container (see ../desktop-docker-test.sh). $1 = full | nolibs
set -u
MODE=$1
export DEBIAN_FRONTEND=noninteractive
pass=0; fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; shift; [ $# -gt 0 ] && echo "$*" | sed 's/^/     | /' | tail -25; fail=$((fail+1)); }

apt-get update -qq >/dev/null 2>&1
PKGS="curl ca-certificates xvfb dbus-x11 xdotool x11-apps procps sudo"
[ "$MODE" = full ] && PKGS="$PKGS libgtk-3-0 libwebkit2gtk-4.1-0"
apt-get install -y -qq $PKGS >/dev/null 2>&1 || { echo "FAIL apt install"; exit 1; }
id tester >/dev/null 2>&1 || useradd -m -s /bin/bash tester

# Everything below runs as an unprivileged user in a clean HOME, inside a virtual X display.
cat > /home/tester/body.sh <<'BODY'
set -u
export PATH="$HOME/.local/bin:$PATH"
T0=$(date +%s)
out=$(sh $HOME/install.sh --desktop 2>&1 </dev/null); rc=$?
EL=$(( $(date +%s) - T0 ))
echo "$out" > /tmp/install.log
echo "INSTALL_RC=$rc INSTALL_SECS=$EL"
BODY
chmod 755 /home/tester/body.sh
install -m 755 -o tester /install.sh /home/tester/install.sh   # the mount may be unreadable for tester

# One virtual display + session bus that outlives each command (a GUI started by the
# installer must survive until the checks run; xvfb-run would kill it on exit).
su tester -c "nohup Xvfb :99 -screen 0 1280x800x24 >/tmp/xvfb.log 2>&1 &"
sleep 2
BUSVARS=$(su tester -c "dbus-launch --sh-syntax")
eval "$BUSVARS"
xrun() { su tester -c "export DISPLAY=:99 DBUS_SESSION_BUS_ADDRESS='$DBUS_SESSION_BUS_ADDRESS'; cd ~; $1"; }

echo "== D1: public install.sh --desktop from release $DENYOUT_VERSION"
res=$(xrun "bash ~/body.sh" 2>&1)
echo "$res" | grep -E "INSTALL_RC|INSTALL_SECS"
log=$(cat /tmp/install.log 2>/dev/null)
rc=$(echo "$res" | sed -n 's/.*INSTALL_RC=\([0-9]*\).*/\1/p' | head -1)
secs=$(echo "$res" | sed -n 's/.*INSTALL_SECS=\([0-9]*\).*/\1/p' | head -1)
H=/home/tester
[ "$rc" = 0 ] && ok "D1 installer exit 0" || bad "D1 installer exit ${rc:-?}" "$log"
[ -n "$secs" ] && [ "$secs" -le 120 ] && ok "D1 installer finished in ${secs}s (<=120)" || bad "D1 installer slow or missing time (${secs:-?}s)"
echo "$log" | grep -q "checksum ok" && ok "D1 CLI checksum ok" || bad "D1 CLI checksum" "$log"
[ -x $H/.local/bin/denyout-cli ] && ok "D1 denyout-cli installed" || bad "D1 denyout-cli missing"

if [ "$MODE" = full ]; then
  echo "$log" | grep -q "GUI checksum ok" && ok "D1 GUI checksum ok" || bad "D1 GUI checksum ok not printed (no .sha256 for this release?)" "$log"
  [ -x $H/.local/bin/denyout ] && ok "D1 denyout GUI installed" || bad "D1 denyout GUI missing" "$log"
  v=$(su tester -c "$H/.local/bin/denyout --version" 2>&1)
  echo "$v" | grep -q "${DENYOUT_VERSION#v}" && ok "D1 denyout --version = $v" || bad "D1 denyout --version" "$v"

  echo "== D2: GUI binary loads and is running headless"
  miss=$(ldd $H/.local/bin/denyout 2>&1 | grep "not found\|No such file")
  [ -z "$miss" ] && [ -x $H/.local/bin/denyout ] && ok "D2 no missing shared libraries" || bad "D2 missing libs" "$miss"
  sleep 8
  if pgrep -u tester -x denyout >/dev/null; then ok "D2 denyout process alive 8 s after install"; else bad "D2 denyout not running after desktop --install" "$log"; fi
  cli_st=$(su tester -c "$H/.local/bin/denyout-cli version" 2>&1)
  [ -n "$cli_st" ] && [ -x $H/.local/bin/denyout-cli ] && ok "D2 denyout-cli version: $cli_st" || bad "D2 denyout-cli version empty"

  echo "== D3: desktop --install side effects"
  mode_f=$(cat $H/.config/denyout/install-mode 2>/dev/null)
  [ "$mode_f" = desktop ] && ok "D3 install-mode=desktop" || bad "D3 install-mode '${mode_f:-missing}'"
  # By design (internal/desktop/install.go) login launch is registered only after the user
  # picks a mode in the first-run window, so a fresh install must have none.
  ls $H/.config/autostart/*enyout*.desktop >/dev/null 2>&1 && bad "D3 autostart registered before the user chose a mode" "$(ls $H/.config/autostart)" || ok "D3 no autostart before first-run choice (by design)"
  grep -q '"protection_on": *false' $H/.config/denyout/desktop.json 2>/dev/null && ok "D3 desktop.json protection_on=false" || bad "D3 desktop.json" "$(cat $H/.config/denyout/desktop.json 2>/dev/null)"
  command -v nft >/dev/null 2>&1 && nft list table inet denyout >/dev/null 2>&1 && bad "D3 nft table exists after desktop --install (Protect must stay Off)" || ok "D3 Protect Off: no nft table"

  echo "== D3b: upgrade (installer run again): one instance, no duplicate autostart"
  xrun "bash ~/body.sh" >/dev/null 2>&1
  sleep 8
  n=$(pgrep -u tester -x denyout | wc -l)
  [ "$n" -eq 1 ] && ok "D3b one denyout instance after re-install ($n)" || bad "D3b $n denyout instances after re-install"

  [ -x $H/.local/bin/denyout-cli ] || { bad "D7 skipped: nothing installed to uninstall"; echo "== $MODE: $pass passed, $fail failed"; exit 1; }
  echo "== D7: uninstall leaves nothing behind"
  uo=$(xrun "$H/.local/bin/denyout-cli uninstall" 2>&1 </dev/null); urc=$?
  echo "$uo" | tail -5 | sed 's/^/     | /'
  sleep 2
  pgrep -u tester -f denyout >/dev/null && bad "D7 denyout processes left" "$(pgrep -u tester -af denyout)" || ok "D7 no denyout processes"
  [ ! -e $H/.local/bin/denyout-cli ] && [ ! -e $H/.local/bin/denyout ] && ok "D7 binaries removed" || bad "D7 binaries left" "$(ls $H/.local/bin)"
  ls $H/.config/autostart/*enyout*.desktop >/dev/null 2>&1 && bad "D7 autostart entry left" || ok "D7 no autostart entry"
  [ -d $H/.config/denyout ] && bad "D7 config dir left" "$(ls -R $H/.config/denyout | head)" || ok "D7 config dir removed"
  [ "$urc" = 0 ] && ok "D7 uninstall exit 0" || bad "D7 uninstall exit $urc"
else
  echo "== D1b: GUI libs missing: installer must finish, CLI must work, message must name the missing package"
  [ -x $H/.local/bin/denyout-cli ] && su tester -c "$H/.local/bin/denyout-cli version" >/dev/null 2>&1 && ok "D1b CLI works without GUI libs" || bad "D1b CLI broken"
  [ ! -e $H/.local/bin/denyout ] && ok "D1b non-starting GUI binary not kept" || bad "D1b dead GUI binary left installed"
  echo "$log" | grep -qiE "libwebkit2gtk-4.1-0" && ok "D1b installer names the missing GUI library" || bad "D1b installer is silent about missing libwebkit2gtk-4.1-0 / libgtk-3-0" "$log"
fi

echo "== $MODE: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
