#!/bin/sh
# Checks OpenDisco's AppImage inside a test container: the file's AppImage mark, the command line
# and its terms gate, and the app opening under Xvfb on its terms of use (a screenshot in
# /tmp/opendisco-terms.png), with the girepository-2.0 it loaded. Containers have no FUSE, so the
# AppImage runs extracted. Exits non-zero on the first failure.
#   sh check_appimage.sh /path/to/OpenDisco-<version>-linux-x86_64.AppImage
set -eu
IMG="$1"
HOME=$(mktemp -d)
export HOME APPIMAGE_EXTRACT_AND_RUN=1
fail() { echo "FAIL: $*"; exit 1; }

[ "$(od -An -tx1 -j8 -N3 "$IMG" | tr -d ' ')" = 414902 ] || fail "no AppImage type 2 mark"
echo "== $("$IMG" --version)"
code=0; "$IMG" --interfaces </dev/null >/dev/null 2>&1 || code=$?
[ "$code" = 2 ] || fail "with the terms not accepted, the command line exited $code, not 2"
echo "== command line before accepting: exit 2"

Xvfb :99 -screen 0 1400x1000x24 >/dev/null 2>&1 &
XVFB=$!
trap 'kill "$XVFB" 2>/dev/null || true' EXIT
sleep 2
SESSION=""; command -v dbus-run-session >/dev/null && SESSION="dbus-run-session --"
DISPLAY=:99 $SESSION "$IMG" >/tmp/opendisco-app.log 2>&1 &
sleep 25
APP=$(pgrep -f 'usr/bin/opendisco' | head -1) || true
[ -n "$APP" ] || { cat /tmp/opendisco-app.log; fail "the app isn't running"; }
echo "== the app is open after 25 s"
DISPLAY=:99 xwininfo -root -tree | grep -i '"opendisco"' | head -1 || fail "no window with the opendisco class"
echo "== girepository-2.0: $(grep -o '/[^ ]*libgirepository-2.0[^ ]*' /proc/$APP/maps | sort -u)"
if command -v import >/dev/null; then DISPLAY=:99 import -window root /tmp/opendisco-terms.png
else DISPLAY=:99 magick import -window root /tmp/opendisco-terms.png; fi
kill "$APP" 2>/dev/null || true
sleep 2
if grep -qi "traceback" /tmp/opendisco-app.log; then cat /tmp/opendisco-app.log; fail "a traceback"; fi
[ ! -e "$HOME/.local/share/opendisco/terms.json" ] || fail "something recorded an acceptance"

"$IMG" --accept-terms --interfaces </dev/null >/dev/null || fail "--accept-terms --interfaces"
grep -q '"channel": "github"' "$HOME/.local/share/opendisco/terms.json" || fail "the record's channel"
echo "== accepted on the command line: $(grep -o '"version": "[^"]*"' "$HOME/.local/share/opendisco/terms.json" | tail -1)"
echo "PASS"
