#!/bin/bash
# Build OpenDisco's AppImage inside an Ubuntu 24.04 container: build_packages.py --only appimage runs
# it, with the source in /src. Ubuntu 24.04's GLib (2.80) is the oldest current PyGObject builds
# with, and its C library (2.39) the oldest the result runs on: Ubuntu 24.04, Debian 13, Fedora 40,
# Linux Mint 22 and later.
#
# The AppImage carries a relocatable Python (python-build-standalone), PyGObject and pycairo
# compiled here, Toga and the app; it uses the system's GTK 3 and WebKitGTK 4.1, as GTK apps do
# where bundling GTK breaks themes and input methods. Writes /out/<the AppImage> and the source
# package of the one system library it carries, girepository-2.0 (LGPL), for the release.
set -euo pipefail
VERSION="$1"
ARCH=x86_64

# Pinned downloads: python-build-standalone's Python, and AppImage's static runtime (no libfuse2).
PYTHON_URL="https://github.com/astral-sh/python-build-standalone/releases/download/20261021/cpython-3.13.17%2B20261021-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"
PYTHON_SHA256=f829adc9d888e76c8801b4799ed444188d35239fcae3a9808a99ec5cb0d8d92c
RUNTIME_URL="https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-x86_64"
RUNTIME_SHA256=617aa77314d57c8b8e4fae9c3f0b35af7b30d5529cb69e98f64f92510ed98a46
# The same versions as the .deb and .rpm bundle (THIRD-PARTY-NOTICES.md).
REQUIREMENTS="pygobject==3.58.1 pycairo==1.29.2 toga-core==0.5.7 toga-gtk==0.5.7 travertino==0.5.7
              platformdirs==4.13.5 packaging==26.3"

HERE=/src/packaging/linux/appimage
APPDIR=/build/OpenDisco.AppDir
NAME="OpenDisco-$VERSION-linux-$ARCH.AppImage"
# Every file dated the release, so the same source makes the same AppImage.
STAMP=$(date -d "$(sed -n "s/^## $VERSION (\(.*\))$/\1/p" /src/CHANGELOG.md) 12:00 UTC" +%s)

export DEBIAN_FRONTEND=noninteractive
sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources  # apt-get source
apt-get update -qq
apt-get install -y -qq --no-install-recommends build-essential pkg-config libgirepository-2.0-dev \
    libcairo2-dev libgirepository-2.0-0 squashfs-tools curl ca-certificates dpkg-dev >/dev/null

fetch() {  # url sha256 dest
    curl -fsSL --retry 3 -o "$3" "$1"
    echo "$2  $3" | sha256sum -c --quiet || { echo "error: $1 doesn't match its SHA-256" >&2; exit 1; }
}

echo "--- Python"
rm -rf /build && mkdir -p "$APPDIR/usr" /out
fetch "$PYTHON_URL" "$PYTHON_SHA256" /build/python.tar.gz
tar -xzf /build/python.tar.gz -C "$APPDIR/usr"  # usr/python
PY="$APPDIR/usr/python/bin/python3"
SITE=$("$PY" -c 'import sysconfig; print(sysconfig.get_path("purelib"))')

echo "--- PyGObject, pycairo and Toga"
# PyGObject and pycairo compile here, against Ubuntu 24.04's GLib, girepository-2.0 and cairo.
"$PY" -m pip install --quiet --no-cache-dir --disable-pip-version-check --no-warn-script-location $REQUIREMENTS
"$PY" -m pip uninstall --quiet --yes pip
rm -rf "$APPDIR"/usr/python/bin/pip* "$APPDIR"/usr/python/bin/idle* "$APPDIR"/usr/python/bin/pydoc*

echo "--- OpenDisco"
cp -r /src/src/opendisco "$SITE/"
find "$SITE/opendisco" \( -name __pycache__ -o -name .DS_Store -o -name '*.icns' -o -name '*.ico' \
    -o -name '*.ps1' \) -prune -exec rm -rf {} +
install -D -m 644 "$HERE/opendisco" "$APPDIR/usr/bin/opendisco"

echo "--- trimming"
# What a GUI app over GTK never uses: Tk (and the X11 libraries it brings), IDLE, the test suite,
# and the interactive interpreter's line editing and terminal UI (readline, curses), and gdbm.
LIB=$(dirname "$SITE")
rm -rf "$LIB"/{test,idlelib,tkinter,turtledemo,turtle.py,ensurepip,lib2to3} \
       "$LIB"/lib-dynload/{_tkinter,readline,_gdbm,_dbm,_curses,_curses_panel}* "$LIB"/curses "$APPDIR"/usr/python/lib/{tcl,tk,itcl,thread,Tix}* \
       "$APPDIR"/usr/python/lib/lib{tcl,tk}* "$APPDIR"/usr/python/share "$APPDIR"/usr/python/include
# python-build-standalone builds its modules into libpython, except _tkinter and _dbm, which links
# Berkeley DB (Sleepycat licence: copyleft over the whole app). Anything else showing up here in a
# newer Python needs its licence checked (THIRD-PARTY-NOTICES.md) before it ships.
if [ -n "$(ls -A "$LIB/lib-dynload" 2>/dev/null)" ]; then
    echo "error: new modules in lib-dynload: $(ls "$LIB/lib-dynload" | tr '\n' ' ')" >&2
    exit 1
fi
find "$APPDIR" -name __pycache__ -prune -exec rm -rf {} +
SOURCE_DATE_EPOCH=$STAMP "$PY" -m compileall -q -j0 --invalidation-mode unchecked-hash "$LIB" "$APPDIR/usr/bin" >/dev/null

echo "--- girepository-2.0, for systems without it"
mkdir -p "$APPDIR/usr/lib/fallback"
cp -L /usr/lib/$ARCH-linux-gnu/libgirepository-2.0.so.0 "$APPDIR/usr/lib/fallback/"
GLIB=$(dpkg-query -W -f '${source:Version}' libgirepository-2.0-0)
(cd /out && apt-get source -qq --download-only "glib2.0=$GLIB" >/dev/null)

echo "--- AppDir"
install -m 755 "$HERE/AppRun" "$APPDIR/AppRun"
install -m 644 "$HERE/opendisco.desktop" "$APPDIR/com.michaelfroehlke.opendisco.desktop"
install -m 644 /src/src/opendisco/resources/icon.png "$APPDIR/com.michaelfroehlke.opendisco.png"
ln -sf com.michaelfroehlke.opendisco.png "$APPDIR/.DirIcon"
mkdir -p "$APPDIR/usr/share/metainfo" "$APPDIR/usr/share/doc/opendisco"
# AppStream metadata, with a release entry for each version in CHANGELOG.md.
"$PY" -I - /src/CHANGELOG.md "$HERE/com.michaelfroehlke.opendisco.metainfo.xml" \
    > "$APPDIR/usr/share/metainfo/com.michaelfroehlke.opendisco.appdata.xml" <<'METAINFO'
import re, sys
changelog, template = (open(name, encoding="utf-8").read() for name in sys.argv[1:])
releases = re.findall(r"^## (\d+(?:\.\d+)+) \((\d{4}-\d{2}-\d{2})\)", changelog, re.M)
lines = "\n".join(f'    <release version="{v}" date="{d}"/>' for v, d in releases)
print(template.replace("@RELEASES@", lines), end="")
METAINFO
cp /src/LICENSE /src/NOTICE /src/TERMS.md "$APPDIR/usr/share/doc/opendisco/"

echo "--- AppImage"
mksquashfs "$APPDIR" /build/app.squashfs -root-owned -noappend -quiet -no-progress -comp zstd \
    -Xcompression-level 19 -all-time "$STAMP" -mkfs-time "$STAMP" >/dev/null
fetch "$RUNTIME_URL" "$RUNTIME_SHA256" /build/runtime
cat /build/runtime /build/app.squashfs > "/out/$NAME"
chmod 755 "/out/$NAME"
ls -l /out
