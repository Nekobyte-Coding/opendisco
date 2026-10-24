#!/bin/sh
# Add OpenDisco (this folder's copy) to the desktop's app menu.
# Run it again after moving the folder; remove the entry with: ./install-desktop-entry.sh --remove
set -e
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
ENTRY="${XDG_DATA_HOME:-$HOME/.local/share}/applications/opendisco.desktop"

if [ "$1" = "--remove" ]; then
    rm -f "$ENTRY"
    echo "Removed $ENTRY"
    exit 0
fi

mkdir -p "$(dirname "$ENTRY")"
cat > "$ENTRY" <<EOF
[Desktop Entry]
Type=Application
Name=OpenDisco
Comment=Find and diagnose Ubiquiti and other WISP gear
Exec="$HERE/opendisco"
Icon=$HERE/src/opendisco/resources/icon.png
Terminal=false
Categories=Network;Utility;
EOF
chmod 644 "$ENTRY"
echo "Added OpenDisco to the app menu ($ENTRY)."
