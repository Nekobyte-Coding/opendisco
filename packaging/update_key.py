"""The update key in a release build (docs/UPDATES.md): written to src/opendisco/resources/update-key
for the build only, and removed again after it, so it's never committed (.gitignore has it too).

The key comes from OPENDISCO_UPDATE_KEY, or on a Mac from the login keychain item "OpenDisco
Update Key" (security add-generic-password -a opendisco -s "OpenDisco Update Key" -w, which asks
for it), the same as the Android keystore password. A build without one stops, unless it's given
--no-update-key (a test build: that copy can't update itself).

    sys.exit(update_key.run(main, also=[MIRROR]))   # in a build script, instead of sys.exit(main())

The key is never printed: only its last 4 characters.
"""
from __future__ import annotations

import base64
import binascii
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESOURCE = Path("src") / "opendisco" / "resources" / "update-key"
KEYCHAIN_ITEM = "OpenDisco Update Key"
FLAG = "--no-update-key"


def valid(text: str) -> bool:
    """Base64url (padded or not) for at least 32 bytes, as updatekey.valid."""
    if not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", text or ""):
        return False
    bare = text.rstrip("=")
    try:
        return len(base64.urlsafe_b64decode(bare + "=" * (-len(bare) % 4))) >= 32
    except (binascii.Error, ValueError):
        return False


def find() -> str:
    key = os.environ.get("OPENDISCO_UPDATE_KEY", "").strip()
    if not key and sys.platform == "darwin" and shutil.which("security"):
        r = subprocess.run(["security", "find-generic-password", "-s", KEYCHAIN_ITEM, "-w"], capture_output=True,
                           text=True)
        key = r.stdout.strip() if r.returncode == 0 else ""
    return key


def run(main, also=()) -> int:
    """Run a build script's main() with the key in place, then remove it (from the source and from
    the build folders in also, which hold copies of src/)."""
    if FLAG in sys.argv:
        sys.argv.remove(FLAG)
        print("warning: building without the update key: this copy won't update itself", file=sys.stderr)
        return main()
    if any(a in sys.argv for a in ("-h", "--help", "--create-key")):
        return main()
    key = find()
    if not key:
        sys.exit("error: no update key: set OPENDISCO_UPDATE_KEY, or keep it in the login keychain as "
                 f'"{KEYCHAIN_ITEM}" (see docs/UPDATES.md); {FLAG} builds a copy that can\'t update itself')
    if not valid(key):
        sys.exit("error: the update key isn't base64url for 32 bytes or more")
    path = ROOT / RESOURCE
    path.write_text(key + "\n", encoding="ascii")
    path.chmod(0o644)  # the installed app reads it as whichever user runs it
    print(f"Building with the update key …{key[-4:]}")
    try:
        return main()
    finally:
        for folder in (ROOT, *also):
            (Path(folder) / RESOURCE).unlink(missing_ok=True)
