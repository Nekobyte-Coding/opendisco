#!/usr/bin/env python3
"""Fetch xterm.js (the terminal emulator in the app's Terminal tab) into the app's resources.

It's bundled rather than loaded from the web because the app is used on networks with no
internet. Each package comes from the npm registry and is checked against the sha512 the
registry publishes for it before anything is extracted.

    python3 packaging/fetch_xterm.py
"""
import base64
import hashlib
import io
import json
import sys
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "src" / "opendisco" / "resources" / "xterm"
# package, version, {file in the package: name in DEST}
PACKAGES = [
    ("@xterm/xterm", "5.5.0", {"lib/xterm.js": "xterm.js", "css/xterm.css": "xterm.css",
                               "LICENSE": "LICENSE"}),
    ("@xterm/addon-fit", "0.10.0", {"lib/addon-fit.js": "addon-fit.js"}),
]


def get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def main() -> int:
    DEST.mkdir(parents=True, exist_ok=True)
    for name, version, files in PACKAGES:
        meta = json.loads(get(f"https://registry.npmjs.org/{name}/{version}"))
        algo, _, digest = meta["dist"]["integrity"].partition("-")
        tarball = get(meta["dist"]["tarball"])
        if algo != "sha512" or hashlib.sha512(tarball).digest() != base64.b64decode(digest):
            sys.exit(f"error: {name}@{version} doesn't match the registry's sha512; not using it")
        with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as tar:
            for inner, out in files.items():
                data = tar.extractfile(f"package/{inner}").read()
                (DEST / out).write_bytes(data)
                print(f"{name}@{version} {inner} -> {out} ({len(data)} bytes)")
    (DEST / "VERSIONS").write_text("".join(f"{n} {v}\n" for n, v, _ in PACKAGES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
