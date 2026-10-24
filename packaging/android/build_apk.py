#!/usr/bin/env python3
"""Build OpenDisco's Android app (.apk), from a copy outside iCloud.

The first run downloads Java and Google's Android SDK into Briefcase's cache and asks you to
accept Google's SDK license, so run it in a terminal you can answer in. The .apk is signed with
Android's debug key: fine to sideload (allow "Install unknown apps"), not for the Play Store.

    .venv/bin/python packaging/android/build_apk.py
"""
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIRROR = Path.home() / "Library" / "Caches" / "opendisco" / "android-build"
NEEDED = ("src", "pyproject.toml", "LICENSE", "CHANGELOG.md")
SKIP = shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store")


def main() -> int:
    briefcase = Path(sys.executable).with_name("briefcase")
    if not briefcase.exists():
        sys.exit("error: run this with the project's venv: .venv/bin/python packaging/android/build_apk.py")
    version = re.search(r'__version__ = "([^"]+)"', (ROOT / "src" / "opendisco" / "__init__.py").read_text())[1]
    MIRROR.mkdir(parents=True, exist_ok=True)
    for name in NEEDED:
        src, dst = ROOT / name, MIRROR / name
        if dst.is_dir():
            shutil.rmtree(dst)
        elif dst.exists():
            dst.unlink()
        shutil.copytree(src, dst, ignore=SKIP) if src.is_dir() else shutil.copyfile(src, dst)
    shutil.rmtree(MIRROR / "build" / "opendisco" / "android", ignore_errors=True)  # fresh: picks up the version
    for step in (["create"], ["build"], ["package", "--packaging-format", "debug-apk"]):
        subprocess.run([str(briefcase), step[0], "android", *step[1:]], cwd=MIRROR, check=True)
    apk = max((MIRROR / "dist").glob("*.apk"), key=lambda p: p.stat().st_mtime)
    dest = ROOT / "dist" / f"OpenDisco-{version}-android.apk"
    dest.parent.mkdir(exist_ok=True)
    shutil.copyfile(apk, dest)
    print(f"Built {dest} ({dest.stat().st_size / 1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
