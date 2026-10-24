#!/usr/bin/env python3
"""Build OpenDisco's macOS app and .dmg with Briefcase, from a copy outside iCloud.

macOS code signing fails on files iCloud Drive has touched (it adds attributes that it keeps
putting back), and this project lives in an iCloud-synced Documents folder. So this copies
the sources to ~/Library/Caches/opendisco/macos-build, builds there, and copies the
finished .dmg into dist/.

    .venv/bin/python packaging/macos/build_dmg.py           # update and rebuild
    .venv/bin/python packaging/macos/build_dmg.py --fresh   # start the app bundle from scratch
"""
import argparse
import plistlib
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIRROR = Path.home() / "Library" / "Caches" / "opendisco" / "macos-build"
NEEDED = ("src", "pyproject.toml", "LICENSE")  # all Briefcase reads
SKIP = shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store")


def built_version():
    """The version in the already-built app's Info.plist, if there is one."""
    for plist in (MIRROR / "build").glob("*/macos/app/*.app/Contents/Info.plist"):
        with open(plist, "rb") as f:
            return plistlib.load(f).get("CFBundleShortVersionString")
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the macOS app and .dmg.")
    parser.add_argument("--fresh", action="store_true", help="recreate the app bundle (and its packages)")
    args = parser.parse_args()
    briefcase = Path(sys.executable).with_name("briefcase")
    if not briefcase.exists():
        sys.exit("error: run this with the project's venv: .venv/bin/python packaging/macos/build_dmg.py")

    # briefcase update refreshes the code but not Info.plist, so a new version (or a new app
    # name) needs the app bundle made again, or Finder keeps showing the old version.
    version = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M).group(1)
    if args.fresh or built_version() not in (None, version):
        shutil.rmtree(MIRROR, ignore_errors=True)
    MIRROR.mkdir(parents=True, exist_ok=True)
    for name in NEEDED:  # shutil copies data only on macOS, so no iCloud attributes come along
        src, dst = ROOT / name, MIRROR / name
        if dst.is_dir():
            shutil.rmtree(dst)
        elif dst.exists():
            dst.unlink()
        if src.is_dir():
            shutil.copytree(src, dst, ignore=SKIP)
        else:
            shutil.copyfile(src, dst)

    steps = [["update", "--update-resources"]] if (MIRROR / "build").exists() else [["create"]]
    steps += [["build"], ["package", "--adhoc-sign"]]
    for step in steps:
        subprocess.run([str(briefcase), step[0], "macOS", *step[1:], "--no-input"], cwd=MIRROR, check=True)

    dmg = max((MIRROR / "dist").glob("*.dmg"), key=lambda p: p.stat().st_mtime)
    (ROOT / "dist").mkdir(exist_ok=True)
    shutil.copyfile(dmg, ROOT / "dist" / dmg.name)
    print(f"Built {ROOT / 'dist' / dmg.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
