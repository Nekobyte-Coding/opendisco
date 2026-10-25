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
import struct
import subprocess
import sys
import uuid
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


def mac_cpus() -> str:
    """Which Macs the built app runs on, for the .dmg's name: universal, apple-silicon or intel."""
    binary = next((MIRROR / "build").glob("*/macos/app/*.app/Contents/MacOS/*"))
    archs = set(subprocess.run(["lipo", "-archs", str(binary)], capture_output=True, text=True,
                               check=True).stdout.split())
    return "universal" if {"arm64", "x86_64"} <= archs else "apple-silicon" if "arm64" in archs else "intel"


LC_UUID = 0x1B
FAT_MAGIC, MH_MAGIC_64 = 0xCAFEBABE, 0xFEEDFACF


def give_own_uuid(binary: Path, bundle_id: str) -> list:
    """Give the app's launcher its own Mach-O UUID, one per CPU, the same in every version.

    Briefcase builds every macOS app from one prebuilt launcher, so they all carry the same UUID,
    and macOS's Local Network privacy finds apps by it: with an older OpenDisco (another app ID) or
    any other Briefcase app on the Mac, it applied that app's setting to OpenDisco, showed no
    prompt, and blocked its traffic, so scans found nothing. Returns the new UUIDs."""
    data = bytearray(binary.read_bytes())
    if struct.unpack_from(">I", data, 0)[0] == FAT_MAGIC:  # universal: one Mach-O per CPU
        count = struct.unpack_from(">I", data, 4)[0]
        slices = [struct.unpack_from(">iiIII", data, 8 + 20 * n)[2] for n in range(count)]
    else:
        slices = [0]
    done = []
    for start in slices:
        magic, cputype, _sub, _type, ncmds = struct.unpack_from("<IiiII", data, start)
        if magic != MH_MAGIC_64:
            raise SystemExit(f"error: {binary} isn't a 64-bit Mach-O")
        at = start + 32  # load commands follow the 64-bit header
        for _ in range(ncmds):
            cmd, size = struct.unpack_from("<II", data, at)
            if cmd == LC_UUID:
                new = uuid.uuid5(uuid.NAMESPACE_DNS, f"{bundle_id}.launcher.{cputype}")
                data[at + 8:at + 24] = new.bytes
                done.append(str(new).upper())
                break
            at += size
    binary.write_bytes(bytes(data))
    return done


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
        if step[0] == "package":
            # pip writes the packages' command-line scripts with this machine's Python (and so its
            # folders) on their first line; the app doesn't use them. Drop them before signing.
            for scripts in (MIRROR / "build").glob("*/macos/app/*.app/Contents/Resources/app_packages/bin"):
                shutil.rmtree(scripts)
            for app in (MIRROR / "build").glob("*/macos/app/*.app"):  # before signing, which covers it
                with open(app / "Contents" / "Info.plist", "rb") as f:
                    info = plistlib.load(f)
                uuids = give_own_uuid(app / "Contents" / "MacOS" / info["CFBundleExecutable"],
                                      info["CFBundleIdentifier"])
                print(f"Launcher UUIDs: {', '.join(uuids)}")
        subprocess.run([str(briefcase), step[0], "macOS", *step[1:], "--no-input"], cwd=MIRROR, check=True)

    dmg = max((MIRROR / "dist").glob("*.dmg"), key=lambda p: p.stat().st_mtime)
    (ROOT / "dist").mkdir(exist_ok=True)
    dest = ROOT / "dist" / f"OpenDisco-{version}-macos-{mac_cpus()}.dmg"
    shutil.copyfile(dmg, dest)
    print(f"Built {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
