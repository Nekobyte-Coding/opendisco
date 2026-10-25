#!/usr/bin/env python3
"""Build OpenDisco's iOS app with Briefcase, from a copy outside iCloud, for the iOS Simulator
or an iPhone.

Like the other platforms' builds, this copies the sources to ~/Library/Caches/opendisco/ios-build
and builds there (code signing fails on files iCloud Drive has touched). The copy leaves out what
the iOS app can't use: the SSH device tools and the Terminal tab (iOS runs no ssh or ping),
OpenDisco's self-update (Apple allows installs from the App Store, TestFlight or Xcode only: App
Review Guideline 2.5.2) and the Windows helpers.

The iPhone build is signed by Xcode's automatic signing for team DGUTLQN548 and the app ID
com.michaelfroehlke.opendisco, with the entitlements pyproject.toml lists for iOS: the multicast
entitlement, which Apple grants on request, lets the app send UBNT discovery's broadcasts and
multicast. Xcode must be signed into an Apple account on that team (Xcode > Settings >
Accounts); -allowProvisioningUpdates lets it make the development certificate and profile. The
iPhone needs Developer Mode on (Settings > Privacy & Security > Developer Mode) and a cable to
this Mac (or, once paired, the same network).

    .venv/bin/python packaging/ios/build_ios.py --simulator "iPhone 17 Pro"  # build, run in the Simulator
    .venv/bin/python packaging/ios/build_ios.py --device "NAME"              # build, install and open on an iPhone
    .venv/bin/python packaging/ios/build_ios.py --device "NAME" --no-launch  # install only
    .venv/bin/python packaging/ios/build_ios.py --fresh ...                  # make the Xcode project again

--device takes the iPhone's name as Finder shows it, or its identifier from
`xcrun devicectl list devices`. The built apps stay in the copy (build/opendisco/ios/xcode/build/
Debug-iphonesimulator and Debug-iphoneos); nothing goes to dist/.
"""
import argparse
import plistlib
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIRROR = Path.home() / "Library" / "Caches" / "opendisco" / "ios-build"
NEEDED = ("src", "pyproject.toml", "LICENSE", "CHANGELOG.md")
SKIP = shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store")
# In src/opendisco, left out of the iOS app (app.py and core.py import none of them there)
DESKTOP_ONLY = ("update.py", "devicetools.py", "devicegui.py", "sshrun.py", "credstore.py", "terminal.py",
                "winnet.py", "phone_android.py", "resources/xterm", "resources/get-npcap.ps1",
                "resources/update-windows.ps1", "resources/icon.ico", "resources/icon.icns")
PROJECT = MIRROR / "build" / "opendisco" / "ios" / "xcode"
TEAM = "DGUTLQN548"
APP_ID = "com.michaelfroehlke.opendisco"
ICON_SIZES = (20, 29, 40, 58, 60, 76, 80, 87, 120, 152, 167, 180, 1024)
SPLASH_SIZES = (640, 1280, 1920)  # the launch screen's picture
TRUST_HINT = """\
If the iPhone refused to open it:
  - Developer Mode off: Settings > Privacy & Security > Developer Mode, turn it on, restart the
    iPhone and confirm with Turn On.
  - "Untrusted Developer": Settings > General > VPN & Device Management, tap the Apple
    Development entry under Developer App, then Trust.
  - Locked: unlock the iPhone and run this again with the same --device."""


def run(cmd, **kwargs) -> None:
    subprocess.run([str(c) for c in cmd], check=True, **kwargs)


def copy_sources() -> bool:
    """Refresh the copy; True when pyproject.toml changed (briefcase update doesn't redo
    Info.plist, so the Xcode project is then made again)."""
    config = MIRROR / "pyproject.toml"
    old = config.read_bytes() if config.exists() else None
    MIRROR.mkdir(parents=True, exist_ok=True)
    for name in NEEDED:  # shutil copies data only on macOS, so no iCloud attributes come along
        src, dst = ROOT / name, MIRROR / name
        if dst.is_dir():
            shutil.rmtree(dst)
        elif dst.exists():
            dst.unlink()
        shutil.copytree(src, dst, ignore=SKIP) if src.is_dir() else shutil.copyfile(src, dst)
    package = MIRROR / "src" / "opendisco"
    for name in DESKTOP_ONLY:
        path = package / name
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)
    # The iOS icons are drawn outside the sources, so they don't ride along inside the app.
    text = config.read_text(encoding="utf-8")
    config.write_text(text.replace('icon = "src/opendisco/resources/icon"', 'icon = "ios-icons/icon"', 1),
                      encoding="utf-8")
    write_icons(MIRROR / "ios-icons")
    return old != config.read_bytes()


def write_icons(folder: Path) -> None:
    """Briefcase takes an icon-<size>.png for each size iOS uses: the icon square and opaque, as
    Apple requires (iOS rounds the corners itself); the launch screen shows the rounded one."""
    sys.path.insert(0, str(ROOT / "packaging"))
    try:
        import make_icons
        from PIL import Image
    except ImportError:
        sys.exit("error: drawing the iOS icons needs Pillow: .venv/bin/pip install Pillow")
    folder.mkdir(exist_ok=True)
    square, rounded = make_icons.draw(full_bleed=True).convert("RGB"), make_icons.draw()
    for sizes, icon in ((ICON_SIZES, square), (SPLASH_SIZES, rounded)):
        for size in sizes:
            icon.resize((size, size), Image.LANCZOS).save(folder / f"icon-{size}.png")


def wanted_entitlements() -> dict:
    config = tomllib.loads((MIRROR / "pyproject.toml").read_text(encoding="utf-8"))
    return config["tool"]["briefcase"]["app"]["opendisco"]["iOS"].get("entitlement", {})


def build_for_device() -> Path:
    """Build and sign for iPhones. Briefcase's iOS template has no entitlements file, so this
    writes one from pyproject.toml and checks the signed app carries every entitlement."""
    wanted = wanted_entitlements()
    info = PROJECT / "OpenDisco" / "OpenDisco-Info.plist"  # rewritten as briefcase build does: one of each key
    info.write_bytes(plistlib.dumps(plistlib.loads(info.read_bytes())))
    entitlements = PROJECT / "OpenDisco" / "OpenDisco.entitlements"
    entitlements.write_bytes(plistlib.dumps(wanted))
    run(["xcodebuild", "build", "-project", PROJECT / "OpenDisco.xcodeproj", "-configuration", "Debug",
         "-sdk", "iphoneos", "-destination", "generic/platform=iOS", "-allowProvisioningUpdates", "-quiet",
         f"DEVELOPMENT_TEAM={TEAM}", "CODE_SIGN_STYLE=Automatic", "CODE_SIGN_IDENTITY=Apple Development",
         f"CODE_SIGN_ENTITLEMENTS={entitlements}"])
    app = PROJECT / "build" / "Debug-iphoneos" / "OpenDisco.app"
    signed = subprocess.run(["codesign", "-d", "--entitlements", "-", "--xml", str(app)], capture_output=True,
                            check=True).stdout
    granted = plistlib.loads(signed) if signed.strip() else {}
    missing = [key for key, value in wanted.items() if granted.get(key) != value]
    if missing:
        sys.exit(f"error: the signed app lacks {', '.join(missing)}: its App ID ({APP_ID}) needs the capability "
                 "turned on in the Apple Developer portal (Identifiers > the App ID > Capabilities, or Additional "
                 "Capabilities for ones Apple granted on request)")
    print(f"Signed for team {TEAM} with {', '.join(wanted) or 'no extra entitlements'}.")
    return app


def install(device: str, app: Path, launch: bool) -> int:
    run(["xcrun", "devicectl", "device", "install", "app", "--device", device, app])
    if not launch:
        return 0
    opened = subprocess.run(["xcrun", "devicectl", "device", "process", "launch", "--device", device,
                             "--terminate-existing", APP_ID])
    if opened.returncode:
        print(TRUST_HINT, file=sys.stderr)
    return opened.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the iOS app for the Simulator or an iPhone.")
    where = parser.add_mutually_exclusive_group(required=True)
    where.add_argument("--simulator", nargs="?", const="", metavar="NAME",
                       help='build for the iOS Simulator and run it there (e.g. "iPhone 17 Pro"; none: Briefcase asks)')
    where.add_argument("--device", metavar="NAME", help="build for an iPhone, install it and open it")
    parser.add_argument("--no-launch", action="store_true", help="build (and install) without opening the app")
    parser.add_argument("--fresh", action="store_true", help="make the Xcode project (and its packages) again")
    args = parser.parse_args()
    briefcase = Path(sys.executable).with_name("briefcase")
    if not briefcase.exists():
        sys.exit("error: run this with the project's venv: .venv/bin/python packaging/ios/build_ios.py")
    changed = copy_sources()
    if args.fresh or changed or not (PROJECT / "OpenDisco.xcodeproj").exists():
        shutil.rmtree(PROJECT.parent, ignore_errors=True)
        run([briefcase, "create", "iOS"], cwd=MIRROR)
    else:
        run([briefcase, "update", "iOS", "--update-resources"], cwd=MIRROR)
    if args.device is None:
        run([briefcase, "build", "iOS"], cwd=MIRROR)
        if not args.no_launch:  # shows the app's output until Ctrl+C
            run([briefcase, "run", "iOS", *(["-d", args.simulator] if args.simulator else [])], cwd=MIRROR)
        return 0
    return install(args.device, build_for_device(), launch=not args.no_launch)


if __name__ == "__main__":
    sys.exit(main())
