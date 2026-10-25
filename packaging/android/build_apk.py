#!/usr/bin/env python3
"""Build OpenDisco's Android app (.apk), release-signed, from a copy outside iCloud.

The first run downloads Java and Google's Android SDK into Briefcase's cache and asks to accept
Google's SDK license, so run it in a terminal that can answer.

The .apk is signed with OpenDisco's release key. Android only installs an update signed with the
same key as the installed app, so the key and its password must be kept (and backed up) for as
long as the app is released. They live outside the project:

    key:       ~/Library/Application Support/OpenDisco Signing/opendisco-release.jks
               (or $OPENDISCO_KEYSTORE)
    password:  the "OpenDisco Android signing" item in the login keychain
               (or $OPENDISCO_KEYSTORE_PASSWORD)

    .venv/bin/python packaging/android/build_apk.py              # build and sign, into dist/
    .venv/bin/python packaging/android/build_apk.py --out DIR    # into another folder
    .venv/bin/python packaging/android/build_apk.py --create-key # once: make the release key
"""
import argparse
import os
import re
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIRROR = Path.home() / "Library" / "Caches" / "opendisco" / "android-build"
NEEDED = ("src", "pyproject.toml", "LICENSE", "CHANGELOG.md")
SKIP = shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store")
TOOLS = Path.home() / "Library" / "Caches" / "org.beeware.briefcase" / "tools"  # Briefcase's Java and SDK
JAVA_HOME = TOOLS / "java17" / "Contents" / "Home"
KEYSTORE = Path(os.environ.get("OPENDISCO_KEYSTORE")
                or Path.home() / "Library" / "Application Support" / "OpenDisco Signing" / "opendisco-release.jks")
KEYCHAIN_ITEM = "OpenDisco Android signing"
ALIAS = "opendisco"


def keystore_password() -> str:
    if os.environ.get("OPENDISCO_KEYSTORE_PASSWORD"):
        return os.environ["OPENDISCO_KEYSTORE_PASSWORD"]
    r = subprocess.run(["security", "find-generic-password", "-s", KEYCHAIN_ITEM, "-w"], capture_output=True,
                       text=True)
    if r.returncode:
        sys.exit(f"error: no keystore password: set OPENDISCO_KEYSTORE_PASSWORD, or keep it in the keychain as "
                 f'"{KEYCHAIN_ITEM}"')
    return r.stdout.strip()


def create_key() -> None:
    """Make the release key, with a random password kept in the login keychain."""
    if KEYSTORE.exists():
        sys.exit(f"error: {KEYSTORE} already exists; a new key couldn't update installs signed with it")
    password = secrets.token_urlsafe(24)
    KEYSTORE.parent.mkdir(parents=True, exist_ok=True)
    KEYSTORE.parent.chmod(0o700)
    env = dict(os.environ, OPENDISCO_KEYSTORE_PASSWORD=password)
    subprocess.run([str(JAVA_HOME / "bin" / "keytool"), "-genkeypair",
                    "-keystore", str(KEYSTORE), "-storetype", "PKCS12", "-alias", ALIAS,
                    "-keyalg", "RSA", "-keysize", "4096", "-validity", "10000",
                    "-dname", "CN=Michael Froehlke, O=OpenDisco",
                    "-storepass:env", "OPENDISCO_KEYSTORE_PASSWORD", "-keypass:env", "OPENDISCO_KEYSTORE_PASSWORD"],
                   env=env, check=True)
    KEYSTORE.chmod(0o600)
    subprocess.run(["security", "add-generic-password", "-a", ALIAS, "-s", KEYCHAIN_ITEM, "-U", "-w", password],
                   check=True)
    print(f"Created {KEYSTORE}; its password is in the login keychain as \"{KEYCHAIN_ITEM}\".\n"
          "Back up both: without them, no later version can update an installed copy.")


def sign(unsigned: Path, dest: Path) -> None:
    build_tools = max((TOOLS / "android_sdk" / "build-tools").iterdir(), key=lambda p: [
        int(n) if n.isdigit() else 0 for n in p.name.split(".")])
    aligned = unsigned.with_name("aligned.apk")
    subprocess.run([str(build_tools / "zipalign"), "-P", "16", "-f", "4", str(unsigned), str(aligned)], check=True)
    # apksigner runs whichever java is first on the PATH (an old Intel-only JDK, say): use Briefcase's.
    env = dict(os.environ, OPENDISCO_KEYSTORE_PASSWORD=keystore_password(), JAVA_HOME=str(JAVA_HOME),
               PATH=f"{JAVA_HOME / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}")
    subprocess.run([str(build_tools / "apksigner"), "sign", "--ks", str(KEYSTORE), "--ks-key-alias", ALIAS,
                    "--ks-pass", "env:OPENDISCO_KEYSTORE_PASSWORD", "--key-pass", "env:OPENDISCO_KEYSTORE_PASSWORD",
                    "--v4-signing-enabled", "false",  # v4 is only for adb incremental installs
                    "--out", str(dest), str(aligned)], env=env, check=True)
    aligned.unlink()
    subprocess.run([str(build_tools / "apksigner"), "verify", "--print-certs", str(dest)], env=env, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the release-signed Android .apk.")
    parser.add_argument("--create-key", action="store_true", help="make the release key (once)")
    parser.add_argument("--out", type=Path, default=ROOT / "dist", help="folder for the .apk (default: dist)")
    parser.add_argument("--work", type=Path, default=MIRROR,
                        help=f"folder the project is copied to and built in (default: {MIRROR})")
    args = parser.parse_args()
    if args.create_key:
        create_key()
        return 0
    briefcase = Path(sys.executable).with_name("briefcase")
    if not briefcase.exists():
        sys.exit("error: run this with the project's venv: .venv/bin/python packaging/android/build_apk.py")
    if not KEYSTORE.exists():
        sys.exit(f"error: no release key at {KEYSTORE}: restore it from its backup (or, for a first release "
                 "only, make one with --create-key)")
    version = re.search(r'__version__ = "([^"]+)"', (ROOT / "src" / "opendisco" / "__init__.py").read_text())[1]
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    for name in NEEDED:
        src, dst = ROOT / name, work / name
        if dst.is_dir():
            shutil.rmtree(dst)
        elif dst.exists():
            dst.unlink()
        shutil.copytree(src, dst, ignore=SKIP) if src.is_dir() else shutil.copyfile(src, dst)
    shutil.rmtree(work / "build" / "opendisco" / "android", ignore_errors=True)  # fresh: picks up the version
    shutil.rmtree(work / "dist", ignore_errors=True)
    for step in (["create"], ["build"], ["package", "--packaging-format", "apk"]):
        subprocess.run([str(briefcase), step[0], "android", *step[1:]], cwd=work, check=True)
    unsigned = next((work / "dist").glob("*.apk"))
    dest = args.out.resolve() / f"OpenDisco-{version}-android.apk"
    dest.parent.mkdir(parents=True, exist_ok=True)
    sign(unsigned, dest)
    print(f"Built {dest} ({dest.stat().st_size / 1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
