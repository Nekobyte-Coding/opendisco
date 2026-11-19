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

It also runs on Linux, as the Build Android workflow does (.forgejo/workflows/build-android.yml):
there the keystore comes from OPENDISCO_KEYSTORE_BASE64 (the .jks file in base64), written to an
owner-only temporary file for the signing and deleted after it, and the password from
OPENDISCO_KEYSTORE_PASSWORD; Briefcase's tools are in ~/.cache/briefcase (or $BRIEFCASE_HOME), and
OPENDISCO_ACCEPT_ANDROID_LICENSES=1 answers yes to Google's SDK license questions. The signed .apk
must carry the release certificate (RELEASE_CERT_SHA256), or the build stops: Android won't let
an .apk signed with another key update an installed copy.
"""
import argparse
import base64
import binascii
import contextlib
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAC = sys.platform == "darwin"
CACHES = (Path.home() / "Library" / "Caches" if MAC
          else Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"))
MIRROR = CACHES / "opendisco" / "android-build"
NEEDED = ("src", "pyproject.toml", "LICENSE", "CHANGELOG.md")
SKIP = shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store")
# Briefcase's Java and Android SDK (it downloads them on the first build)
TOOLS = (Path(os.environ["BRIEFCASE_HOME"]) / "tools" if os.environ.get("BRIEFCASE_HOME")
         else CACHES / ("org.beeware.briefcase" if MAC else "briefcase") / "tools")
KEYSTORE = Path(os.environ.get("OPENDISCO_KEYSTORE")
                or Path.home() / "Library" / "Application Support" / "OpenDisco Signing" / "opendisco-release.jks")
KEYCHAIN_ITEM = "OpenDisco Android signing"
ALIAS = "opendisco"
# SHA-256 of the release certificate (O=OpenDisco, CN=Michael Froehlke), as apksigner verify
# --print-certs shows it; every release .apk so far carries it (1.8.2 checked).
RELEASE_CERT_SHA256 = "8d8d61931fecec8af7d6e7ecf06acc99eb73b79cf288f6336351107e38518842"


def java_home() -> Path:
    """Briefcase's JDK (a macOS bundle on a Mac), or else the JAVA_HOME it was told to use."""
    for home in (TOOLS / "java17" / "Contents" / "Home", TOOLS / "java17"):
        if (home / "bin" / "java").exists():
            return home
    if os.environ.get("JAVA_HOME") and (Path(os.environ["JAVA_HOME"]) / "bin" / "java").exists():
        return Path(os.environ["JAVA_HOME"])
    sys.exit(f"error: no JDK in {TOOLS} and no JAVA_HOME: run a Briefcase Android build once first")


def keystore_password() -> str:
    if os.environ.get("OPENDISCO_KEYSTORE_PASSWORD"):
        return os.environ["OPENDISCO_KEYSTORE_PASSWORD"]
    if not MAC or not shutil.which("security"):
        sys.exit("error: no keystore password: set OPENDISCO_KEYSTORE_PASSWORD")
    r = subprocess.run(["security", "find-generic-password", "-s", KEYCHAIN_ITEM, "-w"], capture_output=True,
                       text=True)
    if r.returncode:
        sys.exit(f"error: no keystore password: set OPENDISCO_KEYSTORE_PASSWORD, or keep it in the keychain as "
                 f'"{KEYCHAIN_ITEM}"')
    return r.stdout.strip()


@contextlib.contextmanager
def keystore():
    """The release keystore: OPENDISCO_KEYSTORE_BASE64 decoded into an owner-only temporary file
    (deleted afterwards), or else the file at KEYSTORE."""
    data = "".join(os.environ.get("OPENDISCO_KEYSTORE_BASE64", "").split())
    if not data:
        if not KEYSTORE.exists():
            sys.exit(f"error: no release key at {KEYSTORE}: restore it from its backup, set "
                     "OPENDISCO_KEYSTORE_BASE64 (or, for a first release only, make one with --create-key)")
        yield KEYSTORE
        return
    try:
        raw = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        sys.exit("error: OPENDISCO_KEYSTORE_BASE64 isn't base64")
    fd, name = tempfile.mkstemp(prefix="opendisco-release-", suffix=".jks")  # 0600
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
        yield Path(name)
    finally:
        Path(name).unlink(missing_ok=True)


def create_key() -> None:
    """Make the release key, with a random password kept in the login keychain."""
    if KEYSTORE.exists():
        sys.exit(f"error: {KEYSTORE} already exists; a new key couldn't update installs signed with it")
    password = secrets.token_urlsafe(24)
    KEYSTORE.parent.mkdir(parents=True, exist_ok=True)
    KEYSTORE.parent.chmod(0o700)
    env = dict(os.environ, OPENDISCO_KEYSTORE_PASSWORD=password)
    subprocess.run([str(java_home() / "bin" / "keytool"), "-genkeypair",
                    "-keystore", str(KEYSTORE), "-storetype", "PKCS12", "-alias", ALIAS,
                    "-keyalg", "RSA", "-keysize", "4096", "-validity", "10000",
                    "-dname", "CN=Michael Froehlke, O=OpenDisco",
                    "-storepass:env", "OPENDISCO_KEYSTORE_PASSWORD", "-keypass:env", "OPENDISCO_KEYSTORE_PASSWORD"],
                   env=env, check=True)
    KEYSTORE.chmod(0o600)
    # Through security's own prompt (-i), not its command line: an argument shows in ps, and in the
    # error printed if it fails. (-X: the password as hex, as credstore.py gives it.)
    subprocess.run(["security", "-i"], input=f'add-generic-password -U -a "{ALIAS}" -s "{KEYCHAIN_ITEM}" '
                                             f'-X {password.encode().hex()}\n', text=True, check=True)
    print(f"Created {KEYSTORE}; its password is in the login keychain as \"{KEYCHAIN_ITEM}\".\n"
          "Back up both: without them, no later version can update an installed copy.")


def sign(unsigned: Path, dest: Path, store: Path) -> None:
    build_tools = max((TOOLS / "android_sdk" / "build-tools").iterdir(), key=lambda p: [
        int(n) if n.isdigit() else 0 for n in p.name.split(".")])
    aligned = unsigned.with_name("aligned.apk")
    subprocess.run([str(build_tools / "zipalign"), "-P", "16", "-f", "4", str(unsigned), str(aligned)], check=True)
    # apksigner runs whichever java is first on the PATH (an old Intel-only JDK, say): use Briefcase's.
    java = java_home()
    env = dict(os.environ, OPENDISCO_KEYSTORE_PASSWORD=keystore_password(), JAVA_HOME=str(java),
               PATH=f"{java / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}")
    subprocess.run([str(build_tools / "apksigner"), "sign", "--ks", str(store), "--ks-key-alias", ALIAS,
                    "--ks-pass", "env:OPENDISCO_KEYSTORE_PASSWORD", "--key-pass", "env:OPENDISCO_KEYSTORE_PASSWORD",
                    "--v4-signing-enabled", "false",  # v4 is only for adb incremental installs
                    "--out", str(dest), str(aligned)], env=env, check=True)
    aligned.unlink()
    shown = subprocess.run([str(build_tools / "apksigner"), "verify", "--print-certs", str(dest)], env=env,
                           check=True, capture_output=True, text=True).stdout
    print(shown, end="")
    certs = re.findall(r"certificate SHA-256 digest: ([0-9a-fA-F]{64})", shown)
    if not certs or {c.lower() for c in certs} != {RELEASE_CERT_SHA256}:
        dest.unlink(missing_ok=True)
        sys.exit(f"error: the .apk is signed with {', '.join(certs) or 'no certificate'}, not the release "
                 f"certificate {RELEASE_CERT_SHA256}: installed copies wouldn't take it as an update")


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
    if not "".join(os.environ.get("OPENDISCO_KEYSTORE_BASE64", "").split()) and not KEYSTORE.exists():
        sys.exit(f"error: no release key at {KEYSTORE}: restore it from its backup, set OPENDISCO_KEYSTORE_BASE64 "
                 "(or, for a first release only, make one with --create-key)")
    keystore_password()  # stops here, before the build, when there's none
    version = re.search(r'__version__ = "([^"]+)"', (ROOT / "src" / "opendisco" / "__init__.py").read_text())[1]
    python = re.search(r'chaquopy\s*\{[^}]*version\s*=\s*"(3\.\d+)"', (ROOT / "pyproject.toml").read_text())
    if python and not shutil.which(f"python{python[1]}"):  # Chaquopy's pip runs on the same version
        sys.exit(f"error: the Android app is built with Python {python[1]}, and Chaquopy needs python{python[1]} "
                 f"on this computer to install its packages: " + (f"brew install python@{python[1]}" if MAC else
                                                                  f"put python{python[1]} on the PATH"))
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
    # Google's SDK license: Briefcase asks through sdkmanager the first time. In CI, where nobody can
    # answer, OPENDISCO_ACCEPT_ANDROID_LICENSES=1 answers yes (whoever runs the workflow accepts it).
    answers = "y\n" * 50 if os.environ.get("OPENDISCO_ACCEPT_ANDROID_LICENSES") == "1" else None
    for step in (["create"], ["build"], ["package", "--packaging-format", "apk"]):
        subprocess.run([str(briefcase), step[0], "android", *step[1:]], cwd=work, check=True, input=answers,
                       text=answers is not None)
    unsigned = next((work / "dist").glob("*.apk"))
    dest = args.out.resolve() / f"OpenDisco-{version}-android.apk"
    dest.parent.mkdir(parents=True, exist_ok=True)
    with keystore() as store:
        sign(unsigned, dest, store)
    print(f"Built {dest} ({dest.stat().st_size / 1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import update_key  # the update key goes in for the build only (docs/UPDATES.md)
    sys.exit(update_key.run(main, also=[MIRROR]))
