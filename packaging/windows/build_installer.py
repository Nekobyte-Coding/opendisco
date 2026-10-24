#!/usr/bin/env python3
"""Build OpenDisco's Windows installer (setup.exe), on macOS, Linux or Windows.

Briefcase only builds Windows apps on Windows, so this assembles the same parts Briefcase
uses: the official embeddable Python for Windows from python.org, Toga's Windows backend
installed from Windows wheels, and the app's code. NSIS then wraps them into a per-user
setup.exe that needs no administrator rights to install.

Needs Python 3.11+ with pip, and NSIS's makensis (macOS: brew install makensis;
Debian/Ubuntu: apt install nsis; Windows: https://nsis.sourceforge.io).

    python3 packaging/windows/build_installer.py
"""
import argparse
import hashlib
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PYTHON_VERSION = "3.13.17"  # embeddable builds exist for 3.13 bugfix releases; pythonnet supports it
TOGA_VERSION = "0.5.7"
PYWINPTY_VERSION = "2.0.15"  # Windows consoles (ConPTY) for the Terminal tab's SSH and ping


def app_version() -> str:
    text = (ROOT / "src" / "opendisco" / "__init__.py").read_text()
    return re.search(r'__version__ = "([^"]+)"', text).group(1)


def download(url: str, dest: Path) -> Path:
    if not dest.exists():
        print(f"Downloading {url}")
        part = dest.with_name(dest.name + ".part")
        with urllib.request.urlopen(url, timeout=120) as response, open(part, "wb") as f:
            shutil.copyfileobj(response, f)
        part.rename(dest)
    return dest


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the Windows installer (setup.exe).")
    parser.add_argument("--python", default=PYTHON_VERSION, help=f"Python to bundle (default {PYTHON_VERSION})")
    parser.add_argument("--out", default=str(ROOT / "dist"), help="where setup.exe goes (default dist/)")
    args = parser.parse_args()

    makensis = shutil.which("makensis")
    if not makensis:
        sys.exit("error: makensis not found (macOS: brew install makensis; Debian/Ubuntu: apt install nsis)")
    version = app_version()
    major_minor = ".".join(args.python.split(".")[:2])
    # Keep the 40 MB of staging out of iCloud-synced folders on a Mac.
    work = (Path.home() / "Library" / "Caches" / "opendisco" / "windows-installer" if sys.platform == "darwin"
            else ROOT / "build" / "windows-installer")
    stage, cache = work / "stage", work / "cache"
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True)
    cache.mkdir(parents=True, exist_ok=True)

    # 1. Python: the official embeddable build. Its ._pth file fixes sys.path, so add the
    #    bundled packages and the app (relative to python\) and turn on site.
    name = f"python-{args.python}-embed-amd64.zip"
    archive = download(f"https://www.python.org/ftp/python/{args.python}/{name}", cache / name)
    print(f"{name} sha256 {hashlib.sha256(archive.read_bytes()).hexdigest()}")
    with zipfile.ZipFile(archive) as z:
        z.extractall(stage / "python")
    short = major_minor.replace(".", "")
    (stage / "python" / f"python{short}._pth").write_text(
        f"python{short}.zip\n.\nLib\\site-packages\n..\\app\nimport site\n")

    # 2. Toga's Windows backend and its dependencies (pythonnet, Pillow...), and pywinpty, as
    #    Windows wheels.
    print(f"Installing toga-winforms {TOGA_VERSION} and pywinpty {PYWINPTY_VERSION} for Windows, "
          f"Python {major_minor}")
    subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check",
                    "--target", str(stage / "python" / "Lib" / "site-packages"),
                    "--platform", "win_amd64", "--python-version", major_minor, "--implementation", "cp",
                    "--only-binary=:all:", "--no-compile", f"toga-winforms=={TOGA_VERSION}",
                    f"pywinpty=={PYWINPTY_VERSION}"], check=True)

    # 3. The app, plus a command-line launcher: "opendisco.cmd --quick" works like ./opendisco.py
    shutil.copytree(ROOT / "src" / "opendisco", stage / "app" / "opendisco",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.icns"))
    (stage / "opendisco.cmd").write_text('@"%~dp0python\\python.exe" -m opendisco %*\r\n')
    for name in ("LICENSE", "NOTICE"):  # Apache 2.0, as .txt so Windows opens them
        shutil.copyfile(ROOT / name, stage / f"{name}.txt")

    # 4. The installer.
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    setup = out / f"OpenDisco-{version}-windows-x64-setup.exe"  # 64-bit Python; Windows on ARM emulates it
    numeric = ".".join((version.split(".") + ["0"] * 4)[:4])
    subprocess.run([makensis, "-V2", "-NOCD", f"-DVERSION={version}", f"-DVERSION_NUMERIC={numeric}",
                    f"-DSTAGE={stage}", f"-DOUTFILE={setup}",
                    f"-DICON={stage / 'app' / 'opendisco' / 'resources' / 'icon.ico'}",
                    str(Path(__file__).with_name("installer.nsi"))], check=True)
    print(f"Built {setup} ({setup.stat().st_size / 1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
