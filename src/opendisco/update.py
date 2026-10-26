"""Keeping OpenDisco up to date from its GitHub releases: ask GitHub for the latest release,
download this platform's installer, check it against the SHA-256 GitHub lists for it, and
install it the way this copy was installed. app.py asks the questions and shows the progress;
everything here runs in a worker thread and uses the standard library only.

OPENDISCO_UPDATE_URL replaces the GitHub API address, so tests can serve a release of their own.
"""
import hashlib
import json
import os
import platform
import plistlib
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from opendisco import __version__, core, tls

REPO = "Nekobyte-Coding/opendisco"
API_URL = os.environ.get("OPENDISCO_UPDATE_URL") or f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_PAGE = f"https://github.com/{REPO}/releases"
APP_ID = "com.michaelfroehlke.opendisco"
USER_AGENT = f"OpenDisco/{__version__}"  # GitHub's API refuses requests without one
HERE = Path(__file__).resolve().parent  # this copy's opendisco package
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
CREATE_NEW_PROCESS_GROUP = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)


class UpdateError(Exception):
    """What stopped a check, download or install, worded for the app to show."""


@dataclass
class Asset:
    name: str
    url: str
    size: int
    sha256: str  # "" when GitHub lists no digest for it


@dataclass
class Release:
    version: str  # "1.5.0"
    title: str
    notes: str  # Markdown
    page: str
    assets: dict  # file name -> Asset

    @property
    def newer(self) -> bool:
        return version_key(self.version) > version_key(__version__)


def version_key(text: str) -> tuple:
    """(1, 5, 0) for "1.5.0" or "v1.5.0"; () for anything else, which is never newer."""
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", str(text).strip())
    return tuple(int(n) for n in m.groups()) if m else ()


# -- talking to GitHub ---------------------------------------------------------------
def _get(url: str, timeout: float, accept: str = ""):
    headers = {"User-Agent": USER_AGENT}
    if accept:
        headers["Accept"] = accept
    request = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=tls.context()))
    return opener.open(request, timeout=timeout)


def _reason(e: Exception) -> str:
    reason = getattr(e, "reason", None) or e
    return str(getattr(reason, "strerror", None) or reason)


def latest(timeout: float = 10) -> Release:
    """The latest release (GitHub leaves out drafts and pre-releases)."""
    try:
        with _get(API_URL, timeout, "application/vnd.github+json") as r:
            data = json.loads(r.read(4 << 20))
    except urllib.error.HTTPError as e:
        raise UpdateError(f"GitHub answered {e.code} {e.reason}") from e  # 403: rate limit; 404: no release
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise UpdateError(f"couldn't reach GitHub ({_reason(e)})") from e
    tag = str(data.get("tag_name") or "")
    if not version_key(tag):
        raise UpdateError(f"the latest release's tag, {tag!r}, isn't a version number")
    assets = {}
    for a in data.get("assets") or []:
        digest = str(a.get("digest") or "")
        sha256 = digest[7:].lower() if digest.lower().startswith("sha256:") else ""
        assets[a.get("name")] = Asset(a.get("name"), a.get("browser_download_url"), int(a.get("size") or 0), sha256)
    return Release(tag.lstrip("v"), str(data.get("name") or tag), str(data.get("body") or ""),
                   str(data.get("html_url") or RELEASES_PAGE), assets)


def excerpt(markdown: str, limit: int = 700) -> str:
    """The start of the release notes as plain text, for the update's question."""
    lines = []
    for line in markdown.replace("\r\n", "\n").split("\n"):
        line = line.rstrip()
        if line.startswith("#"):
            line = line.lstrip("#").strip()
        elif line.lstrip().startswith(("- ", "* ")):
            indent = len(line) - len(line.lstrip())
            line = " " * indent + "• " + line.lstrip()[2:]
        line = re.sub(r"\*\*(.+?)\*\*|__(.+?)__", lambda m: m[1] or m[2], line)
        line = re.sub(r"`([^`]*)`", r"\1", line)
        line = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", line)
        if line or (lines and lines[-1]):
            lines.append(line)
    text = "\n".join(lines).strip()
    if len(text) > limit:
        cut = text.rfind("\n", 0, limit)
        text = text[:cut if cut > limit // 2 else limit].rstrip() + "\n…"
    return text


# -- how this copy was installed -------------------------------------------------------
def installed_as() -> tuple:
    """(kind, what an update replaces) for this copy of the app:
      ("macos", the .app)  ("windows", the install folder)  ("deb" or "rpm", None)
      ("tarball", the portable folder)  ("appimage", the AppImage file)  ("android", None)
      ("source", None): a checkout, a pip install or anything else, which updates its own way."""
    plat = core.platform_name()
    if plat == "android":
        return "android", None
    if plat == "macos":
        bundle = HERE.parents[3] if len(HERE.parents) > 3 else HERE  # X.app/Contents/Resources/app/opendisco
        if (bundle.suffix == ".app" and HERE.parents[1].name == "Resources"
                and _bundle_info(bundle).get("CFBundleIdentifier") == APP_ID):
            return "macos", bundle
    elif plat == "windows":
        folder = HERE.parents[1]  # <install folder>\app\opendisco
        if (HERE.parent.name.lower() == "app" and (folder / "Uninstall.exe").is_file()
                and (folder / "python" / "pythonw.exe").is_file()):
            return "windows", folder
    elif plat == "linux":
        image, mounted = os.environ.get("APPIMAGE"), os.environ.get("APPDIR")  # set by the AppImage's runtime
        if image and mounted and str(HERE).startswith(str(Path(mounted).resolve()) + os.sep) and Path(image).is_file():
            return "appimage", Path(image)
        if str(HERE).startswith(("/usr/lib/opendisco/", "/usr/lib64/opendisco/")):
            owner = HERE / "__init__.py"
            for kind, query in (("deb", ["dpkg-query", "-S", str(owner)]), ("rpm", ["rpm", "-qf", str(owner)])):
                if shutil.which(query[0]) and _quiet(query) == 0:
                    return kind, None
        folder = HERE.parents[1]  # <portable folder>/src/opendisco
        if HERE.parent.name == "src" and (folder / "opendisco").is_file() and (folder / "README-LINUX.md").is_file():
            return "tarball", folder
    return "source", None


def _quiet(argv: list) -> int:
    try:
        return subprocess.run(argv, capture_output=True, timeout=30).returncode
    except (OSError, subprocess.SubprocessError):
        return -1


def _bundle_info(bundle: Path) -> dict:
    try:
        with open(bundle / "Contents" / "Info.plist", "rb") as f:
            return plistlib.load(f)
    except (OSError, ValueError, plistlib.InvalidFileException):
        return {}


def asset_names(version: str, kind: str) -> list:
    """The release files that install this kind of copy, best first."""
    arm = platform.machine().lower() in ("arm64", "aarch64")
    return {"macos": [f"OpenDisco-{version}-macos-universal.dmg",
                      f"OpenDisco-{version}-macos-{'apple-silicon' if arm else 'intel'}.dmg"],
            "windows": [f"OpenDisco-{version}-windows-x64-setup.exe"],  # Windows on ARM runs it emulated
            "deb": [f"OpenDisco-{version}-ubuntu-24.04-{'arm64' if arm else 'amd64'}.deb"],
            "rpm": [f"OpenDisco-{version}-fedora-44-{'aarch64' if arm else 'x86_64'}.rpm"],
            "tarball": [f"OpenDisco-{version}-linux.tar.gz"],
            "appimage": [f"OpenDisco-{version}-linux-{'aarch64' if arm else 'x86_64'}.AppImage"],
            "android": [f"OpenDisco-{version}-android.apk"]}.get(kind, [])


def pick_asset(release: Release, kind: str):
    return next((release.assets[name] for name in asset_names(release.version, kind) if name in release.assets), None)


def cannot_update(kind: str, target) -> str:
    """Why this copy can't replace itself, or "" when it can."""
    if kind == "macos":
        if "/AppTranslocation/" in str(target) or _read_only(target):
            return (f"OpenDisco is running from {target.parent}, which can't be changed (a disk image, or "
                    "a download macOS keeps apart). Move OpenDisco.app to the Applications folder, open it "
                    "from there, and update again")
    if kind in ("tarball", "appimage") and not (os.access(target, os.W_OK) and os.access(target.parent, os.W_OK)):
        return f"this user can't change {target}"
    if kind == "windows" and not os.access(target, os.W_OK):
        return f"this user can't change {target}"
    return ""


def _read_only(path: Path) -> bool:
    try:
        return bool(os.statvfs(path).f_flag & os.ST_RDONLY)
    except (OSError, AttributeError):
        return False


# -- downloading -------------------------------------------------------------------
def download(asset: Asset, folder: Path, progress=None, cancel=None, timeout: float = 30) -> Path:
    """Download an asset into folder and check its SHA-256 against the one GitHub lists; only a
    file that matches is kept, under its own name. progress(done, total) is called as it
    goes; setting cancel (a threading.Event) stops it."""
    if not re.fullmatch(r"[0-9a-f]{64}", asset.sha256):
        raise UpdateError(f"GitHub lists no SHA-256 checksum for {asset.name}, so it can't be checked")
    dest = Path(folder) / asset.name
    if dest.is_file() and _sha256(dest) == asset.sha256:  # downloaded and checked already
        if progress:
            progress(dest.stat().st_size, dest.stat().st_size)
        return dest
    part = dest.with_name(dest.name + ".part")
    digest, done, shown = hashlib.sha256(), 0, 0.0
    try:
        with _get(asset.url, timeout) as r, open(part, "wb") as f:
            total = int(r.headers.get("Content-Length") or asset.size or 0)
            while True:
                if cancel is not None and cancel.is_set():
                    raise UpdateError("cancelled")
                chunk = r.read(1 << 16)
                if not chunk:
                    break
                f.write(chunk)
                digest.update(chunk)
                done += len(chunk)
                if progress and time.monotonic() - shown > 0.1:
                    shown = time.monotonic()
                    progress(done, total)
        if progress:
            progress(done, total)
    except UpdateError:
        part.unlink(missing_ok=True)
        raise
    except (urllib.error.URLError, OSError, ValueError) as e:
        part.unlink(missing_ok=True)
        raise UpdateError(f"downloading {asset.name} failed ({_reason(e)})") from e
    if digest.hexdigest() != asset.sha256:
        part.unlink(missing_ok=True)
        raise UpdateError(f"{asset.name} doesn't match the SHA-256 checksum GitHub lists for it (it's "
                          f"{digest.hexdigest()[:16]}…, not {asset.sha256[:16]}…), so it wasn't used")
    part.replace(dest)
    return dest


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def download_folder() -> Path:
    return Path(tempfile.mkdtemp(prefix="opendisco-update-"))


# -- installing ------------------------------------------------------------------
def _run(argv: list, what: str, log, timeout: float = 600) -> str:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout,
                           creationflags=CREATE_NO_WINDOW if core.IS_WINDOWS else 0)
    except (OSError, subprocess.SubprocessError) as e:
        raise UpdateError(f"{what} failed ({e})") from e
    out = "\n".join(l for l in (r.stdout + r.stderr).strip().splitlines() if "is deprecated" not in l)  # hdiutil's
    if out:
        log(out)
    if r.returncode:
        last = next((l.strip() for l in reversed(out.splitlines()) if l.strip()), f"exit code {r.returncode}")
        raise UpdateError(f"{what} failed: {last}")
    return r.stdout


def _sudo(why: str, log) -> list:
    """The prefix that runs a command as root: sudo, after the app's password prompt."""
    if os.geteuid() == 0:
        return []
    try:
        core.authorize_sudo(why, log)
    except SystemExit as e:
        raise UpdateError(str(e.code).removeprefix("error: ")) from e
    return ["sudo", "-n"]


def install_macos(dmg: Path, bundle: Path, version: str, log) -> None:
    """Replace bundle with the OpenDisco.app on the .dmg. The new copy is made beside it and
    checked first, then the two are swapped, so a failure leaves this copy as it was."""
    sudo = []
    if not (os.access(bundle.parent, os.W_OK) and os.access(bundle, os.W_OK)):
        sudo = _sudo(f"Updating {bundle} needs an administrator password.", log)
    staged = bundle.with_name(f".{bundle.stem}-{version}.app")  # same folder, so the swap is a rename
    old = bundle.with_name(f".{bundle.stem}-replaced-{os.getpid()}.app")
    mount = Path(tempfile.mkdtemp(prefix="opendisco-dmg-"))
    try:
        _run(["hdiutil", "attach", "-quiet", "-nobrowse", "-readonly", "-noautoopen", "-mountpoint", str(mount), str(dmg)],
             "Opening the disk image", log, timeout=180)
        try:
            new = next((p for p in sorted(mount.glob("*.app")) if _bundle_info(p).get("CFBundleIdentifier") == APP_ID),
                       None)
            if new is None:
                raise UpdateError(f"{dmg.name} holds no OpenDisco.app")
            found = _bundle_info(new).get("CFBundleShortVersionString")
            if found != version:
                raise UpdateError(f"{dmg.name} holds OpenDisco {found}, not {version}")
            if staged.exists():
                _run(sudo + ["rm", "-rf", str(staged)], "Clearing an earlier attempt", log)
            log(f"Copying the new OpenDisco.app next to {bundle}")
            _run(sudo + ["ditto", str(new), str(staged)], "Copying the new app", log)
        finally:
            if _quiet(["hdiutil", "detach", str(mount), "-quiet"]):
                _quiet(["hdiutil", "detach", str(mount), "-quiet", "-force"])
    finally:
        try:
            mount.rmdir()
        except OSError:
            pass
    try:
        _run(["codesign", "--verify", "--deep", "--strict", str(staged)], "Checking the new app's signature", log)
        _run(sudo + ["mv", str(bundle), str(old)], f"Moving {bundle.name} aside", log)
    except UpdateError:
        _quiet(sudo + ["rm", "-rf", str(staged)])
        raise
    try:
        _run(sudo + ["mv", str(staged), str(bundle)], "Putting the new app in place", log)
    except UpdateError:
        _quiet(sudo + ["mv", str(old), str(bundle)])
        _quiet(sudo + ["rm", "-rf", str(staged)])
        raise
    _quiet(sudo + ["rm", "-rf", str(old)])
    log(f"Replaced {bundle} with OpenDisco {version}")


def install_package(path: Path, kind: str, log) -> None:
    """Install a .deb with apt or an .rpm with dnf, as root (the app asks for the password)."""
    os.chmod(path.parent, 0o755)  # apt reads the file as its own unprivileged user
    os.chmod(path, 0o644)
    if kind == "deb":
        argv = ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", str(path)]
    elif shutil.which("dnf"):
        argv = ["dnf", "install", "-y", str(path)]
    else:
        argv = ["rpm", "-U", str(path)]
    sudo = _sudo(f"Installing {path.name} needs an administrator password.", log)
    log(f"Installing {path.name} with {argv[2] if kind == 'deb' else argv[0]}")
    _run(sudo + argv, f"Installing {path.name}", log)


def install_tarball(archive: Path, folder: Path, version: str, log) -> None:
    """Replace the portable version's folder with the one in the archive. It's unpacked and
    checked beside the folder first, then the two are swapped; anything added to the folder
    that the new version doesn't have is copied over."""
    work = Path(tempfile.mkdtemp(prefix=f".{folder.name}-update-", dir=folder.parent))
    old = folder.with_name(f".{folder.name}-replaced-{os.getpid()}")
    try:
        try:
            with tarfile.open(archive) as tar:
                if hasattr(tarfile, "data_filter"):
                    tar.extractall(work, filter="data")
                else:  # Python before 3.11.4
                    for m in tar.getmembers():
                        if m.name.startswith("/") or ".." in Path(m.name).parts or m.issym() or m.islnk():
                            raise UpdateError(f"{archive.name} holds an unsafe path ({m.name})")
                    tar.extractall(work)
        except (tarfile.TarError, OSError) as e:
            raise UpdateError(f"unpacking {archive.name} failed ({e})") from e
        tops = list(work.iterdir())
        new = tops[0] if len(tops) == 1 else None
        init = new / "src" / "opendisco" / "__init__.py" if new else None
        if not (init and init.is_file() and (new / "opendisco").is_file()):
            raise UpdateError(f"{archive.name} isn't OpenDisco's portable version")
        found = re.search(r'__version__ = "([^"]+)"', init.read_text(encoding="utf-8"))
        if not found or found[1] != version:
            raise UpdateError(f"{archive.name} holds OpenDisco {found[1] if found else '?'}, not {version}")
        for item in folder.iterdir():
            if not (new / item.name).exists():
                if item.is_dir() and not item.is_symlink():
                    shutil.copytree(item, new / item.name, symlinks=True)
                else:
                    shutil.copy2(item, new / item.name, follow_symlinks=False)
        try:
            folder.rename(old)
        except OSError as e:
            raise UpdateError(f"moving {folder} aside failed ({e.strerror})") from e
        try:
            new.rename(folder)
        except OSError as e:
            old.rename(folder)
            raise UpdateError(f"putting the new version in {folder} failed ({e.strerror})") from e
        shutil.rmtree(old, ignore_errors=True)
        log(f"Replaced {folder} with OpenDisco {version}")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def install_appimage(image: Path, target: Path, version: str, log) -> None:
    """Put the new AppImage in place of this one, under this one's name (where a menu entry or an
    AppImage manager points): copied beside it, then swapped in, so a failure leaves this one.
    The running copy carries on from its own, still open, file."""
    with open(image, "rb") as f:
        head = f.read(16)
    if not (head.startswith(b"\x7fELF") and head[8:11] == b"AI\x02"):  # the type 2 AppImage mark
        raise UpdateError(f"{image.name} isn't an AppImage")
    new = target.with_name(f".{target.name}-update-{os.getpid()}")
    try:
        shutil.copyfile(image, new)
        new.chmod(0o755)
        new.replace(target)
    except OSError as e:
        new.unlink(missing_ok=True)
        raise UpdateError(f"putting the new version in place of {target} failed ({e.strerror})") from e
    log(f"Replaced {target} with OpenDisco {version}")


def start_windows_update(setup: Path, folder: Path, log_file: Path) -> None:
    """Hand over to update-windows.ps1, which waits for the app to quit, runs the installer
    silently over the same folder, and opens the app again."""
    script = setup.with_name("update-windows.ps1")  # the installer replaces the app's own copy
    shutil.copyfile(HERE / "resources" / "update-windows.ps1", script)
    subprocess.Popen(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                      "-WindowStyle", "Hidden", "-File", str(script), "-AppPid", str(os.getpid()),
                      "-Setup", str(setup), "-Dir", str(folder), "-Log", str(log_file)],
                     creationflags=CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP, close_fds=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def relaunch_command(kind: str, target) -> list:
    """What opens the updated app (macOS, Linux)."""
    if kind == "macos":
        return ["/usr/bin/open", str(target)]
    if kind == "tarball":
        return [str(target / "opendisco")]
    if kind == "appimage":
        return [str(target)]
    return [shutil.which("opendisco") or "/usr/bin/opendisco"]


def relaunch_after_exit(argv: list) -> None:
    """Run argv once this process has quit. Started any sooner, the new copy would hand over to
    this one and stop: macOS and GTK keep one copy of an app running."""
    subprocess.Popen(["/bin/sh", "-c", 'while kill -0 "$0" 2>/dev/null; do sleep 0.2; done; exec "$@"',
                      str(os.getpid()), *argv], start_new_session=True, close_fds=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
