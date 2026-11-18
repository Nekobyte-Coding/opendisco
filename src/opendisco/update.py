"""Keeping OpenDisco up to date from its own update server, with GitHub's releases as the
fallback: read the release list, check the release's signed SHA256SUMS against OpenDisco's
release key (signing.py), download this platform's installer and check it against that list,
and install it the way this copy was installed. app.py asks the questions and shows the
progress; everything here runs in a worker thread and uses the standard library only.
docs/UPDATES.md has the server's side.

find() asks the update server first. Only when that fails (no key, a refused key, no answer, an
unreadable list, a newer release whose SHA256SUMS isn't signed with the release key) does it ask
GitHub (GITHUB_REPO's releases). Both sources are checked the same way: nothing is installed
without a good signature.

Every request to the update server carries the install's update key (updatekey.py) in
X-Update-Key; the server answers 404 to a request without the right one. GitHub is never sent
the key. A redirect is followed only on the same host, and for GitHub also to its download hosts
(GITHUB_REDIRECTS), https only.

The update source is https://git.nekohosting.moe/updates/opendisco, or OPENDISCO_UPDATE_URL, or
the update_source setting: https only, with no user name, password, query or fragment. Another
source set that way is asked alone, without the GitHub fallback.
"""
import base64
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
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from opendisco import __version__, core, signing, tls, updatekey
from opendisco.i18n import _, tr

DEFAULT_SOURCE = "https://git.nekohosting.moe/updates/opendisco"
RELEASES_PAGE = "https://git.nekohosting.moe/nekobyte-coding/opendisco/releases"
SUMS, SIGNATURE = "SHA256SUMS", "SHA256SUMS.sig"
GITHUB_REPO = "Nekobyte-Coding/opendisco"  # the public repository: the fallback
GITHUB_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases"
GITHUB_PAGE = f"https://github.com/{GITHUB_REPO}/releases"
GITHUB_REDIRECTS = ("objects.githubusercontent.com", "release-assets.githubusercontent.com")
MAX_LIST = 1 << 20  # releases.json
MAX_SMALL = 64 << 10  # SHA256SUMS, its signature, update-key
MAX_REDIRECTS = 3
ALLOW_HTTP = False  # the tests' local server only; never set by the app
APP_ID = "com.michaelfroehlke.opendisco"
USER_AGENT = f"OpenDisco/{__version__}"
HERE = Path(__file__).resolve().parent  # this copy's opendisco package
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
CREATE_NEW_PROCESS_GROUP = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)


class UpdateError(Exception):
    """What stopped a check, download or install, worded for the app to show (in its language;
    "cancelled", a stopped download, stays as it is: app.py looks for it)."""


class KeyRefused(UpdateError):
    """The server wouldn't answer this install's key, or there's no key to send."""


def key_refused() -> str:
    return _("this install's update key isn't accepted. Install the latest release once by hand")


def no_key() -> str:
    return _("this install has no update key. Install the latest release once by hand")


@dataclass
class Asset:
    name: str
    url: str
    size: int
    sha256: str = ""  # from the release's signed SHA256SUMS (prepare())
    origin: str = ""  # "github" for a GitHub release's file (no key sent), "" for the update server's


@dataclass
class Release:
    version: str  # "1.5.0"
    title: str
    notes: str  # Markdown
    page: str
    assets: dict  # file name -> Asset
    tag: str = ""
    base: str = ""  # <source>/<tag>, where its files are
    prerelease: bool = False
    sums: dict = field(default_factory=dict)  # file name -> SHA-256, once checked (prepare())
    origin: str = ""  # "github" for GitHub's releases, "" for the update server

    @property
    def newer(self) -> bool:
        return version_key(self.version) > version_key(__version__)


def version_key(text: str) -> tuple:
    """A sortable key for "1.5.0", "v1.5.0" or a pre-release such as "1.6.0-rc.1" (before 1.6.0);
    () for anything else, which is never newer."""
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*))?", str(text).strip())
    if not m:
        return ()
    numbers = tuple(int(n) for n in m.groups()[:3])
    if m[4] is None:
        return numbers + ((1,),)
    return numbers + ((0, *((0, int(p), "") if p.isdigit() else (1, 0, p) for p in m[4].split("."))),)


def source(url: str = "") -> str:
    """The update source to use, checked: https, a host, and no user name, password, query or
    fragment; without a trailing slash."""
    text = str(url or os.environ.get("OPENDISCO_UPDATE_URL") or DEFAULT_SOURCE).strip()
    bad = UpdateError(_("the update source isn't a usable https:// address"))
    if any(c.isspace() or ord(c) < 32 for c in text) or "\\" in text:
        raise bad
    parts = urllib.parse.urlsplit(text)
    if parts.scheme != "https" and not (ALLOW_HTTP and parts.scheme == "http"):
        raise bad
    if "@" in parts.netloc:
        raise UpdateError(_("the update source can't hold a user name or password"))
    try:
        port = parts.port
    except ValueError:
        raise bad from None
    if not parts.hostname or parts.query or parts.fragment or "?" in text or "#" in text:
        raise bad
    netloc = parts.hostname.lower() + (f":{port}" if port else "")
    return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path.rstrip("/"), "", ""))


def _plain(name: str) -> bool:
    """A file or tag name that stays in its folder."""
    return (isinstance(name, str) and bool(name) and name not in (".", "..") and len(name) <= 255
            and not any(c in name for c in "/\\") and all(c.isprintable() for c in name))


# -- talking to the update server --------------------------------------------------------
def _origin(url: str) -> tuple:
    parts = urllib.parse.urlsplit(url)
    return parts.scheme, (parts.hostname or "").lower(), parts.port or {"https": 443, "http": 80}.get(parts.scheme)


class _SameHost(urllib.request.HTTPRedirectHandler):
    """Follows a redirect only to the same scheme, host and port, or to one of hosts over https,
    at most MAX_REDIRECTS times."""
    max_redirections = MAX_REDIRECTS

    def __init__(self, hosts=()):
        super().__init__()
        self.allowed = {("https", host, 443) for host in hosts}

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        newurl = urllib.parse.urljoin(req.full_url, newurl)
        if _origin(newurl) != _origin(req.full_url) and _origin(newurl) not in self.allowed:
            raise UpdateError(tr("the update server sent the request on to another address ({host}), so it was "
                                 "refused", host=_origin(newurl)[1] or "?"))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _get(url: str, key, timeout: float, github: bool = False):
    headers = {"User-Agent": USER_AGENT}
    if github:  # never the key
        if url.startswith(GITHUB_API):
            headers["Accept"] = "application/vnd.github+json"
    elif key is not None:
        headers["X-Update-Key"] = key.value
    request = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=tls.context()),
                                         _SameHost(GITHUB_REDIRECTS if github else ()))
    return opener.open(request, timeout=timeout)


def _reason(e: Exception) -> str:
    reason = getattr(e, "reason", None) or e
    return str(getattr(reason, "strerror", None) or reason)


def _open(url: str, key, timeout: float, what: str = "", github: bool = False):
    """Open url with the key (GitHub: without it). what names the file for a 404 once the release
    list was read; without it (the list itself), a 404 means the key wasn't taken: the server
    answers so (GitHub: that there's no release)."""
    if not github and key is None:
        raise KeyRefused(no_key())
    try:
        return _get(url, key, timeout, github)
    except urllib.error.HTTPError as e:
        e.close()
        if github and e.code == 404 and not what:
            raise UpdateError(_("the update server lists no release")) from None
        if not github and (e.code in (401, 403) or (e.code == 404 and not what)):
            raise KeyRefused(key_refused()) from None
        if e.code == 404:
            raise UpdateError(tr("the update server has no {file}", file=what)) from None
        raise UpdateError(tr("the OpenDisco update server answered {code} {reason}", code=e.code,
                             reason=e.reason)) from None
    except UpdateError:
        raise
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise UpdateError(tr("couldn't reach the OpenDisco update server ({reason})", reason=_reason(e))) from None


def _small(url: str, key, timeout: float, what: str, limit: int = MAX_SMALL, github: bool = False) -> bytes:
    with _open(url, key, timeout, what, github) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise UpdateError(tr("{file} on the update server is too large", file=what))
    return data


def latest(key, url: str = "", timeout: float = 10, prereleases: bool = False) -> Release:
    """The newest release on the update server (pre-releases only when asked for)."""
    base = source(url)
    try:
        data = json.loads(_small(f"{base}/releases.json", key, timeout, "", MAX_LIST))
    except (ValueError, UnicodeDecodeError):
        data = None
    if not isinstance(data, list):
        raise UpdateError(_("the update server's release list can't be read"))
    best = None
    for item in data:
        if not isinstance(item, dict) or (item.get("prerelease") and not prereleases):
            continue
        tag = str(item.get("tag") or "")
        version = str(item.get("version") or tag).lstrip("v")
        if not _plain(tag) or not version_key(version):
            continue
        if best is None or version_key(version) > version_key(best[1]):
            best = item, version, tag
    if best is None:
        raise UpdateError(_("the update server lists no release"))
    item, version, tag = best
    folder = f"{base}/{urllib.parse.quote(tag)}"
    assets = {}
    for a in item.get("assets") or []:
        name = a.get("name") if isinstance(a, dict) else None
        if _plain(name):
            try:
                size = max(0, int(a.get("size") or 0))
            except (TypeError, ValueError):
                size = 0
            assets[name] = Asset(name, f"{folder}/{urllib.parse.quote(name)}", size)
    page = str(item.get("html_url") or "")
    return Release(version, str(item.get("name") or tag), str(item.get("notes") or ""),
                   page if page.startswith("https://") else RELEASES_PAGE, assets, tag, folder,
                   bool(item.get("prerelease")))


def latest_github(timeout: float = 10, prereleases: bool = False) -> Release:
    """The newest release on GITHUB_REPO's releases page (pre-releases only when asked for); its
    files are downloaded from github.com/<repo>/releases/download/<tag>/, never with the key."""
    url = f"{GITHUB_API}?per_page=30" if prereleases else f"{GITHUB_API}/latest"
    try:
        data = json.loads(_small(url, None, timeout, "", MAX_LIST, github=True))
    except (ValueError, UnicodeDecodeError):
        data = None
    items = data if isinstance(data, list) else [data] if isinstance(data, dict) else None
    if items is None:
        raise UpdateError(_("the update server's release list can't be read"))
    best = None
    for item in items:
        if not isinstance(item, dict) or item.get("draft") or (item.get("prerelease") and not prereleases):
            continue
        tag = str(item.get("tag_name") or "")
        version = tag.lstrip("v")
        if not _plain(tag) or not version_key(version):
            continue
        if best is None or version_key(version) > version_key(best[1]):
            best = item, version, tag
    if best is None:
        raise UpdateError(_("the update server lists no release"))
    item, version, tag = best
    folder = f"https://github.com/{GITHUB_REPO}/releases/download/{urllib.parse.quote(tag)}"
    assets = {}
    for a in item.get("assets") or []:
        name = a.get("name") if isinstance(a, dict) else None
        if _plain(name):
            try:
                size = max(0, int(a.get("size") or 0))
            except (TypeError, ValueError):
                size = 0
            assets[name] = Asset(name, f"{folder}/{urllib.parse.quote(name)}", size, origin="github")
    page = str(item.get("html_url") or "")
    return Release(version, str(item.get("name") or tag), str(item.get("body") or ""),
                   page if page.startswith("https://github.com/") else GITHUB_PAGE, assets, tag, folder,
                   bool(item.get("prerelease")), origin="github")


def find(key, url: str = "", timeout: float = 10, prereleases: bool = False, log=None) -> Release:
    """The newest release: from the update server first, and from GitHub only when that fails.
    A newer release's signature is checked here already (verify_sums()), so a source whose
    SHA256SUMS isn't signed with the release key counts as failed. When both fail, the update
    server's error is raised. Another update source (url, OPENDISCO_UPDATE_URL) is asked alone.
    log(text) gets which source answered and why GitHub was asked (never the key)."""
    log = log or (lambda text: None)
    base = source(url)
    if base != DEFAULT_SOURCE:
        return latest(key, base, timeout, prereleases)
    try:
        release = latest(key, base, timeout, prereleases)
        if release.newer:
            verify_sums(release, key, timeout)
        log(f"Update check: asked {base}.")
        return release
    except UpdateError as e:
        first = e
    log(f"Update check: {base} failed ({first}); asking GitHub ({GITHUB_REPO}).")
    try:
        release = latest_github(timeout, prereleases)
        if release.newer:
            verify_sums(release, None, timeout)
    except UpdateError as e:
        log(f"Update check: GitHub failed too ({e}).")
        raise first from None
    log(f"Update check: asked GitHub ({GITHUB_REPO}).")
    return release


def parse_sums(text: bytes) -> dict:
    """SHA256SUMS (sha256sum's format: "<hex>  <name>") as {name: hex}."""
    sums = {}
    try:
        lines = text.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        raise UpdateError(_("the release's SHA256SUMS can't be read")) from None
    for line in lines:
        if not line.strip():
            continue
        m = re.fullmatch(r"([0-9a-fA-F]{64}) [ *](.+)", line)
        if not m or not _plain(m[2]) or m[2] in sums:
            raise UpdateError(_("the release's SHA256SUMS can't be read"))
        sums[m[2]] = m[1].lower()
    return sums


def verify_sums(release: Release, key, timeout: float = 30) -> dict:
    """Download the release's SHA256SUMS and SHA256SUMS.sig (from wherever it came from), check
    the signature against OpenDisco's release key, and keep the list in release.sums."""
    github = release.origin == "github"
    sums = _small(f"{release.base}/{SUMS}", key, timeout, SUMS, github=github)
    raw = _small(f"{release.base}/{SIGNATURE}", key, timeout, SIGNATURE, 1024, github=github)
    try:
        signature = base64.b64decode(raw.strip(), validate=True)
        public = signing.public_key()
    except (ValueError, OSError):
        signature, public = b"", b""
    if not public or not signing.verify(public, sums, signature):
        raise UpdateError(_("the release's SHA256SUMS isn't signed with OpenDisco's release key, so nothing "
                            "was installed"))
    release.sums = parse_sums(sums)
    return release.sums


def prepare(release: Release, asset: Asset, key, timeout: float = 30):
    """Check the release's SHA256SUMS against its signature and OpenDisco's release key, and
    take the asset's SHA-256 from it. Returns the release's update key (checked against the
    list too), or None when it has none. A GitHub release need not carry its update-key file."""
    github = release.origin == "github"
    verify_sums(release, key, timeout)
    if asset.name not in release.sums:
        raise UpdateError(tr("{file} isn't in the release's signed SHA256SUMS, so it can't be checked",
                             file=asset.name))
    asset.sha256 = release.sums[asset.name]
    if updatekey.NAME not in release.sums or (github and updatekey.NAME not in release.assets):
        return None
    data = _small(f"{release.base}/{updatekey.NAME}", key, timeout, updatekey.NAME, 1024, github=github)
    if hashlib.sha256(data).hexdigest() != release.sums[updatekey.NAME]:
        raise UpdateError(tr("{file} doesn't match the release's signed SHA256SUMS, so nothing was installed",
                             file=updatekey.NAME))
    text = data.decode("ascii", "replace").strip()
    if not updatekey.valid(text):
        raise UpdateError(tr("the release's {file} isn't an update key", file=updatekey.NAME))
    return text


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
            return tr("OpenDisco is running from {folder}, which can't be changed (a disk image, or a download "
                      "macOS keeps apart). Move OpenDisco.app to the Applications folder, open it from there, and "
                      "update again", folder=target.parent)
    if kind in ("tarball", "appimage") and not (os.access(target, os.W_OK) and os.access(target.parent, os.W_OK)):
        return tr("this user can't change {path}", path=target)
    if kind == "windows" and not os.access(target, os.W_OK):
        return tr("this user can't change {path}", path=target)
    return ""


def _read_only(path: Path) -> bool:
    try:
        return bool(os.statvfs(path).f_flag & os.ST_RDONLY)
    except (OSError, AttributeError):
        return False


# -- downloading -------------------------------------------------------------------
def download(asset: Asset, folder: Path, key, progress=None, cancel=None, timeout: float = 30) -> Path:
    """Download an asset into folder and check its SHA-256 against the release's signed
    SHA256SUMS (prepare() first); only a file that matches is kept, under its own name.
    progress(done, total) is called as it goes; setting cancel (a threading.Event) stops it."""
    if not re.fullmatch(r"[0-9a-f]{64}", asset.sha256) or not _plain(asset.name):
        raise UpdateError(tr("{file} isn't in the release's signed SHA256SUMS, so it can't be checked",
                             file=asset.name))
    dest = Path(folder) / asset.name
    if dest.is_file() and _sha256(dest) == asset.sha256:  # downloaded and checked already
        if progress:
            progress(dest.stat().st_size, dest.stat().st_size)
        return dest
    part = dest.with_name(dest.name + ".part")
    digest, done, shown = hashlib.sha256(), 0, 0.0
    try:
        with _open(asset.url, key, timeout, asset.name, asset.origin == "github") as r, open(part, "wb") as f:
            total = asset.size or int(r.headers.get("Content-Length") or 0)
            limit = asset.size or (4 << 30)
            while True:
                if cancel is not None and cancel.is_set():
                    raise UpdateError("cancelled")
                chunk = r.read(1 << 16)
                if not chunk:
                    break
                done += len(chunk)
                if done > limit:
                    raise UpdateError(tr("{file} is larger than the release lists, so it wasn't used",
                                         file=asset.name))
                f.write(chunk)
                digest.update(chunk)
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
        raise UpdateError(tr("downloading {file} failed ({reason})", file=asset.name, reason=_reason(e))) from e
    if digest.hexdigest() != asset.sha256:
        part.unlink(missing_ok=True)
        raise UpdateError(tr("{file} doesn't match the release's signed SHA256SUMS (it's {found}…, not "
                             "{listed}…), so it wasn't used", file=asset.name, found=digest.hexdigest()[:16],
                             listed=asset.sha256[:16]))
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
    """Run a step of an install; what names it ("Copying the new app", translated) for its error."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout,
                           creationflags=CREATE_NO_WINDOW if core.IS_WINDOWS else 0)
    except (OSError, subprocess.SubprocessError) as e:
        raise UpdateError(tr("{what} failed ({error})", what=what, error=e)) from e
    out = "\n".join(l for l in (r.stdout + r.stderr).strip().splitlines() if "is deprecated" not in l)  # hdiutil's
    if out:
        log(out)
    if r.returncode:
        last = next((l.strip() for l in reversed(out.splitlines()) if l.strip()),
                    tr("exit code {code}", code=r.returncode))
        raise UpdateError(tr("{what} failed: {detail}", what=what, detail=last))
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
        sudo = _sudo(tr("Updating {app} needs an administrator password.", app=bundle), log)
    staged = bundle.with_name(f".{bundle.stem}-{version}.app")  # same folder, so the swap is a rename
    old = bundle.with_name(f".{bundle.stem}-replaced-{os.getpid()}.app")
    mount = Path(tempfile.mkdtemp(prefix="opendisco-dmg-"))
    try:
        _run(["hdiutil", "attach", "-quiet", "-nobrowse", "-readonly", "-noautoopen", "-mountpoint", str(mount), str(dmg)],
             _("Opening the disk image"), log, timeout=180)
        try:
            new = next((p for p in sorted(mount.glob("*.app")) if _bundle_info(p).get("CFBundleIdentifier") == APP_ID),
                       None)
            if new is None:
                raise UpdateError(tr("{file} holds no OpenDisco.app", file=dmg.name))
            found = _bundle_info(new).get("CFBundleShortVersionString")
            if found != version:
                raise UpdateError(tr("{file} holds OpenDisco {found}, not {version}", file=dmg.name, found=found,
                                     version=version))
            if staged.exists():
                _run(sudo + ["rm", "-rf", str(staged)], _("Clearing an earlier attempt"), log)
            log(f"Copying the new OpenDisco.app next to {bundle}")
            _run(sudo + ["ditto", str(new), str(staged)], _("Copying the new app"), log)
        finally:
            if _quiet(["hdiutil", "detach", str(mount), "-quiet"]):
                _quiet(["hdiutil", "detach", str(mount), "-quiet", "-force"])
    finally:
        try:
            mount.rmdir()
        except OSError:
            pass
    try:
        _run(["codesign", "--verify", "--deep", "--strict", str(staged)], _("Checking the new app's signature"), log)
        _run(sudo + ["mv", str(bundle), str(old)], tr("Moving {name} aside", name=bundle.name), log)
    except UpdateError:
        _quiet(sudo + ["rm", "-rf", str(staged)])
        raise
    try:
        _run(sudo + ["mv", str(staged), str(bundle)], _("Putting the new app in place"), log)
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
    sudo = _sudo(tr("Installing {file} needs an administrator password.", file=path.name), log)
    log(f"Installing {path.name} with {argv[2] if kind == 'deb' else argv[0]}")
    _run(sudo + argv, tr("Installing {file}", file=path.name), log)


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
                            raise UpdateError(tr("{file} holds an unsafe path ({path})", file=archive.name,
                                                 path=m.name))
                    tar.extractall(work)
        except (tarfile.TarError, OSError) as e:
            raise UpdateError(tr("unpacking {file} failed ({error})", file=archive.name, error=e)) from e
        tops = list(work.iterdir())
        new = tops[0] if len(tops) == 1 else None
        init = new / "src" / "opendisco" / "__init__.py" if new else None
        if not (init and init.is_file() and (new / "opendisco").is_file()):
            raise UpdateError(tr("{file} isn't OpenDisco's portable version", file=archive.name))
        found = re.search(r'__version__ = "([^"]+)"', init.read_text(encoding="utf-8"))
        if not found or found[1] != version:
            raise UpdateError(tr("{file} holds OpenDisco {found}, not {version}", file=archive.name,
                                 found=found[1] if found else "?", version=version))
        for item in folder.iterdir():
            if not (new / item.name).exists():
                if item.is_dir() and not item.is_symlink():
                    shutil.copytree(item, new / item.name, symlinks=True)
                else:
                    shutil.copy2(item, new / item.name, follow_symlinks=False)
        try:
            folder.rename(old)
        except OSError as e:
            raise UpdateError(tr("moving {path} aside failed ({error})", path=folder, error=e.strerror)) from e
        try:
            new.rename(folder)
        except OSError as e:
            old.rename(folder)
            raise UpdateError(tr("putting the new version in {path} failed ({error})", path=folder,
                                 error=e.strerror)) from e
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
        raise UpdateError(tr("{file} isn't an AppImage", file=image.name))
    new = target.with_name(f".{target.name}-update-{os.getpid()}")
    try:
        shutil.copyfile(image, new)
        new.chmod(0o755)
        new.replace(target)
    except OSError as e:
        new.unlink(missing_ok=True)
        raise UpdateError(tr("putting the new version in place of {path} failed ({error})", path=target,
                             error=e.strerror)) from e
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
