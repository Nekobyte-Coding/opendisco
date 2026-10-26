"""Firmware checks, firmware updates, config editing and login changes for one device, over SSH.

Each action is offered only for the device families whose steps are documented by Ubiquiti
(see FAMILY_NOTES); the GUI (devicegui) asks for the login and shows progress, and everything
here runs in a worker thread.

- Firmware checks ask Ubiquiti's public firmware server (fw-update.ubnt.com) for the latest
  release for the device's platform: UniFi gear is listed by board name ("platform"), airMAX,
  airFiber, EdgeRouter and the rest by product name.
- Updates download the release in the app, check its size and SHA-256, copy it to the device
  with scp and start the family's installer, then wait for the device to restart.
- airOS keeps its whole configuration in one file, /tmp/system.cfg: it's edited as text, saved
  to flash, or saved and applied in place the way the web UI's Apply does.
- A new login goes into the same file, its password hashed the way the device hashes the one
  it has now (airOS uses MD5-crypt), and only after that hash is checked against the current
  password. A factory password (FACTORY_LOGINS) isn't taken, and a device the User logs in to
  with a factory login is flagged (note_login).
- Config backups (every family but UniFi, whose controller keeps its config): the device's
  config file, kept in the app's data folder by MAC with the time it was taken, and uploaded
  again (Restore) only to the same model. airMAX, airFiber and LTU keep theirs in
  /tmp/system.cfg; EdgeRouters in /config/config.boot, which is loaded and committed through
  EdgeOS's own config commands.
- Reboot, Locate (the LED blinks: UniFi access points and switches only), and Scan from a
  device given by its address, for devices the app hasn't found itself (over a VPN).
"""
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from opendisco import core

if core.platform_name() in ("ios", "android"):  # no ssh program there: asyncssh, with the same calls
    from opendisco import phonessh as sshrun
else:
    from opendisco import sshrun
    if not sshrun.available():  # no ssh and scp (the AppImage or the portable version on a bare system)
        from opendisco import phonessh
        if phonessh.available():  # (the AppImage brings asyncssh, the portable version's setup installs it)
            sshrun = phonessh
OWN_SSH = sshrun.__name__ == "opendisco.phonessh"  # the app's own SSH client, not the system's ssh and scp

INDEX_URL = "https://fw-update.ubnt.com/api/firmware-latest"
INDEX_TTL = 1800  # seconds the firmware list is kept before asking again
USER_AGENT = "OpenDisco"

# airMAX firmware platforms: M (XM, XW, TI) and AC (XC, WA, 2XC, 2WA). Their firmware string starts
# with it ("XC.qca955x.v8.7.11...") and the firmware server lists it as the product.
AIROS_PLATFORMS = {"XM", "XW", "TI", "XC", "WA", "2XC", "2WA"}
UNIFI_OS_PRODUCTS = {"unifi-dream", "unifi-cloudkey", "unifi-nvr"}
FAMILY_NAMES = {"airos": "airOS", "unifi": "UniFi", "unifi-os": "UniFi OS", "edgeos": "EdgeOS"}

# How each family's firmware is installed over SSH, after the file is copied to `path`.
#  airos:    Ubiquiti's airOS scripts (the airOS SDK's /sbin/fwupdate and mca-fwupdate): -c checks
#            /tmp/fwupdate.bin, -m installs it while rebooting. The UISP Help Center gives the same
#            steps for EdgeSwitch XP, and Ubiquiti Community answers for airMAX.
#  unifi:    help.ui.com "UniFi - Advanced Updating Techniques", UniFi Access Point/Switch (No Internet).
#  unifi-os: the same article, UniFi Consoles/Gateways (No Internet), UniFi OS 2 and later.
UPDATE_STEPS = {
    "airos": {"path": "/tmp/fwupdate.bin", "check": "/sbin/fwupdate -c", "install": "/sbin/fwupdate -m"},
    "unifi": {"path": "/tmp/fwupdate.bin", "check": None, "install": "syswrapper.sh upgrade2"},
    "unifi-os": {"path": "/tmp/fwupdate.bin", "check": None, "install": "ubnt-systool fwupdate /tmp/fwupdate.bin"},
}
# airOS config (from the airOS SDK's /etc/profile and rc.softrestart): "save" is cfgmtd -w -p /etc/,
# which writes /tmp/system.cfg to flash; rc.softrestart save applies the changes it finds against
# /tmp/running.cfg (restarting only what it must) and then writes them to flash itself.
AIROS_CONFIG = "/tmp/system.cfg"
AIROS_RUNNING = "/tmp/running.cfg"
AIROS_SAVE = "cfgmtd -w -p /etc/"
AIROS_APPLY = "/usr/etc/rc.d/rc.softrestart save"
UPDATE_LOG = "/tmp/opendisco-update.log"
CONFIG_LOG = "/tmp/opendisco-config.log"
STAGED_CONFIG = "/tmp/system.cfg.opendisco"  # the new config arrives here first, then replaces it at once

# Config backups and uploads, by the kind of config file a family keeps (config_kind):
#  airos:  airMAX, as above.
#  isp:    airFiber (classic, 60 and 60 XG/HD), LTU and GigaBeam: the same /tmp/system.cfg, which
#          the UISP Help Center gives for all of them ("ISP Wireless - Reset Device to Factory
#          Default Settings": "cp /usr/etc/system.cfg /tmp/system.cfg; save; reboot" for airMAX,
#          airFiber and LTU). Save and Apply only where the device has airOS's cfgmtd and
#          rc.softrestart, checked on it first.
#  edgeos: EdgeRouter. It boots from /config/config.boot ("EdgeRouter - Archiving and Managing
#          the Configuration Files", UISP Help Center): Save writes that file, for the next boot;
#          Apply loads it, commits and saves (the article's configure; load; commit; save),
#          through vyatta-cfg-cmd-wrapper, EdgeOS's config commands for scripts, whose begin,
#          load, commit, save, discard and end map one to one onto them (Vyatta's
#          scripts/vyatta-cfg-cmd-wrapper and vyatta-load-config.pl).
CONFIG_FILES = {"airos": AIROS_CONFIG, "isp": AIROS_CONFIG, "edgeos": "/config/config.boot"}
CONFIG_NAMES = {"airos": "system.cfg", "isp": "system.cfg", "edgeos": "config.boot"}
# airFiber classic (AF24, AF5...), airFiber 60 (GP), airFiber 60 XG/HD (AF60), GigaBeam (GBE), by
# the platform their firmware string starts with; LTU by its platform or model name.
ISP_PLATFORMS = {"AF24", "AF24HD", "AF5", "AF5U", "AF5X", "AF2X", "AF3X", "AF4X", "AF11FX", "GP", "AF60", "GBE"}
EDGEOS_CONFIG = "/config/config.boot"
EDGEOS_STAGED = "/tmp/opendisco-config.boot"
EDGEOS_SCRIPT = "/tmp/opendisco-config.sh"
EDGEOS_WRAPPER = "/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper"
EDGEOS_MARK = "vyatta-config-version"  # EdgeOS's load asks at a terminal before loading a file without it
# Reboot, by family:
#  airos, isp: reboot (the UISP Help Center article above: "...; save; reboot").
#  edgeos:     sudo /sbin/reboot, which EdgeOS's own "reboot now" runs (vyatta-op's templates/reboot/now,
#              scripts/vyatta-reboot.pl); the admin login may use sudo without a password.
#  unifi:      syswrapper.sh restart, which the controller's restart runs (ubnt-systool reboot, in
#              UniFi's /usr/bin/syswrapper.sh; it does nothing while the device is busy upgrading).
#  unifi-os:   reboot (UniFi OS is Debian; the root login).
REBOOT = {"airos": "reboot", "isp": "reboot", "edgeos": "sudo -n /sbin/reboot", "unifi": "syswrapper.sh restart",
          "unifi-os": "reboot"}
REBOOT_LOG = "/tmp/opendisco-reboot-$(id -u).log"  # one per login: /tmp is shared, and a file of another's can't be replaced
# Locate: the LED blinks until it's stopped. Only UniFi access points and switches have a command
# for it that's known: syswrapper.sh set-locate / unset-locate, what the UniFi controller runs
# (UniFi's /usr/bin/syswrapper.sh), which also sets /proc/ubnthal/status/IsLocated (the
# "locating" its discovery replies report). airOS, EdgeOS and UniFi OS have none documented.
LOCATE = {"unifi": ("syswrapper.sh set-locate", "syswrapper.sh unset-locate")}
LOCATE_STATE = "/proc/ubnthal/status/IsLocated"
BACKUP_FOLDER = "config-backups"
BACKUP_ROOT = None  # the backups' folder: the GUI sets it to <its data folder>/config-backups
# The EdgeSwitch family (by its firmware platform), whose CLI isn't a shell: its config travels
# only through its web UI or a TFTP/FTP server ("EdgeSwitch & EdgeSwitch X - Backup and Restore
# the Configuration", UISP Help Center).
EDGESWITCH_PLATFORMS = {"eswh", "esgh", "esx", "esxp"}

# Why an action isn't offered for a family, as the menu shows it.
_NO_CONFIG = {"unifi": "set by its UniFi controller", "unifi-os": "UniFi OS: in its own settings",
              "edgeswitch": "EdgeSwitch: in its web UI", "": "not for this device"}
NOT_OFFERED = {
    "update": {"edgeos": "not for EdgeOS yet", "": "not for this device"},
    "config": dict(_NO_CONFIG, edgeos="not for EdgeOS here"),
    "edit": _NO_CONFIG, "backup": _NO_CONFIG, "upload": _NO_CONFIG,
    "login": {"unifi": "set by its UniFi controller", "unifi-os": "UniFi OS: in its own settings",
              "edgeos": "not for EdgeOS yet", "isp": "airMAX only", "": "not for this device"},
    "scan": {"": "not for this device"},
    "reboot": {"edgeswitch": "EdgeSwitch: in its web UI", "": "not for this device"},
    "locate": {"airos": "airOS has no LED command", "isp": "no LED command known",
               "edgeos": "EdgeOS has no LED command", "unifi-os": "UniFi OS: from its UniFi app",
               "": "not for this device"},
}
# Scan from device: every family's Linux has the kernel's ARP table; airOS lists the stations
# associated with it (wstalist, the web UI's station list, JSON); lldpd's lldpcli, where the
# device runs lldpd, lists its LLDP neighbours.
SCAN_FAMILIES = {"airos", "unifi", "unifi-os", "edgeos"}
SCAN_FILE = "/tmp/opendisco-scan.txt"
SCAN_HOW = {"stations": "its station list", "lldp": "its LLDP neighbours", "arp": "its ARP table"}
FROM_DEVICE = "from-device"


class ToolError(Exception):
    """Something the action can't do, said in terms of the device."""


class LostConnection(ToolError):
    """The connection broke while writing the config. outcome: "not done" (the device still has
    its earlier config) or "unknown" (the app couldn't reach it again to find out)."""

    def __init__(self, message: str, outcome: str):
        super().__init__(message)
        self.outcome = outcome


# ---------------------------------------------------------------------------
# Families
# ---------------------------------------------------------------------------

def family(d) -> str:
    """"airos", "unifi" (access points and switches), "unifi-os" (consoles), "edgeos", or ""
    for anything else (airFiber, LTU, UISP, other makers)."""
    raw = d.info.get("firmware") or ""
    platform = d.fw_platform
    if platform.upper() in AIROS_PLATFORMS:
        return "airos"
    if d.console:
        return "unifi-os"
    if re.fullmatch(r"(?i)e\d{2,4}", platform):
        return "edgeos"
    if re.match(r"(BZ|US|USW)\.", raw):  # BZ.qca956x.v6.5.28..., BZ.mt7621_5.60.1+12923..., US.bcm5334x...
        return "unifi"
    return ""


def config_kind(d) -> str:
    """The kind of config file it keeps (CONFIG_FILES): "airos", "isp" (airFiber, LTU,
    GigaBeam), "edgeos", or "" for none the app can back up (UniFi's is its controller's)."""
    fam = family(d)
    if fam in ("airos", "edgeos"):
        return fam
    if fam:
        return ""
    if d.fw_platform.upper() in ISP_PLATFORMS or re.match(
            r"(?i)ltu", d.fw_platform or d.info.get("platform") or d.model or ""):
        return "isp"
    return ""


def _kind(d) -> str:
    """The family an action's reason is looked up by: family(), else "isp" or "edgeswitch"."""
    fam = family(d)
    if fam:
        return fam
    if config_kind(d) == "isp":
        return "isp"
    return "edgeswitch" if d.fw_platform in EDGESWITCH_PLATFORMS else ""


def offers(d, action: str) -> tuple:
    """(offered, why not) for "update", "config" (the airOS editor: system.cfg), "edit" (the
    config editor for every kind), "backup", "upload", "login", "scan", "reboot" or "locate"."""
    fam, kind = family(d), config_kind(d)
    if action == "update":
        ok = fam in UPDATE_STEPS
    elif action == "scan":
        ok = fam in SCAN_FAMILIES
    elif action == "config":
        ok = kind in ("airos", "isp")
    elif action in ("edit", "backup", "upload"):
        ok = bool(kind)
    elif action == "reboot":
        ok = (kind or fam) in REBOOT
    elif action == "locate":
        ok = fam in LOCATE
    else:
        ok = fam == "airos"
    return ok, "" if ok else NOT_OFFERED[action].get(_kind(d), NOT_OFFERED[action][""])


# ---------------------------------------------------------------------------
# Versions
# ---------------------------------------------------------------------------

def device_version(d) -> str:
    """The version a device runs, from its firmware string: "8.7.11" from
    XC.qca955x.v8.7.11.46972..., "2.0.9-hotfix.7" from e50.v2.0.9-hotfix.7..., "5.60.1" from
    BZ.mt7621_5.60.1+12923..., or a plain "5.2.10"."""
    raw = d.info.get("firmware") or ""
    version = r"(\d+\.\d+(?:\.\d+)?)"  # what follows is the build number and date
    m = (re.search(rf"\.v{version}(-hotfix\.\d+)?", raw) or re.search(rf"_{version}", raw)
         or re.match(rf"v?{version}", raw) or re.match(rf"v?{version}", d.firmware or ""))
    return "".join(g for g in m.groups() if g) if m else ""


def release_version(item: dict) -> str:
    """"8.7.25" from v8.7.25, "6.8.2" from v6.8.2+15592, "2.0.9-hotfix.2" as it is."""
    return re.sub(r"\+.*$", "", str(item.get("version", "")).lstrip("v"))


def version_key(text: str) -> tuple:
    m = re.match(r"v?(\d+(?:\.\d+)*)(?:-hotfix\.(\d+))?", text or "")
    if not m:
        return ()
    numbers = [int(n) for n in m.group(1).split(".")]
    numbers += [0] * (4 - len(numbers))
    return tuple(numbers) + (int(m.group(2) or 0),)


# ---------------------------------------------------------------------------
# Ubiquiti's firmware server
# ---------------------------------------------------------------------------

_INDEX = None  # (when fetched, items)
_CONTEXT = None


def https_context() -> ssl.SSLContext:
    """Certificates checked as usual. A Python without its own CA list on macOS gets the system's;
    phones get tls.context()'s (Android's own roots, certifi's on iOS)."""
    global _CONTEXT
    if _CONTEXT is None and core.platform_name() in ("ios", "android"):
        from opendisco import tls
        _CONTEXT = tls.context()
    if _CONTEXT is None:
        ctx = ssl.create_default_context()
        if not ctx.cert_store_stats().get("x509_ca") and sys.platform == "darwin":
            try:
                pem = subprocess.run(["security", "find-certificate", "-a", "-p",
                                      "/System/Library/Keychains/SystemRootCertificates.keychain"],
                                     capture_output=True, text=True, timeout=20).stdout
                if pem:
                    ctx.load_verify_locations(cadata=pem)
            except (OSError, subprocess.SubprocessError, ssl.SSLError):
                pass
        _CONTEXT = ctx
    return _CONTEXT


def _open(url: str, timeout: float = 30):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    return urllib.request.urlopen(request, timeout=timeout, context=https_context() if url.startswith("https:") else None)


def firmware_index(refresh: bool = False) -> list:
    """Every product's latest firmware, as the firmware server lists it (one request, kept a while)."""
    global _INDEX
    if _INDEX and not refresh and time.time() - _INDEX[0] < INDEX_TTL:
        return _INDEX[1]
    try:
        with _open(INDEX_URL) as reply:
            items = json.loads(reply.read().decode("utf-8"))["_embedded"]["firmware"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise ToolError(f"Ubiquiti's firmware server didn't answer ({_reason(e)}).") from None
    _INDEX = (time.time(), [i for i in items if isinstance(i, dict)])
    return _INDEX[1]


def _reason(e) -> str:
    reason = getattr(e, "reason", None) or e
    return str(getattr(reason, "strerror", None) or reason)


def find_release(d, items: list) -> dict | None:
    """The latest release for the device: by board name (UniFi) or product name (the rest),
    exactly first and then ignoring case. Customer-specific builds (-cs) and other variants are
    skipped unless the device runs one."""
    raw = (d.info.get("firmware") or "").lower()
    names = list(dict.fromkeys(n for n in (d.fw_platform, d.info.get("platform") or "") if n))

    def usable(item) -> bool:
        if item.get("channel") != "release" or not item.get("_links", {}).get("data", {}).get("href"):
            return False
        variant = re.search(r"-([a-z]+)", str(item.get("version", "")).lower())
        return not variant or variant.group(1) == "hotfix" or variant.group(1) in raw

    for fold in (False, True):
        for name in names:
            wanted = name.lower() if fold else name
            found = [i for i in items if usable(i) and wanted in
                     ((str(i.get("platform", "")).lower(), str(i.get("product", "")).lower()) if fold
                      else (i.get("platform"), i.get("product")))]
            if found:
                return max(found, key=lambda i: version_key(release_version(i)))
    return None


@dataclass
class Check:
    current: str  # the version it runs ("" if unknown)
    release: dict | None  # the latest release the server lists for it
    platform: str

    @property
    def latest(self) -> str:
        return release_version(self.release) if self.release else ""

    @property
    def newer(self) -> bool:
        return bool(self.release and self.current and version_key(self.latest) > version_key(self.current))

    @property
    def date(self) -> str:
        return str((self.release or {}).get("created", ""))[:10]

    @property
    def size(self) -> int:
        return int((self.release or {}).get("file_size") or 0)


def check_firmware(d, refresh: bool = False) -> Check:
    items = firmware_index(refresh)
    return Check(device_version(d), find_release(d, items), d.fw_platform or d.info.get("platform") or "")


def cve_issues(d) -> list:
    """The device's known vulnerabilities, as the CVE check lists them in its issues."""
    return [message for _level, tag, message in d.issues if str(tag).upper().startswith("CVE")]


def summary(d, check: Check) -> str:
    """What the firmware check found, in a sentence or three."""
    what = check.platform or "this device"
    if not check.release:
        text = f"Ubiquiti's firmware server lists no release for {what}."
    elif not check.current:
        text = f"The latest release for {what} is {check.latest} ({check.date}); the version it runs is unknown."
    elif check.newer:
        text = (f"Firmware {check.latest} is out for {what} (released {check.date}, {fmt_size(check.size)}); "
                f"it runs {check.current}.")
    else:
        text = f"Up to date: it runs {check.current}; the latest release for {what} is {check.latest} ({check.date})."
    cves = cve_issues(d)
    if cves:
        text += (f"\n\nKnown vulnerabilities in {check.current or 'its firmware'}: {len(cves)}. "
                 + ("Updating to " + check.latest + " is advised." if check.newer else
                    "No newer release is listed yet.")
                 + "\n" + "\n".join(f"- {c}" for c in cves[:8]) + ("\n- …" if len(cves) > 8 else ""))
    return text


def fmt_size(size: int) -> str:
    return f"{size / 1e9:.2f} GB" if size >= 1e9 else f"{size / 1e6:.1f} MB"


def fits(d, release: dict) -> str:
    """Why this release can't be installed by the app on this device ("" when it can)."""
    fam = family(d)
    product, platform = str(release.get("product", "")), str(release.get("platform", ""))
    if fam == "airos" and not (product.upper() in AIROS_PLATFORMS and platform == "airmax"):
        return "The release found isn't airMAX firmware."
    if fam == "unifi":
        if product != "unifi-firmware":
            return "The release found isn't for a UniFi access point or switch."
        if platform == "USMULT" or platform.startswith("UGW"):
            return f"{platform} firmware needs extra steps the app doesn't do."
    if fam == "unifi-os":
        if product not in UNIFI_OS_PRODUCTS:
            return "The release found isn't UniFi OS firmware."
        if version_key(device_version(d))[:1] < (2,):
            return "UniFi OS 1.x installs differently: update it in its own settings first."
    return ""


# ---------------------------------------------------------------------------
# Downloading
# ---------------------------------------------------------------------------

def download_release(release: dict, folder: Path, progress=None, stop=None) -> Path:
    """Download a release into folder (reused when it's there already), checking its size and
    SHA-256 against what the firmware server says. progress(bytes so far, total)."""
    url = release["_links"]["data"]["href"]
    want = str(release.get("sha256_checksum") or "").lower()
    size = int(release.get("file_size") or 0)
    if not re.fullmatch(r"[0-9a-f]{64}", want):
        raise ToolError("The firmware server gives no SHA-256 for this release, so it can't be checked.")
    folder.mkdir(parents=True, exist_ok=True)
    name = re.sub(r"[^A-Za-z0-9._+-]", "_", url.rsplit("/", 1)[-1]) or "firmware.bin"
    path = folder / f"{want[:12]}-{name}"
    for old in folder.iterdir():  # other devices may be using theirs: only old leftovers go
        try:
            if old != path and time.time() - old.stat().st_mtime > 2 * 86400:
                old.unlink()
        except OSError:
            pass
    if path.exists() and path.stat().st_size == size and _sha256(path) == want:
        if progress:
            progress(size, size)
        return path
    part = path.with_suffix(path.suffix + ".part")
    digest, done = hashlib.sha256(), 0
    try:
        with _open(url, timeout=60) as reply, open(part, "wb") as out:
            total = int(reply.headers.get("Content-Length") or size or 0)
            while True:
                if stop is not None and stop.is_set():
                    raise ToolError("Cancelled.")
                chunk = reply.read(1 << 20)
                if not chunk:
                    break
                out.write(chunk)
                digest.update(chunk)
                done += len(chunk)
                if progress:
                    progress(done, total)
    except OSError as e:
        part.unlink(missing_ok=True)
        raise ToolError(f"Downloading the firmware failed ({_reason(e)}).") from None
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    if size and done != size:
        part.unlink(missing_ok=True)
        raise ToolError(f"The download is {done:,} bytes, not the {size:,} the firmware server lists.")
    if digest.hexdigest() != want:
        part.unlink(missing_ok=True)
        raise ToolError("The download's SHA-256 doesn't match the firmware server's: it was damaged on the way.")
    os.replace(part, path)
    return path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _md5(path: Path) -> str:
    digest = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Installing
# ---------------------------------------------------------------------------

def detached(command: str, log: str, run: str = "") -> str:
    """Run a command on the device so it carries on when the SSH session ends (it ignores the
    hang-up), its output and exit code going to a log file there. With run, the log first
    names that run, before the command starts: a log without it means the command never
    arrived."""
    body = f"sh -c 'trap \"\" HUP; {command}; echo \"opendisco-exit=$?\"' </dev/null"
    if run:
        return f"echo opendisco-run={run} >{log}; {body} >>{log} 2>&1 &"
    return f"rm -f {log}; {body} >{log} 2>&1 &"


def install_firmware(d, login: sshrun.Login, path: Path, report, stop=None) -> float:
    """Copy the firmware to the device, check it there and start the installer, then wait for
    the device to go down and come back. report(text, percent or None). Returns the seconds it
    was offline."""
    steps = UPDATE_STEPS[family(d)]
    target = steps["path"]
    report("Making room on the device…", None)
    sshrun.run(login, f"rm -f {target}", stop=stop)
    report(f"Copying the firmware to {target}…", 0)
    sshrun.upload(login, path, target, progress=lambda p: report(None, p), stop=stop)

    report("Checking the copy on the device…", None)
    copied = _said_md5(sshrun.run(login, _ARRIVED.format(path=target), stop=stop).out)
    if copied and copied != _md5(path):
        sshrun.run(login, f"rm -f {target}", stop=stop)
        raise ToolError("The copy on the device doesn't match the download: it was damaged on the way.")
    if steps["check"]:
        result = sshrun.run(login, steps["check"], timeout=120, stop=stop)
        if result.code:
            sshrun.run(login, f"rm -f {target}", stop=stop)
            said = _said(result)
            raise ToolError("The device rejected the firmware file" + (f": {said}" if said else "."))
    upgrade_time = 0
    if family(d) == "airos":
        result = sshrun.run(login, "sed -n 's/^board.upgrade=//p' /etc/board.info 2>/dev/null", stop=stop)
        upgrade_time = int(result.out.strip()) if result.out.strip().isdigit() else 0

    if stop is not None and stop.is_set():
        raise ToolError("Cancelled.")
    report("Starting the installation. The device restarts on its own: don't unplug it.", None)
    sshrun.run(login, detached(steps["install"], UPDATE_LOG), timeout=60)
    went_down = wait_for(login.ip, login.port, up=False, within=300, report=report,
                         what="Installing: waiting for the device to restart…")
    if not went_down:
        said = ""
        try:
            said = sshrun.run(login, f"cat {UPDATE_LOG}").out.strip()
        except sshrun.SSHError:
            pass
        said = re.sub(r"opendisco-exit=\d+\s*", "", said).strip()
        raise ToolError("The device didn't restart, so the firmware wasn't installed"
                        + (f". It said: {said}" if said else "."))
    started = time.monotonic()
    within = max(900, upgrade_time * 3)
    if not wait_for(login.ip, login.port, up=True, within=within, report=report,
                    what="Installing: the device is offline while it writes the firmware…"):
        raise ToolError(f"The device hasn't come back after {within // 60} minutes. It may still be installing: "
                        "give it a few more minutes before power-cycling it.")
    return time.monotonic() - started


def _said(result: sshrun.Result) -> str:
    lines = [l.strip() for l in (result.out + "\n" + result.err).splitlines()
             if l.strip() and "password" not in l.lower() and not l.startswith("Warning: Permanently added")]
    return " ".join(lines)[-300:]


def answers(ip: str, port: int, timeout: float = 3) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_for(ip: str, port: int, up: bool, within: float, report=None, what: str = "", stop=None) -> bool:
    """Wait until SSH answers (up) or stops answering (not up) on the device, for up to `within`
    seconds."""
    start = time.monotonic()
    while time.monotonic() - start < within:
        if stop is not None and stop.is_set():
            return False
        if answers(ip, port) == up:
            return True
        if report:
            report(f"{what} {time.monotonic() - start:.0f}s", None)
        time.sleep(3)
    return False


# ---------------------------------------------------------------------------
# airOS config
# ---------------------------------------------------------------------------

def _fetch(login: sshrun.Login, path: str, stop=None) -> str:
    folder = Path(tempfile.mkdtemp(prefix="opendisco-"))
    try:
        local = folder / "config"
        sshrun.download(login, path, local, stop=stop)
        return local.read_bytes().decode("utf-8", "replace")
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def read_config(login: sshrun.Login, stop=None) -> tuple:
    """(the working config /tmp/system.cfg, whether it has changes not applied yet)."""
    config = _fetch(login, AIROS_CONFIG, stop)
    try:
        running = _fetch(login, AIROS_RUNNING, stop)
    except sshrun.SSHError:
        running = None
    return config, running is not None and _lines(running) != _lines(config)


def _lines(text: str) -> list:
    return sorted(l for l in text.replace("\r", "").split("\n") if l.strip())


def config_problems(text: str, kind: str = "airos") -> list:
    """What the device wouldn't read: for airOS (and airFiber, LTU), lines that aren't
    key=value; for EdgeOS, braces that don't pair up, or no version line (its load would ask
    at a terminal whether to go on)."""
    if kind == "edgeos":
        problems, depth = [], 0
        body = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        for n, line in enumerate(body.replace("\r", "").split("\n"), 1):
            unquoted = re.sub(r'"(?:[^"\\]|\\.)*"', '""', line)
            depth += unquoted.count("{") - unquoted.count("}")
            if depth < 0:
                problems.append(f"line {n}: a }} with no {{ before it")
                depth = 0
        if depth:
            problems.append(f"{depth} {{ without a }} to close it")
        if not body.strip():
            problems.append("it's empty")
        if EDGEOS_MARK not in text:
            problems.append(f"no {EDGEOS_MARK} line at the end, which every config EdgeOS saves has")
        return problems
    return [f"line {n}: {line[:60]}" for n, line in enumerate(text.replace("\r", "").split("\n"), 1)
            if line.strip() and not re.match(r"[A-Za-z0-9_.-]+=", line)]


def lines_changed(old: str, new: str) -> int:
    """How many lines differ between two configs: an edited line counts once (not as one line
    taken out and one put in), as do one added and one removed."""
    import difflib
    a, b = old.replace("\r", "").splitlines(), new.replace("\r", "").splitlines()
    return sum(max(i2 - i1, j2 - j1) for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False)
               .get_opcodes() if tag != "equal")


def write_config(login: sshrun.Login, text: str, apply: bool, report=None, stop=None,
                 new_login: sshrun.Login | None = None, confirm_within: float = 240, check_tools: bool = False) -> str:
    """Write the config and save it to flash; with apply, apply it in place too (rc.softrestart
    save, which saves it as well). new_login: the login the config sets, which replaces `login`
    once it's applied. check_tools: first make sure the device has airOS's cfgmtd (and
    rc.softrestart to apply), for airFiber and LTU. Returns what happened.

    It's done so a broken connection can't leave the device half-changed, and the app can say
    exactly what happened: the config goes to a file of its own and is checked there (a break
    here: nothing changed); then one command on the device moves it into place and saves or
    applies it, detached from the session, logging the outcome (a break here: the device
    finishes on its own, and the app reconnects to read how it went). LostConnection when it
    can't tell, or when the config never got there."""
    text = _unix(text)
    what = "applied" if apply else "saved"
    say = report or (lambda message: None)
    untouched = f"Connection lost: config not {what}. It didn't reach the device, which still has its earlier config."
    if check_tools:
        tools = config_tools(login, "isp", stop)
        if not tools["apply" if apply else "save"]:
            raise ToolError(tools["why"])
    if apply:
        try:
            running = _fetch(login, AIROS_RUNNING, stop)
            stored = _fetch(login, AIROS_CONFIG, stop) if _lines(running) == _lines(text) else ""
        except sshrun.SSHError as e:
            if e.kind in ("auth", "key", "cancelled"):
                raise
            raise LostConnection(f"{untouched} ({e})", "not done") from None
        # Both: a config saved to flash but not applied (Save) is what the next reboot runs.
        if _lines(running) == _lines(text) and _lines(stored) == _lines(text):
            return "Nothing to apply: the device already runs this config."
    # It runs this config already, but has another saved: saving it is all there is to do (airOS's
    # rc.softrestart save does nothing at all when the saved config matches the running one).
    runs_it = apply and _lines(running) == _lines(text)

    say("Copying the config to the device…")
    _stage(login, [(text, STAGED_CONFIG)], what, untouched, stop)
    say("Applying it: the device restarts the services the change affects…" if apply else "Saving it to flash…")
    # Detached: applying can restart SSH itself, which would end a command run in the session.
    code, said, sent, dropped = _run_staged(
        login, f"mv -f {STAGED_CONFIG} {AIROS_CONFIG} && " + (AIROS_APPLY if apply and not runs_it else AIROS_SAVE),
        STAGED_CONFIG, what, apply, [new_login, login] if new_login else [login], confirm_within, stop, say)
    if code:
        raise ToolError(("Applying" if apply else "Saving") + " failed" + (f": {said[-300:]}" if said else "."))
    done = ("It already ran this config: saved to flash, so it runs it after a reboot too." if runs_it
            else "Applied and saved to flash." if apply else "Saved to flash. It takes effect at the next reboot.")
    if not sent or (dropped and not apply):  # applying restarts SSH: drops then are expected
        done += " The connection dropped meanwhile: the device finished on its own, checked after reconnecting."
    return done


def _unix(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text if text.endswith("\n") else text + "\n"


def _stage(login: sshrun.Login, files: list, what: str, untouched: str, stop=None) -> None:
    """Copy each (text, path on the device) there and check it arrived whole; a break here
    leaves the device as it was (LostConnection "not done")."""
    folder = Path(tempfile.mkdtemp(prefix="opendisco-"))
    try:
        for n, (text, path) in enumerate(files):
            local = folder / f"file{n}"
            local.write_bytes(text.encode("utf-8"))
            sshrun.upload(login, local, path, stop=stop)
            arrived = sshrun.run(login, _ARRIVED.format(path=path), stop=stop).out
            if not _arrived_whole(arrived, local):
                sshrun.run(login, "rm -f " + " ".join(p for _t, p in files), stop=stop)
                raise ToolError(f"The config arrived damaged, so it wasn't {what}; the device still has its earlier one.")
    except sshrun.SSHError as e:
        if e.kind in ("auth", "key", "cancelled"):
            raise
        raise LostConnection(f"{untouched} ({e})", "not done") from None
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def _run_staged(login: sshrun.Login, command: str, staged: str, what: str, apply: bool, logins: list,
                within: float, stop, say) -> tuple:
    """Start the command that takes the staged file, detached, and read how it went (reconnecting
    as needed). Returns (exit code, what it said, whether the start went through, whether the
    connection dropped); LostConnection when it never started or the app can't tell."""
    run = secrets.token_hex(6)
    sent = True
    try:
        sshrun.run(login, detached(command, CONFIG_LOG, run), timeout=60, stop=stop)
    except sshrun.SSHError as e:
        if e.kind in ("auth", "key"):
            raise
        sent = False  # it may or may not have got there
        say(f"Connection lost while starting it ({e}). Reconnecting to find out what the device did…")
    state, code, said, dropped = _confirm(logins, run, within, stop, say, staged)
    if state == "done":
        return code, said, sent, dropped
    if state == "not started":
        try:
            sshrun.run(login, f"rm -f {staged}", stop=stop)
        except sshrun.SSHError:
            pass
        raise LostConnection(f"Connection lost before the device got the command: config not {what}. It still has "
                             "its earlier config.", "not done")
    if not sent:
        raise LostConnection(f"Connection lost: the app can't tell whether the config was {what}, as it couldn't "
                             "reach the device again. Reload the config once the device answers to see.", "unknown")
    raise LostConnection(f"Connection lost after the device started {'applying' if apply else 'saving'} it. It "
                         "finishes on its own, but the app couldn't reach it again to confirm. Reload the config once "
                         "it answers." + (" If the change moved its address, VLAN or SSH port, that's expected."
                                         if apply else ""), "unknown")


# A file's MD5 and size as the device sees it, each after a marker: on Windows the output comes
# through the console, mixed with ssh's password prompt, and its lines can run together.
_ARRIVED = "echo md5=$(md5sum < {path} 2>/dev/null); echo size=$(wc -c < {path})"


def _said_md5(said: str) -> str:
    m = re.search(r"md5=([0-9a-f]{32})", said)
    return m.group(1) if m else ""


def _arrived_whole(said: str, local: Path) -> bool:
    """The MD5 and size the device reports (_ARRIVED) match the file sent (no md5sum there:
    the size alone)."""
    copied, size = _said_md5(said), re.search(r"size=\s*(\d+)", said)
    if copied and copied != _md5(local):
        return False
    return bool(size) and int(size.group(1)) == local.stat().st_size


def _confirm(logins, run: str, within: float, stop, say, staged: str = STAGED_CONFIG) -> tuple:
    """Read the outcome of a detached config command from its log, reconnecting as needed (the
    new login works once it's applied, the old one until then). Returns (state, exit code, what
    it said, whether a reconnect was needed): "done", "not started" (the log doesn't name the
    run, or names it but the config was never moved into place), or "unknown"."""
    start, dropped, first = time.monotonic(), False, True
    while time.monotonic() - start < within:
        time.sleep(1 if first else 3)
        first = False
        out = None
        for attempt in logins:
            try:
                out = sshrun.run(attempt, f"cat {CONFIG_LOG} 2>/dev/null; test -e {staged} && echo "
                                          "opendisco-staged", timeout=30, stop=stop).out
                break
            except sshrun.SSHError as e:
                if e.kind in ("key", "cancelled") or (e.kind == "auth" and len(logins) == 1):
                    raise
        if out is None:
            dropped = True
            say(f"Reconnecting to find out what the device did… {time.monotonic() - start:.0f}s")
            continue
        if f"opendisco-run={run}" not in out:
            return "not started", None, "", dropped
        m = re.search(r"opendisco-exit=(\d+)", out)
        if m:
            said = re.sub(r"opendisco-(run|exit)=\w+\s*|opendisco-staged\s*", "", out).strip()
            return "done", int(m.group(1)), said, dropped
        if "opendisco-staged" in out and time.monotonic() - start > 15:
            return "not started", None, "", dropped  # it never got as far as moving the config into place
    return "unknown", None, "", dropped


# ---------------------------------------------------------------------------
# Config backups and uploads: airMAX, airFiber, LTU, EdgeOS
# ---------------------------------------------------------------------------

def config_tools(login: sshrun.Login, kind: str, stop=None) -> dict:
    """What the device can do with a new config: {"save": bool, "apply": bool, "why": what's
    missing}. airMAX has both (the airOS SDK); airFiber and LTU are asked for airOS's cfgmtd
    and rc.softrestart; EdgeOS for its config commands, and a login in their vyattacfg group."""
    if kind == "airos":
        return {"save": True, "apply": True, "why": ""}
    if kind == "isp":
        out = sshrun.run(login, "command -v cfgmtd >/dev/null && echo has-save; "
                                f"test -x {AIROS_APPLY.split()[0]} && echo has-apply", stop=stop).out
        save, apply = "has-save" in out, "has-apply" in out
        why = ("" if save and apply else "It has no cfgmtd, so the app can't save a config to its flash." if not save
               else "It has no rc.softrestart to apply a config in place: Save it, then Reboot it.")
        return {"save": save, "apply": save and apply, "why": why}
    if kind == "edgeos":
        out = sshrun.run(login, f"test -x {EDGEOS_WRAPPER} && echo has-wrapper; id -Gn", stop=stop).out
        if "has-wrapper" not in out:
            return {"save": False, "apply": False, "why": f"It has no {EDGEOS_WRAPPER}: it doesn't look like EdgeOS."}
        groups = out.replace("has-wrapper", "").split()
        if "vyattacfg" not in groups and "root" not in groups:
            return {"save": False, "apply": False,
                    "why": f"The login {login.user} isn't in EdgeOS's vyattacfg group, which changing the config "
                           "needs (an admin login is)."}
        return {"save": True, "apply": True, "why": ""}
    return {"save": False, "apply": False, "why": "The app can't write this device's config."}


def read_device_config(login: sshrun.Login, kind: str, stop=None) -> tuple:
    """(its config, whether it has changes not applied yet): airOS's working config
    /tmp/system.cfg; EdgeOS's boot config /config/config.boot (changes committed since without
    saving aren't in it)."""
    if kind in ("airos", "isp"):
        return read_config(login, stop)
    if kind == "edgeos":
        return _fetch(login, EDGEOS_CONFIG, stop), False
    raise ToolError("The app can't read this device's config.")


def push_config(login: sshrun.Login, kind: str, text: str, apply: bool, report=None, stop=None) -> str:
    """Save the config (it takes effect at the next boot) or apply it now too. Returns what
    happened; ToolError, LostConnection or SSHError when it didn't."""
    if kind in ("airos", "isp"):
        return write_config(login, text, apply, report, stop, check_tools=kind == "isp")
    if kind == "edgeos":
        return write_edgeos(login, text, apply, report, stop)
    raise ToolError("The app can't write this device's config.")


def edgeos_script(apply: bool) -> str:
    """The script that takes the staged config.boot on an EdgeRouter. Apply: begin; load; commit;
    save; end, as EdgeOS's configure, load, commit and save do. Save: the same load, only to
    check EdgeOS reads it, then discard; the file becomes /config/config.boot, which the next
    boot loads. Exit codes: 3 no staged file, 4 no config session, 5 load failed, 6 commit
    failed, 7 saving failed, 8 writing config.boot failed."""
    if apply:
        act = ('  if grep -q "No configuration changes to commit" "$OUT"; then echo "opendisco: nothing to commit"\n'
               '  elif ! $W commit; then rc=6; echo "commit failed:"; tail -n 20 /var/log/vyatta/vyatta-commit.log; fi\n'
               '  [ $rc = 0 ] && { $W save || rc=7; }\n'
               'fi\n'
               '[ $rc = 0 ] || $W discard\n'
               '$W end\n')
    else:
        act = ('  :  # only checked: nothing is committed\n'
               'fi\n'
               '$W discard >/dev/null\n'
               '$W end\n'
               f'[ $rc = 0 ] && {{ cat "$F.run" > {EDGEOS_CONFIG} || rc=8; }}\n')
    return ("#!/bin/sh\n"
            f"# OpenDisco: {'loads, commits and saves' if apply else 'checks, then saves for the next boot,'} "
            f"the config in {EDGEOS_STAGED}.\n"
            "# EdgeOS's config commands run in its vyattacfg group, as its own scripts do.\n"
            'if [ "$1" != in-group ] && [ "$(id -u)" != 0 ] && [ "$(id -gn)" != vyattacfg ] '
            "&& command -v sg >/dev/null; then\n"
            f'  exec sg vyattacfg -c "sh {EDGEOS_SCRIPT} in-group"\n'
            "fi\n"
            f"W={EDGEOS_WRAPPER}\n"
            f"F={EDGEOS_STAGED}\n"
            "OUT=/tmp/opendisco-load.out\n"
            'mv -f "$F" "$F.run" || exit 3\n'
            'cp "$F.run" "$F.load" || exit 3  # load migrates the file it loads in place\n'
            'trap \'rm -f "$F.run" "$F.load" "$OUT"\' EXIT\n'
            '$W begin || { echo "EdgeOS did not start a config session."; exit 4; }\n'
            '$W load "$F.load" >"$OUT" 2>&1\n'
            "rc=$?\n"
            'cat "$OUT"\n'
            '[ $rc = 0 ] && grep -qiE "fail|error|invalid|warning|cannot" "$OUT" && rc=5\n'
            "if [ $rc = 0 ]; then\n" + act +
            "exit $rc\n")


EDGEOS_FAILURES = {
    3: "The config didn't arrive in place, so nothing was changed.",
    4: "EdgeOS didn't start a config session, so nothing was changed",
    5: "EdgeOS didn't load it, so nothing was changed",
    6: "EdgeOS loaded it, but the commit failed. Parts of it may be active now; its boot config is unchanged, so a "
       "reboot returns to that",
    7: "It's applied, but saving it to the boot config failed: it runs the new config only until the next reboot",
    8: f"EdgeOS reads it, but writing {EDGEOS_CONFIG} failed, so nothing was changed",
}


def boot_lines(text: str) -> list:
    """config.boot's lines without comments, quotes or indentation, to compare two of them."""
    body = re.sub(r"/\*.*?\*/", "", text.replace("\r", ""), flags=re.S)
    return [l.strip().replace('"', "") for l in body.split("\n") if l.strip()]


def write_edgeos(login: sshrun.Login, text: str, apply: bool, report=None, stop=None,
                 confirm_within: float = 300) -> str:
    """Save an EdgeRouter's config for the next boot, or load, commit and save it now. Staged and
    run detached like write_config, so a dropped connection (a commit can restart SSH) leaves
    the device finishing on its own, and the app reconnects to read how it went."""
    text = _unix(text)
    problems = config_problems(text, "edgeos")
    if problems:
        raise ToolError("It isn't a config EdgeOS reads: " + "; ".join(problems[:5]) + ".")
    what = "applied" if apply else "saved"
    say = report or (lambda message: None)
    untouched = f"Connection lost: config not {what}. It didn't reach the device, which still has its earlier config."
    tools = config_tools(login, "edgeos", stop)
    if not tools["apply"]:
        raise ToolError(tools["why"])
    say("Copying the config to the device…")
    _stage(login, [(edgeos_script(apply), EDGEOS_SCRIPT), (text, EDGEOS_STAGED)], what, untouched, stop)
    say("Loading and committing it: EdgeOS restarts what the change affects…" if apply
        else "Checking that EdgeOS reads it, then saving it as the boot config…")
    code, said, sent, dropped = _run_staged(login, f"sh {EDGEOS_SCRIPT}", EDGEOS_STAGED, what, apply, [login],
                                            confirm_within, stop, say)
    nothing = "opendisco: nothing to commit" in said
    said = "\n".join(l for l in said.split("\n") if not l.startswith("opendisco:")).strip()
    if code:
        raise ToolError(EDGEOS_FAILURES.get(code, f"It failed (exit code {code})")
                        + (f". EdgeOS said: {said[-400:]}" if said and code != 3 else "."))
    try:
        stored = _fetch(login, EDGEOS_CONFIG, stop)
    except sshrun.SSHError:
        stored = None
    if apply and nothing:
        done = "It already runs this config: saved as its boot config too."
    elif apply:
        done = "Loaded, committed and saved: it runs the new config, and boots with it."
    else:
        done = (f"Checked (EdgeOS reads it) and saved as {EDGEOS_CONFIG}: it takes effect at the next reboot. Until "
                "then, any other change saved on it (web UI, CLI, UISP) replaces it.")
    if stored is None:
        done += f" The app couldn't read {EDGEOS_CONFIG} back to compare."
    elif boot_lines(stored) != boot_lines(text):
        changed = lines_changed("\n".join(boot_lines(text)), "\n".join(boot_lines(stored)))
        done += (f" EdgeOS stored it with {changed} line(s) different from the file: it writes the config in its own "
                 "order and format.")
    if not sent or (dropped and not apply):
        done += " The connection dropped meanwhile: the device finished on its own, checked after reconnecting."
    return done


# -- the backups ---------------------------------------------------------------

@dataclass
class Backup:
    """One saved config: the file itself, and what's known of where it came from (meta, from
    the .json beside it: mac, ip, name, model, platform, firmware, kind, file, reason, saved)."""
    path: Path
    when: float  # when it was taken (seconds since 1970)
    meta: dict

    @property
    def date(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.when))

    @property
    def reason(self) -> str:
        return str(self.meta.get("reason") or "")

    def text(self) -> str:
        return self.path.read_bytes().decode("utf-8", "replace")


def backup_root(root=None) -> Path:
    """Where backups are kept: one folder per device, named by its MAC (aa-bb-cc-dd-ee-ff)."""
    if root:
        return Path(root)
    if BACKUP_ROOT:
        return Path(BACKUP_ROOT)
    from opendisco import vulns
    return vulns.default_data_dir() / BACKUP_FOLDER


def backup_folder(mac: str, root=None) -> Path:
    return backup_root(root) / core.norm_mac(mac).replace(":", "-")


def save_backup(d, text: str, kind: str, reason: str = "backup", root=None) -> Backup:
    """Keep a config of the device: <MAC folder>/<date>_<time>_<file name>, and beside it the
    same name + .json with where it came from."""
    if not d.mac:
        raise ToolError("Without its MAC address the app can't file a backup of it.")
    folder = backup_folder(d.mac, root)
    folder.mkdir(parents=True, exist_ok=True)
    when = time.time()
    stamp, name = time.strftime("%Y-%m-%d_%H%M%S", time.localtime(when)), CONFIG_NAMES[kind]
    path, n = folder / f"{stamp}_{name}", 2
    while path.exists():
        path, n = folder / f"{stamp}-{n}_{name}", n + 1
    data = text.encode("utf-8")
    meta = {"mac": d.mac, "ip": d.ip, "name": d.name, "model": d.model,
            "platform": d.fw_platform or d.info.get("platform") or "",
            "firmware": d.info.get("firmware") or d.firmware or "", "kind": kind, "file": CONFIG_FILES[kind],
            "reason": reason, "saved": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(when)),
            "sha256": hashlib.sha256(data).hexdigest(), "app": f"OpenDisco {core.__version__}"}
    for target, content in ((path, data), (_meta_path(path), json.dumps(meta, indent=1).encode("utf-8"))):
        part = target.with_name(target.name + ".part")
        part.write_bytes(content)
        os.replace(part, target)
    return Backup(path, when, meta)


def _meta_path(path: Path) -> Path:
    return path.with_name(path.name + ".json")


def _read_meta(path: Path) -> dict:
    try:
        meta = json.loads(_meta_path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return meta if isinstance(meta, dict) else {}


def list_backups(mac: str | None = None, root=None) -> list:
    """Saved configs, the newest first, as Backups (.path, .when, .date, .reason, .meta): one
    device's (by its MAC), or with mac None every device's."""
    if mac:
        folders = [backup_folder(mac, root)]
    else:
        top = backup_root(root)
        folders = [f for f in top.iterdir() if f.is_dir()] if top.is_dir() else []
    found = []
    for folder in folders:
        if not folder.is_dir():
            continue
        for path in folder.iterdir():
            if path.name.endswith((".json", ".part")) or not path.is_file():
                continue
            meta = _read_meta(path)
            when = None
            try:
                when = time.mktime(time.strptime(str(meta.get("saved", ""))[:19], "%Y-%m-%dT%H:%M:%S"))
            except ValueError:
                pass
            found.append(Backup(path, when or path.stat().st_mtime, meta))
    return sorted(found, key=lambda b: b.when, reverse=True)


def backup_macs(root=None) -> list:
    """The MACs (aa:bb:cc:dd:ee:ff) that have a backups folder."""
    top = backup_root(root)
    if not top.is_dir():
        return []
    return sorted(f.name.replace("-", ":") for f in top.iterdir()
                  if f.is_dir() and re.fullmatch(r"(?:[0-9a-f]{2}-){5}[0-9a-f]{2}", f.name))


def delete_backup(backup: Backup) -> None:
    backup.path.unlink(missing_ok=True)
    _meta_path(backup.path).unlink(missing_ok=True)


def read_config_file(path) -> tuple:
    """(the text, what's known of it) for a config file to upload: a saved backup's .json
    when it has one beside it, else nothing."""
    path = Path(path)
    if path.stat().st_size > 4_000_000:
        raise ToolError(f"{path.name} is {path.stat().st_size:,} bytes: far too big for a device's config.")
    data = path.read_bytes()
    if b"\0" in data[:4096]:
        raise ToolError(f"{path.name} isn't a text file (a web UI's backup archive is unpacked first).")
    return data.decode("utf-8", "replace"), _read_meta(path)


def same_model(d, meta: dict) -> bool | None:
    """Whether a backup's device is the same model as d: None when the backup doesn't say."""
    theirs = [str(meta.get(k) or "").strip().lower() for k in ("platform", "model")]
    ours = [(d.fw_platform or d.info.get("platform") or "").strip().lower(), (d.model or "").strip().lower()]
    pairs = [(a, b) for a, b in zip(theirs, ours) if a and b]
    return all(a == b for a, b in pairs) if pairs else None


def upload_check(d, kind: str, text: str, meta: dict) -> tuple:
    """(why it can't go to this device, what to confirm first): the file must be the device's
    kind of config, and a backup of the same model; one that doesn't say which model it's from,
    or is another device's, is asked about first."""
    problems = config_problems(text, kind)
    other = "airos" if kind == "edgeos" else "edgeos"
    if problems and text.strip() and not config_problems(text, other):
        return (f"It's {'an EdgeOS' if other == 'edgeos' else 'an airOS-style'} {CONFIG_NAMES[other]}, not the "
                f"{CONFIG_NAMES[kind]} this device keeps.", "")
    if problems:
        return (f"It isn't a {CONFIG_NAMES[kind]} that {_kind_name(kind)} reads: " + "; ".join(problems[:5]) + ".", "")
    if meta.get("kind") and meta["kind"] != kind:
        return f"It's a {CONFIG_NAMES.get(meta['kind'], meta['kind'])}, not this device's {CONFIG_NAMES[kind]}.", ""
    model = d.model or d.fw_platform or "device"
    match = same_model(d, meta)
    if match is False:
        return (f"It's from model {meta.get('model') or meta.get('platform')}, and this device is model {model}: a "
                "config goes back only to the same model.", "")
    warn = []
    if match is None:
        warn.append(f"The file doesn't say which model it's from. Upload only a config from another {model}: settings "
                    "for other hardware (radios, interfaces) can leave it unreachable.")
    if meta.get("mac") and d.mac and core.norm_mac(meta["mac"]) != d.mac:
        warn.append(f"It's from another device ({meta['mac']}{', ' + meta['name'] if meta.get('name') else ''}): its "
                    "address, name and logins come with it.")
    return "", "\n\n".join(warn)


def _kind_name(kind: str) -> str:
    return {"airos": "airOS", "isp": "the device", "edgeos": "EdgeOS"}.get(kind, "the device")


def config_diff(old: str, new: str) -> tuple:
    """(a unified diff from the device's config to the new one, how many lines change)."""
    import difflib
    a, b = old.replace("\r", "").splitlines(), new.replace("\r", "").splitlines()
    diff = "\n".join(difflib.unified_diff(a, b, "on the device", "to upload", n=2, lineterm=""))
    return diff, lines_changed(old, new)


# ---------------------------------------------------------------------------
# Reboot and Locate
# ---------------------------------------------------------------------------

def _uptime(login: sshrun.Login, stop=None) -> float | None:
    """Its uptime in seconds; None when it doesn't answer."""
    try:
        out = sshrun.run(login, "cat /proc/uptime", timeout=25, stop=stop).out.split()
    except sshrun.SSHError as e:
        if e.kind in ("key", "cancelled"):
            raise
        return None
    try:
        return float(out[0])
    except (IndexError, ValueError):
        return -1.0  # it answers, but doesn't say


def reboot(login: sshrun.Login, d, report=None, stop=None, within: float = 600) -> float:
    """Restart the device with its family's command (REBOOT) and wait until it's back: it has
    stopped answering, or its uptime started again. report(text). Returns the seconds it took."""
    command = REBOOT[config_kind(d) or family(d)]
    say = report or (lambda message: None)
    before = _uptime(login, stop)
    if before is None:
        raise ToolError(f"{login.where} doesn't answer over SSH.")
    say("Restarting it…")
    try:
        sshrun.run(login, detached(command, REBOOT_LOG), timeout=30, stop=stop)
    except sshrun.SSHError as e:
        if e.kind in ("auth", "key", "cancelled"):
            raise  # otherwise the connection dropping as it goes down
    start, down = time.monotonic(), False
    while time.monotonic() - start < within:
        if stop is not None and stop.is_set():
            raise ToolError("Stopped waiting. The device carries on restarting by itself.")
        time.sleep(3)
        now = _uptime(login)
        elapsed = time.monotonic() - start
        if now is None:
            down = True
        elif down or 0 <= now < before:
            return elapsed
        else:  # still up: the command may have failed (no sudo, say), or not taken
            try:
                said = sshrun.run(login, f"cat {REBOOT_LOG} 2>/dev/null", timeout=25).out
            except sshrun.SSHError:
                said = ""
            failed = re.search(r"opendisco-exit=([1-9]\d*)", said)
            if failed or elapsed > 90:
                said = re.sub(r"opendisco-exit=\d+\s*", "", said).strip()
                raise ToolError("It didn't restart" + (f". It said: {said[-300:]}" if said else
                                                       " (it may be busy, upgrading its firmware)."))
        say(("Restarting: waiting for it to come back… " if down else "Restarting… ") + f"{elapsed:.0f}s")
    raise ToolError(f"It hasn't come back after {within // 60:.0f} minutes. Give it a few more before power-cycling it.")


def locate(login: sshrun.Login, d, on: bool = True, stop=None) -> bool | None:
    """Start (or stop) blinking its LED. Returns whether it's locating now, as it says (None:
    it doesn't say)."""
    start, end = LOCATE[family(d)]
    result = sshrun.run(login, f"{start if on else end}; echo; cat {LOCATE_STATE} 2>/dev/null", stop=stop)
    if "not found" in result.out + result.err:
        raise ToolError(f"It has no {start.split()[0]}.")
    state = (result.out.split() or [""])[-1].lower()
    return True if state == "true" else False if state == "false" else None


# ---------------------------------------------------------------------------
# Scan from a device
# ---------------------------------------------------------------------------

@dataclass
class Sighting:
    """One device that another device knows of."""
    how: str  # "stations", "lldp" or "arp" (SCAN_HOW)
    mac: str = ""
    ip: str = ""
    name: str = ""
    model: str = ""
    firmware: str = ""
    port: str = ""  # the finder's interface it's on


def scan_command(fam: str) -> str:
    """One command that writes everything the device can tell about its neighbours to SCAN_FILE,
    which then travels by scp (Windows' console would wrap long JSON lines). Its own name,
    interfaces and addresses come too, for a device given only by its address."""
    parts = ["echo @@arp", "cat /proc/net/arp"]
    if fam == "airos":
        parts += ["echo @@stations", "wstalist"]
    elif not fam:  # not known yet: airOS, airFiber and LTU have wstalist
        parts += ["echo @@stations", "if command -v wstalist >/dev/null; then wstalist; fi"]
    parts += ["echo @@lldp",
              "if command -v lldpcli >/dev/null; then lldpcli -f keyvalue show neighbors details 2>/dev/null"
              " || sudo -n lldpcli -f keyvalue show neighbors details; fi",
              "echo @@self", "uname -n",
              "for i in /sys/class/net/*; do echo link ${i##*/} $(cat $i/address 2>/dev/null); done",
              "ip -o -4 addr show 2>/dev/null || ifconfig", "echo @@end"]
    return "sh -c '" + "; ".join(f"{p} 2>/dev/null" if not p.startswith(("echo", "if", "for")) else p
                                 for p in parts) + \
           f"' >{SCAN_FILE} 2>/dev/null"


def read_scan(login: sshrun.Login, fam: str, stop=None) -> str:
    sshrun.run(login, scan_command(fam), timeout=90, stop=stop)
    try:
        try:
            return _fetch(login, SCAN_FILE, stop)
        except sshrun.SSHError as e:
            if e.kind != "forwarding":
                raise
            return sshrun.run(login, f"cat {SCAN_FILE}", timeout=90, stop=stop).out  # through the hop's client
    finally:
        try:
            sshrun.run(login, f"rm -f {SCAN_FILE}", stop=stop)
        except sshrun.SSHError:
            pass


def parse_scan(text: str) -> list:
    sections, name = {}, None
    for line in text.replace("\r", "").split("\n"):
        if line.startswith("@@"):
            name = line[2:].strip()
            sections[name] = []
        elif name:
            sections[name].append(line)
    found = _arp_sightings(sections.get("arp", []))
    found += _station_sightings("\n".join(sections.get("stations", [])))
    found += _lldp_sightings(sections.get("lldp", []))
    return found


_MAC = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")


def _arp_sightings(lines) -> list:
    """/proc/net/arp: IP address, HW type, Flags, HW address, Mask, Device. Flag 0x2: complete."""
    found = []
    for line in lines[1:]:
        f = line.split()
        if len(f) >= 6 and _MAC.fullmatch(f[3]) and f[3] != "00:00:00:00:00:00":
            try:
                complete = int(f[2], 16) & 0x2
            except ValueError:
                continue
            if complete:
                found.append(Sighting("arp", f[3].lower(), f[0], port=f[5]))
    return found


def _station_sightings(text: str) -> list:
    """wstalist: a JSON list of stations, each with mac, lastip and name, and on airOS 8 a
    "remote" object with what the station says about itself (hostname, platform, version)."""
    try:
        stations = json.loads(text) if text.strip() else []
    except ValueError:
        return []
    if isinstance(stations, dict):
        stations = stations.get("stations") or stations.get("sta") or []
    found = []
    for s in stations if isinstance(stations, list) else []:
        if not isinstance(s, dict) or not _MAC.fullmatch(str(s.get("mac", ""))):
            continue
        remote = s.get("remote") if isinstance(s.get("remote"), dict) else {}
        ip = str(s.get("lastip") or "")
        found.append(Sighting("stations", str(s["mac"]).lower(), "" if ip == "0.0.0.0" else ip,
                              str(remote.get("hostname") or s.get("name") or ""), str(remote.get("platform") or ""),
                              str(remote.get("version") or ""), str(s.get("ifname") or "")))
    return found


def _lldp_sightings(lines) -> list:
    """lldpcli -f keyvalue: lldp.<port>.via=LLDP starts each neighbour, then chassis.mac,
    chassis.name, chassis.descr, chassis.mgmt-ip (IPv4 and IPv6), port.descr..."""
    found, current = [], None
    for line in lines:
        m = re.match(r"lldp\.([^.=]+)\.([^=]+)=(.*)", line)
        if not m:
            continue
        port, key, value = m.groups()
        if key == "via" or current is None:
            current = Sighting("lldp", port=port)
            found.append(current)
        if key == "chassis.mac" or (key == "chassis.id" and _MAC.fullmatch(value)):
            current.mac = current.mac or value.lower()
        elif key == "chassis.name":
            current.name = value
        elif key == "chassis.descr":
            current.model = value
        elif key == "chassis.mgmt-ip" and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", value) and not current.ip:
            current.ip = value
    return [s for s in found if s.mac or s.ip]


@dataclass
class Identity:
    """What a device says of itself in a scan: its name, the MAC of the interface that has the
    address the app logged in to, and all its interfaces' MACs."""
    name: str = ""
    mac: str = ""
    macs: tuple = ()


def parse_self(text: str, ip: str) -> Identity:
    """The @@self section: uname -n, "link <interface> <MAC>" lines, then ip -o -4 addr's lines
    ("2: eth0    inet 192.168.1.20/24 brd ...") or ifconfig's blocks ("eth0  Link encap:Ethernet
    HWaddr ..." with "inet addr:192.168.1.20")."""
    lines, on = [], False
    for line in text.replace("\r", "").split("\n"):
        if line.startswith("@@"):
            on = line[2:].strip() == "self"
        elif on:
            lines.append(line)
    links, owner, block = {}, "", ""
    for line in lines:
        f = line.split()
        if len(f) == 3 and f[0] == "link" and _MAC.fullmatch(f[2]) and f[2] != "00:00:00:00:00:00":
            links[f[1]] = f[2].lower()
            continue
        m = re.match(r"\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)", line)
        if m:
            owner = owner or (m.group(1) if m.group(2) == ip else "")
            continue
        m = re.match(r"(\S+)\s+Link encap", line)
        if m:
            block = m.group(1)
        elif re.search(rf"inet (addr:)?{re.escape(ip)}\b", line) and block:
            owner = owner or block
    owner = owner.split("@")[0]  # "eth0.10@eth0"
    name = lines[0].strip() if lines and not lines[0].startswith("link ") else ""
    mac = links.get(owner) or links.get(owner.split(":")[0], "")  # an alias such as "eth0:1"
    return Identity(name, core.norm_mac(mac) if mac else "", tuple(sorted({core.norm_mac(m) for m in links.values()})))


def scan_from_address(res, login: sshrun.Login, local: set = frozenset()) -> tuple:
    """Scan from a device given by its address and login (over a VPN, say), whether or not
    this computer found it: it becomes the device that what it sees is listed under, the way
    Scan from device does it. A device already in the table with that address or MAC is that
    device. local: this computer's MACs. Returns (the device, what it saw, the devices it
    knows of, the ones that were new)."""
    text = read_scan(login, "")
    sightings, me = parse_scan(text), parse_self(text, login.ip)
    finder = (res.inv.find(mac=me.mac) if me.mac else None) or res.inv.find(ip=login.ip)
    if finder is None or (me.mac and not finder.mac):
        finder = res.inv.lookup(mac=me.mac or None, ip=login.ip)  # files a device known by address under its MAC
    finder.add_ip(login.ip)
    finder.via.add("ssh")
    finder.services.setdefault(login.port, "ssh")
    if me.name:
        finder.info.setdefault("hostname", me.name)
    seen, new = merge_scan(res, finder, sightings, set(local) | set(me.macs))
    return finder, sightings, seen, new


def relink(res, old_key: str, d) -> None:
    """After a device known by its address is filed under its MAC (a discovery reply arrived):
    what was found through it stays listed under it."""
    if d is not None and d.key != old_key:
        for dev in res.inv.devices.values():
            if dev.found_by.get("key") == old_key:
                dev.found_by["key"] = d.key
        res.devices = core.sorted_devices(res.inv)


def merge_scan(res, finder, sightings: list, local: set = frozenset()) -> tuple:
    """Add what the finder knows of to the scan's inventory, seen via "from-device". A device
    this computer hadn't found itself is listed under the finder (found_by), and so is one
    attached to it directly (a station or an LLDP neighbour); one this computer found that is
    merely in the finder's ARP table isn't, or a gateway would collect the whole network.
    local: this computer's MACs (core.local_macs()), and any of the finder's own. Returns
    (devices it knows of, the ones that were new)."""
    from opendisco import core
    above, up = {finder.key}, finder  # the finder's own chain, so no loop is made
    while up and up.found_by.get("key") and up.found_by["key"] not in above:
        above.add(up.found_by["key"])
        up = res.inv.devices.get(up.found_by["key"])
    order = {"stations": 0, "lldp": 1, "arp": 2}  # the most telling first
    seen, new = [], []
    for s in sorted(sightings, key=lambda s: order[s.how]):
        mac = core.norm_mac(s.mac) if s.mac else None
        ip = s.ip if s.ip and core._usable_ip(s.ip) else ""
        if (not mac and not ip) or mac in local or mac == finder.mac or (ip and ip in finder.ips):
            continue
        dev = (res.inv.find(mac=mac) if mac else None) or (res.inv.find(ip=ip) if ip else None)
        known = dev is not None and bool(dev.via - {FROM_DEVICE})
        if dev is None:
            dev = res.inv.lookup(mac=mac, ip=ip or None)
            new.append(dev)
        dev.add_ip(ip)
        dev.via.add(FROM_DEVICE)
        if (not dev.found_by and dev.key not in above and (not known or s.how != "arp")):
            dev.found_by = {"key": finder.key, "ip": finder.ip, "how": SCAN_HOW[s.how]}
        if s.how == "lldp" and not dev.lldp:
            dev.lldp = {k: v for k, v in (("system", s.name), ("description", s.model), ("chassis_mac", mac)) if v}
        elif s.how == "stations":
            for key, value in (("hostname", s.name), ("platform", s.model), ("firmware", s.firmware)):
                if value:
                    dev.info.setdefault(key, value)
        if dev not in seen:
            seen.append(dev)
    res.devices = core.sorted_devices(res.inv)
    if res.diag_args:
        core.diagnose(res.inv, *res.diag_args)
    return seen, new


# ---------------------------------------------------------------------------
# Logins
# ---------------------------------------------------------------------------

# Ubiquiti's factory logins: ubnt/ubnt (airMAX, airFiber, LTU, EdgeRouters, EdgeSwitches, UISP gear and
# older UniFi devices), ui/ui (newer UniFi devices until adopted), root with ubnt or ui (UniFi gateways
# until adopted). Anyone who can reach a device that still takes one can log in to it.
FACTORY_LOGINS = {("ubnt", "ubnt"), ("ui", "ui"), ("root", "ubnt"), ("root", "ui")}
FACTORY_PASSWORDS = {password for _user, password in FACTORY_LOGINS}


def is_factory(login) -> bool:
    return (login.user, login.password) in FACTORY_LOGINS


def note_login(d, login) -> bool:
    """Keep whether a login that just worked on d is a factory one, by its MAC in
    core.FACTORY_LOGINS_FOUND, which core.diagnose flags (FACTORY-LOGIN). Another user's login
    says nothing about the factory one; the same user's with another password means it was
    changed. True when that changed what's known (or d has no MAC to keep it by, and the login
    is a factory one): the time to save it, and with a factory login to say so."""
    if not d.mac:
        return is_factory(login)
    mac, found = core.norm_mac(d.mac), core.FACTORY_LOGINS_FOUND
    known = found.get(mac)
    if is_factory(login):
        found[mac] = [login.user, login.password]
        return known != found[mac]
    if known and known[0] == login.user:
        del found[mac]
        return True
    return False


def forget_factory_login(d) -> None:
    """d was given a new login (Change login), which replaced a factory one it took."""
    if d.mac:
        core.FACTORY_LOGINS_FOUND.pop(core.norm_mac(d.mac), None)


def change_login(text: str, user: str, password: str, new_user: str, new_password: str) -> tuple:
    """The config with the login `user` renamed to new_user and its password replaced, hashed
    the way the device hashed the current one. The current hash is checked against `password`
    first, so a hash the device can't read is never written. Returns (config, scheme)."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", new_user):
        raise ToolError("A username is 1 to 32 letters, digits, dots, dashes or underscores, starting with a "
                        "letter or digit.")
    if not new_password or any(ord(c) < 32 for c in new_password):
        raise ToolError("The new password can't be empty or hold control characters.")
    if new_password in FACTORY_PASSWORDS:
        raise ToolError(f"{new_password} is a factory password, the first one anyone tries: choose another.")
    lines = text.replace("\r", "").split("\n")
    names = {m.group(1): (n, line.split("=", 1)[1]) for n, line in enumerate(lines)
             if (m := re.match(r"users\.(\d+)\.name=", line))}
    slot = next((k for k, (_n, name) in names.items() if name == user), None)
    if slot is None:
        raise ToolError(f"The device's config has no login named {user}.")
    if any(name == new_user for k, (_n, name) in names.items() if k != slot):
        raise ToolError(f"The device already has another login named {new_user}.")
    key = f"users.{slot}.password="
    at = next((n for n, line in enumerate(lines) if line.startswith(key)), None)
    if at is None:
        raise ToolError(f"The device's config has no password for {user}.")
    current = lines[at][len(key):]
    scheme = hash_scheme(current)
    if not scheme:
        raise ToolError("The device stores its password in a format the app doesn't write (not MD5-crypt or "
                        "SHA-crypt), so it's left alone. Change it in the device's web UI.")
    if not verify_password(password, current):
        raise ToolError("The stored password doesn't match the one just used to log in, so the app can't be "
                        "sure how the device hashes passwords. Nothing was changed.")
    lines[names[slot][0]] = f"users.{slot}.name={new_user}"
    lines[at] = key + new_hash(new_password, current)
    return "\n".join(lines), scheme


# MD5-crypt ($1$) and SHA-crypt ($5$, $6$), the formats crypt(3) reads, written out here
# because Python 3.13 dropped the crypt module. airOS reads MD5-crypt only; matching the
# device's current hash keeps it that way.
_ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_SALT = re.compile(r"[./0-9A-Za-z]*")


def hash_scheme(stored: str) -> str:
    if re.fullmatch(r"\$1\$[^$]{0,8}\$[./0-9A-Za-z]{22}", stored):
        return "MD5-crypt"
    if re.fullmatch(r"\$5\$(rounds=\d+\$)?[^$]{0,16}\$[./0-9A-Za-z]{43}", stored):
        return "SHA-256-crypt"
    if re.fullmatch(r"\$6\$(rounds=\d+\$)?[^$]{0,16}\$[./0-9A-Za-z]{86}", stored):
        return "SHA-512-crypt"
    return ""


def verify_password(password: str, stored: str) -> bool:
    if not hash_scheme(stored):
        return False
    return secrets.compare_digest(crypt(password, stored), stored)


def new_hash(password: str, like: str) -> str:
    """A hash of password in the same scheme (and rounds) as `like`, with a new random salt."""
    if like.startswith("$1$"):
        return md5_crypt(password, _random_salt(8))
    m = re.match(r"\$([56])\$(rounds=\d+\$)?", like)
    if not m:
        raise ValueError("unsupported scheme")
    return crypt(password, f"${m.group(1)}${m.group(2) or ''}{_random_salt(16)}$")


def crypt(password: str, setting: str) -> str:
    """crypt(3) for the $1$, $5$ and $6$ schemes; setting is a stored hash or "$id$[rounds=N$]salt$"."""
    if setting.startswith("$1$"):
        return md5_crypt(password, setting[3:].split("$", 1)[0])
    m = re.match(r"\$([56])\$(?:rounds=(\d+)\$)?([^$]*)", setting)
    if not m:
        raise ValueError("unsupported scheme")
    return sha_crypt(password, m.group(3), int(m.group(2)) if m.group(2) else None, m.group(1) == "6")


def _random_salt(n: int) -> str:
    return "".join(secrets.choice(_ITOA64) for _ in range(n))


def _b64(b2: int, b1: int, b0: int, n: int) -> str:
    w, out = (b2 << 16) | (b1 << 8) | b0, ""
    for _ in range(n):
        out += _ITOA64[w & 0x3F]
        w >>= 6
    return out


def md5_crypt(password: str, salt: str) -> str:
    pw, salt = password.encode("utf-8"), salt[:8]
    s = salt.encode("ascii")
    alt = hashlib.md5(pw + s + pw).digest()
    ctx = pw + b"$1$" + s
    left = len(pw)
    while left > 0:
        ctx += alt[:min(16, left)]
        left -= 16
    i = len(pw)
    while i:
        ctx += b"\0" if i & 1 else pw[:1]
        i >>= 1
    final = hashlib.md5(ctx).digest()
    for i in range(1000):
        c = (pw if i & 1 else final) + (s if i % 3 else b"") + (pw if i % 7 else b"") + (final if i & 1 else pw)
        final = hashlib.md5(c).digest()
    f = final
    out = "".join(_b64(f[a], f[b], f[c], 4) for a, b, c in ((0, 6, 12), (1, 7, 13), (2, 8, 14), (3, 9, 15), (4, 10, 5)))
    return f"$1${salt}${out}{_b64(0, 0, f[11], 2)}"


_SHA256_ORDER = ((0, 10, 20), (21, 1, 11), (12, 22, 2), (3, 13, 23), (24, 4, 14),
                 (15, 25, 5), (6, 16, 26), (27, 7, 17), (18, 28, 8), (9, 19, 29))
_SHA512_ORDER = ((0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4), (47, 5, 26), (6, 27, 48),
                 (28, 49, 7), (50, 8, 29), (9, 30, 51), (31, 52, 10), (53, 11, 32), (12, 33, 54), (34, 55, 13),
                 (56, 14, 35), (15, 36, 57), (37, 58, 16), (59, 17, 38), (18, 39, 60), (40, 61, 19), (62, 20, 41))


def sha_crypt(password: str, salt: str, rounds: int | None, sha512: bool) -> str:
    """SHA-crypt as Ulrich Drepper specified it (glibc's $5$ and $6$)."""
    new = hashlib.sha512 if sha512 else hashlib.sha256
    size = 64 if sha512 else 32
    pw, s = password.encode("utf-8"), salt[:16].encode("ascii")
    count = 5000 if rounds is None else min(max(rounds, 1000), 999_999_999)
    b = new(pw + s + pw).digest()
    a = new(pw + s)
    left = len(pw)
    while left > size:
        a.update(b)
        left -= size
    a.update(b[:left])
    i = len(pw)
    while i:
        a.update(b if i & 1 else pw)
        i >>= 1
    a = a.digest()
    dp = new(pw * len(pw)).digest()
    p = (dp * (len(pw) // size + 1))[:len(pw)]
    ds = new(s * (16 + a[0])).digest()
    sp = (ds * (len(s) // size + 1))[:len(s)]
    c = a
    for i in range(count):
        h = new(p if i & 1 else c)
        if i % 3:
            h.update(sp)
        if i % 7:
            h.update(p)
        h.update(c if i & 1 else p)
        c = h.digest()
    if sha512:
        out = "".join(_b64(c[x], c[y], c[z], 4) for x, y, z in _SHA512_ORDER) + _b64(0, 0, c[63], 2)
    else:
        out = "".join(_b64(c[x], c[y], c[z], 4) for x, y, z in _SHA256_ORDER) + _b64(0, c[31], c[30], 3)
    prefix = f"${'6' if sha512 else '5'}$" + (f"rounds={count}$" if rounds is not None else "")
    return f"{prefix}{salt[:16]}${out}"
