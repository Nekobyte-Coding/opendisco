"""Firmware checks, firmware updates, config editing and login changes for one device, over SSH.

Each action is offered only for the device families whose steps are documented by Ubiquiti
(see FAMILY_NOTES); the GUI (devicegui) asks for the login and shows progress, and everything
here runs in a worker thread.

- Firmware checks ask Ubiquiti's public firmware server (fw-update.ubnt.com) for the latest
  release for the device's platform: UniFi gear is listed by board name ("platform"), airMAX,
  airFiber, EdgeRouter and the rest by product name.
- Updates download the release in the app, check its size and SHA-256, copy it to the device
  with scp and start the family's installer, then wait for the device to restart. An
  EdgeRouter adds the image with EdgeOS's own command, and the app restarts it once EdgeOS
  shows the new image as the one it boots.
- airOS keeps its whole configuration in one file, /tmp/system.cfg: it's edited as text, saved
  to flash, or saved and applied in place the way the web UI's Apply does.
- A new login goes into the same file, its password hashed the way the device hashes the one
  it has now (airOS uses MD5-crypt), and only after that hash is checked against the current
  password. On an EdgeRouter it goes through EdgeOS's config commands, which hash it
  themselves; a renamed login is made and checked before the old one is deleted. A factory
  password (FACTORY_LOGINS) isn't taken, and a device the User logs in to with a factory login
  is flagged (note_login).
- Config backups (every family but UniFi, whose controller keeps its config): the device's
  config file, kept in the app's data folder by MAC with the time it was taken, and uploaded
  again (Restore) only to the same model. airMAX, airFiber and LTU keep theirs in
  /tmp/system.cfg; EdgeRouters in /config/config.boot, which is loaded and committed through
  EdgeOS's own config commands. Back up all backs up every device with a saved login, a few at
  a time (back_up_all); two backups, or a backup and the config now, are compared line by line
  (config_diff).
- Reboot, Locate (the LED blinks: UniFi access points and switches only), and Scan from a
  device given by its address, for devices the app hasn't found itself (over a VPN).
- Link health (airMAX): the radio's mca-status and wstalist, which linkhealth reads.
"""
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from dataclasses import dataclass, field, replace
from pathlib import Path

from opendisco import core, linkhealth
from opendisco.i18n import _, N_, sentences, tr

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
#  edgeos:   UISP Help Center "EdgeRouter - How to Upgrade the EdgeOS Firmware", Command Line: the file
#            copied with SCP to /tmp/firmware.tar, "add system image /tmp/firmware.tar", "show system
#            image" to check the new image is the default boot, then "reboot". The op commands go through
#            vyatta-op-cmd-wrapper, as "EdgeRouter - Run Operational Mode Command from Scripts" runs them.
#            EdgeOS keeps two images: the new one replaces the one not running, and the one running now
#            stays as the backup. add system image (EdgeOS's /usr/bin/ubnt-upgrade) asks its questions on
#            standard input; given none, it takes each default, as pressing Enter does: replace the backup
#            image (Yes), go on and lose config changes not saved (No: it stops), delete the backup first
#            when there isn't room for both (Yes). The wrapper exits 0 whatever the command did (EdgeOS's
#            _vyatta_op_run), so what happened is read from show system image.
EDGEOS_OP = "/opt/vyatta/bin/vyatta-op-cmd-wrapper"
EDGEOS_IMAGE = "/tmp/firmware.tar"
# EdgeOS has logins of its own, each its own Linux user, and /tmp is shared: a log another login left
# there can't be replaced (one deleted by Change login, say), so each login writes its own.
EDGEOS_UPDATE_LOG = "/tmp/opendisco-update-$(id -u).log"
EDGEOS_CONFIG_LOG = "/tmp/opendisco-config-$(id -u).log"
UPDATE_STEPS = {
    "airos": {"path": "/tmp/fwupdate.bin", "check": "/sbin/fwupdate -c", "install": "/sbin/fwupdate -m"},
    "unifi": {"path": "/tmp/fwupdate.bin", "check": None, "install": "syswrapper.sh upgrade2"},
    "unifi-os": {"path": "/tmp/fwupdate.bin", "check": None, "install": "ubnt-systool fwupdate /tmp/fwupdate.bin"},
    "edgeos": {"path": EDGEOS_IMAGE, "check": None, "install": f"{EDGEOS_OP} add system image {EDGEOS_IMAGE}"},
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
BACKUP_AT_ONCE = 3  # devices Back up all backs up at the same time
# The EdgeSwitch family (by its firmware platform), whose CLI isn't a shell: its config travels
# only through its web UI or a TFTP/FTP server ("EdgeSwitch & EdgeSwitch X - Backup and Restore
# the Configuration", UISP Help Center).
EDGESWITCH_PLATFORMS = {"eswh", "esgh", "esx", "esxp"}

# Why an action isn't offered for a family, as the menu shows it.
_NO_CONFIG = {"unifi": N_("set by its UniFi controller"), "unifi-os": N_("UniFi OS: in its own settings"),
              "edgeswitch": N_("EdgeSwitch: in its web UI"), "": N_("not for this device")}
NOT_OFFERED = {
    "update": {"": N_("not for this device")},
    "config": dict(_NO_CONFIG, edgeos=N_("not for EdgeOS here")),
    "edit": _NO_CONFIG, "backup": _NO_CONFIG, "upload": _NO_CONFIG,
    "login": {"unifi": N_("set by its UniFi controller"), "unifi-os": N_("UniFi OS: in its own settings"),
              "isp": N_("airMAX and EdgeOS only"), "": N_("not for this device")},
    "scan": {"": N_("not for this device")},
    "link": {"": N_("airMAX only")},
    "reboot": {"edgeswitch": N_("EdgeSwitch: in its web UI"), "": N_("not for this device")},
    "locate": {"airos": N_("airOS has no LED command"), "isp": N_("no LED command known"),
               "edgeos": N_("EdgeOS has no LED command"), "unifi-os": N_("UniFi OS: from its UniFi app"),
               "": N_("not for this device")},
}
# Scan from device: every family's Linux has the kernel's ARP table; airOS lists the stations
# associated with it (wstalist, the web UI's station list, JSON); lldpd's lldpcli, where the
# device runs lldpd, lists its LLDP neighbours.
SCAN_FAMILIES = {"airos", "unifi", "unifi-os", "edgeos"}
SCAN_FILE = "/tmp/opendisco-scan.txt"
LINK_FILE = "/tmp/opendisco-link.txt"
SCAN_HOW = {"stations": N_("its station list"), "lldp": N_("its LLDP neighbours"), "arp": N_("its ARP table")}
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
    config editor for every kind), "backup", "upload", "login", "scan", "reboot", "locate" or
    "link" (link health)."""
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
    elif action == "link":
        ok = fam == "airos"
    else:  # login
        ok = fam in ("airos", "edgeos")
    return ok, "" if ok else _(NOT_OFFERED[action].get(_kind(d), NOT_OFFERED[action][""]))


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
        raise ToolError(tr("Ubiquiti's firmware server didn't answer ({reason}).", reason=_reason(e))) from None
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
    what = check.platform or _("this device")
    if not check.release:
        text = tr("Ubiquiti's firmware server lists no release for {platform}.", platform=what)
    elif not check.current:
        text = tr("The latest release for {platform} is {latest} ({date}); the version it runs is unknown.",
                  platform=what, latest=check.latest, date=check.date)
    elif check.newer:
        text = tr("Firmware {latest} is out for {platform} (released {date}, {size}); it runs {current}.",
                  latest=check.latest, platform=what, date=check.date, size=fmt_size(check.size), current=check.current)
    else:
        text = tr("Up to date: it runs {current}; the latest release for {platform} is {latest} ({date}).",
                  current=check.current, platform=what, latest=check.latest, date=check.date)
    cves = cve_issues(d)
    if cves:
        text += ("\n\n" + sentences(tr("Known vulnerabilities in {firmware}: {count}.",
                                       firmware=check.current or _("its firmware"), count=len(cves)),
                                    tr("Updating to {latest} is advised.", latest=check.latest) if check.newer else
                                    _("No newer release is listed yet."))
                 + "\n" + "\n".join(f"- {c}" for c in cves[:8]) + ("\n- …" if len(cves) > 8 else ""))
    return text


def fmt_size(size: int) -> str:
    return f"{size / 1e9:.2f} GB" if size >= 1e9 else f"{size / 1e6:.1f} MB"


def fits(d, release: dict) -> str:
    """Why this release can't be installed by the app on this device ("" when it can)."""
    fam = family(d)
    product, platform = str(release.get("product", "")), str(release.get("platform", ""))
    if fam == "airos" and not (product.upper() in AIROS_PLATFORMS and platform == "airmax"):
        return _("The release found isn't airMAX firmware.")
    if fam == "unifi":
        if product != "unifi-firmware":
            return _("The release found isn't for a UniFi access point or switch.")
        if platform == "USMULT" or platform.startswith("UGW"):
            return tr("{platform} firmware needs extra steps the app doesn't do.", platform=platform)
    if fam == "unifi-os":
        if product not in UNIFI_OS_PRODUCTS:
            return _("The release found isn't UniFi OS firmware.")
        if version_key(device_version(d))[:1] < (2,):
            return _("UniFi OS 1.x installs differently: update it in its own settings first.")
    if fam == "edgeos" and (platform != "edgerouter" or product.lower() != d.fw_platform.lower()):
        return tr("The release found isn't EdgeRouter firmware for {platform}.", platform=d.fw_platform)
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
        raise ToolError(_("The firmware server gives no SHA-256 for this release, so it can't be checked."))
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
                    raise ToolError(_("Cancelled."))
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
        raise ToolError(tr("Downloading the firmware failed ({reason}).", reason=_reason(e))) from None
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    if size and done != size:
        part.unlink(missing_ok=True)
        raise ToolError(tr("The download is {done:,} bytes, not the {size:,} the firmware server lists.", done=done,
                           size=size))
    if digest.hexdigest() != want:
        part.unlink(missing_ok=True)
        raise ToolError(_("The download's SHA-256 doesn't match the firmware server's: it was damaged on the way."))
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


# The report after which a firmware update can't be stopped any more (the GUIs take Cancel away when it
# comes): the installer starting, on airOS and UniFi, then on EdgeOS.
INSTALL_STARTS = (N_("Starting the installation. The device restarts on its own: don't unplug it."),
                  N_("Starting the installation: EdgeOS writes the new image to its flash, which takes a few minutes. "
                     "Don't unplug it."))


def install_firmware(d, login: sshrun.Login, path: Path, report, stop=None, version: str = "") -> float:
    """Copy the firmware to the device, check it there and start the installer, then wait for
    the device to go down and come back. report(text, percent or None). version: the release's,
    which an EdgeRouter must show as its default boot image before it's restarted. Returns the
    seconds it was offline."""
    steps = UPDATE_STEPS[family(d)]
    target = steps["path"]
    report(_("Making room on the device…"), None)
    sshrun.run(login, f"rm -f {target}", stop=stop)
    if family(d) == "edgeos":
        free = re.findall(r"^\S+\s+\d+\s+\d+\s+(\d+)", sshrun.run(login, "df -k /tmp", stop=stop).out, re.M)
        if free and int(free[-1]) * 1024 < path.stat().st_size + (4 << 20):
            raise ToolError(tr("It has {free} free in /tmp, too little for the {size} firmware file, so nothing was "
                               "copied.", free=fmt_size(int(free[-1]) * 1024), size=fmt_size(path.stat().st_size)))
    report(tr("Copying the firmware to {path}…", path=target), 0)
    sshrun.upload(login, path, target, progress=lambda p: report(None, p), stop=stop)

    report(_("Checking the copy on the device…"), None)
    copied = _said_md5(sshrun.run(login, _ARRIVED.format(path=target), stop=stop).out)
    if copied and copied != _md5(path):
        sshrun.run(login, f"rm -f {target}", stop=stop)
        raise ToolError(_("The copy on the device doesn't match the download: it was damaged on the way."))
    if steps["check"]:
        result = sshrun.run(login, steps["check"], timeout=120, stop=stop)
        if result.code:
            sshrun.run(login, f"rm -f {target}", stop=stop)
            said = _said(result)
            raise ToolError(tr("The device rejected the firmware file: {said}", said=said) if said else
                            _("The device rejected the firmware file."))
    if family(d) == "edgeos":
        return _install_edgeos(d, login, target, version, report, stop)
    upgrade_time = 0
    if family(d) == "airos":
        result = sshrun.run(login, "sed -n 's/^board.upgrade=//p' /etc/board.info 2>/dev/null", stop=stop)
        upgrade_time = int(result.out.strip()) if result.out.strip().isdigit() else 0

    if stop is not None and stop.is_set():
        raise ToolError(_("Cancelled."))
    report(_(INSTALL_STARTS[0]), None)
    sshrun.run(login, detached(steps["install"], UPDATE_LOG), timeout=60)
    went_down = wait_for(login.ip, login.port, up=False, within=300, report=report,
                         what=_("Installing: waiting for the device to restart…"))
    if not went_down:
        said = ""
        try:
            said = sshrun.run(login, f"cat {UPDATE_LOG}").out.strip()
        except sshrun.SSHError:
            pass
        said = re.sub(r"opendisco-exit=\d+\s*", "", said).strip()
        raise ToolError(tr("The device didn't restart, so the firmware wasn't installed. It said: {said}", said=said)
                        if said else _("The device didn't restart, so the firmware wasn't installed."))
    started = time.monotonic()
    within = max(900, upgrade_time * 3)
    if not wait_for(login.ip, login.port, up=True, within=within, report=report,
                    what=_("Installing: the device is offline while it writes the firmware…")):
        raise ToolError(tr("The device hasn't come back after {minutes} minutes. It may still be installing: give it "
                           "a few more minutes before power-cycling it.", minutes=within // 60))
    return time.monotonic() - started


# -- EdgeOS's two images -----------------------------------------------------------------

@dataclass
class Image:
    """One of the two firmware images an EdgeRouter keeps, as show system image lists it."""
    name: str  # "v2.0.9-hotfix.7.5622731.230615.0857"
    running: bool
    default: bool  # the one it boots next

    @property
    def version(self) -> str:
        """"2.0.9-hotfix.7" from v2.0.9-hotfix.7.5622731.230615.0857, "1.9.7-hotfix.4" from
        v1.9.7+hotfix.4.5024279.170803.0249, "3.0.1" from v3.0.1.5862409.250924.1407."""
        m = re.match(r"v?(\d+\.\d+(?:\.\d+)?)([-+]hotfix\.\d+)?", self.name)
        return m.group(1) + (m.group(2) or "").replace("+", "-") if m else self.name


def parse_images(text: str) -> list:
    """show system image's list: each image's name, followed by "(running image)" and "(default
    boot)" where they apply (EdgeOS's ubnt-upgrade --show prints it so)."""
    return [Image(m.group(1), "(running image)" in m.group(2), "(default boot)" in m.group(2))
            for m in re.finditer(r"(?m)^\s*(v\d[\w.+-]*)[ \t]*((?:\((?:running image|default boot)\)[ \t]*)*)",
                                 text.replace("\r", ""))]


def edgeos_images(login: sshrun.Login, stop=None) -> list:
    """Its images, from show system image."""
    result = sshrun.run(login, f"{EDGEOS_OP} show system image </dev/null", timeout=90, stop=stop)
    images = parse_images(result.out)
    if not images:
        said = _said(result)
        raise ToolError(tr("EdgeOS didn't list its firmware images: {said}", said=said) if said else
                        _("EdgeOS didn't list its firmware images."))
    return images


# How EdgeOS's ubnt-upgrade itself asks whether the running config has changes committed but not
# saved, which installing would lose: lines of difference between the boot config and the active one.
EDGEOS_UNSAVED = ("cli-shell-api showConfig --show-cfg1 /config/config.boot --show-cfg2 @ACTIVE "
                  "--show-context-diff")


def edgeos_unsaved(login: sshrun.Login, stop=None) -> bool | None:
    """Whether its running config has changes committed but not saved; None when it can't tell."""
    out = sshrun.run(login, "if command -v cli-shell-api >/dev/null; then echo opendisco-unsaved="
                            f"$({EDGEOS_UNSAVED} 2>/dev/null | wc -l); fi", timeout=60, stop=stop).out
    m = re.search(r"opendisco-unsaved=\s*(\d+)", out)
    return int(m.group(1)) > 0 if m else None


EDGEOS_UNSAVED_TEXT = N_("It has config changes that are committed but not saved, which installing would lose: "
                         "EdgeOS's installer stops for them. Save them (save, in its CLI) or undo them, then update "
                         "it.")


def edgeos_update_note(login: sshrun.Login, version: str, stop=None) -> str:
    """What installing version does to an EdgeRouter's two images, said before it's confirmed;
    ToolError when EdgeOS would stop at config changes not saved."""
    if edgeos_unsaved(login, stop):
        raise ToolError(_(EDGEOS_UNSAVED_TEXT))
    return image_plan(edgeos_images(login, stop), version)


def image_plan(images: list, version: str) -> str:
    """What installing version does to the images it keeps, in a sentence."""
    running = next((i for i in images if i.running), None)
    other = next((i for i in images if not i.running), None)
    if running and other:
        return tr("EdgeOS keeps two firmware images: {version} goes in as the one it boots, and {running}, which it "
                  "runs now, stays as the backup; {backup}, the backup it has now, is deleted.",
                  version=version, running=running.version, backup=other.version)
    if running:
        return tr("EdgeOS keeps two firmware images: {version} goes in as the one it boots, and {running}, which it "
                  "runs now, stays as the backup.", version=version, running=running.version)
    if other:
        return tr("EdgeOS keeps two firmware images: {version} goes in as the one it boots; {backup}, the backup it "
                  "has now, is deleted.", version=version, backup=other.version)
    return tr("EdgeOS keeps two firmware images: {version} goes in as the one it boots.", version=version)


def _install_edgeos(d, login: sshrun.Login, target: str, version: str, report, stop) -> float:
    """add system image, run detached and logged; then, once show system image has the new image
    as the default boot, restart the router to run it. Returns the seconds it took to come back."""
    before = edgeos_images(login, stop)
    if stop is not None and stop.is_set():
        raise ToolError(_("Cancelled."))
    report(_(INSTALL_STARTS[1]), None)
    run = secrets.token_hex(6)
    sshrun.run(login, detached(UPDATE_STEPS["edgeos"]["install"], EDGEOS_UPDATE_LOG, run), timeout=60)
    start, said = time.monotonic(), None
    while said is None:
        time.sleep(3)
        try:
            out = sshrun.run(login, f"cat {EDGEOS_UPDATE_LOG} 2>/dev/null; echo opendisco-read", timeout=30).out
        except sshrun.SSHError as e:
            if e.kind in ("auth", "key"):
                raise
            out = ""  # it carries on by itself: ask again
        if f"opendisco-run={run}" in out and "opendisco-exit=" in out:
            said = out.replace("opendisco-read", "")
        elif "opendisco-read" in out and f"opendisco-run={run}" not in out:  # named before it starts
            try:
                sshrun.run(login, f"rm -f {target}")
            except sshrun.SSHError:
                pass
            raise ToolError(_("EdgeOS's installer didn't start (the app couldn't write its log in /tmp), so nothing "
                              "was installed."))
        elif time.monotonic() - start > 1200:
            raise ToolError(_("EdgeOS hasn't finished adding the image after 20 minutes, so the app didn't restart "
                              "it. Look at show system image in its CLI before restarting it."))
        else:
            report(tr("Installing: EdgeOS is writing the new image… {seconds:.0f}s", seconds=time.monotonic() - start),
                   None)
    said = re.sub(r"opendisco-(?:run|exit)=\w+\s*", "", said).strip()
    try:
        sshrun.run(login, f"rm -f {target}")  # done with, whatever it did
    except sshrun.SSHError:
        pass
    after = edgeos_images(login)
    new = next((i for i in after if i.default), None)
    if new is None or version_key(new.version) != version_key(version):
        lost = [i.version for i in before if i.name not in {a.name for a in after}]
        raise ToolError(sentences(_edgeos_refused(said), _("It wasn't restarted."),
                                  tr("EdgeOS had already deleted its backup image, {image}.", image=lost[0]) if lost
                                  else ""))
    kept = next((i for i in after if not i.default), None)
    report(tr("EdgeOS added {image} as the image it boots; {backup} stays as the backup. Restarting it to run the new "
              "one…", image=new.name, backup=kept.version) if kept else
           tr("EdgeOS added {image} as the image it boots. Restarting it to run the new one…", image=new.name), None)
    try:
        return reboot(login, d, report=lambda text: report(text, None), within=900)
    except ToolError as e:
        raise ToolError(tr("EdgeOS added {version} as the image it boots, but restarting it failed: {error} It runs "
                           "the new firmware once it's restarted.", version=version, error=e)) from None


def _edgeos_refused(said: str) -> str:
    """Why add system image installed nothing, from what it said (EdgeOS's ubnt-upgrade's messages)."""
    if "changes have not been saved" in said:
        return sentences(_("Nothing was installed."), _(EDGEOS_UNSAVED_TEXT))
    if "needs a reboot before upgrade" in said:
        return _("EdgeOS already has a new image waiting for a restart, so it took no other: Reboot it, then update "
                 "it.")
    if "does not support the device" in said:
        return _("EdgeOS says the image isn't for this router, so it installed nothing.")
    if "enough disk space" in said:
        return _("There isn't room for the new image on its flash, so nothing was installed.")
    last = ([l.strip() for l in said.split("\n") if l.strip()] or [""])[-1][-300:]  # its verdict
    return (tr("EdgeOS didn't install the image. It said: {said}", said=last) if last else
            _("EdgeOS didn't install the image."))


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
                problems.append(tr("line {line}: a }} with no {{ before it", line=n))
                depth = 0
        if depth:
            problems.append(tr("{count} {{ without a }} to close it", count=depth))
        if not body.strip():
            problems.append(_("it's empty"))
        if EDGEOS_MARK not in text:
            problems.append(tr("no {mark} line at the end, which every config EdgeOS saves has", mark=EDGEOS_MARK))
        return problems
    return [tr("line {line}: {text}", line=n, text=line[:60])
            for n, line in enumerate(text.replace("\r", "").split("\n"), 1)
            if line.strip() and not re.match(r"[A-Za-z0-9_.-]+=", line)]


def lines_changed(old: str, new: str) -> int:
    """How many lines differ between two configs: an edited line counts once (not as one line
    taken out and one put in), as do one added and one removed."""
    import difflib
    a, b = old.replace("\r", "").splitlines(), new.replace("\r", "").splitlines()
    return sum(max(i2 - i1, j2 - j1) for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False)
               .get_opcodes() if tag != "equal")


# What a config change that didn't happen, or may not have, says, by what it was to do: "applied" or
# "saved" (write_config, write_edgeos), "changed" (change_edgeos_login).
_UNTOUCHED = {
    "applied": N_("Connection lost: config not applied. It didn't reach the device, which still has its earlier "
                  "config."),
    "saved": N_("Connection lost: config not saved. It didn't reach the device, which still has its earlier config."),
}
_DAMAGED = {
    "applied": N_("The config arrived damaged, so it wasn't applied; the device still has its earlier one."),
    "saved": N_("The config arrived damaged, so it wasn't saved; the device still has its earlier one."),
    "changed": N_("The config arrived damaged, so it wasn't changed; the device still has its earlier one."),
}
_NOT_STARTED = {
    "applied": N_("Connection lost before the device got the command: config not applied. It still has its earlier "
                  "config."),
    "saved": N_("Connection lost before the device got the command: config not saved. It still has its earlier "
                "config."),
    "changed": N_("Connection lost before the device got the command: config not changed. It still has its earlier "
                  "config."),
}
_CANT_TELL = {
    "applied": N_("Connection lost: the app can't tell whether the config was applied, as it couldn't reach the "
                  "device again. Reload the config once the device answers to see."),
    "saved": N_("Connection lost: the app can't tell whether the config was saved, as it couldn't reach the device "
                "again. Reload the config once the device answers to see."),
    "changed": N_("Connection lost: the app can't tell whether the config was changed, as it couldn't reach the "
                  "device again. Reload the config once the device answers to see."),
}


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
    untouched = _(_UNTOUCHED[what])
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
            return _("Nothing to apply: the device already runs this config.")
    # It runs this config already, but has another saved: saving it is all there is to do (airOS's
    # rc.softrestart save does nothing at all when the saved config matches the running one).
    runs_it = apply and _lines(running) == _lines(text)

    say(_("Copying the config to the device…"))
    _stage(login, [(text, STAGED_CONFIG)], what, untouched, stop)
    say(_("Applying it: the device restarts the services the change affects…") if apply else _("Saving it to flash…"))
    # Detached: applying can restart SSH itself, which would end a command run in the session.
    code, said, sent, dropped = _run_staged(
        login, f"mv -f {STAGED_CONFIG} {AIROS_CONFIG} && " + (AIROS_APPLY if apply and not runs_it else AIROS_SAVE),
        STAGED_CONFIG, what, apply, [new_login, login] if new_login else [login], confirm_within, stop, say)
    if code:
        if apply:
            raise ToolError(tr("Applying failed: {said}", said=said[-300:]) if said else _("Applying failed."))
        raise ToolError(tr("Saving failed: {said}", said=said[-300:]) if said else _("Saving failed."))
    done = (_("It already ran this config: saved to flash, so it runs it after a reboot too.") if runs_it
            else _("Applied and saved to flash.") if apply
            else _("Saved to flash. It takes effect at the next reboot."))
    if not sent or (dropped and not apply):  # applying restarts SSH: drops then are expected
        done = sentences(done, _("The connection dropped meanwhile: the device finished on its own, checked after "
                                 "reconnecting."))
    return done


def _unix(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text if text.endswith("\n") else text + "\n"


def _stage(login: sshrun.Login, files: list, what: str, untouched: str, stop=None, private: bool = False) -> None:
    """Copy each (text, path on the device) there and check it arrived whole; a break here
    leaves the device as it was (LostConnection "not done"). private: readable by the login only
    (the copy keeps the mode of a file that's there, or takes this one's)."""
    folder = Path(tempfile.mkdtemp(prefix="opendisco-"))
    try:
        for n, (text, path) in enumerate(files):
            local = folder / f"file{n}"
            local.write_bytes(text.encode("utf-8"))
            if private:
                os.chmod(local, 0o600)
            sshrun.upload(login, local, path, stop=stop)
            arrived = sshrun.run(login, _ARRIVED.format(path=path), stop=stop).out
            if not _arrived_whole(arrived, local):
                sshrun.run(login, "rm -f " + " ".join(p for _t, p in files), stop=stop)
                raise ToolError(_(_DAMAGED[what]))
    except sshrun.SSHError as e:
        if e.kind in ("auth", "key", "cancelled"):
            raise
        raise LostConnection(f"{untouched} ({e})", "not done") from None
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def _run_staged(login: sshrun.Login, command: str, staged: str, what: str, apply: bool, logins: list,
                within: float, stop, say, log: str = CONFIG_LOG) -> tuple:
    """Start the command that takes the staged file, detached, and read how it went (reconnecting
    as needed). Returns (exit code, what it said, whether the start went through, whether the
    connection dropped); LostConnection when it never started or the app can't tell."""
    run = secrets.token_hex(6)
    sent = True
    try:
        sshrun.run(login, detached(command, log, run), timeout=60, stop=stop)
    except sshrun.SSHError as e:
        if e.kind in ("auth", "key"):
            raise
        sent = False  # it may or may not have got there
        say(tr("Connection lost while starting it ({error}). Reconnecting to find out what the device did…", error=e))
    state, code, said, dropped = _confirm(logins, run, within, stop, say, staged, log)
    if state == "done":
        return code, said, sent, dropped
    if state == "not started":
        try:
            sshrun.run(login, f"rm -f {staged}", stop=stop)
        except sshrun.SSHError:
            pass
        raise LostConnection(_(_NOT_STARTED[what]), "not done")
    if not sent:
        raise LostConnection(_(_CANT_TELL[what]), "unknown")
    if apply:
        raise LostConnection(_("Connection lost after the device started applying it. It finishes on its own, but the "
                               "app couldn't reach it again to confirm. Reload the config once it answers. If the "
                               "change moved its address, VLAN or SSH port, that's expected."), "unknown")
    raise LostConnection(_("Connection lost after the device started saving it. It finishes on its own, but the app "
                           "couldn't reach it again to confirm. Reload the config once it answers."), "unknown")


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


def _confirm(logins, run: str, within: float, stop, say, staged: str = STAGED_CONFIG,
             log: str = CONFIG_LOG) -> tuple:
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
                out = sshrun.run(attempt, f"cat {log} 2>/dev/null; test -e {staged} && echo "
                                          "opendisco-staged", timeout=30, stop=stop).out
                break
            except sshrun.SSHError as e:
                if e.kind in ("key", "cancelled") or (e.kind == "auth" and len(logins) == 1):
                    raise
        if out is None:
            dropped = True
            say(tr("Reconnecting to find out what the device did… {seconds:.0f}s", seconds=time.monotonic() - start))
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
        why = ("" if save and apply else _("It has no cfgmtd, so the app can't save a config to its flash.") if not save
               else _("It has no rc.softrestart to apply a config in place: Save it, then Reboot it."))
        return {"save": save, "apply": save and apply, "why": why}
    if kind == "edgeos":
        out = sshrun.run(login, f"test -x {EDGEOS_WRAPPER} && echo has-wrapper; id -Gn", stop=stop).out
        if "has-wrapper" not in out:
            return {"save": False, "apply": False,
                    "why": tr("It has no {program}: it doesn't look like EdgeOS.", program=EDGEOS_WRAPPER)}
        groups = out.replace("has-wrapper", "").split()
        if "vyattacfg" not in groups and "root" not in groups:
            return {"save": False, "apply": False,
                    "why": tr("The login {user} isn't in EdgeOS's vyattacfg group, which changing the config needs (an "
                              "admin login is).", user=login.user)}
        return {"save": True, "apply": True, "why": ""}
    return {"save": False, "apply": False, "why": _("The app can't write this device's config.")}


def read_device_config(login: sshrun.Login, kind: str, stop=None) -> tuple:
    """(its config, whether it has changes not applied yet): airOS's working config
    /tmp/system.cfg; EdgeOS's boot config /config/config.boot (changes committed since without
    saving aren't in it)."""
    if kind in ("airos", "isp"):
        return read_config(login, stop)
    if kind == "edgeos":
        return _fetch(login, EDGEOS_CONFIG, stop), False
    raise ToolError(_("The app can't read this device's config."))


def push_config(login: sshrun.Login, kind: str, text: str, apply: bool, report=None, stop=None) -> str:
    """Save the config (it takes effect at the next boot) or apply it now too. Returns what
    happened; ToolError, LostConnection or SSHError when it didn't."""
    if kind in ("airos", "isp"):
        return write_config(login, text, apply, report, stop, check_tools=kind == "isp")
    if kind == "edgeos":
        return write_edgeos(login, text, apply, report, stop)
    raise ToolError(_("The app can't write this device's config."))


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
            + _edgeos_in_group(EDGEOS_SCRIPT) +
            f"W={EDGEOS_WRAPPER}\n"
            f"F={EDGEOS_STAGED}\n"
            "OUT=/tmp/opendisco-load.out\n"
            'mv -f "$F" "$F.run" || exit 3\n'
            'cp "$F.run" "$F.load" || exit 3  # load migrates the file it loads in place\n'
            f'trap \'rm -f "$F.run" "$F.load" "$OUT" {EDGEOS_SCRIPT}\' EXIT  # another login can\'t replace them\n'
            '$W begin || { echo "EdgeOS did not start a config session."; exit 4; }\n'
            '$W load "$F.load" >"$OUT" 2>&1\n'
            "rc=$?\n"
            'cat "$OUT"\n'
            '[ $rc = 0 ] && grep -qiE "fail|error|invalid|warning|cannot" "$OUT" && rc=5\n'
            "if [ $rc = 0 ]; then\n" + act +
            "exit $rc\n")


EDGEOS_FAILURES = {
    3: N_("The config didn't arrive in place, so nothing was changed."),
    4: N_("EdgeOS didn't start a config session, so nothing was changed"),
    5: N_("EdgeOS didn't load it, so nothing was changed"),
    6: N_("EdgeOS loaded it, but the commit failed. Parts of it may be active now; its boot config is unchanged, so a "
          "reboot returns to that"),
    7: N_("It's applied, but saving it to the boot config failed: it runs the new config only until the next reboot"),
    8: N_("EdgeOS reads it, but writing /config/config.boot failed, so nothing was changed"),  # EDGEOS_CONFIG
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
        raise ToolError(tr("It isn't a config EdgeOS reads: {problems}.", problems="; ".join(problems[:5])))
    what = "applied" if apply else "saved"
    say = report or (lambda message: None)
    untouched = _(_UNTOUCHED[what])
    tools = config_tools(login, "edgeos", stop)
    if not tools["apply"]:
        raise ToolError(tools["why"])
    say(_("Copying the config to the device…"))
    _stage(login, [(edgeos_script(apply), EDGEOS_SCRIPT), (text, EDGEOS_STAGED)], what, untouched, stop)
    say(_("Loading and committing it: EdgeOS restarts what the change affects…") if apply
        else _("Checking that EdgeOS reads it, then saving it as the boot config…"))
    code, said, sent, dropped = _run_staged(login, f"sh {EDGEOS_SCRIPT}", EDGEOS_STAGED, what, apply, [login],
                                            confirm_within, stop, say, EDGEOS_CONFIG_LOG)
    nothing = "opendisco: nothing to commit" in said
    said = "\n".join(l for l in said.split("\n") if not l.startswith("opendisco:")).strip()
    if code:
        failed = _(EDGEOS_FAILURES[code]) if code in EDGEOS_FAILURES else tr("It failed (exit code {code})", code=code)
        raise ToolError(tr("{failed}. EdgeOS said: {said}", failed=failed, said=said[-400:]) if said and code != 3
                        else failed + ".")
    try:
        stored = _fetch(login, EDGEOS_CONFIG, stop)
    except sshrun.SSHError:
        stored = None
    if apply and nothing:
        done = _("It already runs this config: saved as its boot config too.")
    elif apply:
        done = _("Loaded, committed and saved: it runs the new config, and boots with it.")
    else:
        done = tr("Checked (EdgeOS reads it) and saved as {file}: it takes effect at the next reboot. Until then, any "
                  "other change saved on it (web UI, CLI, UISP) replaces it.", file=EDGEOS_CONFIG)
    if stored is None:
        done = sentences(done, tr("The app couldn't read {file} back to compare.", file=EDGEOS_CONFIG))
    elif boot_lines(stored) != boot_lines(text):
        changed = lines_changed("\n".join(boot_lines(text)), "\n".join(boot_lines(stored)))
        done = sentences(done, tr("EdgeOS stored it with {count} line(s) different from the file: it writes the config "
                                  "in its own order and format.", count=changed))
    if not sent or (dropped and not apply):
        done = sentences(done, _("The connection dropped meanwhile: the device finished on its own, checked after "
                                 "reconnecting."))
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
        raise ToolError(_("Without its MAC address the app can't file a backup of it."))
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
        raise ToolError(tr("{name} is {size:,} bytes: far too big for a device's config.", name=path.name,
                           size=path.stat().st_size))
    data = path.read_bytes()
    if b"\0" in data[:4096]:
        raise ToolError(tr("{name} isn't a text file (a web UI's backup archive is unpacked first).", name=path.name))
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
        if other == "edgeos":
            return tr("It's an EdgeOS {file}, not the {own} this device keeps.", file=CONFIG_NAMES[other],
                      own=CONFIG_NAMES[kind]), ""
        return tr("It's an airOS-style {file}, not the {own} this device keeps.", file=CONFIG_NAMES[other],
                  own=CONFIG_NAMES[kind]), ""
    if problems:
        return (tr("It isn't a {file} that {system} reads: {problems}.", file=CONFIG_NAMES[kind],
                   system=_(_kind_name(kind)), problems="; ".join(problems[:5])), "")
    if meta.get("kind") and meta["kind"] != kind:
        return tr("It's a {file}, not this device's {own}.", file=CONFIG_NAMES.get(meta['kind'], meta['kind']),
                  own=CONFIG_NAMES[kind]), ""
    model = d.model or d.fw_platform or _("device")
    match = same_model(d, meta)
    if match is False:
        return (tr("It's from model {theirs}, and this device is model {model}: a config goes back only to the same "
                   "model.", theirs=meta.get('model') or meta.get('platform'), model=model), "")
    warn = []
    if match is None:
        warn.append(tr("The file doesn't say which model it's from. Upload only a config from another {model}: "
                       "settings for other hardware (radios, interfaces) can leave it unreachable.", model=model))
    if meta.get("mac") and d.mac and core.norm_mac(meta["mac"]) != d.mac:
        warn.append(tr("It's from another device ({device}): its address, name and logins come with it.",
                       device=meta['mac'] + (', ' + meta['name'] if meta.get('name') else '')))
    return "", "\n\n".join(warn)


def _kind_name(kind: str) -> str:
    return {"airos": "airOS", "isp": N_("the device"), "edgeos": "EdgeOS"}.get(kind, N_("the device"))


def config_diff(old: str, new: str, old_name: str | None = None, new_name: str | None = None) -> tuple:
    """(a unified diff from one config to the other, how many lines change): by default from
    the device's config to one to upload; a comparison names its two (a backup's date, "on the
    device now")."""
    import difflib
    old_name = _("on the device") if old_name is None else old_name
    new_name = _("to upload") if new_name is None else new_name
    a, b = old.replace("\r", "").splitlines(), new.replace("\r", "").splitlines()
    diff = "\n".join(difflib.unified_diff(a, b, old_name, new_name, n=2, lineterm=""))
    return diff, lines_changed(old, new)


def read_current(login: sshrun.Login, kind: str, stop=None) -> str:
    """The config the device has now, as a backup of it keeps it (read_device_config)."""
    return read_device_config(login, kind, stop)[0]


def back_up(login: sshrun.Login, d, kind: str, stop=None) -> tuple:
    """Read the device's config and keep it, unless it's the same as its last backup: Back up
    all, run again, doesn't keep copy after copy of a config that hasn't changed. Returns
    ("backed up", the new Backup) or ("unchanged", the last one)."""
    text = read_current(login, kind, stop)
    kept = list_backups(d.mac) if d.mac else []
    try:
        if kept and kept[0].path.read_bytes() == text.encode("utf-8"):
            return "unchanged", kept[0]
    except OSError:
        pass
    return "backed up", save_backup(d, text, kind, "backup")


# -- backing up every device -------------------------------------------------------------

@dataclass
class BackupJob:
    """One device in a Back up all run: its saved login, reaching it through the devices on its
    route (login.via), and how it went."""
    d: object
    kind: str
    login: object = None  # None: no saved login (skipped)
    hops: list = field(default_factory=list)  # the devices on its route, the nearest first
    missing: str = ""  # a device on its route has no saved login: it's backed up only if it answers directly
    state: str = N_("waiting")  # waiting, backing up, backed up, unchanged, failed, skipped, stopped
    said: str = ""  # why it failed or was skipped
    backup: Backup | None = None  # the new one (backed up), or the last one (unchanged)

    @property
    def keys(self) -> set:
        """The devices its SSH sessions log in to: itself, and the ones on its route."""
        return {self.d.key, *(h.key for h in self.hops if self.login is not None and self.login.via)}

    @property
    def text(self) -> str:
        """How it went, for its line in the report."""
        if self.state == "backed up":
            return tr("backed up ({date})", date=self.backup.date)
        if self.state == "unchanged":
            return tr("unchanged since its last backup ({date})", date=self.backup.date)
        if self.state == "failed":
            return tr("failed: {reason}", reason=self.said)
        if self.state == "skipped":
            return tr("skipped: {reason}", reason=self.said)
        if self.state == "stopped":
            return _("not backed up: stopped")
        return _("backing up…") if self.state == "backing up" else _(self.state)

    @property
    def can_retry(self) -> bool:
        """Its own Back up button (which asks for the login) helps: it has an address and a MAC."""
        return self.state in ("skipped", "failed", "stopped") and bool(self.d.ip and self.d.mac)


def backup_jobs(devices, saved_login, route, none: str = N_("no saved login")) -> list:
    """A BackupJob for each device that keeps a config (config_kind). saved_login(d, via) is its
    saved login, reaching it through the logins via (None: there's none); route(d) the devices on
    the way to it, the nearest first. The ones that can't be backed up as they are come last,
    skipped: no saved login (none says so: the phones keep a password only while the app runs),
    no address, no MAC to file the backup under."""
    none = _(none)
    jobs, skipped = [], []
    for d in devices:
        kind = config_kind(d)
        if not kind:
            continue
        job = BackupJob(d, kind)
        if not d.ip or not d.mac:
            job.state, job.said = "skipped", _("no IP address") if not d.ip else _("no MAC address to file it under")
            skipped.append(job)
            continue
        via = ()
        for hop in route(d):
            login = saved_login(hop, via)
            if login is None:
                job.missing = tr("{reason} for {device}, on the way to it", reason=none, device=hop.ip or hop.mac)
                via = ()
                break
            via += (login,)
            job.hops.append(hop)
        job.login = saved_login(d, via)
        if job.login is None:
            job.state, job.said = "skipped", none
            skipped.append(job)
        else:
            jobs.append(job)
    return jobs + skipped


def back_up_all(jobs: list, report=None, stop: threading.Event | None = None, at_once: int = BACKUP_AT_ONCE,
                busy: dict | None = None) -> None:
    """Back up each waiting job's device (back_up), at_once at a time, each in a thread of its own;
    returns when all are done. A job holds its device and the ones on its route while it runs, so
    no device ever has two of its SSH sessions at once. busy: device key -> what else is running
    on it, shared with the other tools (the desktop's): a job's devices are marked "backing up"
    while it runs, and one busy with something else waits its turn, failing if it's still busy
    when nothing else is left. report(job) from a worker thread whenever a job changes. stop: none
    starts after it's set, and those running are cancelled."""
    say = report or (lambda job: None)
    busy = {} if busy is None else busy
    pending = [job for job in jobs if job.state == "waiting"]
    held, running = set(), [0]
    changed = threading.Condition()

    def run(job, keys):
        try:
            _back_up_job(job, stop)
        except Exception as e:  # a bug, not the device: it fails alone
            job.state, job.said = "failed", f"{type(e).__name__}: {e}"
        finally:
            with changed:
                held.difference_update(keys)
                for key in keys:
                    if busy.get(key) in ("backing up", "a backup through it"):
                        busy.pop(key, None)
                running[0] -= 1
                changed.notify_all()
            say(job)

    with changed:
        while pending and not (stop is not None and stop.is_set()):
            ready = next((job for job in pending if not job.keys & held and not any(busy.get(k) for k in job.keys)),
                         None)
            if ready is None and not running[0]:  # the rest wait on devices busy with another tool
                for job in pending:
                    what = next((busy[k] for k in job.keys if busy.get(k)), N_("another tool"))
                    job.state, job.said = "failed", tr("busy ({task})", task=_(what))
                    say(job)
                pending = []
                break
            if ready is None or running[0] >= at_once:
                changed.wait(1)
                continue
            pending.remove(ready)
            keys = ready.keys
            held.update(keys)
            for key in keys:
                busy[key] = N_("backing up") if key == ready.d.key else N_("a backup through it")  # shown by the GUI
            running[0] += 1
            ready.state = "backing up"
            say(ready)
            threading.Thread(target=run, args=(ready, keys), daemon=True).start()
        while running[0]:
            changed.wait(1)
    for job in pending:  # stopped before their turn
        job.state = "stopped"
        say(job)


def _back_up_job(job: BackupJob, stop) -> None:
    """One device's backup, reaching it directly when it answers from here (as logging in to it
    by hand does: devicegui.ask_route), else through the devices on its route."""
    login = job.login
    if (login.via or job.missing) and answers(login.ip, login.port, 2):
        login = replace(login, via=())
    elif job.missing:
        job.state, job.said = "skipped", job.missing
        return
    try:
        job.state, job.backup = back_up(login, job.d, job.kind, stop)
    except sshrun.SSHError as e:
        job.state, job.said = ("stopped", "") if e.kind == "cancelled" else ("failed", str(e))
    except (ToolError, OSError) as e:
        job.state, job.said = "failed", str(e)


def backup_summary(jobs: list) -> str:
    """"3 backed up, 2 unchanged, 1 failed, 4 skipped": how many of each, the ones there are."""
    counts = {}
    for job in jobs:
        counts[job.state] = counts.get(job.state, 0) + 1
    said = {"backed up": tr("{count} backed up", count=counts.get("backed up")),
            "unchanged": tr("{count} unchanged", count=counts.get("unchanged")),
            "failed": tr("{count} failed", count=counts.get("failed")),
            "skipped": tr("{count} skipped", count=counts.get("skipped")),
            "stopped": tr("{count} stopped", count=counts.get("stopped")),
            "backing up": tr("{count} backing up", count=counts.get("backing up")),
            "waiting": tr("{count} waiting", count=counts.get("waiting"))}  # in this order
    return ", ".join(said[s] for s in said if counts.get(s)) or _("no devices that keep a config")


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
        raise ToolError(tr("{device} doesn't answer over SSH.", device=login.where))
    say(_("Restarting it…"))
    try:
        sshrun.run(login, detached(command, REBOOT_LOG), timeout=30, stop=stop)
    except sshrun.SSHError as e:
        if e.kind in ("auth", "key", "cancelled"):
            raise  # otherwise the connection dropping as it goes down
    start, down = time.monotonic(), False
    while time.monotonic() - start < within:
        if stop is not None and stop.is_set():
            raise ToolError(_("Stopped waiting. The device carries on restarting by itself."))
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
                raise ToolError(tr("It didn't restart. It said: {said}", said=said[-300:]) if said else
                                _("It didn't restart (it may be busy, upgrading its firmware)."))
        say(tr("Restarting: waiting for it to come back… {seconds:.0f}s", seconds=elapsed) if down else
            tr("Restarting… {seconds:.0f}s", seconds=elapsed))
    raise ToolError(tr("It hasn't come back after {minutes:.0f} minutes. Give it a few more before power-cycling it.",
                       minutes=within // 60))


def locate(login: sshrun.Login, d, on: bool = True, stop=None) -> bool | None:
    """Start (or stop) blinking its LED. Returns whether it's locating now, as it says (None:
    it doesn't say)."""
    start, end = LOCATE[family(d)]
    result = sshrun.run(login, f"{start if on else end}; echo; cat {LOCATE_STATE} 2>/dev/null", stop=stop)
    if "not found" in result.out + result.err:
        raise ToolError(tr("It has no {program}.", program=start.split()[0]))
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


def _read_written(login: sshrun.Login, command: str, path: str, stop=None) -> str:
    """Run a command that writes its output to path on the device, then bring the file back."""
    sshrun.run(login, command, timeout=90, stop=stop)
    try:
        try:
            return _fetch(login, path, stop)
        except sshrun.SSHError as e:
            if e.kind != "forwarding":
                raise
            return sshrun.run(login, f"cat {path}", timeout=90, stop=stop).out  # through the hop's client
    finally:
        try:
            sshrun.run(login, f"rm -f {path}", stop=stop)
        except sshrun.SSHError:
            pass


def read_scan(login: sshrun.Login, fam: str, stop=None) -> str:
    return _read_written(login, scan_command(fam), SCAN_FILE, stop)


def sections(text: str) -> dict:
    """What the scan and link commands write: {section: [lines]}, each after its "@@name" line."""
    found, name = {}, None
    for line in text.replace("\r", "").split("\n"):
        if line.startswith("@@"):
            name = line[2:].strip()
            found[name] = []
        elif name:
            found[name].append(line)
    return found


def parse_scan(text: str) -> list:
    parts = sections(text)
    found = _arp_sightings(parts.get("arp", []))
    found += _station_sightings("\n".join(parts.get("stations", [])))
    found += _lldp_sightings(parts.get("lldp", []))
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
    found = []
    for s in linkhealth.station_list(text):
        if not _MAC.fullmatch(str(s.get("mac", ""))):
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


# Link health (airMAX): mca-status, airOS's summary of the radio (its mode, channel, noise floor
# and, on a station, its signal and rates; ubntbox, airOS's multi-call program, runs it where it
# isn't a command of its own), and wstalist, its station list, both written to LINK_FILE and
# brought back by scp like a scan's.
LINK_COMMAND = (f"sh -c 'echo @@status; mca-status 2>/dev/null || ubntbox mca-status 2>/dev/null; echo @@stations; "
                f"wstalist 2>/dev/null; echo @@end' >{LINK_FILE} 2>/dev/null")


def read_link(login: sshrun.Login, stop=None) -> dict:
    """The radio's link health (linkhealth.parse); a ToolError when it isn't an airOS radio."""
    parts = sections(_read_written(login, LINK_COMMAND, LINK_FILE, stop))
    status = [line for line in parts.get("status", []) if line.strip()]
    if not any("=" in line for line in status):
        raise ToolError(tr("{device} has no mca-status: it isn't an airOS radio.", device=login.where))
    return linkhealth.parse(status, "\n".join(parts.get("stations", [])))


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


def _check_password(new_password: str) -> None:
    if not new_password or any(ord(c) < 32 for c in new_password):
        raise ToolError(_("The new password can't be empty or hold control characters."))
    if new_password in FACTORY_PASSWORDS:
        raise ToolError(tr("{password} is a factory password, the first one anyone tries: choose another.",
                           password=new_password))


def change_login(text: str, user: str, password: str, new_user: str, new_password: str) -> tuple:
    """The config with the login `user` renamed to new_user and its password replaced, hashed
    the way the device hashed the current one. The current hash is checked against `password`
    first, so a hash the device can't read is never written. Returns (config, scheme)."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", new_user):
        raise ToolError(_("A username is 1 to 32 letters, digits, dots, dashes or underscores, starting with a "
                          "letter or digit."))
    _check_password(new_password)
    lines = text.replace("\r", "").split("\n")
    names = {m.group(1): (n, line.split("=", 1)[1]) for n, line in enumerate(lines)
             if (m := re.match(r"users\.(\d+)\.name=", line))}
    slot = next((k for k, (_n, name) in names.items() if name == user), None)
    if slot is None:
        raise ToolError(tr("The device's config has no login named {user}.", user=user))
    if any(name == new_user for k, (_n, name) in names.items() if k != slot):
        raise ToolError(tr("The device already has another login named {user}.", user=new_user))
    key = f"users.{slot}.password="
    at = next((n for n, line in enumerate(lines) if line.startswith(key)), None)
    if at is None:
        raise ToolError(tr("The device's config has no password for {user}.", user=user))
    current = lines[at][len(key):]
    scheme = hash_scheme(current)
    if not scheme:
        raise ToolError(_("The device stores its password in a format the app doesn't write (not MD5-crypt or "
                          "SHA-crypt), so it's left alone. Change it in the device's web UI."))
    if not verify_password(password, current):
        raise ToolError(_("The stored password doesn't match the one just used to log in, so the app can't be "
                          "sure how the device hashes passwords. Nothing was changed."))
    lines[names[slot][0]] = f"users.{slot}.name={new_user}"
    lines[at] = key + new_hash(new_password, current)
    return "\n".join(lines), scheme


# -- EdgeOS logins --------------------------------------------------------------------------
# UISP Help Center "EdgeRouter - User Accounts" (CLI): set system login user <user> authentication
# plaintext-password <secret>, set system login user <user> level admin, commit; save; log in again with
# the new login, then delete system login user ubnt, commit; save. The commands go through
# vyatta-cfg-cmd-wrapper, as for config uploads. EdgeOS's commit hashes the password itself (SHA-512, with
# mkpasswd) into encrypted-password and blanks plaintext-password (its templates, system/login/user/...),
# and quotes it with ' to do so. Deleting a login ends its sessions first (Vyatta/Login/User.pm): one more
# reason the old one is deleted only once the new one has logged in. The password is on the command line
# of EdgeOS's commands while they run, as when it's typed in its CLI; the script that holds it is
# readable by the login alone, and deletes itself as it starts.
EDGEOS_LOGIN_SCRIPT = "/tmp/opendisco-login.sh"
# EdgeOS 3's rules for a plaintext-password (its template's syntax lines), and what one that breaks a rule is told.
EDGEOS3_PASSWORD = ((r"[a-z]", N_("it has no lower case letter")), (r"[A-Z]", N_("it has no upper case letter")),
                    (r"[0-9]", N_("it has no digit")),
                    (r"[^0-9A-Za-z]", N_("it has no character that's neither a letter nor a digit")))
_WORD = re.compile(r'"(?:[^"\\]|\\.)*"|[^\s"]+')


def _boot_lines(text: str):
    """Each node and setting of a config.boot: (the words of its path, from the top, whether it's a
    node holding others)."""
    body = re.sub(r"/\*.*?\*/", "", text.replace("\r", ""), flags=re.S)
    stack = []
    for line in body.split("\n"):
        line = line.strip()
        if line == "}":
            if stack:
                stack.pop()
        elif line.endswith("{"):
            stack.append([w[1:-1].replace('\\"', '"') if w.startswith('"') else w for w in _WORD.findall(line[:-1])])
            yield [w for part in stack for w in part], True
        elif line:
            words = [w[1:-1].replace('\\"', '"') if w.startswith('"') else w for w in _WORD.findall(line)]
            yield [w for part in stack for w in part] + words, False


def edgeos_users(text: str) -> list:
    """The login names a config.boot has (system login user <name>)."""
    return [path[3] for path, node in _boot_lines(text) if node and len(path) == 4
            and path[:3] == ["system", "login", "user"]]


def boot_settings(text: str, path: tuple) -> list | None:
    """The settings under a node of a config.boot (path: ("system", "login", "user", "ubnt")), each as
    the words that follow the path in EdgeOS's set command: ["level", "admin"], ["authentication",
    "public-keys", "me@laptop", "key", "AAAA…"]. None when it has no such node."""
    found = None
    for words, node in _boot_lines(text):
        if words[:len(path)] == list(path):
            found = found if found is not None else []
            if not node and len(words) > len(path):
                found.append(words[len(path):])
    return found


def edgeos_login(text: str, user: str, new_user: str, new_password: str, version: str = "") -> list:
    """The steps of a new login for an EdgeRouter whose config.boot is text, logged in to as user:
    each a list of config commands (lists of words), committed and saved in turn. A new password is
    one step; a new name two: the new login, with the old one's level and settings, then (logged in
    with it) deleting the old one. version: the EdgeOS it runs, whose password rules apply."""
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", new_user):
        raise ToolError(_("An EdgeOS username is 1 to 32 lower case letters, digits, underscores or dashes, starting "
                          "with a letter or an underscore."))
    _check_password(new_password)
    if "'" in new_password:
        raise ToolError(_("EdgeOS can't take a ' in a password: it quotes the password with them to hash it."))
    if version_key(version)[:1] >= (3,):
        lacks = ([_("it's shorter than 12 characters")] if len(new_password) < 12 else []) + [
            _(lack) for pattern, lack in EDGEOS3_PASSWORD if not re.search(pattern, new_password)]
        if lacks:
            raise ToolError(tr("EdgeOS 3 won't take this password: {problems}.", problems="; ".join(lacks)))
    users = edgeos_users(text)
    if user not in users:
        raise ToolError(tr("Its boot config has no login named {user}, so the app can't tell how it's set up.",
                           user=user))
    if new_user != user and new_user in users:
        raise ToolError(tr("It already has another login named {user}.", user=new_user))
    password = ["set", "system", "login", "user", new_user, "authentication", "plaintext-password", new_password]
    if new_user == user:
        return [[password]]
    kept = [s for s in boot_settings(text, ("system", "login", "user", user)) or []
            if s[:2] not in (["authentication", "encrypted-password"], ["authentication", "plaintext-password"])
            and s[:1] != ["home-directory"]]  # the new login gets a home of its own
    return [[["set", "system", "login", "user", new_user, *s] for s in kept] + [password],
            [["delete", "system", "login", "user", user]]]


def new_login(d, login, text: str, new_user: str, new_password: str) -> tuple:
    """What changing d's login takes, for the windows asking for it: (airMAX: the new config,
    the hash scheme) or (EdgeOS: edgeos_login's steps, None). ToolError when it can't be done."""
    if config_kind(d) == "edgeos":
        return edgeos_login(text, login.user, new_user, new_password, device_version(d)), None
    return change_login(text, login.user, login.password, new_user, new_password)


def new_login_note(d) -> str:
    """How the new password is kept, said where it's typed."""
    if config_kind(d) != "edgeos":
        return _("The new password is stored on the device hashed the way it hashes the current one, never as plain "
                 "text; the app checks its hashing against the current password first.")
    note = _("EdgeOS hashes the new password itself and stores it so, never as plain text.")
    if version_key(device_version(d))[:1] >= (3,):
        note = sentences(note, _("EdgeOS 3 takes a password of 12 characters or more, with lower and upper case "
                                 "letters, a digit and a character that's neither a letter nor a digit."))
    return note


def _edgeos_in_group(script: str) -> str:
    """The start of a script that runs EdgeOS's config commands: in its vyattacfg group, as its own
    scripts do."""
    return ("# EdgeOS's config commands run in its vyattacfg group, as its own scripts do.\n"
            'if [ "$1" != in-group ] && [ "$(id -u)" != 0 ] && [ "$(id -gn)" != vyattacfg ] '
            "&& command -v sg >/dev/null; then\n"
            f'  exec sg vyattacfg -c "sh {script} in-group"\n'
            "fi\n")


def edgeos_login_script(commands: list) -> str:
    """The script for one step of a login change on an EdgeRouter: the config commands, then commit
    and save; one refused, or the commit failing, discards them all. Exit codes: 4 no config
    session, 5 a command refused, 6 commit failed, 7 saving failed."""
    return ("#!/bin/sh\n"
            "# OpenDisco: changes a login on this EdgeRouter, with EdgeOS's config commands, commit and save.\n"
            + _edgeos_in_group(EDGEOS_LOGIN_SCRIPT) +
            f"rm -f {EDGEOS_LOGIN_SCRIPT}  # it holds the new password: read, and gone\n"
            f"W={EDGEOS_WRAPPER}\n"
            "rc=0\n"
            '$W begin || { echo "EdgeOS did not start a config session."; exit 4; }\n'
            + "".join(f"[ $rc = 0 ] && {{ $W {' '.join(shlex.quote(w) for w in words)} || rc=5; }}\n"
                      for words in commands) +
            "if [ $rc = 0 ]; then $W commit || rc=6; fi\n"
            "if [ $rc = 0 ]; then $W save || rc=7; fi\n"
            "case $rc in 5|6) $W discard ;; esac\n"
            "$W end\n"
            "exit $rc\n")


EDGEOS_LOGIN_FAILURES = {
    4: N_("EdgeOS didn't start a config session, so nothing was changed"),
    5: N_("EdgeOS refused the change, so nothing was changed"),
    6: N_("EdgeOS's commit failed, so nothing was changed"),
    7: N_("It's committed, but saving it to the boot config failed: it holds only until the next restart"),
}


def change_edgeos_login(login: sshrun.Login, new: sshrun.Login, steps: list, report=None, stop=None,
                        confirm_within: float = 240) -> str:
    """Change an EdgeRouter's login (the steps of edgeos_login): the new login or password committed
    and saved, then checked by logging in with it; for a new name, the old login is then deleted,
    logged in as the new one. Staged and run detached like write_edgeos. Returns what happened;
    ToolError, LostConnection or SSHError when it didn't."""
    say = report or (lambda message: None)
    tools = config_tools(login, "edgeos", stop)
    if not tools["apply"]:
        raise ToolError(tools["why"])
    script = EDGEOS_LOGIN_SCRIPT
    dropped_any = False
    for n, commands in enumerate(steps):
        acting, logins = (login, [login, new]) if n == 0 else (new, [new])  # each login reads its own log
        both = tr("The new login works; {user} wasn't deleted, so both work now.", user=login.user)
        untouched = (_("Connection lost: the login wasn't changed. The change didn't reach the device.") if n == 0
                     else tr("Connection lost: The new login works; {user} wasn't deleted, so both work now.",
                             user=login.user))
        say(_("Copying the change to the device…") if n == 0 else
            tr("Deleting the old login {old}, logged in as {new}…", old=login.user, new=new.user))
        try:
            sshrun.run(acting, f"rm -f {script}; (umask 077; : >{script})", stop=stop)  # new, and the login's alone
        except sshrun.SSHError as e:
            if e.kind in ("auth", "key", "cancelled"):
                raise
            raise LostConnection(f"{untouched} ({e})", "not done") from None
        _stage(acting, [(edgeos_login_script(commands), script)], "changed", untouched, stop, private=True)
        say(_("Committing and saving it…"))
        code, said, sent, dropped = _run_staged(acting, f"sh {script}", script, "changed", True, logins,
                                                confirm_within, stop, say, EDGEOS_CONFIG_LOG)
        dropped_any = dropped_any or dropped or not sent
        if code:
            failed = (_(EDGEOS_LOGIN_FAILURES[code]) if code in EDGEOS_LOGIN_FAILURES
                      else tr("It failed (exit code {code})", code=code))
            told = tr("{failed}. EdgeOS said: {said}", failed=failed, said=said[-400:]) if said else failed + "."
            if n:
                raise ToolError(sentences(tr("Deleting {user} failed: {reason}", user=login.user, reason=told), both,
                                          tr("Delete {user} in EdgeOS's web UI or CLI.", user=login.user)))
            raise ToolError(told)
        if n == 0:
            say(_("Logging in with the new login…"))
            try:
                sshrun.check_login(new, stop=stop)
            except sshrun.SSHError as e:
                kept = tr("{user} was kept, so both are set on it.", user=login.user) if len(steps) > 1 else ""
                raise ToolError(sentences(tr("EdgeOS took the new login, but logging in with it failed ({error}).",
                                             error=e), kept)) from None
    if len(steps) > 1:
        done = tr("Committed and saved: {new} logs in (checked), and {old} is deleted.", new=new.user, old=login.user)
    else:
        done = tr("Committed and saved: {user} takes the new password (checked by logging in with it).", user=new.user)
    try:
        users = edgeos_users(_fetch(new, EDGEOS_CONFIG, stop))
    except sshrun.SSHError:
        users = None
    if users is None:
        done = sentences(done, tr("The app couldn't read {file} back to check it.", file=EDGEOS_CONFIG))
    elif new.user not in users or (len(steps) > 1 and login.user in users):
        done = sentences(done, tr("Its {file} lists other logins than expected: {users}.", file=EDGEOS_CONFIG,
                                  users=", ".join(users) or _("none")))
    if dropped_any:
        done = sentences(done, _("The connection dropped meanwhile: the device finished on its own, checked after "
                                 "reconnecting."))
    return done


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
