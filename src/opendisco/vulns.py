"""Known vulnerabilities (CVEs) in the firmware of the Ubiquiti gear that discovery identifies.

resources/cves.json lists them: each CVE with the device families and firmware versions it
affects, the version that fixes it, its CVSS severity and a short summary. build_rules() makes
that list from three sources, the first that has a CVE winning:
- CURATED: the ranges checked by hand against Ubiquiti's Security Advisory Bulletins up to
  BULLETINS_REVIEWED, which also covers CVEs the NVD has no product data for;
- newer bulletins, read by parse_bulletin() only where every product, version and fix in a CVE's
  entry is one it understands (BULLETIN_NAMES);
- the NVD's CVE records, whose CPE product names map to families here (CPE_PRODUCTS).
refresh() runs the same build on current data and saves the result in the app's data folder;
check() uses whichever list is newer.

A device is checked only when its family and firmware version are certain: missing a CVE is
better than flagging one falsely. So no match is no proof that a device is safe.

Standard library only, like core.
"""
from __future__ import annotations

import collections
import html
import json
import os
import re
import sys
import threading
import time
import urllib.request
from pathlib import Path

from opendisco import __version__, tls

FORMAT = 1  # of cves.json; a saved list in another format is ignored
BUNDLED = Path(__file__).resolve().parent / "resources" / "cves.json"
CACHE_NAME = "cves.json"  # what refresh() saves in the app's data folder
CACHE_DIR = None  # that folder: the GUI sets it to its data folder, the command line to default_data_dir()
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Every CVE whose CPE data names a Ubiquiti product: "ui" is Ubiquiti's vendor name, "ubnt" its
# older one. The NVD's limit without an API key is 5 requests in 30 seconds.
NVD_QUERIES = ("virtualMatchString=cpe:2.3:o:ui:*", "virtualMatchString=cpe:2.3:a:ui:*",
               "virtualMatchString=cpe:2.3:o:ubnt:*")
NVD_LIMIT = (5, 30.0)
SOURCES = ["NVD (https://nvd.nist.gov)", "Ubiquiti Security Advisory Bulletins (https://community.ui.com/releases)"]


# The NVD's terms of use ask apps that use its API to say this, prominently.
NVD_NOTICE = "This product uses the NVD API but is not endorsed or certified by the NVD."


def nvd_url(cve_id: str) -> str:
    """The NVD's page for a CVE."""
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def default_data_dir() -> Path:
    """The app's data folder, where Toga 0.5 puts it, for the command line to share the app's list."""
    home = Path.home()
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "com.michaelfroehlke.opendisco" / "Data"
    if sys.platform.startswith("win"):
        local = Path(os.environ.get("LOCALAPPDATA") or home / "AppData" / "Local")
        return local / "Nekobyte-Coding" / "OpenDisco" / "Data"  # app.WINDOWS_PUBLISHER
    return Path(os.environ.get("XDG_DATA_HOME") or home / ".local" / "share") / "opendisco"


# ---------------------------------------------------------------------------
# Versions
# ---------------------------------------------------------------------------

_VERSION = re.compile(r"v?(\d+(?:\.\d+)*)(?:-hotfix\.?(\d+))?")
# "XC.qca955x.v8.7.11.46972.220614.0419", "e50.v2.0.9-hotfix.7.5622731.230615.0857": the platform,
# its chip, then the version, a build number (or commit) and the build's date and time.
_FIRMWARE = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9_-]+)?\.v(\d[\w.+-]*)$")
_BUILD_TAIL = re.compile(r"\.[0-9A-Fa-f]{4,}\.\d{6}\.\d{4}$")
_PLAIN = re.compile(r"v?\d+(?:\.\d+){1,2}(?:\.\d{1,3})?(?:-hotfix\.?\d+)?(?:-[A-Za-z][\w.]*)?")  # no build numbers


def version_key(text):
    """A comparable key for a firmware version, or None. "2.0.9-hotfix.7" sorts after 2.0.9
    and its earlier hotfixes; other suffixes ("-cs", "-beta.2") and build metadata ("+34061")
    don't count. A fourth number of four digits or more is a build number and is dropped."""
    m = _VERSION.match(str(text).strip())
    if not m:
        return None
    nums = []
    for part in m.group(1).split("."):
        if len(nums) == 4 or (len(nums) == 3 and len(part) > 3):
            break
        nums.append(int(part))
    if len(nums) < 2:
        return None
    return tuple(nums + [0] * (4 - len(nums))), int(m.group(2) or 0)


def firmware_version(firmware: str):
    """The version in a firmware string: "8.7.11" from XC.qca955x.v8.7.11.46972.220614.0419,
    "2.0.9-hotfix.7" from e50.v2.0.9-hotfix.7.5622731..., "5.1.33" as consoles send it. None when
    the string isn't one of those shapes."""
    fw = (firmware or "").strip()
    m = _FIRMWARE.match(fw)
    rest = _BUILD_TAIL.sub("", m.group(1)) if m else fw
    return rest.lstrip("v") if _PLAIN.fullmatch(rest) else None


# ---------------------------------------------------------------------------
# Device families
# ---------------------------------------------------------------------------

# The platform at the start of the firmware string (as Ubiquiti's firmware server names it) -> family
FIRMWARE_FAMILIES = {
    **dict.fromkeys(("XC", "WA", "2XC", "2WA"), "airmax-ac"),  # airOS 8
    **dict.fromkeys(("XM", "XW", "TI"), "airmax-m"),  # airOS 6 and earlier
    "GP": "af60",  # airFiber 60 and 60 LR
    "AF60": "af60-xg",  # airFiber 60 XG and HD
    "GBE": "gbe",  # airMAX GigaBeam
    **dict.fromkeys(("AF24", "AF24HD", "AF5", "AF5U", "AF5X", "AF2X", "AF3X", "AF4X", "AF11FX"), "airfiber"),
    "ACB": "aircube",
    **dict.fromkeys(("e50", "e100", "e200", "e300", "e1000"), "edgeos"),  # EdgeRouter, by chip
    **dict.fromkeys(("eswh", "esgh"), "edgeswitch"),  # EdgeSwitch 1G and 10G
    "esx": "edgeswitch-x",  # ES-10X, ES-10XP, ES-18X
    "esxp": "edgeswitch-xp",  # ES-5XP, ES-16XP and the TOUGHSwitches it replaced
    **dict.fromkeys(("AirGW", "AirGWP"), "airgateway"),
    **dict.fromkeys(("EP", "EPX"), "edgepower"),
    **dict.fromkeys(("UGW3", "UGW4", "UGWXG"), "usg"),  # USG, USG-Pro-4, USG-XG-8
}
# UniFi OS consoles by the platform they report, as Ubiquiti's device list (static.ui.com/fingerprint)
# and firmware server name them, in the groups the advisories use
CONSOLE_GROUPS = {
    "@dm": ("UDM", "UDMPRO", "UDMPROSE", "UDMPROMAX", "UDMEA4C"),  # Dream Machines: UDMEA4C is the UDM-Beast
    "@dr": ("UDR", "UDR7", "UDR5G"),  # Dream Routers: UDR5G is the UDR-5G-Max
    "@cg": ("UDRULT", "UCGMAX", "UCGF", "UCGA6AD"),  # Cloud Gateways: Ultra, Max, Fiber, Industrial
    "@efg": ("UDMENT", "EFGCORE"),  # Enterprise Fortress Gateway (EFG), Enterprise Firewall Core
    "@ck": ("UCKG2", "UCKP", "UCKENT"),  # Cloud Keys: Gen2, Gen2 Plus, Enterprise
    "@nvr": ("UNVR", "UNVRPRO", "UNVRINS", "UNVRAI4", "UNVRAI8", "ENVR", "ENVRCORE"),  # UNVRAI4/8: UNVR-G2 (Pro)
    "@nas": ("UNAS2", "UNAS2B", "UNAS2W", "UNAS4", "UNAS4B", "UNAS4W", "UNASPRO", "UNASPRO4", "UNASPRO8"),
}
# UDW: Dream Wall; UX: UniFi Express; UXMAX: Express 7; ENAS: Enterprise NAS
CONSOLES = {"UDW", "UX", "UXMAX", "ENAS", *(code for group in CONSOLE_GROUPS.values() for code in group)}
# The ones running UniFi Network: not the NVRs or NAS, nor the EF-Core, which isn't certain to
NETWORK_CONSOLES = CONSOLES - set(CONSOLE_GROUPS["@nvr"]) - set(CONSOLE_GROUPS["@nas"]) - {"ENAS", "EFGCORE"}
# UniFi Gateways: Lite, Max, Fiber, Enterprise, Pro (UXGPROV2: the Pro's current firmware)
UXG_GATEWAYS = {"UXG", "UXGB", "UXGA6AA", "UXGENT", "UXGPRO", "UXGPROV2"}
# Firmware-string prefixes that differ from the platform the console reports
CONSOLE_ALIASES = {"UEX": "UX", "UNVR4": "UNVR"}
UNIFI_APS = {"BZ2", "BZ2LR", "U2HSR", "U2IW", "U2Lv2", "U2O", "U2Sv2", "U5O", "U6ENT", "U6ENTIW", "U6EXT", "U6IW",
             "U6M", "U6MP", "U7EDU", "U7HD", "U7IW", "U7IWP", "U7LR", "U7LT", "U7MP", "U7MSH", "U7NHD", "U7P", "U7PG2",
             "U7PIW", "U7PRO", "U7PROMAX", "U7SHD", "U7UKU", "UAE6", "UAIW6", "UAL6", "UALR6", "UALR6v2", "UALRPL6",
             "UAM6", "UAP6MP", "UAPL6", "UCXG", "UFLHD", "UHDIW", "UXBSDM", "UXSDM"}  # and UAP<hex>; UAPL6 is the U6+
# Switches on the main UniFi switch firmware. The Flex Mini, USW-Ultra and other models with their
# own version numbers aren't here: an advisory's "Version 6.5.32 and earlier" means nothing for them.
UNIFI_SWITCHES = {"S216150", "S224250", "S224500", "S248500", "S248750", "S28150", "US16P150", "US24", "US24P250",
                  "US24P500", "US24PL2", "US24PRO", "US24PRO2", "US48", "US48P500", "US48P750", "US48PL2", "US48PRO",
                  "US48PRO2", "US624P", "US648P", "US68P", "US6XG150", "US8", "US8P150", "US8P60", "USAGGPRO", "USC8",
                  "USC8P450", "USF5P", "USFXG", "USL16LP", "USL16LPB", "USL16P", "USL16PB", "USL24", "USL24B", "USL24P",
                  "USL24PB", "USL48", "USL48B", "USL48P", "USL48PB", "USL8A", "USL8LP", "USL8LPB", "USL8MP", "USLP8P",
                  "USPM16", "USPM16P", "USPM24", "USPM24P", "USPM48", "USPM48P", "USXG", "USXG24", "USWED42", "USWED43",
                  "USWED44", "USWED45", "USWED72", "USWED73", "USWED74", "USWED75", "USWED76", "USWED77", "USWF001",
                  "USWF002", "USWF003", "USWF004", "USWF005", "USWF006", "USWF007", "USWF067", "USWF069"}
UNIFI_FAMILIES = {**dict.fromkeys(CONSOLES, "unifi-os"), **dict.fromkeys(UNIFI_APS, "unifi-ap"),
                  **dict.fromkeys(UNIFI_SWITCHES, "unifi-switch"), **dict.fromkeys(UXG_GATEWAYS, "uxg"),
                  **dict.fromkeys(("ULTE", "ULTEPEU", "ULTEPUS"), "unifi-lte"), "UBB": "ubb", "UBBXG": "ubb"}
_FAMILY_OF = {name.casefold(): (family, name) for table in (FIRMWARE_FAMILIES, UNIFI_FAMILIES)
              for name, family in table.items()}
# The models a rule covers when it names none
DEFAULT_MODELS = {"unifi-network": NETWORK_CONSOLES - {"UX"}}  # the UniFi Express's Network lags behind
# Versions below these aren't checked: legacy APs stay on 4.x, which later advisories don't cover,
# and the first UXG-Pro firmware (1.x) never moved to the line the gateway advisories are about.
FAMILY_FLOORS = {"unifi-ap": "5.0.0", "uxg": "2.0.0"}
FAMILY_SOFTWARE = {"airmax-ac": "airOS", "airmax-m": "airOS", "edgeos": "EdgeOS", "edgeswitch": "EdgeSwitch",
                   "edgeswitch-x": "EdgeSwitch", "edgeswitch-xp": "EdgeSwitch", "unifi-os": "UniFi OS",
                   "uxg": "UniFi OS", "unifi-network": "UniFi Network"}


def _family_of(name):
    name = str(name or "").strip()
    name = CONSOLE_ALIASES.get(name, name)
    hit = _FAMILY_OF.get(name.casefold())
    if hit:
        return hit
    if name.upper().startswith("UAP") and len(name) > 3 and name[3:].isalnum():
        return "unifi-ap", name  # UAPA6xx: the U7 APs are named by a code
    return None


def device_family(d):
    """(family, model) by the platform or model a device reports, or None when it's none the
    list knows."""
    info = d.info
    for name in (info.get("platform"), info.get("model"), info.get("product_name"), d.fw_platform):
        hit = _family_of(name)
        if hit:
            return hit
    return None


def targets(d) -> list:
    """What of a device the list can check: [(family, model, version)]. Empty when its family or
    firmware version isn't certain. A console adds its UniFi Network version."""
    info = d.info
    version = firmware_version(info.get("firmware") or "")
    hit = device_family(d) if version else None
    if not hit:
        return []
    family, model = hit
    found = [(family, model, version)]
    network = info.get("version")
    if family == "unifi-os" and model in NETWORK_CONSOLES and isinstance(network, str):
        network = network.strip().lstrip("v")
        key = version_key(network)
        # Only a version that can be UniFi Network's (5.x and up), and not the firmware's again
        if key and key[0][0] >= 5 and _PLAIN.fullmatch(network) and key != version_key(version):
            found.append(("unifi-network", model, network))
    return found


# ---------------------------------------------------------------------------
# The list
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_current = None  # (data, where it came from)


def _read(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("format") != FORMAT or not isinstance(data.get("cves"), list):
        return None
    return data


def current():
    """(the list in use, "bundled" or "downloaded"): the bundled list, or one refresh() saved in
    CACHE_DIR when that's newer and was built by this version (whose curated ranges it holds)."""
    global _current
    with _lock:
        if _current is None:
            bundled = _read(BUNDLED) or {"format": FORMAT, "generated": "", "cves": []}
            cached = _read(Path(CACHE_DIR) / CACHE_NAME) if CACHE_DIR else None
            if (cached and cached.get("built_by") == __version__
                    and str(cached.get("generated", "")) > str(bundled.get("generated", ""))):
                _current = (cached, "downloaded")
            else:
                _current = (bundled, "bundled")
        return _current


def reload() -> None:
    """Read the lists again (after CACHE_DIR changes or a refresh)."""
    global _current
    with _lock:
        _current = None


def list_info() -> dict:
    data, where = current()
    return {"date": data.get("generated") or None, "cves": len(data["cves"]), "from": where,
            "read_from_advisories": sum(c.get("source") == "advisory" for c in data["cves"]),
            "sources": data.get("sources", SOURCES)}


def list_label() -> str:
    """ "list of 2026-10-24" """
    date = current()[0].get("generated")
    return f"list of {date}" if date else "list (date unknown)"


Match = collections.namedtuple("Match", "cve family version fixed")


def _applies(a: dict, family: str, model: str, key) -> bool:
    if a["family"] != family:
        return False
    models = a.get("models") or DEFAULT_MODELS.get(family)
    if models and model not in models:
        return False
    for floor in (a.get("from"), FAMILY_FLOORS.get(family)):
        if floor and key < version_key(floor):
            return False
    if a.get("before"):
        return key < version_key(a["before"])
    if a.get("through"):  # as precise as the bound: "through 5.1.33" includes 5.1.33.44
        bound, n = version_key(a["through"]), _precision(a["through"])
        return (key[0][:n], key[1]) <= (bound[0][:n], bound[1])
    return False


def _precision(text) -> int:
    """How many numbers a version gives (up to 4): 3 for "5.1.33", 4 for "6.5.28.1"."""
    m = _VERSION.match(str(text).strip())
    return min(4, len(m.group(1).split("."))) if m else 4


def check(d):
    """The known CVEs a device's firmware matches, most severe first, as Matches; [] when it was
    checked and nothing matched; None when its family or firmware version isn't certain."""
    found = targets(d)
    if not found:
        return None
    cves = current()[0]["cves"]
    matches = []
    for family, model, version in found:
        key = version_key(version)
        for cve in cves:
            hit = next((a for a in cve.get("affects", ()) if _applies(a, family, model, key)), None)
            if hit:
                matches.append(Match(cve, family, version, hit.get("fixed")))
    return sorted(matches, key=lambda m: (m.cve.get("score") or 0, m.cve["id"]), reverse=True)


LEVELS = {"critical": "error", "high": "warn", "medium": "warn", "low": "note"}
_RANK = {"note": 0, "warn": 1, "error": 2}


def _software(m: Match) -> str:
    return FAMILY_SOFTWARE.get(m.family, "Firmware")


def issue(matches) -> tuple:
    """(level, message) for a device's Status: each CVE id, and the version that fixes them."""
    level = max((LEVELS.get(m.cve.get("severity"), "warn") for m in matches), key=_RANK.get)
    parts = []
    by_software = collections.OrderedDict()
    for m in matches:
        by_software.setdefault((m.family, m.version), []).append(m)
    for (family, version), group in by_software.items():
        name = _software(group[0])
        counts = collections.Counter(m.cve.get("severity") or "unrated" for m in group)
        tally = ", ".join(f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "unrated") if counts[s])
        n = len(group)
        text = (f"{name} {version} has {n} known vulnerabilit{'y' if n == 1 else 'ies'} ({tally}): "
                + ", ".join(m.cve["id"] for m in group) + ".")
        fixes = [m.fixed for m in group if m.fixed]
        unfixed = [m.cve["id"] for m in group if not m.fixed]
        if fixes:
            best = max(fixes, key=version_key)
            text += f" Upgrade{' UniFi Network' if family == 'unifi-network' else ''} to {best} or later"
            text += f" (no fixed version is named for {', '.join(unfixed)})." if unfixed else "."
        else:
            text += " No fixed version is named: update to the latest firmware."
        parts.append(text)
    return level, " ".join(parts)


def detail_lines(matches) -> list:
    """One line a match, for Details: id, severity, what it affects and what fixes it, summary."""
    lines = []
    for m in matches:
        score = m.cve.get("score")
        rating = f"{m.cve.get('severity') or 'unrated'}{f' {score:g}' if score is not None else ''}"
        fixed = f"fixed in {m.fixed}" if m.fixed else "no fix named"
        lines.append(f"{m.cve['id']:<16} {rating:<13} {_software(m)} {m.version}, {fixed}: {m.cve.get('summary', '')}")
    return lines


def to_dict(matches) -> list:
    return [{"id": m.cve["id"], "severity": m.cve.get("severity"), "score": m.cve.get("score"),
             "software": _software(m), "version": m.version, "fixed_in": m.fixed,
             "summary": m.cve.get("summary"), "published": m.cve.get("published"), "url": nvd_url(m.cve["id"]),
             "source": m.cve.get("source"), "advisory": m.cve.get("advisory")}
            for m in matches]


# ---------------------------------------------------------------------------
# Building the list
# ---------------------------------------------------------------------------

# NVD CPE product -> (family, model, models or None for all of the family). Products not here aren't
# checked: airgateway_firmware, for one, gives its fix as 1.15 where the CVE's text says 1.1.5.
CPE_PRODUCTS = {
    "airmax_ac_firmware": ("airmax-ac", None), "airmax_m_firmware": ("airmax-m", None),
    "airmax_m_xm_firmware": ("airmax-m", "XM"), "airmax_m_xw_firmware": ("airmax-m", "XW"),
    "airmax_m_ti_firmware": ("airmax-m", "TI"),
    "airfiber_af60_firmware": ("af60", None), "airfiber_60_firmware": ("af60", None),
    "airfiber_60-lr_firmware": ("af60", None), "airfiber_af60-xg_firmware": ("af60-xg", None),
    "airfiber_60-xg_firmware": ("af60-xg", None), "airfiber_60-hd_firmware": ("af60-xg", None),
    "airfiber_gigabeam_firmware": ("gbe", None),
    "af5_firmware": ("airfiber", "AF5"), "af5x_firmware": ("airfiber", "AF5X"), "af-2x_firmware": ("airfiber", "AF2X"),
    "airfiber_af24_firmware": ("airfiber", "AF24"), "airfiber_af24hd_firmware": ("airfiber", "AF24HD"),
    "aircube_firmware": ("aircube", None),
    "edgeos": ("edgeos", None), "edgemax_edgerouter_firmware": ("edgeos", None),
    "edgeswitch": ("edgeswitch", None), "edgeswitch_firmware": ("edgeswitch", None),
    "edgeswitch_x": ("edgeswitch-x", None), "edgeswitch_xp_firmware": ("edgeswitch-xp", None),
    "edgemax_edgepower_24v_firmware": ("edgepower", None), "edgemax_edgepower_54v_firmware": ("edgepower", None),
    "usg_firmware": ("usg", "UGW3"), "usg-pro-4_firmware": ("usg", "UGW4"),
    "unifi_uap_firmware": ("unifi-ap", None), "unifi_access_point_firmware": ("unifi-ap", None),
    "unifi_switch_firmware": ("unifi-switch", None),
    "ubb_firmware": ("ubb", "UBB"), "ubb-xg_firmware": ("ubb", "UBBXG"),
    "unifi_network_application": ("unifi-network", None), "unifi_network_controller": ("unifi-network", None),
    "unifi_dream_machine_firmware": ("unifi-os", "UDM"), "unifi_dream_machine_pro_firmware": ("unifi-os", "UDMPRO"),
    "unifi_dream_machine_special_edition_firmware": ("unifi-os", "UDMPROSE"),
    "unifi_dream_machine_pro_max_firmware": ("unifi-os", "UDMPROMAX"),
    "unifi_dream_machine_beast_firmware": ("unifi-os", "UDMEA4C"),
    "enterprise_fortress_gateway_firmware": ("unifi-os", "UDMENT"),
    "enterprise_firewall_core_firmware": ("unifi-os", "EFGCORE"),
    "unifi_cloud_gateway_industrial_firmware": ("unifi-os", "UCGA6AD"),
    "unifi_network_video_recorder_g2_firmware": ("unifi-os", "UNVRAI4"),
    "unifi_network_video_recorder_g2_pro_firmware": ("unifi-os", "UNVRAI8"),
    "unas_2_firmware": ("unifi-os", ("UNAS2", "UNAS2B", "UNAS2W")),
    "unas_4_firmware": ("unifi-os", ("UNAS4", "UNAS4B", "UNAS4W")),
    "unas_pro_firmware": ("unifi-os", "UNASPRO"), "unas_pro_4_firmware": ("unifi-os", "UNASPRO4"),
    "unas_pro_8_firmware": ("unifi-os", "UNASPRO8"),
    "unifi_dream_router_firmware": ("unifi-os", "UDR"), "unifi_dream_router_7_firmware": ("unifi-os", "UDR7"),
    "unifi_dream_router_5g_max_firmware": ("unifi-os", "UDR5G"), "unifi_dream_wall_firmware": ("unifi-os", "UDW"),
    "unifi_cloud_gateway_ultra_firmware": ("unifi-os", "UDRULT"),
    "unifi_cloud_gateway_max_firmware": ("unifi-os", "UCGMAX"),
    "unifi_cloud_gateway_fiber_firmware": ("unifi-os", "UCGF"),
    "unifi_express_firmware": ("unifi-os", "UX"), "unifi_express_7_firmware": ("unifi-os", "UXMAX"),
    "unifi_cloudkey_firmware": ("unifi-os", "UCKG2"), "unifi_cloud_key_gen2_firmware": ("unifi-os", "UCKG2"),
    "cloud_key_gen2": ("unifi-os", "UCKG2"), "unifi_cloud_key_plus_firmware": ("unifi-os", "UCKP"),
    "unifi_cloud_key_gen2_plus_firmware": ("unifi-os", "UCKP"), "cloud_key_gen2_plus": ("unifi-os", "UCKP"),
    "unifi_cloudkey_enterprise_firmware": ("unifi-os", "UCKENT"),
    "unifi_network_video_recorder_firmware": ("unifi-os", "UNVR"),
    "unifi_network_video_recorder_pro_firmware": ("unifi-os", "UNVRPRO"),
    "unifi_network_video_recorder_instant_firmware": ("unifi-os", "UNVRINS"),
    "enterprise_network_video_recorder_firmware": ("unifi-os", "ENVR"),
    "enterprise_network_video_recorder_core_firmware": ("unifi-os", "ENVRCORE"),
}
# EdgeRouter models (CPE hardware or firmware names) -> the chip platform their firmware is built for
EDGEROUTERS = {"er-x": "e50", "er-x-sfp": "e50", "er-10x": "e50", "ep-r6": "e50", "edgerouter_x": "e50",
               "erlite-3": "e100", "erpoe-5": "e100", "er-8": "e200", "erpro-8": "e200", "ep-r8": "e200",
               "er-4": "e300", "er-6p": "e300", "er-12": "e300", "er-12p": "e300", "er-8-xg": "e1000"}
CPE_PRODUCTS.update({f"{name}_firmware": ("edgeos", platform) for name, platform in EDGEROUTERS.items()})

# CVEs checked by hand against Ubiquiti's bulletins (or the NVD's own text, for the ones before them):
# id -> (published, CVSS score, affected ranges, summary). Where the bulletin and the NVD disagree,
# only the range both agree on is used. A range: "family[:models] [>=first] <fixed | <=last | =only
# [fix version]", "fix ?" where no fixed version is named, models comma-separated, @name for a
# group of consoles. These replace what the CPE data would give, and add the CVEs that have none.
CURATED = {
    # airMAX, airFiber, airCube
    "CVE-2010-5330": ("2019-06-11", 9.8, "airmax-m >=4.0.2 <5.3.5",
                      "Command injection through the ifname parameter of the web UI's AP-info page (stainfo.cgi)."),
    "CVE-2015-9266": ("2018-09-05", 9.8, "airmax-m <5.5.10 fix 5.6.2; airmax-m >=5.6.0 <5.6.2; "
                                         "airfiber:AF24,AF24HD,AF5 <2.2.1; airfiber:AF5X <3.0.2.1; airgateway <1.1.5; "
                                         "edgeswitch-xp <1.3.2",
                      "The web UI lets an unauthenticated attacker write files anywhere (directory traversal) "
                      "and gain root."),
    "CVE-2017-0938": ("2019-02-12", 7.5, "airmax-ac <8.3.2; airmax-m <6.0.7; edgeos <1.9.7",
                      "The discovery service (UDP 10001) can be abused to amplify denial-of-service attacks."),
    "CVE-2020-8168": ("2020-05-26", 8.8, "airmax-m <=6.2.0 fix 6.3.0",
                      "Web UI endpoints lack CSRF protection: a page a logged-in user visits can change the "
                      "configuration or firmware."),
    "CVE-2020-8170": ("2020-05-26", 6.1, "airmax-m <=6.2.0 fix 6.3.0",
                      "Reflected cross-site scripting in the web UI can take over the admin's session."),
    "CVE-2020-8171": ("2020-05-26", 9.8, "airmax-m <=6.2.0 fix 6.3.0",
                      "Command injection in several web UI endpoints leads to remote code execution."),
    "CVE-2022-44565": ("2022-12-23", 5.3, "airmax-ac <8.7.11; af60 <2.6.2; af60-xg <1.0.0; gbe <1.4.1",
                       "Status and usage data can be read without proper access checks."),
    "CVE-2026-21639": ("2026-01-08", 8.8, "airmax-ac <=8.7.20 fix 8.7.21; airmax-m <=6.3.22 fix 6.3.24; "
                                          "af60-xg <=1.2.2 fix 1.2.3; af60 <=2.6.7 fix 2.6.8",
                       "Remote code execution by anyone in Wi-Fi range, through a flaw in the airMAX wireless "
                       "protocol."),
    "CVE-2023-23119": ("2023-02-02", 5.9, "airfiber:AF2X <3.2.2 fix ?",
                       "Firmware updates are only checked with a CRC, so a man-in-the-middle can slip in a "
                       "modified image."),
    "CVE-2023-31998": ("2023-07-18", 7.5, "edgeos <=2.0.9-hotfix.6 fix 2.0.9-hotfix.7; aircube <=2.8.8 fix 2.8.9",
                       "A heap overflow lets an attacker crash the UPnP service (when UPnP is on)."),
    "CVE-2026-21638": ("2026-01-08", 8.8, "ubb:UBB <=3.1.5 fix 3.1.7; ubb:UBBXG <=1.2.2 fix 1.2.3",
                       "Remote code execution by anyone in Wi-Fi range, through a flaw in the airMAX wireless "
                       "protocol."),
    # EdgeRouter (EdgeOS) and USG
    "CVE-2017-0932": ("2018-03-22", 8.8, "edgeos <=1.9.1.1",
                      "An operator (read-only) user with SSH access can gain admin (root) rights through the "
                      "Feature functionality."),
    "CVE-2017-0933": ("2018-03-22", 8.0, "edgeos <=1.9.1",
                      "Cross-site request forgery: an operator account can lure an admin into granting it admin "
                      "rights."),
    "CVE-2017-0934": ("2018-03-22", 8.8, "edgeos <=1.9.1",
                      "An operator (read-only) user can read sensitive files and escalate to admin (root)."),
    "CVE-2017-0935": ("2018-03-22", 8.8, "edgeos <=1.9.1.1",
                      "An operator (read-only) user can read sensitive files and escalate to admin (root)."),
    "CVE-2018-5265": ("2019-06-07", 7.2, "edgeos:e100 =1.9.1",
                      "An admin can inject shell commands through the static host mapping settings (EdgeRouter "
                      "Lite)."),
    "CVE-2019-16889": ("2019-09-25", 7.5, "edgeos <2.0.3",
                       "Requests with many different session cookies fill the disk (denial of service)."),
    "CVE-2021-22909": ("2021-05-27", 7.5, "edgeos <=2.0.9 fix 2.0.9-hotfix.1",
                       "Firmware updates can be tampered with by a man-in-the-middle."),
    "CVE-2022-43553": ("2022-12-05", 8.8, "edgeos <=2.0.9-hotfix.4 fix 2.0.9-hotfix.5",
                       "An operator account can run arbitrary admin commands."),
    "CVE-2023-23912": ("2023-02-09", 8.8, "edgeos <=2.0.9-hotfix.5 fix 2.0.9-hotfix.6; usg <=4.4.56 fix 4.4.57",
                       "With DHCPv6 prefix delegation on, an attacker directly on the WAN side can execute code."),
    "CVE-2019-25651": ("2026-03-27", 8.3, "usg <4.4.34",
                       "Traffic to the controller uses AES-CBC, from which an attacker capturing enough of it "
                       "can recover the key."),
    # EdgeSwitch and EdgePower
    "CVE-2018-12590": ("2018-06-20", 7.2, "edgeswitch <=1.7.3",
                       "An admin can escape the restricted CLI through a format-string flaw and run any code."),
    "CVE-2018-12591": ("2018-06-20", 7.2, "edgeswitch <=1.7.3",
                       "An admin can escape the restricted CLI through command injection and run shell commands."),
    "CVE-2019-5445": ("2019-07-10", 4.9, "edgeswitch <1.8.2", "An admin can crash the SSH CLI with crafted commands."),
    "CVE-2019-5446": ("2019-07-10", 7.2, "edgeswitch <1.8.2", "An admin can inject commands that run as root."),
    "CVE-2020-8126": ("2020-02-07", 7.8, "edgeswitch <1.7.1",
                      "An operator (privilege 1) user can become administrator through a CGI script that runs "
                      "local commands."),
    "CVE-2020-8232": ("2020-08-17", 6.5, "edgeswitch <1.8.5 fix 1.9.1",
                      "Read-only users can get information they shouldn't through the SNMP community pages."),
    "CVE-2020-8233": ("2020-08-17", 8.8, "edgeswitch <1.8.5 fix 1.9.1",
                      "A read-only user can run shell commands over the web UI and escalate privileges."),
    "CVE-2020-8234": ("2020-08-21", 9.8, "edgeswitch <1.8.5 fix 1.9.1; edgeswitch >=1.9.0 <1.9.1",
                      "The legacy web UI's admin session cookie can be guessed, leading to a root shell."),
    "CVE-2025-27211": ("2025-08-04", 7.5, "edgeswitch <=1.10.4 fix 1.11.0",
                       "Command injection by an attacker on an adjacent network."),
    "CVE-2025-48978": ("2025-08-21", 7.5, "edgeswitch <=1.11.0 fix 1.11.1",
                       "Command injection by an attacker on an adjacent network (a second flaw)."),
    "CVE-2026-77532": ("2026-08-26", 8.8, "edgeswitch <=1.12.1 fix 1.12.2",
                       "A buffer overflow in DHCPv6 lets an attacker on an adjacent network execute code (when "
                       "DHCPv6 is on)."),
    "CVE-2019-5424": ("2019-04-10", 8.8, "edgeswitch-x <=1.1.0 fix 1.1.1",
                      "A privileged user can run shell commands as root through the SSH CLI."),
    "CVE-2019-5425": ("2019-04-10", 8.8, "edgeswitch-x <=1.1.0 fix 1.1.1",
                      "A logged-in user can run shell commands over SSH, bypassing the CLI, and escalate to root."),
    "CVE-2019-5426": ("2019-04-10", 4.8, "edgeswitch-x <=1.1.0 fix 1.1.1",
                      "With SSH on, its port forwarding works without credentials: an attacker can reach local "
                      "services or relay traffic through the switch."),
    "CVE-2020-8282": ("2020-12-14", 8.8, "edgepower <=1.7.0 fix 1.8.0",
                      "Missing CSRF protection in the web UI allows remote code execution."),
    # UniFi access points, switches, LTE Backup
    "CVE-2021-44527": ("2021-12-07", 6.5, "unifi-switch <=5.64.8 fix 5.76.6",
                       "An attacker already on the network can crash the switch (denial of service)."),
    "CVE-2023-35085": ("2023-08-10", 9.8, "unifi-ap <=6.5.50 fix 6.5.62; unifi-switch <=6.5.32 fix 6.5.59",
                       "An integer overflow in SNMP monitoring (on by default) allows remote code execution."),
    "CVE-2023-38034": ("2023-08-10", 9.8, "unifi-ap <=6.5.53 fix 6.5.62; unifi-switch <=6.5.32 fix 6.5.59",
                       "Command injection in the DHCP client allows remote code execution."),
    "CVE-2024-22054": ("2024-02-20", 7.5, "unifi-ap <6.6.55; unifi-switch <6.6.61; unifi-lte <6.6.57; "
                                          "unifi-os:UX <3.2.5",
                       "A malformed discovery packet can stop device management and discovery (on the UniFi "
                       "Express, in mesh mode only)."),
    "CVE-2024-37380": ("2024-07-22", 5.3, "unifi-ap:UAPL6 <=6.6.65 fix 6.6.74",
                       "Traffic from access points meshed to a U6+ can be forwarded to the wrong VLAN."),
    # UniFi OS consoles
    "CVE-2020-8148": ("2020-04-13", 5.3, "unifi-os:UCKG2,UCKP <1.1.6 fix ?",
                      "Unauthenticated API requests can change the Cloud Key's hostname."),
    "CVE-2020-8157": ("2020-05-02", 6.8, "unifi-os:UCKG2,UCKP <=1.1.10",
                      "Root access through the serial (UART) port without a password."),
    "CVE-2023-28361": ("2023-05-11", 6.5, "unifi-os:UCKG2,UCKP,UNVR,UNVRPRO,UDM,UDMPRO,UDMPROSE,UDR <2.6 fix 3.0.13",
                       "Cross-site WebSocket hijacking: a page a logged-in user visits can read confidential "
                       "information."),
    "CVE-2023-31997": ("2023-07-01", 9.0, "unifi-os:UCKG2,UCKP >=3.1.0 <3.1.13",
                       "Cloud Keys hosting UniFi Network expose its MongoDB database to the local network."),
    "CVE-2025-23091": ("2025-02-01", 5.9, "unifi-os:UDM,UDMPRO,UDMPROSE,UDMPROMAX <=4.0.21 fix 4.1.13; "
                                          "unifi-os:UDW,UCGMAX <=4.0.20 fix 4.1.13; unifi-os:UNVR,UNVRPRO <=4.0.18 "
                                          "fix 4.1.11; unifi-os:UCKG2,UCKP,UCKENT <=4.0.20 fix 4.1.11; "
                                          "unifi-os:UDMENT <=4.0.21 fix 4.1.13",
                       "With Identity Enterprise configured, application updates can be intercepted by a "
                       "man-in-the-middle."),
    "CVE-2026-34908": ("2026-05-22", 10.0, "@064",
                       "Improper access control lets anyone on the network make unauthorized changes."),
    "CVE-2026-34909": ("2026-05-22", 10.0, "@064; unifi-os:UX <=4.0.13 fix 4.0.14",
                       "Path traversal gives access to files that can be used to take over an account on the "
                       "system."),
    "CVE-2026-34910": ("2026-05-22", 10.0, "@064", "Command injection by anyone on the network."),
    "CVE-2026-34911": ("2026-05-22", 7.7, "@064", "Path traversal lets a low-privileged user read sensitive files."),
    "CVE-2026-47368": ("2026-06-12", 8.6, "@065", "Path traversal lets anyone on the network obtain data."),
    "CVE-2026-47369": ("2026-06-12", 9.9, "@065", "A low-privileged user can escalate privileges."),
    "CVE-2026-47370": ("2026-06-12", 9.9, "@065", "Command injection by a low-privileged user."),
    "CVE-2026-48610": ("2026-06-12", 8.1, "unifi-os:UDM,UDMPRO,UDMPROSE,UDMPROMAX,UDMENT,UDW,@dr,UXMAX,@cg <=5.1.12 "
                                          "fix 5.1.15; unifi-os:UDMEA4C <=5.1.11 fix 5.1.15",
                       "Under some network configurations, anyone on the network can make unauthorized changes."),
    "CVE-2026-54401": ("2026-07-02", 8.8, "@066",
                       "Server-side request forgery lets a low-privileged user escalate privileges."),
    "CVE-2026-54402": ("2026-07-02", 8.8, "@066", "Command injection on the host by a low-privileged user."),
    "CVE-2026-54403": ("2026-07-02", 8.6, "@066", "Path traversal bypasses authentication."),
    "CVE-2026-54404": ("2026-07-02", 8.8, "@066", "SQL injection lets a low-privileged user escalate privileges."),
    "CVE-2026-55110": ("2026-07-02", 6.1, "@066",
                       "A CORS misconfiguration lets a malicious page act with a logged-in user's session."),
    "CVE-2026-55112": ("2026-07-02", 8.8, "unifi-os:UDMPRO,UDMPROSE,UDMPROMAX,UDMEA4C,UDW,@dr,UCKP,@nvr,UCGMAX,"
                                          "UCGA6AD,UCGF <=5.1.15 fix 5.1.19",
                       "With UniFi Protect installed, a low-privileged user can escalate privileges on the host "
                       "under certain conditions."),
    "CVE-2026-55116": ("2026-07-02", 9.8, "unifi-os:@dm,UDMENT,UDW,@dr,UXMAX,@cg <=5.1.15 fix 5.1.19; "
                                          "unifi-os:EFGCORE <=5.1.18 fix 5.1.19",
                       "Under some network configurations, anyone on the network can make unauthorized changes."),
    "CVE-2026-77534": ("2026-08-26", 9.9, "@067", "Improper access control lets a low-privileged user escalate "
                                                  "privileges."),
    "CVE-2026-77536": ("2026-08-26", 9.9, "@067", "Improper access control lets a low-privileged user escalate "
                                                  "privileges (a second flaw)."),
    "CVE-2026-77545": ("2026-08-26", 9.0, "@067", "Debug code left in lets a low-privileged user escalate "
                                                  "privileges under certain conditions."),
    "CVE-2026-77549": ("2026-08-26", 9.0, "@067; unifi-os:UX <=4.0.16 fix 4.0.17",
                       "CRLF injection bypasses authentication under certain conditions."),
    "CVE-2026-77550": ("2026-08-26", 10.0, "@067; unifi-os:UX <=4.0.16 fix 4.0.17",
                       "CRLF injection lets anyone on the network bypass authentication."),
    "CVE-2026-77544": ("2026-09-22", 7.5, "@069", "An out-of-bounds write lets anyone on the network crash the "
                                                  "gateway (denial of service)."),
    "CVE-2026-77555": ("2026-09-22", 7.5, "@069", "An out-of-bounds write lets anyone on the network crash the "
                                                  "gateway (a second flaw)."),
    "CVE-2026-77556": ("2026-09-22", 7.5, "@069", "An out-of-bounds read lets anyone on the network crash the "
                                                  "gateway."),
    "CVE-2026-77558": ("2026-09-22", 7.5, "@069", "An out-of-bounds read lets anyone on the network crash the "
                                                  "gateway (a second flaw)."),
    "CVE-2026-95861": ("2026-09-22", 7.5, "@069", "Uncontrolled recursion lets anyone on the network crash the "
                                                  "gateway."),
    "CVE-2026-95862": ("2026-09-22", 7.5, "@069", "An out-of-bounds write lets anyone on the network crash the "
                                                  "gateway (a third flaw)."),
    # UniFi Network on consoles
    "CVE-2021-44530": ("2022-01-14", 9.8, "unifi-network <=6.5.53 fix 6.5.54",
                       "The Log4j flaw (Log4Shell) lets an attacker take control of the application."),
    "CVE-2023-32000": ("2023-07-08", 4.8, "unifi-network <=7.3.83 fix 7.4.156",
                       "Cross-site scripting lets a site administrator gain more rights by luring an admin to a "
                       "page."),
    "CVE-2023-41721": ("2023-10-25", 5.3, "unifi-network:UDM,UDMPRO,UDMPROSE,UDR,UDW <=7.5.176 fix 7.5.187",
                       "Device adoption on gateway consoles lets anyone on the network reach device configuration."),
    "CVE-2025-24292": ("2025-06-29", 6.8, "unifi-network <=9.0.108 fix 9.0.114",
                       "When Enterprise Wi-Fi and the VPN server share a RADIUS profile, a device's MAC address "
                       "can be used to log in to either."),
    "CVE-2026-22557": ("2026-03-19", 10.0, "@062",
                       "Path traversal gives access to files that can be used to take over an account on the "
                       "system."),
    "CVE-2026-22558": ("2026-03-19", 7.7, "@062", "NoSQL injection lets an authenticated user escalate privileges."),
    "CVE-2026-54405": ("2026-07-02", 7.5, "unifi-network <=10.3.58 fix 10.4.57",
                       "Malformed input lets anyone on the network crash the application (denial of service)."),
    "CVE-2026-55114": ("2026-07-02", 8.8, "unifi-network <=10.3.58 fix 10.4.57",
                       "Improper access control lets a low-privileged user escalate privileges in the "
                       "application."),
    "CVE-2026-55118": ("2026-07-02", 8.3, "unifi-network <=10.3.58 fix 10.4.57",
                       "Improper access control lets a low-privileged user escalate privileges under certain "
                       "conditions."),
    "CVE-2026-56842": ("2026-07-02", 7.5, "unifi-network <=10.3.58 fix 10.4.57",
                       "Users whose access was removed can keep their privileges under certain conditions."),
    "CVE-2026-77535": ("2026-08-26", 9.1, "unifi-network <=10.4.57 fix 10.5.67",
                       "A high-privileged user can inject commands that run on adopted devices."),
    "CVE-2026-77541": ("2026-08-26", 9.1, "unifi-network <=10.4.57 fix 10.5.67",
                       "Improper access control lets a high-privileged user escalate privileges."),
}
# Ranges several bulletins share, named by bulletin
BULLETINS = {
    "@062": "unifi-network <=10.1.85 fix 10.1.89; unifi-network >=10.2.0 <=10.2.93 fix 10.2.97; "
            "unifi-network:UX <=9.0.114 fix 9.0.118",
    "@064": "unifi-os:UCGA6AD <=5.0.13 fix 5.1.12; unifi-os:UDM,UDMPRO,UDMPROSE,UDMPROMAX,UDMENT,UDW,UDR,UDR7,UXMAX,"
            "UNVR,UNVRPRO,UNVRINS,ENVR,UDRULT,UCGMAX,UCGF <=5.0.16 fix 5.1.12; unifi-os:UDR5G,ENVRCORE,@ck <=5.0.17 "
            "fix 5.1.12; unifi-os:UNVRAI4,UNVRAI8 <=5.1.11 fix 5.1.12; unifi-os:UDMEA4C <=5.1.8 fix 5.1.11; "
            "unifi-os:@nas <=5.1.8 fix 5.1.10",
    "@065": "unifi-os:UDM,UDMPRO,UDMPROSE,UDMPROMAX,UDMENT,UDW,@dr,UXMAX,@ck,@nvr,@cg <=5.1.12 fix 5.1.15; "
            "unifi-os:UDMEA4C <=5.1.11 fix 5.1.15; unifi-os:@nas <=5.1.10 fix 5.1.16; unifi-os:UX <=4.0.14 fix 4.0.15",
    "@066": "unifi-os:@dm,UDMENT,UDW,@dr,UXMAX,@ck,@nvr,@cg <=5.1.15 fix 5.1.19; unifi-os:@nas <=5.1.16 fix 5.1.19; "
            "unifi-os:EFGCORE <=5.1.18 fix 5.1.19",
    "@067": "unifi-os:@ck,@nvr,ENAS,@dm,@efg,@dr,@cg,UDW,UXMAX <=5.1.26 fix 5.1.31; unifi-os:@nas <=5.1.26 fix 5.1.32",
    "@069": "unifi-os:@dm,@efg,@dr,@cg,UDW <=5.1.26 fix 5.1.31; unifi-os:UX <=4.0.20 fix 4.0.21; "
            "unifi-os:UXMAX <=5.1.19 fix 5.1.31; uxg <=5.0.16 fix 5.1.26",
}
# CVEs whose CPE data would give a rule, left out on purpose
SKIPPED = {
    **dict.fromkeys(("CVE-2023-1456", "CVE-2023-1457", "CVE-2023-1458", "CVE-2023-2373", "CVE-2023-2374",
                     "CVE-2023-2375", "CVE-2023-2376", "CVE-2023-2377", "CVE-2023-2378", "CVE-2023-2379"),
                    "disputed, and no fixed version is named"),
    **dict.fromkeys(("CVE-2024-42025", "CVE-2026-54406"), "self-hosted UniFi Network servers only"),
    "CVE-2023-28365": "UniFi applications on Linux: unclear whether consoles are meant",
    "CVE-2023-24104": "names a Network version as the UDM Pro's firmware",
}


def _expand(spec: str) -> list:
    """Ranges in CURATED's notation -> the list's affects entries."""
    out = []
    for part in (p.strip() for p in spec.split(";")):
        if part.startswith("@"):
            out += _expand(BULLETINS[part])
            continue
        words = part.split()
        family, _, models = words[0].partition(":")
        a = {"family": family}
        if models:
            names = []
            for name in models.split(","):
                names += CONSOLE_GROUPS[name] if name.startswith("@") else [name]
            a["models"] = names
        for word, value in zip(words[1:], words[2:] + [""]):
            if word.startswith(">="):
                a["from"] = word[2:]
            elif word.startswith("<="):
                a["through"] = word[2:]
            elif word.startswith("<"):
                a["before"] = a["fixed"] = word[1:]
            elif word.startswith("="):
                a["from"] = a["through"] = word[1:]
            elif word == "fix":
                a["fixed"] = None if value == "?" else value
        assert a.get("before") or a.get("through"), part
        if a.get("fixed") is None:
            a.pop("fixed", None)
        out.append(a)
    return out


def _severity(score) -> str | None:
    if not score:
        return None
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def _nvd_score(cve: dict):
    """(severity, score) from the NVD's own rating, else the CNA's, newest CVSS version first."""
    metrics = cve.get("metrics") or {}
    for kind in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        for row in sorted(metrics.get(kind) or [], key=lambda r: r.get("type") != "Primary"):
            score = (row.get("cvssData") or {}).get("baseScore")
            if score is not None:
                return _severity(score), score
    return None, None


def _description(cve: dict) -> str:
    return next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")


def _rules_from_cpe(cve: dict) -> list:
    """Affected ranges from a CVE's CPE data, for the products CPE_PRODUCTS knows."""
    out = []
    for conf in cve.get("configurations") or []:
        matches = [m for node in conf.get("nodes", []) for m in node.get("cpeMatch", [])]
        # EdgeOS CVEs sometimes name the models only as hardware alongside the firmware
        hardware = {(m.get("criteria", "").split(":") + [""] * 5)[4] for m in matches if not m.get("vulnerable")}
        routers = sorted({EDGEROUTERS[name] for name in hardware if name in EDGEROUTERS})
        for m in matches:
            parts = m.get("criteria", "").split(":")
            if not m.get("vulnerable") or len(parts) < 6 or parts[3] not in ("ui", "ubnt"):
                continue
            family, model = CPE_PRODUCTS.get(parts[4], (None, None))
            if not family or "versionStartExcluding" in m:
                continue
            a = {"family": family}
            models = list(model) if isinstance(model, tuple) else [model] if model else \
                routers if family == "edgeos" else []
            if models:
                a["models"] = models
            version = parts[5]
            if version not in ("*", "-", ""):
                a["from"] = a["through"] = version
            else:
                if "versionStartIncluding" in m:
                    a["from"] = m["versionStartIncluding"]
                if "versionEndExcluding" in m:
                    a["before"] = a["fixed"] = m["versionEndExcluding"]
                elif "versionEndIncluding" in m:
                    a["through"] = m["versionEndIncluding"]
                else:
                    continue  # no upper bound: too broad to check
            if all(version_key(v) for k, v in a.items() if k in ("from", "before", "through")):
                out.append(a)
    merged = collections.OrderedDict()  # one entry for the consoles a range shares
    for a in out:
        key = tuple((k, a.get(k)) for k in ("family", "from", "before", "through", "fixed"))
        if key in merged and "models" in merged[key] and "models" in a:
            merged[key]["models"] = sorted(set(merged[key]["models"]) | set(a["models"]))
        elif key not in merged:
            merged[key] = dict(a)
        else:
            merged[key].pop("models", None)
    return list(merged.values())


# The names Ubiquiti's bulletins give products -> what discovery checks them as, in CURATED's
# notation; "" for what discovery can't see (applications, servers, cameras...): understood, with
# nothing to check. A bulletin naming any product not here is left for a person to read.
_BULLETIN_NAMES = [
    ("unifi-os:UDM", "UDM"), ("unifi-os:UDMPRO", "UDM-Pro", "UDM Pro", "UDM Professional"),
    ("unifi-os:UDMPROSE", "UDM-SE", "UDM SE"), ("unifi-os:UDMPROMAX", "UDM-Pro-Max"), ("unifi-os:UDMEA4C", "UDM-Beast"),
    ("unifi-os:UDMENT", "EFG", "Enterprise Fortress Gateway"),
    ("unifi-os:EFGCORE", "EF-Core", "Enterprise Firewall Core"),
    ("unifi-os:UDW", "UDW", "Dream Wall"), ("unifi-os:UDR", "UDR"), ("unifi-os:UDR7", "UDR7"),
    ("unifi-os:UDR5G", "UDR-5G", "UDR-5G-Max"), ("unifi-os:UXMAX", "Express 7", "UX7", "UniFi Express 7"),
    ("unifi-os:UX", "Express", "UniFi Express", "UX"), ("unifi-os:UDRULT", "UCG-Ultra"), ("unifi-os:UCGMAX", "UCG-Max"),
    ("unifi-os:UCGF", "UCG-Fiber"), ("unifi-os:UCGA6AD", "UCG-Industrial"), ("unifi-os:UCKG2", "UCK", "Cloud Key Gen2"),
    ("unifi-os:UCKP", "UCKP", "Cloud Key Gen2 Plus"), ("unifi-os:UCKENT", "UCK-Enterprise"), ("unifi-os:UNVR", "UNVR"),
    ("unifi-os:UNVRPRO", "UNVR-Pro", "UNVR Pro", "UNVR Professional"), ("unifi-os:UNVRINS", "UNVR-Instant"),
    ("unifi-os:UNVRAI4", "UNVR-G2"), ("unifi-os:UNVRAI8", "UNVR-G2-Pro"), ("unifi-os:ENVR", "ENVR"),
    ("unifi-os:ENVRCORE", "ENVR-Core"), ("unifi-os:UNAS2,UNAS2B,UNAS2W", "UNAS-2"),
    ("unifi-os:UNAS4,UNAS4B,UNAS4W", "UNAS-4"), ("unifi-os:UNASPRO", "UNAS-Pro"), ("unifi-os:UNASPRO4", "UNAS-Pro-4"),
    ("unifi-os:UNASPRO8", "UNAS-Pro-8"), ("unifi-os:@dm", "Dream Machines"), ("unifi-os:@dr", "Dream Routers"),
    ("unifi-os:@cg", "Cloud Gateways"), ("unifi-os:@efg", "Enterprise Firewalls"), ("unifi-os:@ck", "Cloud Keys"),
    ("unifi-os:UNVR,UNVRPRO,UNVRINS,UNVRAI4,UNVRAI8", "Network Video Recorders"),
    ("unifi-os:ENVR,ENVRCORE", "Enterprise Network Video Recorders"), ("unifi-os:@nas", "Network Attached Storage"),
    ("unifi-os:ENAS", "Enterprise Network Attached Storage"), ("uxg", "UniFi Gateways"),
    ("unifi-network", "UniFi Network", "UniFi Network Application"),
    ("unifi-ap", "UniFi Access Points", "All UniFi Access Points"), ("unifi-ap:UAPL6", "U6+", "UniFi U6+ Access Point"),
    ("unifi-switch", "UniFi Switches", "All UniFi Switches"), ("unifi-lte", "UniFi LTE Backup"),
    ("usg", "USG", "USGs", "UniFi Security Gateway", "UniFi Security Gateways"),
    ("edgeos", "EdgeRouter", "EdgeRouters", "All EdgeRouters", "EdgeMAX EdgeRouter", "EdgeMAX EdgeRouters"),
    ("edgeswitch", "EdgeSwitch", "EdgeMAX EdgeSwitch"), ("edgepower", "EdgePower"),
    ("airmax-ac", "airMAX AC"), ("airmax-m", "airMAX M"), ("af60", "airFiber AF60", "airFiber 60/LR"),
    ("af60-xg", "airFiber AF60-XG", "airFiber 60 XG/HD"), ("gbe", "GBE", "GigaBeam"),
    ("aircube", "airCube", "Aircubes"),
    ("ubb:UBB", "UBB"), ("ubb:UBBXG", "UBB-XG"),
    ("", "UniFi OS Server", "UniFi Network Server", "UniFi Protect Application", "UniFi Access Application",
     "UniFi Talk Application", "UniFi Connect Application", "UID Enterprise Agent", "UniFi Protect AI Key",
     "UniFi Protect Floodlight", "UniFi Protect Cameras", "UniFi iOS App", "UniFi Android App"),
]
BULLETIN_NAMES = {name.casefold(): spec for spec, *names in _BULLETIN_NAMES for name in names}
_NAME_LIST = re.compile(r",\s*(?:and\s+)?|\s+and\s+")
_AFFECTED = re.compile(r"(?P<names>[^()]+?)\s*\((?:Version\s*|v)(?P<version>\d[\w.-]*) and earlier\)\.?")
_FIX = re.compile(r"Update (?P<names>.+?) (?:firmware )?(?:to )?(?:Version |v)?(?P<version>\d[\w.-]*?) "
                  r"or (?:later|newer)(?: version)?\.?", re.I)
_HEADERS = re.compile(r"(?:Summary \d+ of \d+|Overview|Published:.*|Updated:.*|First Published:.*|Version: [\d.]+|"
                      r"Revision: [\d.]+)$", re.I)


def _named(text: str):
    """[(name, spec)] for a list of product names, or None if any isn't in BULLETIN_NAMES."""
    found = []
    for name in _NAME_LIST.split(text.strip().rstrip(".")):
        name = re.sub(r"^(?:your|the|affected)\s+", "", name.strip(), flags=re.I)
        spec = BULLETIN_NAMES.get(name.casefold())
        if spec is None:
            return None
        found.append((name, spec))
    return found


def _advisory_rules(block: list) -> tuple:
    """(affects, "") for one summary of a bulletin, or ([], why not) unless every product,
    version and fix in it is understood."""
    starts = [n for n, line in enumerate(block) if re.fullmatch(r"Affected Products\s*:?", line, re.I)]
    ends = [n for n, line in enumerate(block) if re.fullmatch(r"Mitigation\s*:?", line, re.I)]
    if len(starts) != 1 or len(ends) != 1 or ends[0] < starts[0]:
        return [], "not in the usual layout"
    tail = next((n for n in range(ends[0] + 1, len(block))
                 if re.match(r"(?:Impact|CVSS|Base Score|CVE)\b", block[n], re.I)), len(block))
    description = " ".join(line for line in block[:starts[0]] if not _HEADERS.match(line))
    fixes = {}
    for line in block[ends[0] + 1:tail]:
        m = _FIX.fullmatch(line)
        for name, spec in (_named(m["names"]) or []) if m and version_key(m["version"]) else []:
            fixes[name.casefold()] = fixes[spec] = m["version"]
    rules = []
    for line in block[starts[0] + 1:ends[0]]:
        line = re.sub(r"^Official Release:\s*", "", line, flags=re.I)
        if re.match(r"Release Candidate:", line, re.I):
            continue  # release candidates aren't checked
        m = _AFFECTED.fullmatch(line)
        if not m and re.search(r"[():]", line):
            return [], f"not understood: {line}"
        names, last = (m["names"], m["version"]) if m else (line, None)
        products = _named(names)
        if products is None:
            return [], f"a product isn't known: {line}"
        for name, spec in products:
            if not spec or (spec == "unifi-network" and re.search(r"self-hosted|network server", description, re.I)):
                continue  # nothing discovery can see
            fixed = fixes.get(name.casefold()) or fixes.get(spec)
            if last and (not version_key(last) or (fixed and version_key(fixed) <= version_key(last))):
                return [], f"versions not understood: {line}"
            if not last and not fixed:
                return [], f"no version for {name}"
            rules += _expand(f"{spec} <={last} fix {fixed or '?'}" if last else f"{spec} <{fixed}")
    return rules, "" if rules else "nothing discovery can check"


def parse_bulletin(text: str, url: str = "", published: str = "") -> tuple:
    """A Security Advisory Bulletin's text -> (list entries for the CVEs whose products and versions
    are all understood, [(CVE ids, why not)] for the others)."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    m = re.search(r"Published:\s*([A-Za-z]+)\.? (\d+),? (\d{4})", text)
    if m:
        try:
            published = time.strftime("%Y-%m-%d", time.strptime(f"{m[1][:3]} {m[2]} {m[3]}", "%b %d %Y"))
        except ValueError:
            pass
    blocks, block = [], []
    for line in lines:
        if re.fullmatch(r"Summary \d+ of \d+", line, re.I) and block:
            blocks.append(block)
            block = []
        block.append(line)
    blocks.append(block)
    entries, skipped = [], []
    for block in blocks:
        ids = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", " ".join(line for line in block
                                                                 if re.match(r"CVE\s*:", line)))))
        if not ids:
            continue
        affects, why = _advisory_rules(block)
        if not affects:
            skipped.append((ids, why))
            continue
        score = re.search(r"Base Score:\s*(\d+(?:\.\d)?)", " ".join(block))
        score = float(score[1]) if score else None
        start = next((n for n, line in enumerate(block) if re.fullmatch(r"Affected Products\s*:?", line, re.I)), 0)
        description = " ".join(line for line in block[:start] if not _HEADERS.match(line))
        summary = re.split(r"(?<=\.)\s", description.strip(), maxsplit=1)[0][:240]
        for cid in ids:
            entries.append({"id": cid, "published": published, "severity": _severity(score), "score": score,
                            "summary": summary, "affects": affects, "source": "advisory", "advisory": url})
    return entries, skipped


def build_rules(nvd_cves, advisories=(), generated=None, carried=()) -> dict:
    """The list from NVD CVE records (the "cve" objects of the API's answers), entries
    parse_bulletin() made from Ubiquiti's bulletins, and CURATED, which wins over both. carried:
    entries from bulletins kept from an earlier list (when the bulletins can't be read now)."""
    by_id = {c["id"]: c for c in nvd_cves if c.get("id")}
    from_advisories = {}
    for entry in list(advisories) + list(carried):  # the newest bulletin first
        from_advisories.setdefault(entry["id"], entry)
    out = []
    every = set(by_id) | set(CURATED) | set(from_advisories)
    for cid in sorted(every, key=lambda i: [int(x) for x in i.split("-")[1:]]):
        if cid in SKIPPED:
            continue
        cve, curated, advisory = by_id.get(cid), CURATED.get(cid), from_advisories.get(cid)
        extra = {}
        if curated:
            published, score, spec, summary = curated
            affects, source = _expand(spec), "curated"
        elif advisory:
            published, score, summary, affects = (advisory[k] for k in ("published", "score", "summary", "affects"))
            source, extra = "advisory", {"advisory": advisory.get("advisory", "")}
        else:
            desc = _description(cve)
            affects = [a for a in _rules_from_cpe(cve)
                       if not (a["family"] == "unifi-network"
                               and re.search(r"self-hosted|network server|running on linux", desc, re.I))]
            published, score, source = cve.get("published", "")[:10], None, "nvd"
            summary = re.split(r"(?<=\.)\s", desc.strip(), maxsplit=1)[0][:240]
        if not affects:
            continue
        severity, nvd_score = _nvd_score(cve) if cve else (None, None)
        if nvd_score is not None:
            score = nvd_score
        out.append({"id": cid, "published": published, "severity": severity or _severity(score), "score": score,
                    "summary": summary, "affects": affects, "source": source, **extra})
    return {"format": FORMAT, "generated": generated or time.strftime("%Y-%m-%d"), "built_by": __version__,
            "sources": SOURCES, "cves": out}


def dumps(data: dict) -> str:
    """The list as JSON, one CVE a line."""
    head = {k: v for k, v in data.items() if k != "cves"}
    lines = [json.dumps(head, ensure_ascii=False)[:-1] + ', "cves": [']
    lines += [" " + json.dumps(c, ensure_ascii=False) + "," for c in data["cves"]]
    if data["cves"]:
        lines[-1] = lines[-1][:-1]
    return "\n".join(lines) + "\n]}\n"


# ---------------------------------------------------------------------------
# Fetching from the NVD
# ---------------------------------------------------------------------------

_sent = collections.deque()  # when recent NVD requests went out
_sent_lock = threading.Lock()


def _wait_turn(deadline: float) -> None:
    """Keep within the NVD's limit for requests without an API key."""
    count, window = NVD_LIMIT
    with _sent_lock:
        now = time.monotonic()
        while _sent and now - _sent[0] > window:
            _sent.popleft()
        wait = window - (now - _sent[0]) + 0.5 if len(_sent) >= count else 0
        if now + wait > deadline:
            raise TimeoutError("ran out of time waiting for the NVD's rate limit")
        if wait:
            time.sleep(wait)
        _sent.append(time.monotonic())
        if len(_sent) > count:
            _sent.popleft()


def fetch_nvd(log=None, timeout: float = 60.0, request_timeout: float = 15.0) -> list:
    """Every NVD CVE record NVD_QUERIES find. Raises OSError, ValueError or TimeoutError when
    the NVD can't be reached, answers with something else or a query finds nothing."""
    deadline = time.monotonic() + timeout
    found = {}
    for query in NVD_QUERIES:
        start = 0
        while True:
            _wait_turn(deadline)
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("ran out of time")
            req = urllib.request.Request(f"{NVD_API}?{query}&resultsPerPage=2000&startIndex={start}",
                                         headers={"User-Agent": f"OpenDisco/{__version__}"})
            with tls.urlopen(req, timeout=min(request_timeout, left)) as resp:
                page = json.load(resp)
            for item in page.get("vulnerabilities", []):
                cve = item.get("cve") or {}
                if cve.get("id"):
                    found[cve["id"]] = cve
            total, size = page.get("totalResults", 0), page.get("resultsPerPage", 0)
            start += size
            if not size or start >= total:
                break
        if log:
            log(f"  {query.split('=')[-1]}: {total} CVEs")
    if not found:  # one query finding nothing is fine; all of them is the NVD answering wrongly
        raise ValueError("the NVD found nothing")
    return list(found.values())


def refresh_due(cache_dir, hours: float = 20) -> bool:
    """Whether the downloaded list is older than this (or missing): the launch check refreshes at
    most about once a day, sparing the NVD's rate limit and phones' data."""
    try:
        age = time.time() - (Path(cache_dir) / CACHE_NAME).stat().st_mtime
    except OSError:
        return True
    return not 0 <= age < hours * 3600


# The community site's own API, not a documented one: the list of bulletins, then each one's text
BULLETIN_FEED = "https://community.svc.ui.com/api/v1/feed/threads?threadType=RELEASE&sort=LATEST&tags=security&limit=50"
BULLETIN_API = "https://community.svc.ui.com/"
# Bulletins published up to this day were read by hand into CURATED; fetch_bulletins() reads newer ones.
BULLETINS_REVIEWED = "2026-10-24"
_BULLETIN_QUERY = ("query GetRelease($id: ID!) { release(id: $id) { "
                   "content { ... on TextContent { content } } importantNotes { ... on TextContent { content } } } }")


def _html_text(markup: str) -> str:
    text = re.sub(r"<(?:br|/p|/li|/h\d|/div|/tr)\b[^>]*>", "\n", markup or "", flags=re.I)
    return html.unescape(re.sub(r"<[^>]+>", "", text)).replace("\xa0", " ")


def fetch_bulletins(timeout: float = 30.0, request_timeout: float = 15.0, since: str | None = None) -> tuple:
    """Ubiquiti's Security Advisory Bulletins published after since (a date: BULLETINS_REVIEWED when
    None, every bulletin when ""), parsed: (parse_bulletin()'s entries for all of them,
    [(CVE ids, why not, bulletin)] for the CVEs left out). Raises OSError, ValueError or
    TimeoutError when they can't be read."""
    deadline = time.monotonic() + timeout
    since = BULLETINS_REVIEWED if since is None else since

    def get(req):
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("ran out of time")
        with tls.urlopen(req, timeout=min(request_timeout, left)) as resp:
            return json.load(resp)

    headers = {"User-Agent": f"OpenDisco/{__version__}"}
    new, cursor = [], None
    while True:
        page = get(urllib.request.Request(BULLETIN_FEED + (f"&cursor={cursor}" if cursor else ""), headers=headers))
        items = page.get("items")
        if not isinstance(items, list):
            raise ValueError("the list of bulletins has changed shape")
        fresh = [i for i in items if not since or str((i.get("stats") or {}).get("createdAt", ""))[:10] > since]
        new += fresh
        cursor = page.get("nextCursor")
        if not cursor or len(fresh) < len(items):
            break
    entries, skipped = [], []
    for item in new:
        body = json.dumps({"query": _BULLETIN_QUERY, "variables": {"id": item["id"]}}).encode()
        data = get(urllib.request.Request(BULLETIN_API, body, dict(headers, **{"content-type": "application/json"})))
        release = (data.get("data") or {}).get("release")
        if not isinstance(release, dict):
            raise ValueError(f"no text for {item.get('title')}")
        text = "\n".join(_html_text(part.get("content", "")) for key in ("content", "importantNotes")
                         for part in release.get(key) or [] if isinstance(part, dict))
        url = f"https://community.ui.com/releases/{item.get('slug', '')}/{item['id']}"
        found, left_out = parse_bulletin(text, url, str((item.get("stats") or {}).get("createdAt", ""))[:10])
        entries += found
        skipped += [(ids, why, item.get("title", "")) for ids, why in left_out]
    return entries, skipped


def refresh(cache_dir, log=None, timeout: float = 60.0) -> bool:
    """Rebuild the list from current NVD data and save it in cache_dir (the app's data folder),
    then use it if it's newer than the bundled one. Takes a few seconds; returns False, keeping
    the list in use, when the NVD can't be reached in time. Safe to run in a background thread."""
    say = log or (lambda msg: None)
    started = time.monotonic()
    try:
        nvd = fetch_nvd(timeout=timeout)
    except (OSError, ValueError, TimeoutError) as e:
        say(f"Couldn't update the CVE list from the NVD: {e}")
        return False
    advisories, carried = [], []
    try:
        advisories, skipped = fetch_bulletins(timeout=max(10.0, timeout - (time.monotonic() - started)))
        for ids, why, title in skipped:
            say(f"Left out {', '.join(ids)} ({title}): {why}")
    except (OSError, ValueError, KeyError, TimeoutError) as e:
        before = _read(Path(cache_dir) / CACHE_NAME) or current()[0]  # what the last refresh read from them
        carried = [c for c in before["cves"] if c.get("source") == "advisory"]
        say(f"Couldn't read Ubiquiti's security advisories ({e}); keeping the {len(carried)} CVE(s) read from "
            "them before.")
    data = build_rules(nvd, advisories, carried=carried)
    path = Path(cache_dir) / CACHE_NAME
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(dumps(data), encoding="utf-8")
        os.replace(tmp, path)
    except OSError as e:
        say(f"Couldn't save the CVE list in {path.parent}: {e}")
        return False
    global CACHE_DIR
    CACHE_DIR = cache_dir
    reload()
    found = sum(c.get("source") == "advisory" for c in data["cves"])
    say(f"CVE list updated: {len(data['cves'])} CVEs as of {data['generated']}"
        + (f" ({found} from advisories newer than the built-in list)" if found else "") + f", saved in {path}")
    return True
