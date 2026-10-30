"""The demo network: a small WISP's tower, made up, for trying OpenDisco without any gear (Apple's
App Store reviewers have none). It's the tower the README's pictures show: every name, MAC and
address in it is invented, and nothing is sent on the network while it shows.

- MODE is the scan-mode list's last entry ("Demo network"); desktops also have Help > Try the
  demo network, phones a button while their list is empty and one in Settings. opendisco --demo
  prints its table on the command line, for docs and tests.
- scan() lists it the way a scan would: each device's own discovery reply, its latency, the latest
  firmware from the made-up firmware server, the sectors' link health (read before: Tower1-Sector-
  South has a weak station), and the diagnostics on all that.
- The device tools work on it: demossh runs them on made-up devices in memory (network() builds
  them from DEVICES), with their configs, logins (demo/demo; ubnt/ubnt on the bench spare, which
  takes its factory login), stations, radio links and firmware (the ER-X keeps two images, and
  updates to EdgeOS 3).
- Demo(app) starts it in the app, and end() ends it (a real scan, or quitting). Its notes, config
  backups, known_hosts, remembered logins and factory-login flags are its own, in a temporary
  folder and in memory, deleted when it ends: nothing reaches the real data folder or
  settings.json. The window's title says Demo, and every export made from it is stamped STAMP
  (stamp_file, stamp_bytes).
"""
from __future__ import annotations

import atexit
import json
import re
import shutil
import sys
import tempfile
import time
import zipfile
from pathlib import Path

from opendisco import FULL_NAME, __version__, core, demossh, devicetools, health, linkhealth, records
from opendisco.i18n import N_, _, tr

MODE = N_("Demo network")
STAMP = records.DEMO_STAMP  # "Demo network: made-up devices"
NOTE = (f"{STAMP}. Nothing was sent on the network: the device tools work on simulated gear. Log in as demo / demo "
        "(the bench spare: ubnt / ubnt).")
NO_WEB_UI = N_("The demo network's devices are made up: they have no web UI to open.")
# What a phone's device tool (phonetools' app.device_job) is doing, for "The demo network's … is still running"
PHONE_JOBS = {"firmware": N_("firmware update"), "login": N_("login change"), "backup": N_("config backup"),
              "upload": N_("config upload"), "reboot": N_("reboot"), "link": N_("link health check"),
              "backup_all": N_("Back up all"), "config": N_("config upload")}  # (Save or Apply in the editor)
DAY = 86400
# The interface Details names for the untagged VLAN, as each system calls its first one
INTERFACE = {"darwin": "en0", "ios": "en0", "win32": "Ethernet", "android": "wlan0"}.get(sys.platform, "eth0")

AIRMAX = "XC.qca955x.v{}.46972.220614.0420"
AIRMAX_WA = "WA.ar934x.v{}.46972.220614.0420"
FACTORY = "fc:ec:da:09:b3:55"  # Bench-Spare-NS5AC: it takes its factory login, ubnt/ubnt
# The tower. name: (MAC, address, model, firmware, uptime, SSID, discovery's wireless mode (3 access
# point, 2 station), SSH port, round trips (ms; None lost), what its radio link reads). A station
# with "via" is on another subnet, behind that sector's link: discovery doesn't reach it, so it's
# found only through the sector (Scan from device); "found" ones were found that way already, and a
# "hidden" one is on a subnet the router doesn't route, so only the sector reaches it at all.
DEVICES = {
    "Tower1-Router": ("74:ac:b9:5d:02:e8", "10.60.12.1", "ER-X",
                      "EdgeRouter.ER-e50.v2.0.9-hotfix.7.5622731.230615.0857", 97 * DAY + 5000, None, None, 22,
                      [0.8, 0.7, 0.9, 0.8], {}),
    "BH-Tower1-to-Tower2": ("74:83:c2:1a:20:01", "10.60.12.2", "AF60-LR", "AF60.v2.6.1", 63 * DAY + 4100, "BH-T1T2",
                            3, 22, [1.1, 0.9, 1.3, 1.0],
                            {"freq": 60480, "chanbw": 2160, "signal": -48, "noise": -82, "distance": 3120,
                             "tx": 1800, "rx": 1800, "ccq": 99}),
    "Tower1-Sector-North": ("f4:92:bf:3c:41:10", "10.60.12.10", "R5AC-PRISM", AIRMAX.format("8.7.11"),
                            63 * DAY + 3900, "Tower1-N", 3, 22, [2.1, 1.8, 2.4, 2.0],
                            {"freq": 5785, "chanbw": 40, "noise": -95, "tx_power": 22}),
    "Tower1-Sector-South": ("f4:92:bf:3c:41:22", "10.60.12.11", "R5AC-PRISM", AIRMAX.format("8.7.11"),
                            63 * DAY + 3870, "Tower1-S", 3, 22, [2.6, 2.2, 2.9, 2.3],
                            {"freq": 5220, "chanbw": 40, "noise": -93, "tx_power": 24}),
    "Tower1-Sector-East": ("24:5a:4c:77:08:31", "10.60.12.12", "LAP-GPS", AIRMAX_WA.format("8.7.11"),
                           18 * DAY + 600, "Tower1-E", 3, 22, [3.4, 3.1, 2.8, 3.0],
                           {"freq": 5500, "chanbw": 20, "noise": -96, "tx_power": 20}),
    "CPE-Ridge-Farm": ("78:45:58:a2:19:04", "10.60.12.40", "LBE-5AC-Gen2", AIRMAX_WA.format("8.7.11"),
                       12 * DAY + 7300, "Tower1-N", 2, 22, [8.8, 9.6, 7.9, 9.1],
                       {"freq": 5785, "chanbw": 40, "signal": -58, "noise": -95, "ccq": 96, "distance": 4200,
                        "tx": 400, "rx": 360}),
    "CPE-Mill-Road": ("e0:63:da:5e:61:7c", "10.60.12.41", "PBE-5AC-Gen2", AIRMAX_WA.format("8.7.11"), 40 * DAY + 210,
                      "Tower1-S", 2, 2222, [38.0, None, 52.4, 41.7, 47.9, None, 36.2, 44.0, 49.3, 39.8],
                      {"freq": 5220, "chanbw": 40, "signal": -79, "chains": [-79, -85], "noise": -92, "ccq": 61,
                       "distance": 9800, "tx": 117, "rx": 87, "latency": 7}),
    "CPE-Grain-Elevator": ("68:d7:9a:30:c4:e2", "10.60.12.42", "NBE-5AC-Gen2", AIRMAX_WA.format("8.7.10"), 184,
                           "Tower1-E", 2, 22, [11.2, 10.4, 12.0, 10.9],
                           {"freq": 5500, "chanbw": 20, "signal": -63, "noise": -96, "ccq": 92, "distance": 6100,
                            "tx": 173, "rx": 144}),
    "Bench-Spare-NS5AC": (FACTORY, "10.60.12.99", "NS-5AC", AIRMAX_WA.format("8.7.4"), 2 * 3600 + 900, None, None,
                          22, [0.6, 0.5, 0.7, 0.6], {}),
    "CPE-Hilltop-Church": ("78:45:58:b1:7a:36", "10.60.13.20", "LBE-5AC-Gen2", AIRMAX_WA.format("8.7.11"),
                           21 * DAY + 4400, "Tower1-N", 2, 22, [14.8, 13.9, 15.6, 14.2],
                           {"freq": 5785, "chanbw": 40, "signal": -63, "noise": -95, "ccq": 90, "distance": 7300,
                            "tx": 300, "rx": 240, "via": "Tower1-Sector-North", "found": True}),
    "CPE-Quarry-Office": ("78:45:58:c4:0e:5b", "10.60.14.40", "LBE-5AC-Gen2", AIRMAX_WA.format("8.7.11"),
                          5 * DAY + 3100, "Tower1-E", 2, 22, [9.4, 10.1, 9.8, 9.2],
                          {"freq": 5500, "chanbw": 20, "signal": -61, "noise": -96, "ccq": 94, "distance": 5400,
                           "tx": 216, "rx": 173, "via": "Tower1-Sector-East", "hidden": True}),
}
# The made-up firmware server's latest releases: (product, platform, version, date)
RELEASES = [("XC", "airmax", "8.7.25", "2026-08-06"), ("WA", "airmax", "8.7.25", "2026-08-06"),
            ("e50", "edgerouter", "3.0.1", "2026-06-17")]
NOTES = {
    "f4:92:bf:3c:41:10": "Tilted 2° down after the ice storm. Check the alignment in spring.",
    "e0:63:da:5e:61:7c": "Customer 1042. Trees are growing into the path: re-aim or raise the mast.",
}


# ---------------------------------------------------------------------------
# The made-up devices and their configs
# ---------------------------------------------------------------------------

def _login(name: str) -> tuple:
    """(user, password) the device takes."""
    mac = DEVICES[name][0]
    return ("ubnt", "ubnt") if mac == FACTORY else ("demo", "demo")


def logins() -> dict:
    """MAC -> {"user", "port", "password"}: what the demo's login windows start with."""
    return {spec[0]: {"user": _login(name)[0], "password": _login(name)[1], "port": spec[7]}
            for name, spec in DEVICES.items()}


def airos_config(name: str, freq: int | None = None, txpower: int = 22) -> str:
    """Its /tmp/system.cfg, as airOS keeps it: a key=value line each, in order."""
    mac, ip, model, firmware, _up, essid, wmode, ssh, _pings, link = DEVICES[name]
    user, password = _login(name)
    salt = mac.replace(":", "")[-8:]
    station, isp = wmode == 2, model.startswith("AF")
    lines = {
        "aaa.1.status": "disabled", "aaa.status": "disabled",
        "bridge.1.devname": "br0", "bridge.1.port.1.devname": "eth0", "bridge.1.port.2.devname": "ath0",
        "bridge.status": "enabled",
        "dhcpc.1.status": "disabled", "dhcpd.1.status": "disabled", "discovery.status": "enabled",
        "netconf.1.devname": "eth0", "netconf.1.status": "enabled", "netconf.2.devname": "ath0",
        "netconf.2.status": "enabled", "netconf.3.devname": "br0", "netconf.3.ip": ip,
        "netconf.3.netmask": "255.255.255.0", "netconf.3.status": "enabled",
        "radio.1.chanbw": str(link.get("chanbw", 40)), "radio.1.freq": str(freq or link.get("freq", 5180)),
        "radio.1.mode": "managed" if station else "master", "radio.1.txpower": str(txpower),
        "resolv.host.1.name": name, "resolv.host.1.status": "enabled",
        "resolv.nameserver.1.ip": "10.60.12.1", "resolv.nameserver.1.status": "enabled",
        "route.1.gateway": ip.rsplit(".", 1)[0] + ".1", "route.1.ip": "0.0.0.0",
        "route.1.netmask": "0", "route.1.status": "enabled", "route.status": "enabled",
        "snmp.contact": "noc@example.net", "snmp.location": "Tower 1" if not station else "Customer site",
        "snmp.status": "enabled", "sshd.port": str(ssh), "sshd.status": "enabled", "system.timezone": "GMT",
        "users.1.name": user, "users.1.password": devicetools.md5_crypt(password, salt), "users.1.status": "enabled",
        "users.status": "enabled",
        "wireless.1.devname": "ath0", "wireless.1.ssid": essid or "ubnt", "wireless.1.status": "enabled",
        "wpa.1.psk": "demo-" + mac.replace(":", "")[-6:], "wpa.status": "enabled",
    }
    if isp:
        lines.update({"radio.1.mode": "master", "wpa.1.psk": "demo-backhaul"})
    if mac == FACTORY:  # as it came out of the box
        lines.update({"snmp.location": "", "snmp.status": "disabled"})
    return "\n".join(f"{k}={v}" for k, v in sorted(lines.items())) + "\n"


def edgeos_config(name: str) -> str:
    """Its /config/config.boot, as EdgeOS saves it."""
    mac, ip, model, firmware, *_rest = DEVICES[name]
    user, password = _login(name)
    hashed = devicetools.sha_crypt(password, mac.replace(":", "")[-8:] + "demo", None, True)
    return f"""firewall {{
    all-ping enable
    broadcast-ping disable
    ipv6-receive-redirects disable
    log-martians enable
    receive-redirects disable
    send-redirects enable
    source-validation disable
    syn-cookies enable
}}
interfaces {{
    ethernet eth0 {{
        address 198.51.100.34/30
        description Upstream
        duplex auto
        speed auto
    }}
    ethernet eth1 {{
        description Tower1-Sector-North
        duplex auto
        speed auto
    }}
    ethernet eth2 {{
        description Tower1-Sector-South
        duplex auto
        speed auto
    }}
    ethernet eth3 {{
        description Tower1-Sector-East
        duplex auto
        speed auto
    }}
    ethernet eth4 {{
        description BH-Tower1-to-Tower2
        duplex auto
        poe {{
            output 24v
        }}
        speed auto
    }}
    loopback lo {{
    }}
    switch switch0 {{
        address {ip}/24
        address 10.60.13.1/24
        description Tower1
        mtu 1500
        switch-port {{
            interface eth1 {{
            }}
            interface eth2 {{
            }}
            interface eth3 {{
            }}
            interface eth4 {{
            }}
            vlan-aware disable
        }}
    }}
}}
protocols {{
    static {{
        route 0.0.0.0/0 {{
            next-hop 198.51.100.33 {{
            }}
        }}
    }}
}}
service {{
    gui {{
        http-port 80
        https-port 443
        older-ciphers enable
    }}
    lldp {{
        interface all {{
        }}
    }}
    ssh {{
        port 22
        protocol-version v2
    }}
}}
system {{
    host-name {name}
    login {{
        user {user} {{
            authentication {{
                encrypted-password {hashed}
                plaintext-password ""
            }}
            level admin
        }}
    }}
    name-server 198.51.100.53
    ntp {{
        server 0.ubnt.pool.ntp.org {{
        }}
    }}
    syslog {{
        global {{
            facility all {{
                level notice
            }}
        }}
    }}
    time-zone UTC
}}


/* Warning: Do not remove the following line. */
/* === vyatta-config-version: "config-management@1:conntrack@1:cron@1:dhcp-relay@1:dhcp-server@4:firewall@5:ipsec@5:nat@3:qos@1:quagga@2:suspend@1:system@5:ubnt-l2tp@1:ubnt-pptp@1:ubnt-udapi-server@1:ubnt-unms@2:ubnt-util@1:vrrp@1:vyatta-netflow@1:webgui@1:webproxy@1:zone-policy@1" === */
/* Release version: {firmware.split(".", 2)[-1] if firmware.startswith("EdgeRouter.") else firmware} */
"""


def network(folder=None) -> demossh.Network:
    """The made-up devices, as they are when the demo starts. folder: where firmware downloads go."""
    gears = {}
    for name, (mac, ip, model, firmware, uptime, essid, wmode, ssh, pings, link) in DEVICES.items():
        kind = "edgeos" if model.startswith("ER-") else "isp" if model.startswith("AF") else "airos"
        files = ({demossh.EDGEOS_CONFIG: edgeos_config(name).encode()} if kind == "edgeos"
                 else {demossh.AIROS_CONFIG: airos_config(name).encode()})
        gears[name] = demossh.Gear(mac, ip, name, model, firmware, kind, uptime, files,
                                   ports={ssh: "ssh", 80: "http", 443: "https"}, essid=essid, wmode=wmode,
                                   pings=pings, direct=not link.get("hidden"), discovery="via" not in link,
                                   is_default=mac == FACTORY, link=link,
                                   address_on="switch0" if kind == "edgeos" else "br0")
    router = gears["Tower1-Router"]
    router.images = [{"name": DEVICES["Tower1-Router"][3].split(".", 2)[2], "running": True, "default": True},
                     {"name": "v2.0.9-hotfix.6.5574651.221230.1015", "running": False, "default": False}]
    for name, gear in gears.items():
        via = gear.link.get("via")
        if via:
            gears[via].stations.append(gear)
            gear.arp = [gears[via], router]
        elif gear.wmode == 2:  # a station on the tower's own subnet
            next(g for g in gears.values() if g.wmode == 3 and g.essid == gear.essid).stations.append(gear)
    for name, gear in gears.items():
        if gear is router:
            gear.arp = [g for g in gears.values() if g is not router and g.direct]
            gear.lldp = [(f"eth{n}", gears[n2]) for n, n2 in
                         enumerate(("Tower1-Sector-North", "Tower1-Sector-South", "Tower1-Sector-East",
                                    "BH-Tower1-to-Tower2"), 1)]
        elif not gear.arp:
            gear.arp = [router, *gear.stations] + ([g for g in gears.values() if gear in g.stations])
    return demossh.Network(list(gears.values()), RELEASES, folder)


# ---------------------------------------------------------------------------
# The scan
# ---------------------------------------------------------------------------

def scan(net: demossh.Network, opts=None) -> core.ScanResult:
    """The demo network as a scan finds it: each device's discovery reply, its ports, latency and
    latest firmware, the stations found through their sector before, the notes, and the
    diagnostics on all that."""
    started = time.monotonic()
    opts = opts or core.parse_args(["--demo"])
    now = time.time()
    inv = core.Inventory()
    for gear in net.gears.values():
        if not (gear.direct and gear.discovery and gear.up):
            continue
        dev, _changes = inv.ingest_ubnt(core.parse_packet(gear.discovery_reply()), (gear.ip, core.UBNT_PORT), "ubnt")
        dev.via.add("mcast")
        dev.ubnt_packets = 6  # a Quick scan's rounds of probes, each answered
        dev.ports, dev.services = sorted(gear.ports), dict(gear.ports)
    for gear in net.gears.values():  # found through its sector's station list (Scan from device)
        if gear.link.get("found") and gear.up:
            finder = inv.find(ip=DEVICES[gear.link["via"]][1])
            dev = inv.lookup(mac=gear.mac, ip=gear.ip)
            dev.add_ip(gear.ip)
            dev.via.add(devicetools.FROM_DEVICE)
            dev.found_by = {"key": finder.key, "ip": finder.ip, "how": devicetools.SCAN_HOW["stations"]}
            dev.info.update(hostname=gear.name, platform=gear.platform, firmware=gear.firmware)  # as wstalist has them
    index = [demossh.release(*r) for r in net.releases]
    for dev in inv.devices.values():
        gear = net.find(dev.ip)
        if not dev.found_by:
            dev.vlan, dev.vlan_label, dev.vlan_parent = 0, "1", INTERFACE
        if gear and gear.pings:
            got = [t for t in gear.pings if t is not None]
            dev.health["latency"] = {"sent": len(gear.pings), "received": len(got), "at": now, "how": "ICMP",
                                     "replies_ms": got}
        if dev.fw_platform:
            check = devicetools.Check(devicetools.device_version(dev), devicetools.find_release(dev, index),
                                      dev.fw_platform or dev.info.get("platform") or "")
            dev.health["firmware"] = {"platform": check.platform, "current": check.current, "latest": check.latest,
                                      "date": check.date, "newer": check.newer, "ahead": False,
                                      "listed": time.strftime("%Y-%m-%d")}
        dev.note = NOTES.get(dev.mac or "", "")
        if gear and gear.stations and gear.kind == "airos":  # its link health, read before (Link health…)
            said = [gear.shell("demo").run(command)[0] for command in ("mca-status", "wstalist")]
            linkhealth.keep(dev, linkhealth.parse([l for l in said[0].splitlines() if l.strip()], said[1]))
    diag_args = ([], [], opts)
    core.diagnose(inv, *diag_args)
    return core.ScanResult(opts, core.sorted_devices(inv), [("note", NOTE)], [], [], [], [], inv, None,
                           time.monotonic() - started, diag_args=diag_args)


class _Clock:
    """time, with time() set: so the backups seed() keeps have dates of their own."""

    def __init__(self, at):
        self.at = at

    def time(self):
        return self.at

    def __getattr__(self, name):
        return getattr(time, name)


def seed(folder, res: core.ScanResult) -> records.Notes:
    """The demo's data folder as the README pictures show it: the notes, and two config backups of
    Tower1-Sector-North (one from three weeks ago, one from before an upload two days ago)."""
    folder = Path(folder)
    notes = records.Notes(folder)
    for d in res.devices:
        if d.mac in NOTES:
            notes.set(d, NOTES[d.mac])
    north = next(d for d in res.devices if d.name == "Tower1-Sector-North")
    real = devicetools.time
    try:
        for days_ago, freq, txpower, reason in ((21, 5745, 24, "backup"), (2, 5745, 22, "before upload")):
            devicetools.time = _Clock(time.time() - days_ago * DAY - 3600 * 5)
            devicetools.save_backup(north, airos_config(north.name, freq, txpower), "airos", reason,
                                    root=folder / devicetools.BACKUP_FOLDER)
    finally:
        devicetools.time = real
    return notes


# ---------------------------------------------------------------------------
# The demo in the app
# ---------------------------------------------------------------------------

_MISSING = object()
FOLDER_PREFIX = "opendisco-demo-"


def _tidy(mobile: bool) -> None:
    """Delete the folders of demos that never ended: a phone stops an app without letting it
    clean up, so any left there are old; on a computer, another copy of the app may be showing
    its demo, so only those a day old go."""
    for old in Path(tempfile.gettempdir()).glob(FOLDER_PREFIX + "*"):
        try:
            if mobile or time.time() - old.stat().st_mtime > DAY:
                shutil.rmtree(old, ignore_errors=True)
        except OSError:
            pass


class Credentials:
    """credstore's stand-in while the demo shows: the made-up devices' passwords, in memory."""

    def __init__(self, passwords: dict):
        self.passwords = dict(passwords)

    def available(self) -> bool:
        return True

    def store_name(self) -> str:
        return "the demo's memory"

    def load(self, mac: str) -> str | None:
        return self.passwords.get(mac)

    def save(self, mac: str, user: str, password: str) -> bool:
        self.passwords[mac] = password
        return True

    def forget(self, mac: str) -> bool:
        return self.passwords.pop(mac, None) is not None


class Demo:
    """The demo network in the app, from its first scan to end(). It gives the app what the demo
    keeps apart (settings.json's hidden devices, SSH user and logins, the notes, known_hosts,
    backups, the firmware lookup) and the device tools demossh in place of the network, and puts
    all of it back when it ends. demossh stays as the modules' sshrun after that: it hands a real
    login to the real module, and refuses a login made for the demo, so a tool still finishing on
    a made-up device can't reach the network."""

    def __init__(self, app):
        self.app = app
        _tidy(app.caps["mobile"])
        self.folder = Path(tempfile.mkdtemp(prefix=FOLDER_PREFIX))
        atexit.register(shutil.rmtree, self.folder, True)
        self.network = network(self.folder)
        self.patches = []  # (object or dict, name, what it was)
        self.ended = False
        self._start()

    def _set(self, target, name, value) -> None:
        if isinstance(target, dict):
            self.patches.append((target, name, target.get(name, _MISSING)))
            target[name] = value
        else:
            self.patches.append((target, name, getattr(target, name, _MISSING)))
            setattr(target, name, value)

    def _start(self) -> None:
        app, mobile = self.app, self.app.caps["mobile"]
        known = logins()
        remembered = {mac: {"user": k["user"], "port": k["port"]} for mac, k in known.items()}
        factory = {FACTORY: ["ubnt", "ubnt"]}  # found before: the bench spare's issue shows from the start
        for key, value in (("hidden", {}), ("ssh_user", "demo"), ("factory_logins", factory),
                           ("device_logins", remembered)):
            self._set(app.settings, key, value)
        self._set(app, "hidden", app.settings["hidden"])
        app._update_hidden_button()
        self._set(core, "FACTORY_LOGINS_FOUND", factory)
        self._set(linkhealth, "READINGS", {})  # the radios' link readings: the demo's own
        self._set(app, "known_hosts", self.folder / "known_hosts")
        self._set(app, "device_notes", seed(self.folder, scan(self.network)))
        linkhealth.READINGS.clear()  # (seed's scan read them; each scan reads them again)
        self._set(app, "firmware", health.Firmware(self.folder, on_found=lambda: app._from_worker(app._health_changed),
                                                   log=lambda m: app._from_worker(app._append_log, m, False)))
        self._set(devicetools, "BACKUP_ROOT", self.folder / devicetools.BACKUP_FOLDER)
        for name in ("answers", "firmware_index", "download_release"):
            self._set(devicetools, name, getattr(demossh, name))
        for name in ("rescan_device", "find_ports", "ping"):
            self._set(core, name, getattr(demossh, name))
        self._set(health, "measure", demossh.measure)
        devicetools.sshrun = demossh  # for good (Demo's docstring says why)
        if mobile:
            from opendisco import phone, phonetools
            phone.phonessh = phonetools.phonessh = demossh
            self._set(app, "phone_passwords", {mac: k["password"] for mac, k in known.items()})
        else:
            from opendisco import devicegui, terminal
            devicegui.sshrun = demossh
            self._set(devicegui, "credstore", Credentials({mac: k["password"] for mac, k in known.items()}))
            self._set(devicegui, "ssh_here", lambda: True)  # with or without an ssh program here
            session = terminal.Session
            self._set(terminal, "Session", demossh.session_factory(session))
            self._set(terminal, "OwnSession", demossh.own_session_factory(session))  # (a computer without ssh)
            self._set(terminal, "in_app_terminals", lambda: True)
        title = app.main_window.title
        self._set(app.main_window, "title", tr("{app} Demo", app=app.formal_name) if mobile else f"{title}: {_(MODE)}")
        if hasattr(app, "_top_changed"):
            app._top_changed()  # Android's title bar
        demossh.NETWORK = self.network

    def scan(self) -> core.ScanResult:
        """The made-up devices as they are now (a firmware update, a new name, a reboot show)."""
        return scan(self.network, core.parse_args(["--demo"]))

    def status(self, res: core.ScanResult) -> str:
        heard = sum(1 for d in res.devices if d.ubnt_packets)
        return tr("{stamp}: {count} device(s), {heard} answered UBNT discovery. Nothing was sent on the network; log in "
                  "as demo / demo.", stamp=_(STAMP), count=len(res.devices), heard=heard)

    def saved_settings(self, settings: dict) -> dict:
        """settings.json's own values of what the demo keeps apart, whatever the app has now."""
        saved = dict(settings)
        for target, name, value in self.patches:
            if target is self.app.settings:
                if value is _MISSING:
                    saved.pop(name, None)
                else:
                    saved[name] = value
        return saved

    def busy(self) -> str:
        """What's still running on a made-up device, which has to finish before the demo ends."""
        app = self.app
        if app.rescanning or app.finding or app.measuring is not None:
            return _("a rescan, port search or latency measurement")
        job = getattr(app, "device_job", None)
        if job:  # (the phones' device tools)
            return _(PHONE_JOBS.get(job["name"], job["name"]))
        if not app.caps["mobile"]:
            from opendisco import devicegui
            if devicegui._busy:
                return ", ".join(sorted({_(doing) for doing in devicegui._busy.values()}))
        return ""

    def end(self, quitting: bool = False) -> None:
        """Close what's open on the made-up devices, put back what the demo replaced, and delete its
        folder. Quitting, the app's parts stay as they are: only the folder goes."""
        if self.ended:
            return
        self.ended = True
        app = self.app
        if not quitting:
            if app.term is not None:
                for session in [s for s in app.term.sessions.values() if getattr(s, "demo", False)]:
                    app.term.close(session)
            if getattr(app, "pinging", None):
                app.pinging[1].set()
            if getattr(app, "ssh", None):
                app.ssh[1].close()
            if not app.caps["mobile"]:
                for window in list(app.windows):  # the device tools' windows, its notes, its hidden devices
                    if window is not app.main_window and window.title != _("Settings"):
                        window.on_close()  # as if closed by hand: each window's own clean-up runs
            demossh.NETWORK = None
            for target, name, value in reversed(self.patches):
                if isinstance(target, dict):
                    if value is _MISSING:
                        target.pop(name, None)
                    else:
                        target[name] = value
                elif value is not _MISSING:
                    setattr(target, name, value)
            app._update_hidden_button()
            if hasattr(app, "_top_changed"):
                app._top_changed()
        shutil.rmtree(self.folder, ignore_errors=True)


# ---------------------------------------------------------------------------
# Exports: stamped
# ---------------------------------------------------------------------------

def file_name(name: str) -> str:
    """An export's name, saying it's the demo's (opendisco-demo-scan-...)."""
    return re.sub(r"^opendisco-", "opendisco-demo-", name) if name.startswith("opendisco-") else f"demo-{name}"


def stamp_bytes(name: str, data: bytes) -> bytes:
    """An export (by its file name's extension) stamped as the demo network's: HTML gets a banner
    and its title (unless it has the stamp already), JSON a "demo" key first, CSV and text a first line. Anything else (a config
    file) is left as it is: a line in it would spoil it."""
    ext = Path(name).suffix.lower()
    bom = data.startswith(b"\xef\xbb\xbf")
    text = data[3 if bom else 0:].decode("utf-8", "surrogateescape")
    if ext in (".html", ".htm"):
        if _(STAMP) in text:  # the Site Report stamps itself (records.site_report's demo)
            return data
        # (the reports are in the app's language; the data exports below keep the English stamp)
        banner = (f'<p style="background:#fff3cd;color:#664d03;border:1px solid #e0c46c;border-radius:6px;'
                  f'padding:8px 12px;font-weight:600">{tr("{stamp}. Nothing in this report is real.", stamp=_(STAMP))}</p>')
        text = re.sub(r"<title>(.*?)</title>", lambda m: f"<title>{tr('Demo: {title}', title=m.group(1))}</title>",
                      text, count=1, flags=re.DOTALL)
        text, n = re.subn(r"<body[^>]*>", lambda m: m.group(0) + banner, text, count=1)
        text = text if n else banner + text
    elif ext == ".json":
        try:
            parsed = json.loads(text)
        except ValueError:
            text = f"{STAMP}\n{text}"
        else:
            parsed = {"demo": STAMP, **parsed} if isinstance(parsed, dict) else {"demo": STAMP, "data": parsed}
            text = json.dumps(parsed, indent=2, ensure_ascii=False, default=str) + "\n"
    elif ext == ".csv":
        text = f'"{STAMP}"\r\n{text}'
    elif ext in (".txt", ".log"):
        text = f"{STAMP}\n\n{text}"
    else:
        return data
    return (b"\xef\xbb\xbf" if bom else b"") + text.encode("utf-8", "surrogateescape")


def stamp_file(path) -> None:
    """Stamp an export file made from the demo network: a .zip's reports and index inside it."""
    path = Path(path)
    if path.suffix.lower() != ".zip":
        path.write_bytes(stamp_bytes(path.name, path.read_bytes()))
        return
    with zipfile.ZipFile(path) as z:
        members = [(info, z.read(info)) for info in z.infolist()]
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("DEMO.txt", f"{STAMP}. Nothing in this archive is real.\n")
        for info, data in members:
            z.writestr(info, stamp_bytes(info.filename, data))


# ---------------------------------------------------------------------------
# The command line: opendisco --demo
# ---------------------------------------------------------------------------

def cli_scan(opts, log) -> core.ScanResult:
    """The demo network for the command line (core.main prints it as it would a scan's)."""
    log(f"{STAMP}: nothing is sent on the network. ({FULL_NAME} {__version__})")
    core.FACTORY_LOGINS_FOUND = {FACTORY: ["ubnt", "ubnt"]}  # as the app shows it
    return scan(network(), opts)
