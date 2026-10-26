"""The demo network's SSH: what sshrun (desktops) and phonessh (phones) give the device tools, for
made-up devices kept in memory, so every tool can be tried without any gear and with nothing sent
on the network.

demo.py puts this module in their place (devicetools.sshrun, devicegui's, phone.py's and
phonetools') once the demo network is showing, and NETWORK holds its devices. The real module is
devicetools' own choice: the system's ssh and scp (sshrun), or the app's own SSH client
(phonessh) on phones and on a computer without ssh. Logins made while
it shows are DemoLogins: their commands, file copies and shells go to the made-up device at that
address. Everything else is the real module's (SSHError, Result, a real Login), so a login of a
real device, made before the demo or after it, goes to the real module as before; a DemoLogin
used after the demo ended fails instead of reaching the network.

Each made-up device (Gear) keeps its files (airOS's /tmp/system.cfg and the copy in flash,
EdgeOS's /config/config.boot, what was copied to /tmp) and runs the commands devicetools sends
through a small shell (Ash): sequences, pipes, redirections, if and for, $(...), and the
background (&), which keeps running after the session ends, as nohup'd commands on the device
do. The commands themselves are Python functions in COMMANDS (cfgmtd, fwupdate, reboot,
wstalist, mca-status, vyatta-cfg-cmd-wrapper...): a tool that sends a new command needs only a
function there. Logins are checked against the users in the device's own running config, hashed
the way the device keeps them, so Change login changes what works. An EdgeRouter keeps two
firmware images (show system image, add system image) and takes EdgeOS's login commands, with
EdgeOS 3's password rules once it runs 3.x; an airMAX radio reads its link as airOS 8 does
(mca-status, wstalist).

Also here: the rest of what the tools reach on the network, made up the same way: answers() (is
SSH up), the firmware server (firmware_index, download_release: a stand-in file, not firmware),
rescanning a device (its discovery reply), port searches, latency and ping, and the desktop
Terminal tab's sessions (session_factory; own_session_factory for a computer without ssh) and
the phones' console (Shell's stand-in, Console).
Delays are like the real ones, only shorter where the real ones take minutes (DELAYS).
"""
import difflib
import fnmatch
import hashlib
import json
import random
import re
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from opendisco import core, devicetools

real = devicetools.sshrun  # the module this one stands in for (it stays devicetools' choice)

NETWORK = None  # the demo's Network while it shows; None otherwise
# Seconds things take on the made-up gear: about what the real gear takes, but minutes are cut short.
DELAYS = {"login": 0.3, "hop": 0.15, "no answer": 1.5, "copy rate": 4_000_000, "save": 1.2, "apply": 2.5,
          "commit": 2.0, "image write": 15.0, "firmware write": 3.0, "firmware offline": 45.0, "reboot offline": 25.0,
          "download": 4.0, "rescan": 1.5, "ping": 1.0}
FIRMWARE_MARK = "OPENDISCO-DEMO-FIRMWARE"  # the stand-in firmware file's first line


@dataclass
class DemoLogin(real.Login):
    """A login made while the demo shows: for a made-up device."""


def __getattr__(name):
    """What isn't simulated is the real module's; Login is DemoLogin while the demo shows."""
    if name == "Login":
        return DemoLogin if NETWORK is not None else real.Login
    return getattr(real, name)


def _demo(login) -> bool:
    return isinstance(login, DemoLogin)


def _network():
    if NETWORK is None:
        raise real.SSHError("The demo network has ended: its made-up devices are gone.", "other")
    return NETWORK


# ---------------------------------------------------------------------------
# What sshrun and phonessh offer
# ---------------------------------------------------------------------------

def available() -> bool:
    return True if NETWORK is not None else real.available()


def run(login, command: str, timeout: float = 60, stop=None):
    """Run a command on the device (real.run for a real login)."""
    if not _demo(login):
        return real.run(login, command, timeout, stop)
    gear = _network().connect(login, stop)
    out, err, code = gear.shell(login.user).run(command, timeout=timeout)
    return real.Result(code, out, err)


def check_login(login, stop=None) -> None:
    if not _demo(login):
        return real.check_login(login, stop)
    run(login, "true", timeout=40, stop=stop)


def upload(login, local: Path, path: str, progress=None, stop=None, idle: float = 120) -> None:
    """Copy a file to the device, as long as a copy of its size takes (a stand-in firmware file
    counts as the size it stands in for)."""
    if not _demo(login):
        return real.upload(login, local, path, progress, stop, idle)
    gear = _network().connect(login, stop)
    data = Path(local).read_bytes()
    claimed = re.search(rb"size=(\d+)", data[:200]) if data.startswith(FIRMWARE_MARK.encode()) else None
    _wait_copy(int(claimed.group(1)) if claimed else len(data), progress, stop)
    gear.check_up(login)
    gear.write(path, data)


def download(login, path: str, local: Path, stop=None) -> None:
    if not _demo(login):
        return real.download(login, path, local, stop)
    gear = _network().connect(login, stop)
    data = gear.read(path)
    if data is None:
        raise real.SSHError(f"Copying failed: scp: {path}: No such file or directory")
    _wait_copy(len(data), None, stop)
    Path(local).write_bytes(data)


def _wait_copy(size: int, progress, stop) -> None:
    seconds = max(0.2, size / DELAYS["copy rate"])
    steps = max(1, int(seconds / 0.25))
    for n in range(1, steps + 1):
        if stop is not None and stop.is_set():
            raise real.SSHError("Cancelled.", "cancelled")
        time.sleep(seconds / steps)
        if progress:
            progress(100 * n // steps)


def ssh_command(login, command, *extra) -> list:
    """What the Terminal tab runs for an SSH session (devicegui): ssh's own arguments, which the
    demo's session (session_factory) reads back."""
    if not _demo(login):
        return real.ssh_command(login, command, *extra)
    jump = ["-J", ",".join(f"{hop.user}@{hop.ip}:{hop.port}" for hop in login.via)] if login.via else []
    return ["ssh", *extra, *jump, "-p", str(login.port), "-o", f"HostKeyAlias={login.alias}",
            "-o", f'UserKnownHostsFile="{login.known_hosts}"', "-l", login.user, login.ip,
            *([command] if command else [])]


def last_hop(login):
    """The device before this one on its route (a DemoLogin stays one)."""
    if not _demo(login):
        return real.last_hop(login)
    *before, hop = login.via
    return DemoLogin(hop.ip, hop.port, hop.user, hop.password, hop.alias, hop.known_hosts, tuple(before))


# ---------------------------------------------------------------------------
# The rest of the network the tools reach
# ---------------------------------------------------------------------------

def answers(ip: str, port: int, timeout: float = 3) -> bool:
    """Whether SSH (or a port) answers there, from this computer."""
    gear = NETWORK.find(ip) if NETWORK else None
    time.sleep(0.05)
    return bool(gear and gear.direct and gear.up and port in gear.ports)


def firmware_index(refresh: bool = False) -> list:
    """The firmware server's list, as far as the made-up gear needs it."""
    time.sleep(0.4)
    return [release(product, platform, version, date) for product, platform, version, date in _network().releases]


def release(product: str, platform: str, version: str, date: str) -> dict:
    """A release as Ubiquiti's firmware server lists it, its file a stand-in (stand_in())."""
    data = stand_in(product, version)
    name = f"{product}.v{version}.demo.bin"
    return {"channel": "release", "product": product, "platform": platform, "version": f"v{version}",
            "created": f"{date}T09:30:00+00:00", "file_size": CLAIMED_SIZE,
            "sha256_checksum": hashlib.sha256(data).hexdigest(), "md5": hashlib.md5(data).hexdigest(),
            "_links": {"data": {"href": f"https://firmware.demo.invalid/{name}"}}}


CLAIMED_SIZE = 27_525_120  # what a stand-in file counts as: about an airMAX AC image


def stand_in(product: str, version: str) -> bytes:
    """The demo's firmware "file": a few lines saying what it stands in for, not firmware."""
    return (f"{FIRMWARE_MARK} product={product} version={version} size={CLAIMED_SIZE}\n"
            "Not firmware: it stands in for a release on the OpenDisco demo network's made-up devices.\n").encode()


def download_release(release_item: dict, folder: Path, progress=None, stop=None) -> Path:
    """Download a release: the stand-in, kept in the demo's folder whatever folder is given."""
    from opendisco import devicetools
    m = re.match(r"(\S+)\.v(\S+)\.demo\.bin$", release_item["_links"]["data"]["href"].rsplit("/", 1)[-1])
    data = stand_in(m.group(1), m.group(2))
    total, steps = int(release_item.get("file_size") or len(data)), 20
    for n in range(1, steps + 1):
        if stop is not None and stop.is_set():
            raise devicetools.ToolError("Cancelled.")
        time.sleep(DELAYS["download"] / steps)
        if progress:
            progress(total * n // steps, total)
    path = _network().folder / f"{release_item['sha256_checksum'][:12]}-{m.group(0)}"
    path.write_bytes(data)
    return path


def rescan_device(res, d, log, seconds: float = 3.0):
    """core.rescan_device: the device's discovery reply (when it's up and this computer reaches
    it), its ports, then every device's diagnostics again."""
    core.STOP.clear()
    time.sleep(DELAYS["rescan"])
    gear = NETWORK.find(d.ip) if NETWORK else None
    answered = False
    if gear and gear.direct and gear.up and gear.discovery:
        dev, _changes = res.inv.ingest_ubnt(core.parse_packet(gear.discovery_reply()), (gear.ip, core.UBNT_PORT),
                                            "ubnt")
        d, answered = dev, True
    if gear and gear.direct and gear.up:
        d.ports = sorted(gear.ports)
        d.services.update(gear.ports)
    elif d.ports is not None:
        d.ports = []
    log(f"Rescanned {d.ip}: " + ("it answered discovery." if answered else "no discovery reply."))
    if res.diag_args:
        core.diagnose(res.inv, *res.diag_args)
    res.devices = core.sorted_devices(res.inv)
    return d, answered


def find_ports(res, d, kind: str, log, progress=None) -> list:
    """core.find_ports: every TCP port, likeliest first, at a made-up speed; what's open is what
    the made-up device has."""
    core.STOP.clear()
    gear = NETWORK.find(d.ip) if NETWORK else None
    reach = gear if gear and gear.direct and gear.up else None
    order = core.search_order(kind, res.inv.devices.values())
    d.ports = d.ports or []
    checked, chunk = 0, 2048
    log(f"Checking every TCP port on {d.ip}" + ("" if kind == "all" else f" for {core.SERVICE_NAMES[kind]}")
        + ", likeliest first...")
    hit = False
    while checked < len(order) and not core.STOP.is_set() and not hit:
        ports = order[checked:checked + chunk]
        checked += len(ports)
        time.sleep(0.12)
        for port in ports:
            service = reach.ports.get(port) if reach else None
            if service:
                d.services[port] = service
                d.ports = sorted(set(d.ports) | {port})
                hit = hit or service == kind
        if progress:
            progress(checked, len(order), len(d.ports))
    d.port_search = {"for": kind, "checked": checked, "at": time.time(), "stopped": checked < 65535 and not hit}
    log(f"  {d.ip}: {checked} TCP ports checked; open: "
        + (", ".join(f"{p} {d.services[p]}" for p in d.ports) or "none"))
    if res.diag_args:
        core.diagnose(res.inv, *res.diag_args)
    res.devices = core.sorted_devices(res.inv)
    return d.ports if kind == "all" else sorted(p for p, k in d.services.items() if k == kind)


def measure(devices, count: int = 4, stop=None) -> str:
    """health.measure: each device's round trips, from what the made-up device answers."""
    time.sleep(DELAYS["ping"])
    for d in devices:
        gear = NETWORK.find(d.ip) if NETWORK and d.ip else None
        replies = [gear.ping_time() for _ in range(count)] if gear and gear.direct and gear.up else [None] * count
        if None in replies or any(r and r > 100 for r in replies):
            replies += [gear.ping_time() if gear and gear.direct and gear.up else None for _ in range(6)]
        got = [r for r in replies if r is not None]
        d.health["latency"] = {"sent": len(replies), "received": len(got), "at": time.time(), "how": "ICMP",
                               "replies_ms": got}
    return "ICMP"


def ping(ip: str, out, stop, interval: float = 1.0, timeout: float = 2.0, count: int = 0, source=None) -> None:
    """core.ping, from this computer (or from source, a made-up device on the way)."""
    gear = NETWORK.find(ip) if NETWORK else None
    out(f"PING {ip} ({ip}): 56 data bytes" if source else f"PING {ip}: 56 data bytes")
    sent, rtts = 0, []
    while not stop() and not (count and sent >= count):
        reach = gear and gear.up and (gear.direct or source is not None)
        rtt = gear.ping_time() if reach else None
        if rtt is not None:
            rtt += 0.4 if source is not None else 0
            rtts.append(rtt)
            out(f"64 bytes from {ip}: {'seq' if source else 'icmp_seq'}={sent} ttl=64 time={rtt:.3f} ms")
        sent += 1
        waited = 0.0
        while waited < interval and not stop():
            time.sleep(0.05)
            waited += 0.05
        if rtt is None and not stop():
            out(f"Request timeout for icmp_seq {sent - 1}")
    out(f"\n--- {ip} ping statistics ---")
    out(f"{sent} packets transmitted, {len(rtts)} packets received, "
        f"{(sent - len(rtts)) / sent * 100 if sent else 0:.1f}% packet loss")
    if rtts:
        mean = sum(rtts) / len(rtts)
        spread = (sum((r - mean) ** 2 for r in rtts) / len(rtts)) ** 0.5
        out(f"round-trip min/avg/max/stddev = {min(rtts):.3f}/{mean:.3f}/{max(rtts):.3f}/{spread:.3f} ms")


# ---------------------------------------------------------------------------
# The made-up devices
# ---------------------------------------------------------------------------

class Network:
    """The made-up devices, by address; releases: (product, platform, version, date) on the
    made-up firmware server; folder: where downloads go (the demo's own)."""

    def __init__(self, gears, releases=(), folder=None):
        self.gears = {g.ip: g for g in gears}
        for g in gears:
            g.network = self
        self.releases = list(releases)
        self.folder = Path(folder) if folder else None

    def find(self, ip: str):
        return self.gears.get(ip)

    def connect(self, login, stop=None):
        """The device at the end of the login's route, logged in to: what ssh would have done
        (each device on the way, its host key, then the password)."""
        route = [*login.via, login]
        for n, hop in enumerate(route):
            time.sleep(DELAYS["login"] if n == 0 else DELAYS["hop"])
            if stop is not None and stop.is_set():
                raise real.SSHError("Cancelled.", "cancelled")
            gear = self.find(hop.ip)
            where = f"{hop.ip}, on the way to {login.ip}," if hop is not login else login.where
            if gear is None or not gear.up or (n == 0 and not gear.direct):
                time.sleep(DELAYS["no answer"])
                raise real.SSHError(f"No SSH answer from {hop.ip} port {hop.port}"
                                    + (f", on the way to {login.ip}" if hop is not login else "") + " (timed out).",
                                    "timeout")
            if hop.port not in gear.ports or gear.ports[hop.port] != "ssh":
                raise real.SSHError(f"Nothing accepts SSH connections on {hop.ip} port {hop.port}"
                                    + (f", on the way to {login.ip}." if hop is not login else "."), "refused")
            gear.check_host_key(hop)
            if not gear.accepts(hop.user, hop.password):
                raise real.SSHError(f"{where} didn't accept the username and password.", "auth")
        return self.find(login.ip)


@dataclass
class Gear:
    """One made-up device: what it says in discovery, its logins and files, and the programs it
    has (by path; their work is COMMANDS'). kind: "airos", "isp" (airFiber), "edgeos"."""
    mac: str
    ip: str
    name: str
    platform: str  # its model, as discovery names it (R5AC-PRISM)
    firmware: str  # its firmware string (XC.qca955x.v8.7.11.46972.220614.0420)
    kind: str
    uptime: float  # seconds, when the demo starts
    files: dict  # path -> bytes
    ports: dict = field(default_factory=lambda: {22: "ssh", 80: "http", 443: "https"})
    essid: str | None = None
    wmode: int | None = None  # discovery's wireless mode: 2 station, 3 access point
    pings: list = field(default_factory=list)  # round trips it answers with (ms), None for a lost one
    direct: bool = True  # this computer reaches it (one behind a sector's link doesn't)
    discovery: bool = True  # it answers UBNT discovery
    is_default: bool = False
    stations: list = field(default_factory=list)  # wstalist: the gear associated with it (airOS)
    lldp: list = field(default_factory=list)  # [(port, gear)] its LLDP neighbours
    arp: list = field(default_factory=list)  # the gear in its ARP table
    interfaces: dict = field(default_factory=dict)  # name -> MAC
    address_on: str = "br0"  # the interface its address is on
    link: dict = field(default_factory=dict)  # a radio link: signal, noise, ccq, distance, capacity...
    host_key: str = ""  # its SSH host key, as known_hosts files it ("ssh-ed25519 AAAA...")
    images: list = field(default_factory=list)  # EdgeOS: {"name", "running", "default"} for its two images

    def __post_init__(self):
        self.network = None
        self.booted = time.time() - self.uptime
        self.down_until = 0.0
        self.next_firmware = None  # what it runs after the reboot under way
        self.lock = threading.RLock()
        self.locating = False
        self.flash = self.files.get(CONFIG_FILES.get(self.kind, ""), b"")  # the config it boots with
        self.pending = {}  # EdgeOS: user -> the config session's candidate config
        self.host_key = self.host_key or _host_key(self.mac)
        self.interfaces = self.interfaces or {"eth0": self.mac, self.address_on: self.mac}
        if self.kind in ("airos", "isp"):
            self.files.setdefault(AIROS_RUNNING, self.files.get(AIROS_CONFIG, b""))
        elif self.kind == "edgeos":  # what it booted with, until a commit changes it
            self.files.setdefault(RUNNING_BOOT, self.files.get(EDGEOS_CONFIG, b""))

    # -- state --------------------------------------------------------------------
    @property
    def up(self) -> bool:
        with self.lock:
            if self.down_until and time.monotonic() >= self.down_until:
                self._boot()
            return not self.down_until

    def check_up(self, login) -> None:
        if not self.up:
            raise real.SSHError(f"The connection to {login.where} dropped: Connection reset by peer", "other")

    def go_down(self, seconds: float, firmware: str | None = None) -> None:
        """It restarts: offline for that long, then back (with that firmware, when given)."""
        with self.lock:
            self.down_until = time.monotonic() + seconds
            self.next_firmware = firmware or self.next_firmware

    def _boot(self) -> None:
        self.down_until = 0.0
        self.booted = time.time()
        if self.next_firmware:
            self.firmware, self.next_firmware = self.next_firmware, None
        boot = next((i for i in self.images if i["default"]), None)
        if boot:  # EdgeOS boots its default image
            for image in self.images:
                image["running"] = image is boot
            self.firmware = re.sub(r"\.v\d.*$", "." + boot["name"], self.firmware)
        self.files = {p: b for p, b in self.files.items() if not p.startswith("/tmp/")}  # /tmp is memory
        self.locating = False
        self.pending.clear()
        if self.kind in ("airos", "isp"):
            self.files[AIROS_CONFIG] = self.files[AIROS_RUNNING] = self.flash
        elif self.kind == "edgeos":
            self.files[RUNNING_BOOT] = self.files.get(EDGEOS_CONFIG, b"")
        self._take_config()

    @property
    def version(self) -> str:
        m = re.search(r"\.v(\d+\.\d+(?:\.\d+)?(?:-hotfix\.\d+)?)", self.firmware)
        return m.group(1) if m else self.firmware

    def read(self, path: str) -> bytes | None:
        """A file, or what the system makes up for one (/proc/uptime, /proc/net/arp...)."""
        with self.lock:
            if path in self.files:
                return self.files[path]
        made = self._made_up(path)
        return made.encode() if made is not None else None

    def write(self, path: str, data: bytes, append: bool = False) -> None:
        with self.lock:
            self.files[path] = (self.files.get(path, b"") if append else b"") + data

    def exists(self, path: str) -> bool:
        return self.read(path) is not None or path in self.programs or self.is_dir(path)

    def is_dir(self, path: str) -> bool:
        path = path.rstrip("/") + "/"
        return path == "/" or any(p.startswith(path) for p in (*self.files, *self.programs, *self._virtual()))

    def listing(self) -> list:
        return sorted({*self.files, *self.programs, *self._virtual()})

    def _virtual(self) -> list:
        return ["/proc/uptime", "/proc/net/arp", *(f"/sys/class/net/{n}/address" for n in self.interfaces)]

    def _made_up(self, path: str) -> str | None:
        if path == "/proc/uptime":
            up = time.time() - self.booted
            return f"{up:.2f} {up * 0.93:.2f}\n"
        if path == "/proc/net/arp":
            rows = ["IP address       HW type     Flags       HW address            Mask     Device"]
            rows += [f"{g.ip:<16} 0x1         0x2         {g.mac}     *        {self.address_on}" for g in self.arp]
            return "\n".join(rows) + "\n"
        m = re.fullmatch(r"/sys/class/net/([^/]+)/address", path)
        if m and m.group(1) in self.interfaces:
            return self.interfaces[m.group(1)] + "\n"
        if path == "/etc/version":
            return self.firmware + "\n"
        if path == "/etc/board.info" and self.kind in ("airos", "isp"):
            return f"board.name={self.platform}\nboard.hwaddr={self.mac.replace(':', '').upper()}\nboard.upgrade=120\n"
        return None

    @property
    def programs(self) -> dict:
        """path -> COMMANDS' name, for what this kind of device has."""
        found = dict(COMMON)
        found.update(PROGRAMS.get(self.kind, {}))
        return found

    # -- logging in ---------------------------------------------------------------
    def users(self) -> dict:
        """user -> password hash, from the config it runs."""
        if self.kind in ("airos", "isp"):
            text = self.files.get(AIROS_RUNNING, b"").decode("utf-8", "replace")
            values = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
            return {values[k]: values.get(k.replace(".name", ".password"), "") for k in values
                    if re.fullmatch(r"users\.\d+\.name", k) and values.get(k.replace(".name", ".status")) != "disabled"}
        text = self.running_boot().decode("utf-8", "replace")
        return {m.group(1): m.group(2) for m in re.finditer(
            r"user (\S+) \{\s*authentication \{\s*encrypted-password \"?([^\"\s]+)\"?", text)}

    def accepts(self, user: str, password: str) -> bool:
        from opendisco import devicetools
        stored = self.users().get(user)
        return bool(stored) and devicetools.verify_password(password, stored)

    def check_host_key(self, login) -> None:
        """Trusted the first time and filed under its alias (known_hosts); a different one is refused."""
        try:
            lines = login.known_hosts.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        filed = [" ".join(line.split()[1:3]) for line in lines if line.split()[:1] == [login.alias]]
        if filed and self.host_key not in filed:
            raise real.SSHError(f"The SSH key of {login.ip} changed since the last connection: it was reset or "
                                "replaced, or something is in between. If that's expected, forget its saved SSH "
                                "key, then try again.", "key")
        if not filed:
            try:
                login.known_hosts.parent.mkdir(parents=True, exist_ok=True)
                with login.known_hosts.open("a", encoding="utf-8") as f:
                    f.write(f"{login.alias} {self.host_key}\n")
            except OSError:
                pass

    def shell(self, user: str):
        return Ash(self, user)

    def uid(self, user: str) -> int:
        """airOS logins are root; EdgeOS's each a Linux user of their own."""
        if self.kind in ("airos", "isp") or user == "root":
            return 0
        return 1000 + int(hashlib.md5(user.encode()).hexdigest(), 16) % 900

    def groups(self, user: str) -> list:
        if self.kind == "edgeos" and user != "root":
            return ["users", "vyattacfg", "adm", "sudo", "dip"]
        return ["root"] if self.uid(user) == 0 else ["users"]

    # -- config ---------------------------------------------------------------------
    def running_boot(self) -> bytes:
        """EdgeOS: the config it runs (what it booted with, and commits since)."""
        return self.files.get(RUNNING_BOOT, b"")

    def _take_config(self) -> None:
        """What the config it runs says of it: its name (and, once its factory login is changed,
        it's no longer a factory-default device)."""
        if self.kind in ("airos", "isp"):
            text = self.files.get(AIROS_RUNNING, b"").decode("utf-8", "replace")
            m = re.search(r"^resolv\.host\.1\.name=(.+)$", text, re.M)
        else:
            text = self.running_boot().decode("utf-8", "replace")
            m = re.search(r"host-name (\S+)", text)
        if m:
            self.name = m.group(1).strip()
        if self.is_default and "ubnt" not in self.users():
            self.is_default = False

    # -- what it says of itself ---------------------------------------------------------
    def discovery_reply(self) -> bytes:
        """Its UBNT discovery v1 reply."""
        mac_b = bytes(int(x, 16) for x in self.mac.split(":"))
        ip_b = bytes(int(x) for x in self.ip.split("."))
        ssh = next((p for p, k in self.ports.items() if k == "ssh"), 22)
        body = (_tlv(0x02, mac_b + ip_b) + _tlv(0x01, mac_b) + _tlv(0x03, self.firmware.encode())
                + _tlv(0x0A, struct.pack(">I", int(time.time() - self.booted))) + _tlv(0x0B, self.name.encode())
                + _tlv(0x0C, self.platform.encode()))
        if self.essid:
            body += _tlv(0x0D, self.essid.encode())
        if self.wmode is not None:
            body += _tlv(0x0E, bytes([self.wmode]))
        body += _tlv(0x0F, struct.pack(">HH", 1, 443)) + _tlv(0x1C, struct.pack(">H", ssh))
        if self.is_default:
            body += _tlv(0x17, b"\x01")
        if self.locating:
            body += _tlv(0x1A, b"\x01")
        return struct.pack(">BBH", 1, 0, len(body)) + body

    def ping_time(self) -> float | None:
        pick = random.choice(self.pings) if self.pings else 1.0
        return None if pick is None else max(0.2, pick * random.uniform(0.85, 1.2))


def _tlv(kind: int, value: bytes) -> bytes:
    return struct.pack(">BH", kind, len(value)) + value


def _host_key(mac: str) -> str:
    """A made-up ed25519 host key, the same for a device every time."""
    import base64
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + hashlib.sha256(mac.encode()).digest()
    return "ssh-ed25519 " + base64.b64encode(blob).decode()


AIROS_CONFIG, AIROS_RUNNING = "/tmp/system.cfg", "/tmp/running.cfg"
EDGEOS_CONFIG, RUNNING_BOOT = "/config/config.boot", "/opt/vyatta/config/active.boot"
CONFIG_FILES = {"airos": AIROS_CONFIG, "isp": AIROS_CONFIG, "edgeos": EDGEOS_CONFIG}


# ---------------------------------------------------------------------------
# The shell
# ---------------------------------------------------------------------------

class _Exit(Exception):
    def __init__(self, code: int):
        super().__init__(code)
        self.code = code


class _Syntax(Exception):
    pass


def _closing(text: str, i: int, close: str) -> int:
    """Where the quote or $( ... ) starting at i ends."""
    if close == "'":
        j = text.find("'", i + 1)
        if j < 0:
            raise _Syntax("unterminated quoted string")
        return j
    depth, j = 0, i
    while j < len(text):
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if close == '"':
            if c == '"' and j > i:
                return j
            if text.startswith("$(", j):
                j = _closing(text, j + 1, ")") + 1
                continue
        else:
            if c in "'\"" and j > i:
                j = _closing(text, j, c) + 1
                continue
            depth += {"(": 1, ")": -1}.get(c, 0)
            if depth == 0:
                return j
        j += 1
    raise _Syntax("unexpected end of file (expecting " + close + ")")


def _lex(text: str) -> list:
    """Words (as typed: quotes and $ kept for expanding), operators and redirections."""
    tokens, word, i = [], None, 0

    def flush():
        nonlocal word
        if word is not None:
            tokens.append(("word", word))
        word = None

    while i < len(text):
        c = text[i]
        if c in " \t":
            flush()
            i += 1
        elif c == "\n":
            flush()
            tokens.append(("op", ";"))
            i += 1
        elif c == "#" and word is None:
            while i < len(text) and text[i] != "\n":
                i += 1
        elif c == "\\":
            word = (word or "") + text[i:i + 2]
            i += 2
        elif c in "'\"":
            j = _closing(text, i, c)
            word, i = (word or "") + text[i:j + 1], j + 1
        elif c == "$" and text[i + 1:i + 2] in ("(", "{"):
            j = _closing(text, i + 1, ")") if text[i + 1] == "(" else text.index("}", i)
            word, i = (word or "") + text[i:j + 1], j + 1
        elif c in "<>":
            fd = int(word) if word is not None and word.isdigit() else None
            if fd is not None:
                word = None
            flush()
            op = ">>" if text.startswith(">>", i) else c
            i += len(op)
            m = re.match(r"&(\d+)", text[i:])
            if m:
                tokens.append(("dup", (1 if fd is None else fd, int(m.group(1)))))
                i += m.end()
            else:
                tokens.append(("redir", (fd if fd is not None else (0 if op == "<" else 1), op)))
        elif c in ";&|()":
            flush()
            two = text[i:i + 2]
            op = two if two in ("&&", "||", ";;") else c
            tokens.append(("op", op))
            i += len(op)
        else:
            word = (word or "") + c
            i += 1
    flush()
    return tokens


class _Parser:
    """Lists of and-or pipelines; if, for, { } and ( ) around them."""

    def __init__(self, tokens):
        self.tokens, self.i = tokens, 0

    def peek(self, kind=None, *values):
        tok = self.tokens[self.i] if self.i < len(self.tokens) else None
        if tok is None or (kind and (tok[0] != kind or (values and tok[1] not in values))):
            return None
        return tok

    def take(self, kind, *values):
        tok = self.peek(kind, *values)
        if tok is None:
            got = self.tokens[self.i][1] if self.i < len(self.tokens) else "end of file"
            raise _Syntax(f"syntax error: unexpected {got!r}")
        self.i += 1
        return tok

    def parse(self) -> list:
        items = self.list(())
        if self.i < len(self.tokens):
            raise _Syntax(f"syntax error: unexpected {self.tokens[self.i][1]!r}")
        return items

    def list(self, stops) -> list:
        items = []
        while True:
            while self.peek("op", ";"):
                self.i += 1
            if self.peek() is None or (stops and (self.peek("word", *stops) or self.peek("op", *stops))):
                return items
            node = self.and_or()
            background = bool(self.peek("op", "&"))
            if self.peek("op", "&", ";"):
                self.i += 1
            items.append((node, background))

    def and_or(self):
        parts = [(None, self.pipeline())]
        while self.peek("op", "&&", "||"):
            op = self.take("op")[1]
            parts.append((op, self.pipeline()))
        return ("and_or", parts)

    def pipeline(self):
        negate = bool(self.peek("word", "!"))
        self.i += negate
        commands = [self.command()]
        while self.peek("op", "|"):
            self.i += 1
            commands.append(self.command())
        return ("pipe", commands, negate)

    def command(self):
        if self.peek("word", "if"):
            self.i += 1
            branches = []
            while True:
                test = self.list(("then",))
                self.take("word", "then")
                body = self.list(("elif", "else", "fi"))
                branches.append((test, body))
                if not self.peek("word", "elif"):
                    break
                self.i += 1
            otherwise = []
            if self.peek("word", "else"):
                self.i += 1
                otherwise = self.list(("fi",))
            self.take("word", "fi")
            return ("if", branches, otherwise, self.redirections())
        if self.peek("word", "case"):
            self.i += 1
            subject = self.take("word")[1]
            self.take("word", "in")
            arms = []
            while True:
                while self.peek("op", ";"):
                    self.i += 1
                if self.peek("word", "esac"):
                    self.i += 1
                    break
                if self.peek("op", "("):
                    self.i += 1
                patterns = [self.take("word")[1]]
                while self.peek("op", "|"):
                    self.i += 1
                    patterns.append(self.take("word")[1])
                self.take("op", ")")
                arms.append((patterns, self.list((";;", "esac"))))
                if self.peek("op", ";;"):
                    self.i += 1
            return ("case", subject, arms, self.redirections())
        if self.peek("word", "for"):
            self.i += 1
            name = self.take("word")[1]
            words = None
            while self.peek("op", ";"):
                self.i += 1
            if self.peek("word", "in"):
                self.i += 1
                words = []
                while self.peek("word") and not self.peek("word", "do"):
                    words.append(self.take("word")[1])
            while self.peek("op", ";"):
                self.i += 1
            self.take("word", "do")
            body = self.list(("done",))
            self.take("word", "done")
            return ("for", name, words, body, self.redirections())
        if self.peek("word", "{"):
            self.i += 1
            body = self.list(("}",))
            self.take("word", "}")
            return ("group", body, self.redirections())
        if self.peek("op", "("):
            self.i += 1
            body = self.list((")",))
            self.take("op", ")")
            return ("subshell", body, self.redirections())
        assigns, words, redirs = [], [], []
        while True:
            tok = self.peek()
            if tok is None or tok[0] == "op":
                break
            self.i += 1
            if tok[0] == "word":
                if not words and re.match(r"[A-Za-z_][A-Za-z0-9_]*=", tok[1]):
                    assigns.append(tuple(tok[1].split("=", 1)))
                else:
                    words.append(tok[1])
            elif tok[0] == "dup":
                redirs.append(("dup", *tok[1]))
            else:
                redirs.append((tok[1][1], tok[1][0], self.take("word")[1]))
        if not (assigns or words or redirs):
            raise _Syntax(f"syntax error: unexpected {(self.peek() or ('', 'end of file'))[1]!r}")
        return ("simple", assigns, words, redirs)

    def redirections(self) -> list:
        redirs = []
        while self.peek("redir") or self.peek("dup"):
            tok = self.take(self.peek()[0])
            redirs.append(("dup", *tok[1]) if tok[0] == "dup" else (tok[1][1], tok[1][0], self.take("word")[1]))
        return redirs


class Ash:
    """A shell on a made-up device for one user: run(command) gives (out, err, exit code). What
    it runs in the background (&) carries on after it returns, with its output going where it
    was redirected (a log file, usually)."""

    def __init__(self, gear: Gear, user: str, args=(), variables=None):
        self.gear, self.user = gear, user
        self.vars = dict(variables or {"HOME": "/root" if gear.uid(user) == 0 else f"/home/{user}",
                                       "USER": user, "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
        self.vars["?"] = "0"
        self.args = list(args)
        self.traps = {}
        self.group = None  # the group sg runs it in

    def run(self, command: str, stdin: str = "", timeout: float = 60) -> tuple:
        out, err = [], []
        code = self.script(command, stdin, out.append, err.append)
        return "".join(out), "".join(err), code

    def script(self, text: str, stdin, out, err) -> int:
        """Run a script; an exit ends it (and runs its EXIT trap)."""
        try:
            items = _Parser(_lex(text)).parse()
        except (_Syntax, ValueError) as e:
            err(f"sh: {e}\n")
            return 2
        try:
            code = self.items(items, stdin, out, err)
        except _Exit as e:
            code = e.code
        trap = self.traps.pop("EXIT", None)
        if trap:
            self.vars["?"] = str(code)
            self.script(trap, "", out, err)
        return code

    # -- running ---------------------------------------------------------------------
    def items(self, items, stdin, out, err) -> int:
        code = int(self.vars.get("?", "0"))
        for node, background in items:
            if background:
                job = Ash(self.gear, self.user, self.args, self.vars)
                threading.Thread(target=job._background, args=(node,), daemon=True).start()
                code = 0
            else:
                code = self.node(node, stdin, out, err)
            self.vars["?"] = str(code)
        return code

    def _background(self, node) -> None:
        try:
            self.node(node, "", lambda s: None, lambda s: None)
        except _Exit:
            pass

    def node(self, node, stdin, out, err) -> int:
        kind = node[0]
        if kind == "and_or":
            code = 0
            for op, pipe in node[1]:
                if op == "&&" and code != 0 or op == "||" and code == 0:
                    continue
                code = self.node(pipe, stdin, out, err)
                self.vars["?"] = str(code)
            return code
        if kind == "pipe":
            data = stdin
            for n, command in enumerate(node[1]):
                last = n == len(node[1]) - 1
                buffer = []
                code = self.node(command, data, out if last else buffer.append, err)
                data = "".join(buffer)
            return int(not code) if node[2] else code
        if kind == "simple":
            return self.simple(node, stdin, out, err)
        stdin, out, err, after = self.redirect(node[-1], stdin, out, err)
        if after is not None:
            return after
        if kind == "if":
            for test, body in node[1]:
                if self.items(test, stdin, out, err) == 0:
                    return self.items(body, stdin, out, err)
            return self.items(node[2], stdin, out, err) if node[2] else 0
        if kind == "for":
            words = self.expand_all(node[2]) if node[2] is not None else list(self.args)
            code = 0
            for word in words:
                self.vars[node[1]] = word
                code = self.items(node[3], stdin, out, err)
            return code
        if kind == "case":
            value = self.expand(node[1], split=False)[0]
            for patterns, body in node[2]:
                if any(fnmatch.fnmatchcase(value, self.expand(p, split=False)[0]) for p in patterns):
                    return self.items(body, stdin, out, err)
            return 0
        if kind == "group":
            return self.items(node[1], stdin, out, err)
        if kind == "subshell":
            inner = Ash(self.gear, self.user, self.args, self.vars)
            try:
                return inner.items(node[1], stdin, out, err)
            except _Exit as e:
                return e.code
        return 0

    def simple(self, node, stdin, out, err) -> int:
        _kind, assigns, words, redirs = node
        values = {name: self.expand(raw, split=False)[0] for name, raw in assigns}
        argv = self.expand_all(words)
        stdin, out, err, failed = self.redirect(redirs, stdin, out, err)
        if failed is not None:
            return failed
        if not argv:
            self.vars.update(values)
            return 0
        try:
            return self.call(argv, stdin, out, err)
        except _Exit:
            raise
        except Exception as e:  # a fault in the simulation reads as the device's
            err(f"{argv[0]}: {type(e).__name__}: {e}\n")
            return 1

    def redirect(self, redirs, stdin, out, err) -> tuple:
        """(stdin, out, err, None), or (..., exit code) when a file can't be opened."""
        streams = {0: stdin, 1: out, 2: err}
        for op, fd, target in redirs:
            if op == "dup":
                streams[fd] = streams.get(target, out)
                continue
            path = self.expand(target, split=False)[0]
            if op == "<":
                data = None if path != "/dev/null" else b""
                data = self.gear.read(path) if data is None else data
                if data is None:
                    err(f"sh: can't open {path}: no such file\n")
                    return stdin, out, err, 1
                streams[fd] = data.decode("utf-8", "surrogateescape")
            elif path == "/dev/null":
                streams[fd] = lambda s: None
            else:
                if op == ">":
                    self.gear.write(path, b"")
                streams[fd] = lambda s, path=path: self.gear.write(path, s.encode("utf-8", "surrogateescape"),
                                                                   append=True)
        return streams[0], streams[1], streams[2], None

    def call(self, argv, stdin, out, err) -> int:
        name = argv[0]
        if name in BUILTINS:
            return BUILTINS[name](self, argv, stdin, out, err)
        path = name if "/" in name else next((p for p in self.gear.programs if p.rsplit("/", 1)[-1] == name), None)
        program = self.gear.programs.get(path) if path else None
        if program is None:
            if "/" in name and self.gear.read(name) is not None:
                return self.script(self.gear.read(name).decode("utf-8", "replace"), stdin, out, err)
            err(f"sh: {name}: not found\n")
            return 127
        return COMMANDS[program](self, argv, stdin, out, err)

    # -- expanding words ------------------------------------------------------------------
    def expand_all(self, words) -> list:
        argv = []
        for raw in words:
            argv += self.expand(raw)
        return argv

    def expand(self, raw: str, split: bool = True) -> list:
        """A word as the command gets it: quotes removed, $variables and $(commands) put in, split
        on spaces where unquoted, and an unquoted * matched against the device's files."""
        fields, current, started, glob = [], [], False, False
        i = 0

        def put(text, quoted):
            nonlocal started
            if quoted or not split:
                current.append(text)
                started = True
                return
            parts = re.split(r"[ \t\n]+", text)
            for n, part in enumerate(parts):
                if n:
                    if started or current:
                        fields.append("".join(current))
                    current.clear()
                    started = False
                if part:
                    current.append(part)
                    started = True

        while i < len(raw):
            c = raw[i]
            if c == "'":
                j = raw.index("'", i + 1)
                put(raw[i + 1:j], True)
                i = j + 1
            elif c == '"':
                j = _closing(raw, i, '"')
                put(self._expand_quoted(raw[i + 1:j]), True)
                i = j + 1
            elif c == "\\":
                put(raw[i + 1:i + 2], True)
                i += 2
            elif c == "$":
                text, i = self._dollar(raw, i)
                put(text, False)
            else:
                glob = glob or c in "*?"
                current.append(c)
                started = True
                i += 1
        if started or current:
            fields.append("".join(current))
        if glob and split:
            matched = []
            for f in fields:
                pattern = re.compile("".join("[^/]*" if c == "*" else "[^/]" if c == "?" else re.escape(c) for c in f))
                found = sorted(p for p in self._paths() if pattern.fullmatch(p)) if any(c in f for c in "*?") else []
                matched += found or [f]
            fields = matched
        return fields if split else ["".join(fields)]

    def _paths(self) -> set:
        """Every file and folder on the device, for * to match."""
        found = set()
        for path in self.gear.listing():
            parts = path.split("/")
            found.update("/".join(parts[:n]) for n in range(2, len(parts) + 1))
        return found

    def _expand_quoted(self, text: str) -> str:
        out, i = [], 0
        while i < len(text):
            c = text[i]
            if c == "\\" and text[i + 1:i + 2] in ('"', "\\", "$", "`"):
                out.append(text[i + 1])
                i += 2
            elif c == "$":
                value, i = self._dollar(text, i)
                out.append(value)
            else:
                out.append(c)
                i += 1
        return "".join(out)

    def _dollar(self, text: str, i: int) -> tuple:
        """What the $... at i stands for, and where it ends."""
        if text.startswith("$(", i):
            j = _closing(text, i + 1, ")")
            inner = Ash(self.gear, self.user, self.args, self.vars)
            out = []
            inner.script(text[i + 2:j], "", out.append, lambda s: None)
            return "".join(out).rstrip("\n"), j + 1
        if text.startswith("${", i):
            j = text.index("}", i)
            m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*|\d|\?)(?:(##|#|%%|%)(.*))?", text[i + 2:j])
            value = self._var(m.group(1)) if m else ""
            if m and m.group(2):
                value = _trim(value, m.group(2), m.group(3))
            return value, j + 1
        m = re.match(r"\$([A-Za-z_][A-Za-z0-9_]*|\d|\?|#)", text[i:])
        if not m:
            return "$", i + 1
        return self._var(m.group(1)), i + m.end()

    def _var(self, name: str) -> str:
        if name.isdigit():
            n = int(name)
            return self.args[n - 1] if 0 < n <= len(self.args) else ("sh" if n == 0 else "")
        if name == "#":
            return str(len(self.args))
        return self.vars.get(name, "")


def _trim(value: str, op: str, pattern: str) -> str:
    """${x##pattern} and the like."""
    cuts = range(len(value) + 1)
    if op.startswith("#"):
        hits = [n for n in cuts if fnmatch.fnmatchcase(value[:n], pattern)]
        return value[(max(hits) if op == "##" else min(hits)):] if hits else value
    hits = [n for n in cuts if fnmatch.fnmatchcase(value[n:], pattern)]
    return value[:(min(hits) if op == "%%" else max(hits))] if hits else value


# ---------------------------------------------------------------------------
# The commands: (shell, argv, stdin, out, err) -> exit code
# ---------------------------------------------------------------------------

def _files(shell, names, stdin, err, who="cat"):
    """Each file's text (stdin for none), with an error for the missing ones."""
    if not names:
        return [("-", stdin)], 0
    found, code = [], 0
    for name in names:
        data = shell.gear.read(name)
        if data is None:
            err(f"{who}: can't open '{name}': No such file or directory\n")
            code = 1
        else:
            found.append((name, data.decode("utf-8", "surrogateescape")))
    return found, code


def _echo(shell, argv, stdin, out, err):
    words, end = argv[1:], "\n"
    if words[:1] == ["-n"]:
        words, end = words[1:], ""
    out(" ".join(words) + end)
    return 0


def _printf(shell, argv, stdin, out, err):
    if len(argv) < 2:
        return 1
    text = argv[1].encode().decode("unicode_escape")
    out(text.replace("%s", "{}").format(*argv[2:]) if "%s" in text else text)
    return 0


def _test(shell, argv, stdin, out, err):
    args = argv[1:-1] if argv[0] == "[" else argv[1:]
    if argv[0] == "[" and argv[-1] != "]":
        err("[: missing ]\n")
        return 2
    negate = args[:1] == ["!"]
    args = args[1:] if negate else args
    ok = False
    if len(args) == 1:
        ok = bool(args[0])
    elif len(args) == 2:
        op, path = args
        ok = {"-e": shell.gear.exists(path), "-f": shell.gear.read(path) is not None,
              "-x": path in shell.gear.programs, "-d": shell.gear.is_dir(path), "-n": bool(path),
              "-z": not path, "-s": bool(shell.gear.read(path))}.get(op, False)
    elif len(args) == 3:
        a, op, b = args
        if op in ("=", "=="):
            ok = a == b
        elif op == "!=":
            ok = a != b
        else:
            try:
                x, y = int(a), int(b)
            except ValueError:
                err(f"sh: {a}: bad number\n")
                return 2
            ok = {"-eq": x == y, "-ne": x != y, "-lt": x < y, "-le": x <= y, "-gt": x > y, "-ge": x >= y}.get(op, False)
    return 0 if ok != negate else 1


def _exit(shell, argv, stdin, out, err):
    raise _Exit(int(argv[1]) if len(argv) > 1 and argv[1].isdigit() else int(shell.vars.get("?", "0")))


def _trap(shell, argv, stdin, out, err):
    if len(argv) >= 3:
        for signal in argv[2:]:
            if signal in ("EXIT", "0"):
                shell.traps["EXIT"] = argv[1]
    return 0


def _sh(shell, argv, stdin, out, err):
    inner = Ash(shell.gear, shell.user)
    inner.group = shell.group
    if len(argv) > 2 and argv[1] == "-c":
        return inner._run_args(argv[2], argv[3:], stdin, out, err)
    if len(argv) > 1:
        data = shell.gear.read(argv[1])
        if data is None:
            err(f"sh: can't open '{argv[1]}': No such file or directory\n")
            return 2
        return inner._run_args(data.decode("utf-8", "replace"), argv[2:], stdin, out, err)
    return inner.script(stdin, "", out, err)


def _run_args(self, text, args, stdin, out, err):
    self.args = list(args)
    return self.script(text, stdin, out, err)


Ash._run_args = _run_args


def _exec(shell, argv, stdin, out, err):
    raise _Exit(shell.call(argv[1:], stdin, out, err) if len(argv) > 1 else 0)


def _sg(shell, argv, stdin, out, err):
    """sg GROUP -c COMMAND: the command, in that group."""
    if len(argv) < 4 or argv[2] != "-c":
        err("usage: sg group -c command\n")
        return 2
    if argv[1] not in shell.gear.groups(shell.user):
        err(f"sg: failed to switch to group {argv[1]}\n")
        return 1
    inner = Ash(shell.gear, shell.user)
    inner.group = argv[1]
    return inner.script(argv[3], stdin, out, err)


def _sudo(shell, argv, stdin, out, err):
    args = [a for a in argv[1:] if a != "-n"]
    if "sudo" not in shell.gear.groups(shell.user) and shell.gear.uid(shell.user) != 0:
        err("sudo: a password is required\n")
        return 1
    return Ash(shell.gear, "root").call(args, stdin, out, err) if args else 0


def _command(shell, argv, stdin, out, err):
    names = [a for a in argv[1:] if not a.startswith("-")]
    if argv[1:2] == ["-v"] or argv[0] == "which":
        code = 1
        for name in names:
            path = next((p for p in shell.gear.programs if p == name or p.rsplit("/", 1)[-1] == name), None)
            if name in BUILTINS:
                path = name
            if path:
                out(path + "\n")
                code = 0
        return code
    return shell.call(names, stdin, out, err) if names else 0


def _cat(shell, argv, stdin, out, err):
    found, code = _files(shell, argv[1:], stdin, err)
    for _name, text in found:
        out(text)
    return code


def _rm(shell, argv, stdin, out, err):
    force, code = "-f" in argv or "-rf" in argv, 0
    for name in (a for a in argv[1:] if not a.startswith("-")):
        with shell.gear.lock:
            if shell.gear.files.pop(name, None) is None and not force:
                err(f"rm: can't remove '{name}': No such file or directory\n")
                code = 1
    return code


def _mv(shell, argv, stdin, out, err):
    names = [a for a in argv[1:] if not a.startswith("-")]
    if len(names) != 2:
        err("mv: missing operand\n")
        return 1
    with shell.gear.lock:
        data = shell.gear.files.pop(names[0], None)
        if data is None:
            err(f"mv: can't rename '{names[0]}': No such file or directory\n")
            return 1
        shell.gear.files[names[1]] = data
    return 0


def _cp(shell, argv, stdin, out, err):
    names = [a for a in argv[1:] if not a.startswith("-")]
    data = shell.gear.read(names[0]) if len(names) == 2 else None
    if data is None:
        err(f"cp: can't stat '{names[0] if names else ''}': No such file or directory\n")
        return 1
    shell.gear.write(names[1], data)
    return 0


def _touch(shell, argv, stdin, out, err):
    for name in argv[1:]:
        if shell.gear.read(name) is None:
            shell.gear.write(name, b"")
    return 0


def _md5sum(shell, argv, stdin, out, err):
    found, code = _files(shell, argv[1:], stdin, err)
    for name, text in found:
        out(f"{hashlib.md5(text.encode('utf-8', 'surrogateescape')).hexdigest()}  {name}\n")
    return code


def _md5sum_bytes(shell, argv, stdin, out, err):
    """md5sum, reading a file's own bytes (a firmware file isn't text)."""
    names = argv[1:]
    if not names:
        return _md5sum(shell, argv, stdin, out, err)
    code = 0
    for name in names:
        data = shell.gear.read(name)
        if data is None:
            err(f"md5sum: can't open '{name}': No such file or directory\n")
            code = 1
        else:
            out(f"{hashlib.md5(data).hexdigest()}  {name}\n")
    return code


def _wc(shell, argv, stdin, out, err):
    found, code = _files(shell, [a for a in argv[1:] if not a.startswith("-")], stdin, err)
    for name, text in found:
        count = len(text.encode("utf-8", "surrogateescape")) if "-c" in argv else text.count("\n")
        out(f"{count}\n" if name == "-" else f"{count} {name}\n")
    return code


def _head_tail(shell, argv, stdin, out, err):
    count, chars, names, args = 10, None, [], iter(argv[1:])
    for a in args:
        if a == "-n":
            count = int(next(args, "10"))
        elif a == "-c":
            chars = int(next(args, "0"))
        elif a.startswith("-") and a[1:].isdigit():
            count = int(a[1:])
        else:
            names.append(a)
    found, code = _files(shell, names, stdin, err)
    for _name, text in found:
        if chars is not None:
            out(text[:chars] if argv[0] == "head" else text[-chars:])
        else:
            lines = text.splitlines(keepends=True)
            out("".join(lines[:count] if argv[0] == "head" else lines[-count:]))
    return code


def _grep(shell, argv, stdin, out, err):
    flags = "".join(a[1:] for a in argv[1:] if a.startswith("-") and len(a) > 1)
    rest = [a for a in argv[1:] if not (a.startswith("-") and len(a) > 1)]
    if not rest:
        err("usage: grep [-qivcE] PATTERN [FILE]...\n")
        return 2
    pattern = re.compile(rest[0], re.I if "i" in flags else 0)
    found, code = _files(shell, rest[1:], stdin, err)
    hits = 0
    for _name, text in found:
        for line in text.splitlines():
            if bool(pattern.search(line)) != ("v" in flags):
                hits += 1
                if "q" not in flags and "c" not in flags:
                    out(line + "\n")
    if "c" in flags:
        out(f"{hits}\n")
    return 0 if hits else (code or 1)


def _sed(shell, argv, stdin, out, err):
    """sed's s/// (with -n and p): what devicetools reads a setting with."""
    quiet = "-n" in argv
    rest = [a for a in argv[1:] if a != "-n"]
    m = re.fullmatch(r"s(.)(.*?)\1(.*?)\1([gp]*)", rest[0]) if rest else None
    if not m:
        err("sed: only s/// is supported here\n")
        return 1
    pattern, repl, flags = re.compile(m.group(2)), m.group(3).replace("\\", "\\\\"), m.group(4)
    found, code = _files(shell, rest[1:], stdin, err)
    for _name, text in found:
        for line in text.splitlines():
            new, n = pattern.subn(repl, line, count=0 if "g" in flags else 1)
            if n and "p" in flags:
                out(new + "\n")
            if not quiet:
                out(new + "\n")
    return code


def _id(shell, argv, stdin, out, err):
    gear, user = shell.gear, shell.user
    groups = gear.groups(user)
    group = shell.group or groups[0]
    if "-u" in argv:
        out(f"{gear.uid(user)}\n")
    elif "-gn" in argv or argv[1:] == ["-g", "-n"]:
        out(group + "\n")
    elif "-Gn" in argv:
        out(" ".join(dict.fromkeys([group, *groups])) + "\n")
    elif "-un" in argv:
        out(user + "\n")
    else:
        out(f"uid={gear.uid(user)}({user}) gid={gear.uid(user)}({group}) groups="
            + ",".join(f"{100 + n}({g})" for n, g in enumerate(groups)) + "\n")
    return 0


def _uname(shell, argv, stdin, out, err):
    gear = shell.gear
    if "-n" in argv:
        out(gear.name + "\n")
    elif "-a" in argv:
        out(f"Linux {gear.name} {'4.14.54' if gear.kind == 'edgeos' else '2.6.32.71'} #1 "
            f"{'mips GNU/Linux' if gear.kind == 'edgeos' else 'mips'}\n")
    else:
        out("Linux\n")
    return 0


def _ip(shell, argv, stdin, out, err):
    if "addr" not in argv and "a" not in argv:
        err("ip: only ip addr is supported here\n")
        return 1
    gear = shell.gear
    out(f"1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n"
        f"5: {gear.address_on}    inet {gear.ip}/24 brd {gear.ip.rsplit('.', 1)[0]}.255 scope global "
        f"{gear.address_on}\\       valid_lft forever preferred_lft forever\n")
    return 0


def _ifconfig(shell, argv, stdin, out, err):
    gear = shell.gear
    for name, mac in gear.interfaces.items():
        out(f"{name:<10}Link encap:Ethernet  HWaddr {mac.upper()}\n")
        if name == gear.address_on:
            out(f"          inet addr:{gear.ip}  Bcast:{gear.ip.rsplit('.', 1)[0]}.255  Mask:255.255.255.0\n")
        out("\n")
    return 0


def _ls(shell, argv, stdin, out, err):
    folder = (next((a for a in argv[1:] if not a.startswith("-")), None) or "/tmp").rstrip("/") + "/"
    names = sorted({p[len(folder):].split("/")[0] for p in shell.gear.listing() if p.startswith(folder)})
    if not names and not shell.gear.is_dir(folder):
        err(f"ls: {folder}: No such file or directory\n")
        return 1
    out("\n".join(names) + ("\n" if names else ""))
    return 0


def _nc(shell, argv, stdin, out, err):
    """nc -z (is the port open) and a banner read: from this device to another one."""
    words, args = [], iter(argv[1:])
    for a in args:
        if a == "-w":
            next(args, None)
        elif not a.startswith("-"):
            words.append(a)
    try:
        ip, port = words[-2], int(words[-1])
    except (IndexError, ValueError):
        err("nc: usage: nc [-z] [-w SEC] HOST PORT\n")
        return 1
    if ip in ("127.0.0.1", "localhost"):
        target = shell.gear
    else:
        target = shell.gear.network.find(ip) if shell.gear.network else None
    service = target.ports.get(port) if target and target.up else None
    if not service:
        return 1
    if "-z" not in argv:
        out({"ssh": "SSH-2.0-dropbear_2019.78\r\n", "http": "HTTP/1.1 302 Found\r\nLocation: /login.cgi\r\n",
             "https": ""}.get(service, ""))
    return 0


def _sleep(shell, argv, stdin, out, err):
    time.sleep(min(10.0, float(argv[1]) if len(argv) > 1 else 0))
    return 0


def _date(shell, argv, stdin, out, err):
    out(time.strftime("%a %b %e %H:%M:%S UTC %Y", time.gmtime()) + "\n")
    return 0


def _uptime(shell, argv, stdin, out, err):
    up = int(time.time() - shell.gear.booted)
    out(f" {time.strftime('%H:%M:%S')} up {core.fmt_uptime(up)},  load average: 0.08, 0.05, 0.01\n")
    return 0


def _hostname(shell, argv, stdin, out, err):
    out(shell.gear.name + "\n")
    return 0


def _true(shell, argv, stdin, out, err):
    return 0


def _false(shell, argv, stdin, out, err):
    return 1


def _help(shell, argv, stdin, out, err):
    names = sorted({*BUILTINS, *(p.rsplit("/", 1)[-1] for p in shell.gear.programs)} - {"[", ":"})
    out("A made-up device on OpenDisco's demo network. Its shell knows:\n" + "  ".join(names) + "\n")
    return 0


# -- what the device itself does ---------------------------------------------------------
def _cfgmtd(shell, argv, stdin, out, err):
    """airOS: cfgmtd -w -p /etc/ writes /tmp/system.cfg to flash (save)."""
    gear = shell.gear
    if "-w" not in argv:
        err("Usage: cfgmtd -w|-r -p /etc/ [-f file]\n")
        return 1
    data = gear.read(AIROS_CONFIG)
    if data is None:
        err(f"cfgmtd: can't open {AIROS_CONFIG}\n")
        return 1
    time.sleep(DELAYS["save"])
    gear.flash = data
    return 0


def _softrestart(shell, argv, stdin, out, err):
    """airOS: rc.softrestart save applies /tmp/system.cfg (restarting what changed) and saves it."""
    gear = shell.gear
    data = gear.read(AIROS_CONFIG)
    if data is None:
        err(f"rc.softrestart: no {AIROS_CONFIG}\n")
        return 1
    time.sleep(DELAYS["apply"])
    with gear.lock:
        gear.files[AIROS_RUNNING] = data
        if "save" in argv:
            gear.flash = data
        gear._take_config()
    return 0


def _fwupdate(shell, argv, stdin, out, err):
    """airOS: /sbin/fwupdate -c checks /tmp/fwupdate.bin; -m installs it, rebooting."""
    gear = shell.gear
    data = gear.read("/tmp/fwupdate.bin")
    if data is None:
        err("Firmware file /tmp/fwupdate.bin not found.\n")
        return 1
    m = re.match(rf"{FIRMWARE_MARK} product=(\S+) version=(\S+)".encode(), data)
    platform = gear.firmware.split(".", 1)[0]
    if not m or m.group(1).decode() != platform:
        err(f"Invalid firmware: it isn't for this device ({platform}).\n")
        return 1
    if "-c" in argv:
        out(f"Firmware check OK: version {m.group(2).decode()}.\n")
        return 0
    if "-m" in argv:
        out("Writing the firmware to flash. The device reboots when it's done.\n")
        time.sleep(DELAYS["firmware write"])
        new = re.sub(r"\.v\d+\.\d+(\.\d+)?", f".v{m.group(2).decode()}", gear.firmware, count=1)
        gear.go_down(DELAYS["firmware offline"], new)
        return 0
    err("Usage: fwupdate -c | -m\n")
    return 1


def _reboot(shell, argv, stdin, out, err):
    if shell.gear.uid(shell.user) != 0:
        err("reboot: Operation not permitted\n")
        return 1
    time.sleep(0.5)
    shell.gear.go_down(DELAYS["reboot offline"])
    return 0


# airOS 8's link figures (mca-status, and wstalist's station objects, as status.cgi's wireless.sta
# lists them): their names and shapes as the link-health session's data sets have them, from
# captures of real 8.7 radios. Each made-up station's link (Gear.link) gives the numbers.
def _expected(link: dict) -> int:
    """The capacity (kbit/s) airOS 8 expects of a 2x2 AC link this wide."""
    return 433000 if link.get("chanbw", 40) >= 40 else 216000


def _station_entry(here, there, link: dict, ap_side: bool) -> dict:
    """One radio as wstalist on `here` lists it: `there`, over the station's link (Gear.link: its
    signal at the access point, its own noise floor...); ap_side: here is the access point."""
    station_noise, ap_noise = link.get("noise", -95), (here if ap_side else there).link.get("noise", -94)
    at_ap = link.get("signal", -60)
    chains_at_ap = link.get("chains") or [at_ap - 1, at_ap - 2]
    at_station, chains_at_station = at_ap + 1, [c + 1 for c in chains_at_ap]
    signal, chains, noise = ((at_ap, chains_at_ap, ap_noise) if ap_side else (at_station, chains_at_station,
                                                                               station_noise))
    r_signal, r_chains, r_noise = ((at_station, chains_at_station, station_noise) if ap_side
                                   else (at_ap, chains_at_ap, ap_noise))
    cinr = max(3, signal - noise - 2)
    dl, ul = int(link.get("tx", 300) * 1000), int(link.get("rx", 300) * 1000)
    expected = _expected(link)
    uptime = int(time.time() - max(here.booted, there.booted))
    weak = cinr < 20
    return {
        "mac": there.mac.upper(), "lastip": there.ip, "associd": 1, "name": "",
        "signal": signal, "rssi": signal + 96, "noisefloor": noise, "chainrssi": [c + 96 for c in chains] + [0],
        "tx_idx": 3 if weak else 8, "rx_idx": 3 if weak else 8, "tx_nss": 2, "rx_nss": 2,
        "tx_latency": link.get("latency", 6 if weak else 1), "distance": link.get("distance", 1500), "uptime": uptime,
        "dl_capacity_expect": expected, "ul_capacity_expect": expected, "cb_capacity_expect": expected,
        "dl_linkscore": min(100, dl * 100 // expected), "ul_linkscore": min(100, ul * 100 // expected),
        "ccq": link.get("ccq", 95),
        "airmax": {"actual_priority": 2, "beam": 0, "desired_priority": 2, "cb_capacity": (dl + ul) // 2,
                   "dl_capacity": dl, "ul_capacity": ul, "atpc_status": 2,
                   "rx": {"usage": 186 if weak else 42, "cinr": cinr},
                   "tx": {"usage": 92 if weak else 24, "cinr": cinr + 1}},
        "remote": {"hostname": there.name, "platform": there.platform, "version": there.firmware,
                   "mode": "ap-ptmp" if not ap_side else "sta-ptmp", "netrole": "bridge",
                   "signal": r_signal, "rssi": r_signal + 96, "noisefloor": r_noise,
                   "chainrssi": [c + 96 for c in r_chains] + [0], "tx_power": link.get("tx_power", 20),
                   "distance": link.get("distance", 1500), "uptime": uptime + 300, "ipaddr": [there.ip]},
        "airos_connected": True,
    }


def _ap_of(gear):
    return next((g for g in (gear.network.gears.values() if gear.network else ()) if gear in g.stations), None)


def _wstalist(shell, argv, stdin, out, err):
    """airOS: the radios linked to it, as its web UI lists them (JSON on one line): an access
    point's stations, or a station's access point."""
    gear = shell.gear
    if gear.stations:
        found = [_station_entry(gear, s, s.link, True) for s in gear.stations if s.up]
    else:
        ap = _ap_of(gear)
        found = [_station_entry(gear, ap, gear.link, False)] if ap and ap.up else []
    out(json.dumps(found, separators=(",", ":")) + "\n")
    return 0


MCA_TAIL = ("cpuUsage=9.0\nloadavg=0.08\nmemTotal=124132\nmemFree=71224\nnetrole=bridge\nlanPlugged=1\n"
            "lanSpeed=1000Mbps-Full\nlatitude=0.000000\nlongitude=0.000000\nstatus_flags=4\n")


def _mca_status(shell, argv, stdin, out, err):
    """airOS: its status, as airOS 8's mca-status prints it: who it is on the first line, then a
    key=value line each, the radio's among them (on a station, its signal and rates)."""
    gear = shell.gear
    link = gear.link or {}
    ap = gear if gear.stations or gear.wmode == 3 else _ap_of(gear)
    radio = (ap.link if ap else link) or {}
    freq = radio.get("freq", link.get("freq", 5180))
    lines = [f"deviceName={gear.name},deviceId={gear.mac.upper()},firmwareVersion={gear.firmware},"
             f"platform={gear.platform},deviceIp={gear.ip}", "",
             f"apMac={(ap or gear).mac.upper()}",
             f"wlanOpmode={'ap-ptmp' if ap is gear else 'sta-ptmp'}",
             f"wlanConnections={len(gear.stations) if ap is gear else 1}",
             f"wlanUptime={int(time.time() - gear.booted)}", f"essid={gear.essid or ''}", "security=WPA2",
             f"freq={freq}", f"centerFreq={freq + 10}", f"txPower={radio.get('tx_power', 22 if ap is gear else 20)}",
             f"chanbw={radio.get('chanbw', 40)}"]
    if ap is gear:
        lines += [f"noise={radio.get('noise', -94)}",
                  f"distance={max([s.link.get('distance', 0) for s in gear.stations] or [0])}",
                  "wlanTxLatency=0"]
    else:
        signal = link.get("signal", -60) + 1
        chains = [c + 1 for c in (link.get("chains") or [signal - 2, signal - 3])]
        lines += [f"signal={signal}", f"chain0Signal={chains[0]}", f"chain1Signal={chains[1]}",
                  f"noise={link.get('noise', -95)}", f"distance={link.get('distance', 1500)}",
                  f"wlanTxRate={link.get('tx', 300)}.0", f"wlanRxRate={link.get('rx', 300)}.0",
                  f"wlanTxLatency={link.get('latency', 1)}"]
    lines += ["wlanPolling=1", f"uptime={int(time.time() - gear.booted)}"]
    out("\n".join(lines) + "\n" + MCA_TAIL)
    return 0


def _ubntbox(shell, argv, stdin, out, err):
    """airOS's multi-call program: ubntbox mca-status."""
    if argv[1:2] == ["mca-status"]:
        return _mca_status(shell, argv[1:], stdin, out, err)
    err(f"ubntbox: applet not found: {argv[1] if len(argv) > 1 else ''}\n")
    return 127


def _df(shell, argv, stdin, out, err):
    """df -k: /tmp, a RAM disk (what an EdgeRouter has room for a firmware file in)."""
    used = sum(len(b) for p, b in shell.gear.files.items() if p.startswith("/tmp/")) // 1024 + 1316
    out("Filesystem           1K-blocks      Used Available Use% Mounted on\n"
        f"tmpfs                   253952 {used:9} {253952 - used:9} {used * 100 // 253952:3}% /tmp\n")
    return 0


def _lldpcli(shell, argv, stdin, out, err):
    lines = []
    for port, g in shell.gear.lldp:
        lines += [f"lldp.{port}.via=LLDP", f"lldp.{port}.chassis.mac={g.mac}", f"lldp.{port}.chassis.name={g.name}",
                  f"lldp.{port}.chassis.descr={g.platform} {g.firmware}", f"lldp.{port}.chassis.mgmt-ip={g.ip}",
                  f"lldp.{port}.port.descr=eth0"]
    out("\n".join(lines) + ("\n" if lines else ""))
    return 0


def _vyatta(shell, argv, stdin, out, err):
    """EdgeOS's config commands for scripts (vyatta-cfg-cmd-wrapper): begin, load, commit, save,
    discard, end, as configure's do."""
    gear, user = shell.gear, shell.user
    if shell.group != "vyattacfg" and gear.uid(user) != 0:
        err("Configuration session must be run as group vyattacfg.\n")
        return 1
    action = argv[1] if len(argv) > 1 else ""
    pending = gear.pending
    if action == "begin":
        pending[user] = gear.running_boot()
        return 0
    if user not in pending and action not in ("end",):
        err("Not in a configuration session.\n")
        return 1
    if action == "load":
        data = gear.read(argv[2]) if len(argv) > 2 else None
        if data is None:
            err(f"Cannot open configuration file {argv[2] if len(argv) > 2 else ''}\n")
            return 1
        from opendisco import devicetools
        problems = devicetools.config_problems(data.decode("utf-8", "replace"), "edgeos")
        if problems:
            out(f"Loading configuration from '{argv[2]}'...\nLoad failed: {problems[0]}\n")
            return 1
        time.sleep(0.8)
        pending[user] = data
        out(f"Loading configuration from '{argv[2]}'...\n\nLoad complete.  Use 'commit' to make changes active.\n")
        return 0
    if action in ("set", "delete"):
        words = argv[2:]
        if words[:3] != ["system", "login", "user"] or len(words) < 4:
            err(f"The demo's EdgeOS changes logins only: {' '.join(argv[1:])}\n")
            return 1
        try:
            pending[user] = _edit_login(pending[user].decode("utf-8", "replace"), action, words[3], words[4:],
                                        gear.version).encode()
        except ValueError as e:
            out(f"{e}\n")
            return 1
        return 0
    if action == "commit":
        if devicetools_lines(pending[user]) == devicetools_lines(gear.running_boot()):
            out("No configuration changes to commit\n")
            return 0
        time.sleep(DELAYS["commit"])
        with gear.lock:
            gear.files[RUNNING_BOOT] = pending[user]
            gear._take_config()
        return 0
    if action == "save":
        out(f"Saving configuration to '{EDGEOS_CONFIG}'...\nDone\n")
        gear.write(EDGEOS_CONFIG, gear.running_boot())
        return 0
    if action == "discard":
        pending[user] = gear.running_boot()
        return 0
    if action == "end":
        pending.pop(user, None)
        return 0
    err(f"Invalid command: {action}\n")
    return 1


def _vyatta_op(shell, argv, stdin, out, err):
    """EdgeOS's operational commands for scripts (vyatta-op-cmd-wrapper): show system image, and
    add system image FILE, which writes the image as ubnt-upgrade does, saying so as it goes. Like
    the real wrapper it exits 0 whatever happened: show system image tells."""
    words, gear = argv[1:], shell.gear
    if words[:3] == ["show", "system", "image"]:
        out("The system currently has the following image(s) installed:\n\n" + "".join(
            f"{i['name']}" + (" (running image)" if i["running"] else "") + (" (default boot)" if i["default"] else "")
            + "\n" for i in gear.images))
    elif words[:3] == ["add", "system", "image"] and len(words) == 4:
        _add_image(gear, words[3], out)
    else:
        out(f"Invalid command: [{' '.join(words)}]\n")
    return 0


def _add_image(gear, path: str, out) -> None:
    out("Checking upgrade image...")
    data = gear.read(path) or b""
    m = re.match(rf"{FIRMWARE_MARK} product=(\S+) version=(\S+)".encode(), data)
    if any(i["default"] and not i["running"] for i in gear.images):
        out("Failed\nThe system needs a reboot before upgrade: a new image is waiting to boot.\n")
        return
    if not m or m.group(1).decode().lower() != gear.firmware.split("ER-", 1)[-1].split(".")[0].lower():
        out("Failed\nThe image does not support the device.\n")
        return
    if devicetools_lines(gear.read(EDGEOS_CONFIG) or b"") != devicetools_lines(gear.running_boot()):
        out("Done\nThe configuration changes have not been saved: save them, or the upgrade loses them. "
            "Upgrade aborted.\n")
        return
    out("Done\nPreparing to upgrade...Done\nCopying upgrade image...Done\nRemoving old image...Done\n")
    with gear.lock:
        gear.images[:] = [i for i in gear.images if i["running"]]
        for image in gear.images:
            image["default"] = False
    time.sleep(DELAYS["image write"])
    with gear.lock:
        gear.images.append({"name": f"v{m.group(2).decode()}.5862409.250924.1407", "running": False, "default": True})
    out("Checking upgrade image...Done\nCopying config data...Done\nFinalizing the upgrade...Done\n"
        "Upgrade completed\n")


def _cli_shell_api(shell, argv, stdin, out, err):
    """EdgeOS's cli-shell-api showConfig --show-cfg1 FILE --show-cfg2 @ACTIVE --show-context-diff:
    the lines where its boot config and the config it runs differ (committed, not saved)."""
    if argv[1:2] != ["showConfig"]:
        err(f"cli-shell-api: {' '.join(argv[1:2])}: not supported here\n")
        return 1
    gear = shell.gear
    boot, active = devicetools_lines(gear.read(EDGEOS_CONFIG) or b""), devicetools_lines(gear.running_boot())
    for line in difflib.unified_diff(boot, active, lineterm="", n=0):
        if line[:1] in "+-" and not line.startswith(("+++", "---")):
            out(line + "\n")
    return 0


def _edit_login(text: str, action: str, name: str, rest: list, version: str) -> str:
    """config.boot with `set|delete system login user NAME REST...` done to it, as EdgeOS does it:
    a plaintext-password is hashed (SHA-512-crypt) into encrypted-password, and checked against
    EdgeOS 3's rules where it runs 3.x. ValueError: what EdgeOS says when it refuses."""
    from opendisco import devicetools
    block = re.compile(rf"(?ms)^( *)user {re.escape(name)} \{{\n.*?^\1\}}\n")
    found = block.search(text)
    if action == "delete":
        if not found:
            raise ValueError(f"Nothing to delete (the specified node [system login user {name}] does not exist)")
        return text[:found.start()] + text[found.end():]
    values = {"encrypted-password": "*", "level": "admin", "full-name": None}
    if found:
        for key in values:
            m = re.search(rf"(?m)^\s*{key} (\S.*)$", found.group(0))
            if m:
                values[key] = m.group(1).strip()
    if rest[:2] == ["authentication", "plaintext-password"] and len(rest) == 3:
        password = rest[2]
        if devicetools.version_key(version)[:1] >= (3,) and (len(password) < 12 or not all(
                re.search(pattern, password) for pattern, _what in devicetools.EDGEOS3_PASSWORD)):
            raise ValueError("Password must be at least 12 characters long and contain lower case, upper case, digit "
                             "and special characters\nValue validation failed\nSet failed")
        salt = hashlib.sha256((name + password).encode()).hexdigest()[:16]
        values["encrypted-password"] = devicetools.sha_crypt(password, salt, None, True)
    elif rest[:1] in (["level"], ["full-name"]) and len(rest) == 2:
        values[rest[0]] = rest[1]
    indent = found.group(1) if found else " " * 8
    rendered = (f"{indent}user {name} {{\n{indent}    authentication {{\n"
                f"{indent}        encrypted-password {values['encrypted-password']}\n"
                f'{indent}        plaintext-password ""\n{indent}    }}\n'
                + (f"{indent}    full-name {values['full-name']}\n" if values["full-name"] else "")
                + f"{indent}    level {values['level']}\n{indent}}}\n")
    if found:
        return text[:found.start()] + rendered + text[found.end():]
    login = re.search(r"(?ms)^( *)login \{\n.*?^\1\}\n", text)
    if not login:
        raise ValueError("The specified configuration node is not valid")
    close = login.end() - len(login.group(1)) - 2  # before the login node's closing brace
    return text[:close] + rendered + text[close:]


def devicetools_lines(data: bytes) -> list:
    from opendisco import devicetools
    return devicetools.boot_lines(data.decode("utf-8", "replace"))


BUILTINS = {"echo": _echo, "printf": _printf, "test": _test, "[": _test, "exit": _exit, "trap": _trap,
            "sh": _sh, "exec": _exec, "command": _command, "which": _command, "true": _true, ":": _true,
            "false": _false, "cat": _cat, "rm": _rm, "mv": _mv, "cp": _cp, "touch": _touch,
            "md5sum": _md5sum_bytes, "wc": _wc, "head": _head_tail, "tail": _head_tail, "grep": _grep,
            "sed": _sed, "id": _id, "uname": _uname, "sleep": _sleep, "date": _date, "uptime": _uptime,
            "hostname": _hostname, "ls": _ls, "nc": _nc, "sg": _sg, "sudo": _sudo, "help": _help,
            "chmod": _true, "mkdir": _true, "sync": _true, "umask": _true, "df": _df}
COMMANDS = {"ip": _ip, "ifconfig": _ifconfig, "cfgmtd": _cfgmtd, "softrestart": _softrestart,
            "fwupdate": _fwupdate, "reboot": _reboot, "wstalist": _wstalist, "mca-status": _mca_status,
            "ubntbox": _ubntbox, "lldpcli": _lldpcli, "vyatta": _vyatta, "vyatta-op": _vyatta_op,
            "cli-shell-api": _cli_shell_api}
# Where each kind of device keeps its programs: path -> COMMANDS' name.
COMMON = {"/sbin/ip": "ip", "/sbin/ifconfig": "ifconfig", "/sbin/reboot": "reboot"}
PROGRAMS = {
    "airos": {"/sbin/cfgmtd": "cfgmtd", "/usr/etc/rc.d/rc.softrestart": "softrestart", "/sbin/fwupdate": "fwupdate",
              "/usr/www/wstalist": "wstalist", "/usr/bin/mca-status": "mca-status", "/bin/ubntbox": "ubntbox"},
    "isp": {"/sbin/cfgmtd": "cfgmtd", "/usr/etc/rc.d/rc.softrestart": "softrestart",
            "/usr/bin/mca-status": "mca-status"},
    "edgeos": {"/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper": "vyatta",
               "/opt/vyatta/bin/vyatta-op-cmd-wrapper": "vyatta-op", "/opt/vyatta/bin/cli-shell-api": "cli-shell-api",
               "/usr/sbin/lldpcli": "lldpcli"},
}


# ---------------------------------------------------------------------------
# Sessions: the phones' console (Console, phonessh.Shell's stand-in) and the Terminal tab's
# ---------------------------------------------------------------------------

class Program:
    """What a terminal shows of an SSH session to a made-up device: the password prompt when it
    has none, the device's welcome and prompt, typed commands echoed and run, Ctrl-C, exit.
    write(text) gets the output; ended(reason) once when it's over (reason "" for exit)."""

    def __init__(self, network, target: dict, write, ended):
        self.network, self.target, self.write, self.ended = network, target, write, ended
        self.line, self.queue, self.busy, self.done = "", [], False, False
        self.lock = threading.Lock()
        self.stage = "password" if not target.get("password") else "login"  # none given: asked, as ssh does
        self.gear = None
        self.shell = None

    def start(self) -> None:
        self.write(f"{self.target['user']}@{self.target['ip']}'s password: ")
        if self.stage != "password":
            self.write("\r\n")
            threading.Thread(target=self._log_in, daemon=True).start()

    def _log_in(self) -> None:
        t = self.target
        try:
            gear = self.network.find(t["ip"])
            time.sleep(DELAYS["login"])
            if gear is None or not gear.up or not (gear.direct or t.get("via")):
                time.sleep(DELAYS["no answer"])
                return self._end(f"ssh: connect to host {t['ip']} port {t['port']}: Operation timed out")
            if gear.ports.get(t["port"]) != "ssh":
                return self._end(f"ssh: connect to host {t['ip']} port {t['port']}: Connection refused")
            if t.get("known_hosts"):
                try:
                    gear.check_host_key(DemoLogin(t["ip"], t["port"], t["user"], "", t["alias"],
                                                  Path(t["known_hosts"])))
                except real.SSHError as e:
                    return self._end(str(e))
            if not gear.accepts(t["user"], t["password"] or ""):
                self.write("Permission denied, please try again.\r\n")
                return self._end(f"{t['user']}@{t['ip']}: Permission denied (publickey,password).")
        except Exception as e:  # never leave the session hanging
            return self._end(f"{type(e).__name__}: {e}")
        self.gear, self.shell = gear, Ash(gear, t["user"])
        if t.get("command"):
            return self._run_once(t["command"])
        self.write(self._welcome() + self._prompt())
        self.stage = "shell"

    def _welcome(self) -> str:
        g = self.gear
        if g.kind == "edgeos":
            text = f"Welcome to EdgeOS\r\n\r\nLinux {g.name} 4.14.54-UBNT #1 SMP mips\r\n"
        else:
            text = ("\r\n\r\nBusyBox v1.25.1 () built-in shell (ash)\r\n"
                    "Enter 'help' for a list of built-in commands.\r\n\r\n")
        return text + ("\x1b[33mOpenDisco demo: a made-up device. Nothing here reaches a network.\x1b[0m\r\n")

    def _prompt(self) -> str:
        g = self.gear
        if g.kind == "edgeos":
            return f"{self.shell.user}@{g.name}:~$ "
        return f"{g.firmware.split('.')[0]}.v{g.version}# "

    def feed(self, text: str) -> None:
        """Keystrokes."""
        for c in text:
            if self.done:
                return
            if self.stage == "password":
                if c in "\r\n":
                    self.write("\r\n")
                    self.target["password"] = self.line
                    self.line, self.stage = "", "login"
                    threading.Thread(target=self._log_in, daemon=True).start()
                elif c in "\x7f\b":
                    self.line = self.line[:-1]
                elif c == "\x03":
                    self.write("^C\r\n")
                    self._end("")
                elif c >= " ":
                    self.line += c
                continue
            if self.stage != "shell":
                continue
            if self.busy:
                if c == "\x03":
                    self.write("^C\r\n")
                continue
            if c in "\r\n":
                command, self.line = self.line, ""
                self.write("\r\n")
                self.busy = True
                threading.Thread(target=self._run, args=(command,), daemon=True).start()
            elif c in "\x7f\b":
                if self.line:
                    self.line = self.line[:-1]
                    self.write("\b \b")
            elif c == "\x03":
                self.line = ""
                self.write("^C\r\n" + self._prompt())
            elif c == "\x04" and not self.line:
                self._end("")
            elif c == "\x15":  # Ctrl-U
                self.write("\b \b" * len(self.line))
                self.line = ""
            elif c >= " " and c != "\x7f":
                self.line += c
                self.write(c)

    def _run(self, command: str) -> None:
        stripped = command.strip()
        if stripped in ("exit", "logout") or stripped.startswith("exit "):
            self.write("logout\r\n")
            return self._end("")
        if stripped.startswith("ping "):
            return self._ping(stripped.split()[-1])
        out, err, _code = self.shell.run(command) if stripped else ("", "", 0)
        text = (out + err).replace("\r\n", "\n").replace("\n", "\r\n")
        if not self.gear.up:
            self.write(text)
            return self._end(f"Connection to {self.target['ip']} closed by remote host.")
        self.busy = False
        self.write(text + self._prompt())

    def _run_once(self, command: str) -> None:
        if command.startswith("ping "):
            self._ping(command.split()[-1])
            return self._end("")
        out, err, code = self.shell.run(command)
        self.write((out + err).replace("\n", "\r\n"))
        self._end("" if code == 0 else f"exit code {code}")

    def _ping(self, ip: str) -> None:
        stop = threading.Event()
        self.stopping = stop
        self.busy = True
        original = self.feed

        def keys(text):
            if "\x03" in text:
                self.write("^C\r\n")
                stop.set()

        self.feed = keys
        try:
            ping(ip, lambda line: self.write(line.replace("\n", "\r\n") + "\r\n"), stop.is_set, source=self.gear)
        finally:
            self.feed = original
        self.busy = False
        if not self.target.get("command"):
            self.write(self._prompt())

    def _end(self, reason: str) -> None:
        with self.lock:
            if self.done:
                return
            self.done = True
        self.ended(reason)


class Console:
    """phonessh.Shell's stand-in: an SSH session in the phones' Tools console, to a made-up
    device. on_output(text) and on_closed(reason) are called from a thread of its own."""

    def __init__(self, login, on_output, on_closed, cols: int = 80, rows: int = 24, command: str | None = None,
                 **more):
        if not _demo(login):
            self.real = real.Shell(login, on_output, on_closed, cols, rows, command=command, **more)
            return
        self.real, self.error = None, None
        self.program = Program(_network(), _target(login, command), on_output, on_closed)
        threading.Thread(target=self.program.start, daemon=True).start()

    def send(self, text: str) -> None:
        if self.real is not None:
            return self.real.send(text)
        self.program.feed(text)

    def resize(self, cols: int, rows: int) -> None:
        if self.real is not None:
            self.real.resize(cols, rows)

    def close(self) -> None:
        if self.real is not None:
            return self.real.close()
        self.program._end("")

    @property
    def alive(self) -> bool:
        return self.real.alive if self.real is not None else not self.program.done


Shell = Console  # what the phones call it (phonessh.Shell)


def _target(login, command: str | None = None) -> dict:
    return {"ip": login.ip, "port": login.port, "user": login.user, "password": login.password,
            "alias": login.alias, "known_hosts": str(login.known_hosts), "via": bool(login.via), "command": command}


def parse_ssh(argv: list) -> dict:
    """What an ssh command line (terminal.ssh_argv, ssh_command) asks for."""
    target = {"port": 22, "user": "", "alias": None, "known_hosts": None, "via": False, "command": None}
    args, rest = iter(argv[1:]), []
    for a in args:
        if a in ("-p", "-l", "-o", "-F", "-J", "-L", "-i", "-b", "-c", "-m", "-E"):
            value = next(args, "")
            if a == "-p":
                target["port"] = int(value)
            elif a == "-l":
                target["user"] = value
            elif a == "-J":
                target["via"] = True
            elif a == "-o":
                key, _, val = value.partition("=")
                if key == "HostKeyAlias":
                    target["alias"] = val
                elif key == "UserKnownHostsFile":
                    target["known_hosts"] = val.strip('"')
        elif a.startswith("-"):
            continue
        else:
            rest.append(a)
            rest += list(args)
    host = rest[0] if rest else ""
    if "@" in host:
        target["user"], host = host.split("@", 1)
    target["ip"] = host
    target["alias"] = target["alias"] or host
    target["command"] = " ".join(rest[1:]) or None
    return target


def session_factory(real_session):
    """terminal.Session's stand-in while the demo shows: an SSH or ping session in the Terminal
    tab, run by Program and ping() instead of ssh and ping. real_session: the real class."""

    class DemoSession(real_session):
        demo = True

        def start(self) -> None:
            self.typed, self.tail = set(), b""
            self.alive = True
            self.program = None
            emit = lambda text: self._emit(text.encode("utf-8"))  # noqa: E731
            if self.kind == "ping" and self.argv and not self.argv[0].endswith("ssh"):
                self.stop = threading.Event()
                ip = self.argv[-1]
                threading.Thread(target=self._ping, args=(ip, emit), daemon=True).start()
                return
            if getattr(self, "forward", None):  # a web UI's forward: there's none to reach
                return self._closed("The demo network's devices are made up: they have no web UI to open.")
            target = dict(self.own) if getattr(self, "own", None) else parse_ssh(self.argv)
            password = self.password
            if isinstance(password, dict):
                password = password.get(target["alias"]) or password.get(target["ip"])
            target["password"] = password
            if not target["user"]:
                target["user"] = "admin"
            self.program = Program(NETWORK, target, emit, self._closed)
            if NETWORK is None:
                return self._closed("The demo network has ended: its made-up devices are gone.")
            self.program.start()

        def _ping(self, ip, emit) -> None:
            ping(ip, lambda line: emit(line.replace("\n", "\r\n") + "\r\n"), self.stop.is_set)
            self.alive = False
            self._emit(self._ended(0))

        def _closed(self, reason: str) -> None:
            if reason:
                self._emit(f"{reason}\r\n".encode())
            self.alive = False
            self._emit(self._ended(255 if reason else 0))

        def write(self, data: bytes) -> None:
            text = data.decode("utf-8", "replace")
            if self.program is not None:
                self.program.feed(text)
            elif "\x03" in text and getattr(self, "stop", None):
                self._emit(b"^C\r\n")
                self.stop.set()

        def resize(self, cols: int, rows: int) -> None:
            if cols >= 2 and rows >= 2:
                self.size = (rows, cols)

        def close(self) -> None:
            self.password = None
            if getattr(self, "stop", None):
                self.stop.set()
            if self.program is not None:
                self.program.done = True
            self.alive = False

    return DemoSession


def own_session_factory(real_session):
    """terminal.OwnSession's stand-in while the demo shows, for a computer without ssh, whose
    sessions start from a login (and a command, or a forward) rather than ssh's arguments.
    real_session: the real Session class."""

    class DemoOwnSession(session_factory(real_session)):
        def __init__(self, sid, device_key, kind, title, login, command=None, forward=None):
            self.own, self.forward = _target(login, command), forward
            super().__init__(sid, device_key, kind, title, [], login.password)

    return DemoOwnSession
