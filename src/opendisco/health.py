"""Device health: the latest firmware for each device's platform, and the latency to each device.

Firmware
- Firmware looks up the latest release for each device's firmware platform (Device.fw_platform)
  on Ubiquiti's firmware server, through devicetools (firmware_index, find_release, Check). The
  server lists every product's latest releases in one reply, so one request answers for every
  platform. The releases are kept in the app's data folder (FIRMWARE_FILE) for about a day, so
  repeat scans don't ask again, and the lookup runs in its own thread, so a scan never waits on it.
- What it finds goes in d.health["firmware"], which the Firmware column, Details and the exports read.

Latency
- measure() pings devices a few times each, all at once, and keeps the round trips in
  d.health["latency"]. A device that loses a ping or answers slowly gets more pings before it
  counts, so one lost or late packet isn't taken for a problem; issues() then flags high
  latency and packet loss.
- Pinging needs no administrator rights: an ICMP datagram socket where the system allows one
  (macOS, iOS, Android, and Linux when net.ipv4.ping_group_range includes the user's group),
  Windows' IcmpSendEcho (iphlpapi.dll, through ctypes), else the system's ping program, whose
  output is read for the times.

Standard library only, like core. devicetools (which imports core) is imported when a lookup runs.
"""
from __future__ import annotations

import json
import math
import os
import random
import re
import select
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from opendisco import core, vulns

FIRMWARE_FILE = "firmware-latest.json"  # in the app's data folder
FIRMWARE_TTL = 20 * 3600  # about a day, like the CVE list (vulns.refresh_due): then it's asked again
FIRMWARE_RETRY = 900  # seconds before asking again after the server didn't answer
CLI_FIRMWARE_WAIT = 10.0  # how long the command line waits for the lookup once the scan is done

PINGS = 4  # pings to each device...
MORE_PINGS = 6  # ...and these more for one that lost a ping or answered slowly, before it counts
PING_TIMEOUT = 1.0  # seconds a reply may take
PING_INTERVAL = 0.25  # seconds between pings to one device
PING_RATE = 200  # pings a second at most, over all the devices
PING_THREADS = 32  # Windows: devices pinged at once (IcmpSendEcho waits for each reply)
PING_PROGRAMS = 16  # ping programs running at once
HIGH_LATENCY_MS = 100  # an average round trip this long is high latency
LOSS_PERCENT = 20  # this share of pings lost is packet loss (2 of 10)


# ---------------------------------------------------------------------------
# The latest firmware
# ---------------------------------------------------------------------------

def _key(d) -> tuple:
    """What a device's answer depends on: find_release reads its platform, board and firmware
    string, and Check the version it runs."""
    return tuple(str(v or "") for v in (d.fw_platform, d.info.get("platform"), d.info.get("firmware"),
                                         d.info.get("version")))


def _trim(item: dict) -> dict:
    """What find_release and Check read of a release, and where its file is."""
    kept = {k: item[k] for k in ("channel", "platform", "product", "version", "created", "file_size",
                                 "sha256_checksum", "md5") if k in item}
    href = item.get("_links", {}).get("data", {}).get("href")
    if href:
        kept["_links"] = {"data": {"href": href}}
    return kept


class Firmware:
    """The latest firmware for devices' platforms, looked up in the background.

    add(devices) gives each device what's known (d.health["firmware"]) and queues the rest. The
    lookup thread reads the releases kept in data_dir, or asks the server when they're missing or
    a day old (falling back on old ones when it doesn't answer), then calls on_found() from its
    thread when it has answers, for a GUI to show them (add() again applies them)."""

    def __init__(self, data_dir=None, on_found=None, log=None):
        self.path = Path(data_dir) / FIRMWARE_FILE if data_dir else None
        self.on_found = on_found
        self.log = log
        self.idle = threading.Event()  # set while no lookup runs
        self.idle.set()
        self._lock = threading.Lock()
        self._found = {}  # _key(d) -> what d.health["firmware"] gets
        self._wanted = {}  # _key(d) -> a device with that key, to look up
        self._releases = None  # (when fetched, release items): the file's or the server's
        self._failed = 0.0  # when the server last didn't answer
        self._thread = None

    def add(self, devices) -> None:
        now = time.time()
        with self._lock:
            if (self._releases and not 0 <= now - self._releases[0] < FIRMWARE_TTL
                    and now - self._failed >= FIRMWARE_RETRY):
                self._found.clear()  # a day old: ask again (and keep using them if the server doesn't answer)
                self._releases = None
            resting = self._releases is None and now - self._failed < FIRMWARE_RETRY  # nothing to go on
            for d in devices:
                if not d.fw_platform:
                    continue
                key = _key(d)
                if key in self._found:
                    d.health["firmware"] = self._found[key]
                elif not resting:
                    self._wanted.setdefault(key, d)
            thread = None
            if self._wanted and self._thread is None:
                thread = self._thread = threading.Thread(target=self._work, daemon=True)
                self.idle.clear()
        if thread:
            thread.start()

    def wait(self, timeout: float) -> bool:
        """Wait for the lookup to finish; False if it's still running after timeout seconds."""
        return self.idle.wait(timeout)

    def _work(self) -> None:
        while True:
            with self._lock:
                wanted = dict(self._wanted)
                if not wanted:
                    self._thread = None
                    self.idle.set()
                    return
            found = {}
            try:
                found = self._look_up(wanted)
            except Exception as e:  # never let a lookup take the app down
                self._failed = time.time()
                self._say(f"Firmware versions not checked: {type(e).__name__}: {e}")
            with self._lock:
                self._found.update(found)
                for key in wanted:
                    self._wanted.pop(key, None)
            if found and self.on_found:
                self.on_found()

    def _look_up(self, wanted: dict) -> dict:
        from opendisco import devicetools
        now = time.time()
        kept = self._releases or self._read()
        if not (kept and 0 <= now - kept[0] < FIRMWARE_TTL) and now - self._failed >= FIRMWARE_RETRY:
            try:
                items = devicetools.firmware_index()
            except devicetools.ToolError as e:
                self._failed = time.time()
                self._say(f"Firmware versions not checked: {e}" + (
                    f" Using its list of {_day(kept[0])}." if kept else ""))
            else:
                kept = (now, [_trim(i) for i in items if i.get("channel") == "release"])
                self._write(kept, devicetools.INDEX_URL)
        if not kept:
            return {}
        self._releases = kept
        listed = _day(kept[0])
        found = {}
        for key, d in wanted.items():
            check = devicetools.Check(devicetools.device_version(d), devicetools.find_release(d, kept[1]),
                                      d.fw_platform or d.info.get("platform") or "")
            ahead = bool(check.latest and check.current
                         and devicetools.version_key(check.current) > devicetools.version_key(check.latest))
            found[key] = {"platform": check.platform, "current": check.current, "latest": check.latest,
                          "date": check.date, "newer": check.newer, "ahead": ahead, "listed": listed}
        return found

    def _read(self):
        if not self.path:
            return None
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return float(data["fetched"]), [i for i in data["releases"] if isinstance(i, dict)]
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def _write(self, kept, source: str) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            part = self.path.with_suffix(".part")
            part.write_text(json.dumps({"fetched": kept[0], "source": source, "releases": kept[1]}),
                            encoding="utf-8")
            os.replace(part, self.path)
        except OSError:
            pass  # still answers this time; the next run asks again

    def _say(self, msg: str) -> None:
        if self.log:
            self.log(msg)


def _day(at: float) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(at))


def firmware_cell(d) -> str:
    """The Firmware column: "8.7.11 (latest: 8.7.25)" when a newer release is out (the version
    compared, without the build number the column shows otherwise), else the version as before."""
    fw = d.health.get("firmware")
    if fw and fw["newer"]:
        return f"{fw['current']} (latest: {fw['latest']})"
    return d.firmware


def latest_version(d) -> str:
    """The latest release for its platform ("" when not looked up, or none is listed)."""
    return (d.health.get("firmware") or {}).get("latest", "")


# ---------------------------------------------------------------------------
# Latency
# ---------------------------------------------------------------------------

def pingable(d, holding: bool = False) -> bool:
    """Whether to ping it after a scan: it has an address, and one this computer can still reach.
    One reached only through a temporary address isn't, once the address is gone (holding: kept)."""
    return bool(d.ip) and core._usable_ip(d.ip) and (holding or not d.alias or d.direct)


def measure(devices, count: int = PINGS, stop=None) -> str:
    """Ping the devices, count times each and all at once, and keep the result in
    d.health["latency"]. One that lost a ping, or answered slowly, gets MORE_PINGS more before
    the result is kept. Returns how it pinged; raises OSError when it can't ping at all."""
    by_ip = {}
    for d in devices:
        if d.ip:
            by_ip.setdefault(d.ip, []).append(d)
    if not by_ip:
        return ""
    how, times = ping_many(list(by_ip), count, stop)
    again = [ip for ip, t in times.items() if _unsure(t)]
    if again and MORE_PINGS and not (stop and stop()):
        _how, more = ping_many(again, MORE_PINGS, stop, how)
        for ip in again:
            times[ip] = times[ip] + more[ip]
    at = time.time()
    for ip, t in times.items():
        result = _stats(t, at, how)
        for d in by_ip[ip]:
            d.health["latency"] = result
    return how


def _unsure(times: list) -> bool:
    """Some replies, but a ping lost or slow ones: worth more pings before it counts."""
    got = [t for t in times if t is not None]
    return bool(got) and (len(got) < len(times) or sum(got) / len(got) >= HIGH_LATENCY_MS)


def _stats(times: list, at: float, how: str) -> dict:
    got = [t for t in times if t is not None]
    out = {"sent": len(times), "received": len(got), "at": at, "how": how}
    if got:
        out.update(avg_ms=round(sum(got) / len(got), 2), min_ms=round(min(got), 2), max_ms=round(max(got), 2),
                   replies_ms=[round(t, 2) for t in got])
    return out


def ping_many(ips: list, count: int, stop=None, how: str = "") -> tuple:
    """Ping each address count times: (how, {ip: [round trip in ms, or None when lost, per ping]}).
    how picks the way (one that worked before); otherwise the first of them the system allows."""
    # Windows has no ICMP datagram sockets, and nothing else has IcmpSendEcho.
    ways = [("IcmpSendEcho" if core.IS_WINDOWS else "ICMP socket", _ping_windows if core.IS_WINDOWS else _ping_socket),
            ("ping program", _ping_program)]
    problems = []
    for name, ping in sorted(ways, key=lambda way: way[0] != how):
        try:
            return name, ping(ips, count, PING_TIMEOUT, PING_INTERVAL, stop)
        except OSError as e:
            problems.append(f"{name}: {e.strerror or e}")
    raise OSError(f"can't ping from here ({'; '.join(problems)})")


def _ping_socket(ips, count, timeout, interval, stop) -> dict:
    """Every address through one ICMP datagram socket: the pings go out PING_RATE a second at
    most and a device's pings interval apart, and each reply is matched to its echo by sequence
    number, identifier and address. Linux sets the identifier to the socket's own; macOS and iOS
    keep the one given (and hand every ICMP packet to every such socket, with its IP header)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)  # replies may come in bursts
    except OSError:
        pass
    ident, seq, body = random.randrange(1, 0x10000), random.randrange(0x10000), bytes(range(56))
    spacing = 1.0 / PING_RATE
    gap = max(interval, len(ips) * spacing)  # one round: a ping to every address
    plan = [(k * gap + i * spacing, ip, k) for k in range(count) for i, ip in enumerate(ips)]
    times = {ip: [None] * count for ip in ips}
    pending = {}  # sequence number -> (address, which ping, when it went)
    idents, sent, start = {ident}, 0, time.perf_counter()
    with sock:
        sock.setblocking(False)
        while (sent < len(plan) or pending) and not (stop and stop()):
            now = time.perf_counter()
            while sent < len(plan) and start + plan[sent][0] <= now:
                _, ip, k = plan[sent]
                sent += 1
                head = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
                packet = struct.pack("!BBHHH", 8, 0, core._icmp_checksum(head + body), ident, seq) + body
                try:
                    sock.sendto(packet, (ip, 0))
                    pending[seq] = (ip, k, time.perf_counter())
                except OSError:
                    pass  # no route, or the system refused: a ping lost
                seq = (seq + 1) & 0xFFFF
                if len(idents) == 1:
                    try:
                        idents.add(sock.getsockname()[1] or ident)  # Linux: the identifier it gave the echoes
                    except OSError:
                        pass
            for n, (_ip, _k, at) in list(pending.items()):
                if now - at > timeout:
                    del pending[n]
            wait = start + plan[sent][0] - now if sent < len(plan) else 0.05
            readable, _, _ = select.select([sock], [], [], min(0.05, max(0.0, wait)))
            if readable:
                _take_replies(sock, pending, times, idents)
    return times


def _take_replies(sock, pending: dict, times: dict, idents: set) -> None:
    while True:
        try:
            data, addr = sock.recvfrom(2048)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            return  # Linux reports an ICMP error on the socket itself: that ping times out
        got = time.perf_counter()
        if data and data[0] >> 4 == 4:  # macOS and iOS hand over the IP header too; Linux doesn't
            data = data[(data[0] & 0x0F) * 4:]
        if len(data) < 8:
            continue
        kind, _code, _sum, ident, n = struct.unpack("!BBHHH", data[:8])
        if kind in core.ICMP_KINDS and len(data) >= 36:  # an error quoting one of the echoes
            inner = data[8:]
            inner = inner[(inner[0] & 0x0F) * 4:]
            if len(inner) >= 8:
                ident, n = struct.unpack("!HH", inner[4:8])
                if ident in idents and n in pending and pending[n][0] == socket.inet_ntoa(data[24:28]):
                    del pending[n]  # unreachable: lost now rather than at the timeout
            continue
        if kind != 0 or ident not in idents or n not in pending or pending[n][0] != addr[0]:
            continue
        ip, k, at = pending.pop(n)
        times[ip][k] = (got - at) * 1000


def _ping_windows(ips, count, timeout, interval, stop) -> dict:
    """Windows: IcmpSendEcho (iphlpapi.dll), which any user may call. It waits for each reply, so
    up to PING_THREADS devices are pinged at once, each in a thread of its own."""
    import ctypes
    from ctypes import wintypes

    api = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
    create, send, close = api.IcmpCreateFile, api.IcmpSendEcho, api.IcmpCloseHandle
    create.restype, create.argtypes = wintypes.HANDLE, []
    # DWORD IcmpSendEcho(HANDLE, IPAddr DestinationAddress, LPVOID RequestData, WORD RequestSize,
    #                    PIP_OPTION_INFORMATION RequestOptions, LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout)
    send.restype = wintypes.DWORD
    send.argtypes = [wintypes.HANDLE, ctypes.c_uint32, ctypes.c_void_p, wintypes.WORD, ctypes.c_void_p,
                     ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
    close.restype, close.argtypes = wintypes.BOOL, [wintypes.HANDLE]
    invalid = ctypes.c_void_p(-1).value  # INVALID_HANDLE_VALUE

    def opened():
        handle = create()
        if handle in (None, invalid):
            raise OSError(ctypes.get_last_error(), "IcmpCreateFile failed")
        return handle

    close(opened())  # fails here, before any thread, when it can't work at all
    payload = b"OpenDisco latency check ".ljust(32, b".")  # 32 bytes, as Windows' ping sends
    # Room for the reply's ICMP_ECHO_REPLY (40 bytes in 64-bit Windows, 28 in 32-bit), its data, an
    # ICMP error's 8 bytes and an IO_STATUS_BLOCK, as the documentation asks, and to spare.
    size = 256 + len(payload)

    def one(ip: str) -> list:
        times = [None] * count
        dest = int.from_bytes(socket.inet_aton(ip), "little")  # IPAddr: the address's bytes in network order
        request, reply = ctypes.create_string_buffer(payload, len(payload)), ctypes.create_string_buffer(size)
        handle = opened()
        try:
            for k in range(count):
                if stop and stop():
                    break
                began = time.perf_counter()
                if send(handle, dest, request, len(payload), None, reply, size, int(timeout * 1000)):
                    # ICMP_ECHO_REPLY starts Address, Status, RoundTripTime (ms): the same in
                    # 32- and 64-bit Windows. Status 0 is IP_SUCCESS; an error comes from a router.
                    address, status, rtt = struct.unpack_from("<III", reply, 0)
                    if status == 0 and address == dest:
                        times[k] = float(rtt)
                rest = interval - (time.perf_counter() - began)
                if rest > 0 and k < count - 1:
                    time.sleep(rest)
        finally:
            close(handle)
        return times

    with ThreadPoolExecutor(max_workers=max(1, min(PING_THREADS, len(ips)))) as pool:
        return dict(zip(ips, pool.map(one, ips)))


# A reply's line in a ping program's output: Windows names the time and then the TTL, in its own
# language ("time=3ms TTL=64", "time<1ms", "Zeit=3ms", "temps=3 ms", "время<1мс"); iputils, BusyBox
# and macOS name the TTL and then the time, in English with LC_ALL=C ("ttl=64 time=0.412 ms").
WINDOWS_REPLY = re.compile(r"([=<])\s*(\d+)\s*[^\s\d=<]*\s+TTL=", re.I)
UNIX_REPLY = re.compile(r"\bttl=\d+.*?\btime([=<])\s*(\d+(?:\.\d+)?)\s*ms", re.I)


def program_times(text: str, count: int) -> list:
    """The round trips in a ping program's output, None for each ping it got no reply to."""
    pattern = WINDOWS_REPLY if core.IS_WINDOWS else UNIX_REPLY
    times = []
    for line in text.splitlines():
        m = pattern.search(line)
        if m and "DUP!" not in line:
            times.append(0.0 if m.group(1) == "<" else float(m.group(2)))
    times = times[:count]
    return times + [None] * (count - len(times))


def _ping_program(ips, count, timeout, interval, stop) -> dict:
    """The system's ping program, PING_PROGRAMS at once: where no ICMP socket is allowed (Linux
    when net.ipv4.ping_group_range leaves the user out) and Windows' API can't be used."""
    exe = core.find_tool("ping") or next((p for p in ("/system/bin/ping", "/sbin/ping", "/bin/ping")
                                          if os.path.exists(p)), None)
    if not exe:
        raise OSError("no ping program")
    if core.IS_WINDOWS:  # Windows' ping waits a second between pings; -w is its timeout in ms
        flags = ["-n", str(count), "-w", str(int(timeout * 1000))]
    elif sys.platform == "darwin":  # -W in ms
        flags = ["-n", "-c", str(count), "-i", str(interval), "-W", str(int(timeout * 1000))]
    else:  # iputils, BusyBox: -W in whole seconds (older iputils take no fraction)
        flags = ["-n", "-c", str(count), "-i", str(interval), "-W", str(max(1, math.ceil(timeout)))]
    env = None if core.IS_WINDOWS else dict(os.environ, LC_ALL="C")
    window = getattr(subprocess, "CREATE_NO_WINDOW", 0) if core.IS_WINDOWS else 0
    limit = count * max(interval, 1.0) + timeout + 5

    def one(ip: str) -> tuple:
        """(round trips, why it couldn't ping: "" when it could)"""
        if stop and stop():
            return [None] * count, ""
        try:
            done = subprocess.run([exe, *flags, ip], capture_output=True, text=True, errors="replace", env=env,
                                  timeout=limit, creationflags=window)
        except subprocess.TimeoutExpired:
            return [None] * count, ""
        except (OSError, subprocess.SubprocessError) as e:
            return [None] * count, str(getattr(e, "strerror", None) or e)
        times = program_times(done.stdout, count)
        # No replies and no statistics: it never pinged (with LC_ALL=C they say "packets transmitted";
        # Windows' are in its own language, so there silence and failure look the same).
        if any(t is not None for t in times) or core.IS_WINDOWS or "transmitted" in done.stdout:
            return times, ""
        said = done.stderr.strip().splitlines() or [f"it stopped with status {done.returncode}"]
        why = next((line for line in said if re.search(r"(?i)permi|denied", line)), said[-1])
        return times, why.split(": ", 1)[-1] if why.startswith(exe) else why

    with ThreadPoolExecutor(max_workers=max(1, min(PING_PROGRAMS, len(ips)))) as pool:
        results = dict(zip(ips, pool.map(one, ips)))
    failed = [why for _times, why in results.values() if why]
    if len(failed) == len(results):
        raise OSError(failed[0])
    return {ip: times for ip, (times, _why) in results.items()}


def _ms(value: float) -> str:
    return f"{value:.1f}" if value < 10 else f"{value:.0f}"


def _loss(lat: dict) -> int:
    """Pings lost, in percent."""
    return round((lat["sent"] - lat["received"]) * 100 / lat["sent"]) if lat.get("sent") else 0


def latency_cell(d) -> str:
    """The Latency column: "3 ms", "12 ms, 25% loss", "no reply" ("" when not measured)."""
    lat = d.health.get("latency")
    if not lat:
        return ""
    if not lat["received"]:
        return "no reply"
    avg = lat["avg_ms"]
    text = "<1 ms" if avg < 1 else f"{avg:.0f} ms"
    return text + (f", {_loss(lat)}% loss" if lat["received"] < lat["sent"] else "")


def issues(d) -> list:
    """Diagnostics from its latency (core.diagnose adds them): packet loss and high latency.
    A device that doesn't answer pings at all isn't flagged: many block them (Windows does)."""
    lat = d.health.get("latency") or {}
    got, sent = lat.get("received", 0), lat.get("sent", 0)
    if not got:
        return []
    found = []
    lost = sent - got
    if lost * 100 >= LOSS_PERCENT * sent:
        found.append(("warn", "PING-LOSS",
                      f"{lost} of {sent} pings went unanswered ({_loss(lat)}% loss). On a wired link that points to a "
                      "bad cable, connector or port, or a speed/duplex mismatch; on a wireless hop, to interference, "
                      "a weak signal or a busy channel; or the device is too busy to answer."))
    if lat["avg_ms"] >= HIGH_LATENCY_MS:
        found.append(("warn", "HIGH-LATENCY",
                      f"Pings take {lat['avg_ms']:.0f} ms on average ({_ms(lat['min_ms'])}-{_ms(lat['max_ms'])} ms "
                      f"over {got} replies): a congested link on the way, interference or a weak signal on a "
                      "wireless hop, or a device short of CPU."))
    return found


def summary(devices) -> str:
    """A measurement in a line, for the Log and status bar."""
    if len(devices) == 1:
        d = devices[0]
        return f"Latency to {d.ip}: {latency_cell(d) or 'not measured'}."
    lats = [d.health.get("latency") or {} for d in devices]
    flagged = Counter(tag for d in devices for _, tag, _ in issues(d))
    bits = [f"{sum(1 for lat in lats if lat.get('received'))} of {len(devices)} devices answered"]
    bits += [f"{flagged[tag]} with {what}" for tag, what in (("PING-LOSS", "packet loss"),
                                                             ("HIGH-LATENCY", "high latency")) if flagged[tag]]
    how = next((lat["how"] for lat in lats if lat.get("how")), "")
    return "Latency: " + ", ".join(bits) + (f" ({how})." if how else ".")


# ---------------------------------------------------------------------------
# Details, exports and the command line
# ---------------------------------------------------------------------------

def detail_rows(d) -> list:
    """[(label, text)] for Details."""
    rows = []
    fw = d.health.get("firmware")
    if fw:
        listed = "" if fw["listed"] == _day(time.time()) else f"; Ubiquiti's list of {fw['listed']}"
        if not fw["latest"]:
            rows.append(("Latest firmware", f"none listed for {fw['platform']} on Ubiquiti's firmware server{listed}"))
        else:
            if fw["newer"]:
                state = f"newer than the {fw['current']} it runs"
            elif fw["ahead"]:
                state = f"it runs {fw['current']}, newer than that"
            elif fw["current"]:
                state = "it runs the latest"
            else:
                state = "the version it runs is unknown"
            rows.append(("Latest firmware", f"{fw['latest']} (released {fw['date']}): {state}{listed}"))
    lat = d.health.get("latency")
    if lat:
        when = time.strftime("%H:%M:%S", time.localtime(lat["at"]))
        if lat["received"]:
            text = (f"{_ms(lat['avg_ms'])} ms on average ({_ms(lat['min_ms'])}-{_ms(lat['max_ms'])} ms), "
                    f"{lat['received']} of {lat['sent']} replies"
                    + (f" ({_loss(lat)}% loss)" if lat["received"] < lat["sent"] else "") + f", {when}")
        else:
            text = f"no reply to {lat['sent']} pings, {when}"
            if d.found_by:
                text += f" (found through {d.found_by.get('ip', 'another device')}: pings from here may not reach it)"
        rows.append(("Latency", text))
    elif d.ip and d.alias and not d.direct:
        rows.append(("Latency", "not measured: reached through a temporary address, removed after the scan"))
    return rows


def to_dict(d) -> dict:
    """The JSON export's part."""
    fw, lat = d.health.get("firmware"), d.health.get("latency")
    return {
        "latest_firmware": {"platform": fw["platform"], "version": fw["latest"] or None, "released": fw["date"] or None,
                            "newer": fw["newer"], "listed": fw["listed"]} if fw else None,  # None: not looked up
        "latency": {"sent": lat["sent"], "received": lat["received"], "loss_percent": _loss(lat),
                    "avg_ms": lat.get("avg_ms"), "min_ms": lat.get("min_ms"), "max_ms": lat.get("max_ms"),
                    "replies_ms": lat.get("replies_ms", []), "method": lat["how"],
                    "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(lat["at"]))} if lat else None,
    }


def check_scan(res, opts, log) -> None:
    """The command line, once a scan is done: each device's latency, and its latest firmware when
    the output shows it (-v, --json, --export); then the diagnostics again. --no-latency and
    --no-firmware-check leave them out, and --listen (which sends nothing) both."""
    if opts.listen or not res.devices:
        return
    lookup = None
    if opts.firmware_check and (opts.verbose or opts.json or opts.export):
        lookup = Firmware(vulns.CACHE_DIR, log=log)
        lookup.add(res.devices)
    if opts.latency:
        devices = [d for d in res.devices if pingable(d)]
        if devices:
            log(f"Measuring latency to {len(devices)} device(s)...")
            try:
                measure(devices)
                log(summary(devices))
            except OSError as e:
                log(f"Latency not measured: {e}")
            except KeyboardInterrupt:
                log("Latency: stopped")
    if lookup:
        if not lookup.wait(CLI_FIRMWARE_WAIT):
            log("Firmware versions not checked: Ubiquiti's firmware server is slow to answer.")
        lookup.add(res.devices)
    if res.diag_args:
        core.diagnose(res.inv, *res.diag_args)
        res.devices = core.sorted_devices(res.inv)
