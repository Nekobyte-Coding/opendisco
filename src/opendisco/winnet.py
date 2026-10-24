"""Windows networking for the scanner: adapters and addresses (PowerShell, whose structured
output doesn't depend on Windows' display language the way ipconfig's does), packet capture
through Npcap, and administrator rights. Imported only on Windows.

Packet capture needs Npcap (npcap.com; Wireshark installs it too). Its default install lets
any user capture, so sniffing doesn't need administrator rights. Temporary addresses do: netsh
changes adapters, so those modes ask Windows (UAC) to run the scan as administrator.
"""
import ctypes
import json
import os
import subprocess
import sys
import threading
import time

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
NPCAP_HELP = ("Packet capture needs Npcap: install it from npcap.com (Wireshark installs it too), keeping "
              "\"Restrict Npcap driver's access to Administrators only\" unticked")
_ADAPTERS = {"at": 0.0, "rows": []}


def powershell_json(command: str) -> list:
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                            f"{command} | ConvertTo-Json -Depth 3"],
                           capture_output=True, text=True, timeout=30, errors="replace", creationflags=CREATE_NO_WINDOW)
        data = json.loads(r.stdout) if r.stdout.strip() else []
    except (OSError, subprocess.SubprocessError, ValueError):
        return []
    return data if isinstance(data, list) else [data]


def adapters(max_age: float = 10.0) -> list:
    """Physical network adapters, cached briefly (PowerShell takes a second to start):
    [{"name", "description", "guid", "mac", "up", "wireless", "speed"}]. name is the adapter's
    name in Windows (InterfaceAlias), which netsh and Npcap's device list key on."""
    if time.monotonic() - _ADAPTERS["at"] > max_age:
        rows = powershell_json("Get-NetAdapter -Physical | Select-Object Name,InterfaceDescription,InterfaceGuid,"
                               "MacAddress,Status,PhysicalMediaType,NdisPhysicalMedium,LinkSpeed,FullDuplex")
        out = []
        for r in rows:
            if not r.get("Name"):
                continue
            media = f"{r.get('PhysicalMediaType') or ''} {r.get('NdisPhysicalMedium') or ''}".lower()
            out.append({"name": r["Name"], "description": r.get("InterfaceDescription") or "",
                        "guid": r.get("InterfaceGuid") or "", "up": str(r.get("Status")) in ("Up", "1"),
                        "mac": (r.get("MacAddress") or "").replace("-", ":").lower(),
                        "wireless": "802.11" in media or "wireless" in media or str(r.get("NdisPhysicalMedium")) == "9",
                        "speed": str(r.get("LinkSpeed") or ""),
                        "duplex": "full-duplex" if r.get("FullDuplex") else ""})
        _ADAPTERS.update(at=time.monotonic(), rows=out)
    return _ADAPTERS["rows"]


def ipv4_addresses() -> list:
    """[(adapter name, ip, prefix length)] for every IPv4 address."""
    rows = powershell_json("Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,IPAddress,PrefixLength")
    out = []
    for r in rows:
        try:
            out.append((r["InterfaceAlias"], r["IPAddress"], int(r["PrefixLength"])))
        except (KeyError, TypeError, ValueError):
            pass
    return out


def install_npcap() -> str:
    """Run get-npcap.ps1: download Npcap's official installer, check its signature, start it, and
    wait for it to finish. Returns "" when Npcap is installed afterwards, else what went wrong."""
    global _WPCAP
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources", "get-npcap.ps1")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script],
                           capture_output=True, text=True, errors="replace", creationflags=CREATE_NO_WINDOW)
    except OSError as e:
        return str(e)
    _WPCAP = None  # look again
    if npcap() is not None:
        return ""
    lines = [l for l in (r.stderr or r.stdout).splitlines() if l.strip()]
    return lines[-1] if r.returncode and lines else "Npcap still isn't installed (was its installer cancelled?)"


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def relaunch_as_admin(args: list) -> bool:
    """Start this program again with administrator rights; Windows asks first (UAC)."""
    params = subprocess.list2cmdline(args)
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1) > 32


def supports_temporary_addresses() -> bool:
    """Windows 10 2004 (build 19041) and later can add a static address next to DHCP's."""
    try:
        return sys.getwindowsversion().build >= 19041
    except AttributeError:
        return False


# ---------------------------------------------------------------------------
# Capture through Npcap
# ---------------------------------------------------------------------------

class _PcapHeader(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long), ("caplen", ctypes.c_uint32),
                ("len", ctypes.c_uint32)]


class _BpfProgram(ctypes.Structure):
    _fields_ = [("bf_len", ctypes.c_uint), ("bf_insns", ctypes.c_void_p)]


_WPCAP = None


def npcap():
    """Npcap's wpcap.dll, or None when Npcap isn't installed."""
    global _WPCAP
    if _WPCAP is None:
        folder = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap")
        try:
            os.add_dll_directory(folder)  # wpcap.dll loads Packet.dll from beside it
            lib = ctypes.CDLL(os.path.join(folder, "wpcap.dll"))
        except (OSError, AttributeError):
            _WPCAP = False
            return None
        lib.pcap_open_live.restype = ctypes.c_void_p
        lib.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
        lib.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.POINTER(_BpfProgram), ctypes.c_char_p, ctypes.c_int,
                                     ctypes.c_uint32]
        lib.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.POINTER(_BpfProgram)]
        lib.pcap_freecode.argtypes = [ctypes.POINTER(_BpfProgram)]
        lib.pcap_next_ex.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(_PcapHeader)),
                                     ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
        lib.pcap_datalink.argtypes = [ctypes.c_void_p]
        lib.pcap_geterr.restype = ctypes.c_char_p
        lib.pcap_geterr.argtypes = [ctypes.c_void_p]
        lib.pcap_close.argtypes = [ctypes.c_void_p]
        _WPCAP = lib
    return _WPCAP or None


def npcap_device(name: str) -> str | None:
    """Npcap's device for a Windows adapter name: \\Device\\NPF_{its GUID}."""
    guid = next((a["guid"] for a in adapters() if a["name"] == name), "")
    return f"\\Device\\NPF_{guid}" if guid else None


def capture(names, seconds: float, on_frames=None, stop=None, snaplen: int = 1600) -> dict:
    """Capture broadcast and multicast Ethernet frames on these adapters at once, like
    tcpdump "ether multicast" in promiscuous mode. on_frames(name, frames) is called as frames
    arrive (from this thread); stop() can end it early. Returns {name: (frames, error)}."""
    lib = npcap()
    if lib is None:
        return {name: ([], NPCAP_HELP) for name in names}
    state = {name: {"frames": [], "new": [], "err": "", "lock": threading.Lock()} for name in names}
    done = threading.Event()

    def reader(name: str) -> None:
        s = state[name]
        device = npcap_device(name)
        if not device:
            s["err"] = "no such adapter"
            return
        errbuf = ctypes.create_string_buffer(256)
        handle = lib.pcap_open_live(device.encode(), snaplen, 1, 250, errbuf)
        if not handle:
            msg = errbuf.value.decode(errors="replace") or "couldn't open the adapter"
            s["err"] = msg + ("" if "denied" not in msg.lower() else
                              " (Npcap is restricted to administrators: run this as administrator)")
            return
        try:
            if lib.pcap_datalink(handle) != 1:
                s["err"] = "not an Ethernet adapter"
                return
            program = _BpfProgram()
            if lib.pcap_compile(handle, ctypes.byref(program), b"ether multicast", 1, 0xFFFFFFFF) == 0:
                lib.pcap_setfilter(handle, ctypes.byref(program))
                lib.pcap_freecode(ctypes.byref(program))
            header = ctypes.POINTER(_PcapHeader)()
            data = ctypes.POINTER(ctypes.c_ubyte)()
            while not done.is_set():
                rc = lib.pcap_next_ex(handle, ctypes.byref(header), ctypes.byref(data))
                if rc == 1:
                    frame = ctypes.string_at(data, header.contents.caplen)
                    with s["lock"]:
                        s["new"].append(frame)
                elif rc < 0:  # 0 is just the 250 ms timeout
                    if rc == -1:
                        s["err"] = (lib.pcap_geterr(handle) or b"").decode(errors="replace")
                    break
        finally:
            lib.pcap_close(handle)

    def collect() -> None:
        for name, s in state.items():
            with s["lock"]:
                new, s["new"] = s["new"], []
            if new:
                s["frames"] += new
                if on_frames:
                    on_frames(name, new)

    threads = [threading.Thread(target=reader, args=(name,), daemon=True) for name in names]
    for t in threads:
        t.start()
    deadline = time.monotonic() + seconds
    try:
        while time.monotonic() < deadline and any(t.is_alive() for t in threads):
            time.sleep(0.25)
            collect()
            if stop and stop():
                break
    finally:
        done.set()
        for t in threads:
            t.join(timeout=2)
        collect()
    return {name: (s["frames"], s["err"]) for name, s in state.items()}


def wifi_association(name: str) -> dict:
    """SSID and BSSID of the access point a Wi-Fi adapter is joined to (netsh wlan)."""
    try:
        out = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, timeout=10,
                             errors="replace", creationflags=CREATE_NO_WINDOW).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    info, current = {}, None
    for line in out.splitlines():
        key, _, value = (part.strip() for part in line.partition(":"))
        if key.lower() == "name":
            current = value
        elif current == name and key.upper() in ("BSSID", "AP BSSID") and value:  # "AP BSSID" on Windows 11
            info["bssid"] = value.split()[0].lower()
        elif current == name and key.upper() == "SSID" and value:
            info["ssid"] = value
    return info
