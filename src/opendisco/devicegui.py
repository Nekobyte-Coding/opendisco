"""The device tools' windows (desktop only): firmware check and update, the config editor, config
backups (list, restore, upload with a diff first), reboot, locate, the new login, Scan from
device (also from an address, for a device not in the table), and the login window they share,
which can remember a device's login in the operating system's credential store. The work itself
is opendisco.devicetools, run in worker threads.

app.py only lists the actions in DEVICE_ACTIONS and calls menu_state(), act() and scan_address().
"""
import asyncio
import os
import re
import socket
import subprocess
import sys
import textwrap
import threading
import time
import traceback
import urllib.parse
import webbrowser
from pathlib import Path

import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW

from opendisco import core, credstore, devicetools, sshrun, terminal, terms

ACTIONS = ("scan_from", "fw_check", "fw_update", "config", "login", "backup", "backups", "upload", "reboot", "locate",
           "forget_login")
_busy: dict = {}  # device key -> what's running on it
_in_use: dict = {}  # downloaded firmware path -> updates using it
_locating: dict = {}  # device key -> the login its LED was set blinking with
_backup_windows: dict = {}  # MAC -> its open Config backups window


ROUTED = ("ssh", "ping", "web", "rescan", "find_http", "find_https", "find_ssh", "all_ports")


def route(app, d) -> list:
    """The devices on the way to d, the nearest to this computer first: the devices it was found
    through (found_by), each through the one before. Empty for a device found directly."""
    devices = app.result.inv.devices if app.result else {}
    chain, seen, current = [], {d.key}, d
    while current.found_by.get("key") in devices and current.found_by["key"] not in seen:
        current = devices[current.found_by["key"]]
        seen.add(current.key)
        chain.insert(0, current)
    return chain


def handles(app, d, name: str) -> bool:
    """Whether this module does the action: the device tools, and for a device behind other
    devices, the app's own SSH, ping, web UI and port actions too."""
    return name in ACTIONS or (name in ROUTED and bool(route(app, d)))


def menu_state(app, d, titles: dict) -> dict:
    """{action: (title, enabled)} for the device tools, and for a device behind others, the
    app's own actions that reach it through them."""
    state = {}
    hops = route(app, d)
    via = f"  (via {' → '.join(h.ip or h.mac for h in hops)})" if hops else ""
    tools = not app.caps["mobile"] and sshrun.available()
    busy = _busy.get(d.key)
    ubiquiti = bool(d.info.get("firmware") or d.info.get("platform"))
    state["fw_check"] = (titles["fw_check"], ubiquiti and not busy)
    for name, action in (("scan_from", "scan"), ("fw_update", "update"), ("config", "edit"), ("login", "login"),
                         ("backup", "backup"), ("upload", "upload"), ("reboot", "reboot"), ("locate", "locate")):
        offered, why = devicetools.offers(d, action)
        title = "Stop locating (LED)" if name == "locate" and d.key in _locating else titles[name]
        if busy:
            title += f"  ({busy})"
        elif not offered:
            title += f"  ({why})"
        elif not tools:
            title += "  (needs ssh and scp)"
        if offered and not busy:
            title += via
        state[name] = (title, bool(d.ip) and offered and tools and not busy)
    idle = bool(app.result) and not (app.running or app.rescanning or app.finding)
    if hops:
        reach = bool(d.ip) and tools and all(h.ip for h in hops)
        for name in ("ssh", "ping", "web"):
            state[name] = (titles[name] + via, reach)
        for name in ("find_http", "find_https", "find_ssh", "all_ports"):
            state[name] = (titles[name] + via, reach and idle)
        state["rescan"] = (titles["rescan"] + "  (discovery can't travel over SSH)", False)
    if state["scan_from"][1] and not idle:  # it adds to the scan's results
        state["scan_from"] = (titles["scan_from"], False)
    state["forget_login"] = (titles["forget_login"], bool(d.mac and _remembered(app, d)))
    kept = len(devicetools.list_backups(d.mac)) if d.mac else 0
    state["backups"] = (titles["backups"] + (f"  ({kept} kept)" if kept else ""),
                        bool(d.mac and (kept or state["backup"][1])))  # filed by MAC: none without one
    return state


def act(app, d, name: str) -> None:
    flow = {"scan_from": scan_flow, "fw_check": check_flow, "fw_update": update_flow, "config": config_flow,
            "login": login_flow, "backup": backup_flow, "backups": backups_flow, "upload": upload_flow,
            "reboot": reboot_flow, "locate": locate_flow, "ssh": routed_ssh, "ping": routed_ping,
            "web": routed_web}.get(name)
    if name in ("find_http", "find_https", "find_ssh", "all_ports"):
        kind = {"find_http": "http", "find_https": "https", "find_ssh": "ssh", "all_ports": "all"}[name]
        flow = lambda app, d: routed_find(app, d, kind)  # noqa: E731
    if flow:
        asyncio.create_task(_guarded(app, d, flow))
    elif name == "forget_login":
        forget_login(app, d)


async def _guarded(app, d, flow):
    try:
        await flow(app, d)
    except Exception as e:  # a bug, not the device: say so rather than fail silently
        app._append_log(traceback.format_exc())
        await app.main_window.dialog(toga.ErrorDialog("Something went wrong", f"{type(e).__name__}: {e}"))


async def _work(fn, *args):
    return await asyncio.get_running_loop().run_in_executor(None, fn, *args)


def _label(d) -> str:
    return f"{d.ip}  {d.name or d.model or d.mac or ''}".strip()


def _fill(text: str, width: int) -> str:
    """Labels don't wrap by themselves (Windows' and macOS's alike): each paragraph broken to
    `width` characters, so it stays inside its window."""
    return "\n".join(textwrap.fill(part, width) if part.strip() else "" for part in str(text).split("\n"))


# ---------------------------------------------------------------------------
# Logins
# ---------------------------------------------------------------------------

def _logins(app) -> dict:
    return app.settings.setdefault("device_logins", {})  # MAC -> {"user", "port"}; passwords in the store


def _remembered(app, d) -> dict | None:
    return _logins(app).get(d.mac) if d.mac else None


def _login(app, d, user: str, password: str, port: int, via: tuple = ()) -> sshrun.Login:
    return sshrun.Login(d.ip, port, user, password, terminal.host_key_alias(d.mac, d.ip), app.known_hosts, via)


async def ask_route(app, d, purpose: str, hops_only: bool = False):
    """The login for d, through the devices on its route (found_by), each asked for in turn,
    nearest first. A device this computer can reach itself is logged in to directly. With
    hops_only, the logins of the devices on the way only (a tuple; empty when it's direct)."""
    hops = route(app, d)
    if hops and await _work(devicetools.answers, d.ip, d.port("ssh"), 2):
        hops = []  # reachable from here after all
    via = ()
    for n, hop in enumerate(hops, 1):
        login = await ask_login(app, hop, f"Device {n} of {len(hops)} on the way to {d.ip}. {purpose}", via)
        if not login:
            return None
        via += (login,)
    if hops_only:
        return via
    if hops:
        purpose += f" Through {' → '.join(h.ip for h in hops)}: each device on the way adds latency."
    return await ask_login(app, d, purpose, via)


def forget_login(app, d) -> None:
    _logins(app).pop(d.mac, None)
    app._save_settings()
    gone = credstore.forget(d.mac)
    app.status.text = (f"Forgot the saved login for {d.ip or d.mac}." if gone
                       else f"Forgot the saved username for {d.ip or d.mac}; {credstore.store_name()} had no password for it.")


async def ask_login(app, d, purpose: str, via: tuple = ()) -> sshrun.Login | None:
    """Ask for the username, password and port, then log in once to check them. Remembers or
    forgets the login as the checkbox says, once it has worked. None when cancelled."""
    saved = _remembered(app, d)
    password = credstore.load(d.mac) if saved and credstore.available() else None
    user = (saved or {}).get("user") or app.settings.get("ssh_user") or ""
    port = int((saved or {}).get("port") or d.port("ssh"))
    problem, remember = "", bool(saved)
    while True:  # until it works or is cancelled, keeping what was typed and ticked
        answer = await _login_window(app, d, purpose, user, password or "", port, remember, problem)
        if answer is None:
            return None
        user, password, port, remember = answer
        login = _login(app, d, user, password, port, via)
        app.status.text = f"Logging in to {login.where}…"
        try:
            await _work(sshrun.check_login, login)
        except sshrun.SSHError as e:
            app.status.text = str(e)
            problem = str(e)
            continue
        app.status.text = f"Logged in to {d.ip} as {user}."
        if remember and d.mac and credstore.available():
            if credstore.save(d.mac, user, password):
                _logins(app)[d.mac] = {"user": user, "port": port}
            else:
                app.status.text = f"Logged in, but {credstore.store_name()} didn't take the password."
        elif saved and not remember:
            _logins(app).pop(d.mac, None)
            credstore.forget(d.mac)
        app._save_settings()
        await warn_factory_login(app, d, login)
        return login


async def warn_factory_login(app, d, login) -> None:
    """Keep whether a login that just worked on d is a factory one, and say so the first time: the
    device keeps its FACTORY-LOGIN issue until it has a new password."""
    if devicetools.note_login(d, login):
        app._save_settings()
        app._rediagnose()
        if devicetools.is_factory(login):
            await app.main_window.dialog(toga.InfoDialog(
                "Factory login", f"{_label(d)}\n\n{core.factory_login_text(login.user, login.password)}"))


async def _login_window(app, d, purpose, user, password, port, remembered, problem):
    answer = app.loop.create_future()
    user_box = toga.TextInput(value=user, placeholder="e.g. ubnt or admin", style=Pack(flex=1))
    password_box = toga.PasswordInput(value=password, style=Pack(flex=1))
    port_box = toga.TextInput(value=str(port), style=Pack(width=80))
    trouble = toga.Label(_fill(problem, 46), style=Pack(flex=1))
    can_remember = bool(d.mac) and credstore.available()
    remember = toga.Switch(f"Remember for this device (in {credstore.store_name()})", value=remembered and can_remember,
                           enabled=can_remember)

    def finish(ok):
        if answer.done():
            return
        if ok:
            text = port_box.value.strip()
            if not user_box.value.strip():
                trouble.text = "The device tools need a username."
                return
            if not text.isdigit() or not 0 < int(text) < 65536:
                trouble.text = _fill("The port is a number from 1 to 65535.", 46)
                return
            answer.set_result((user_box.value.strip(), password_box.value, int(text), remember.value))
        else:
            answer.set_result(None)
        window.close()

    def closing(widget, **kwargs):
        if not answer.done():
            answer.set_result(None)
        return True

    password_box.on_confirm = lambda widget: finish(True)
    user_box.on_confirm = lambda widget: password_box.focus()
    label = Pack(width=80)
    row = Pack(direction=ROW, align_items="center", gap=8)
    note = ("The password goes only to ssh and scp. " +
            (f"Remembered logins are kept in {credstore.store_name()}, never in a file." if can_remember
             else "This computer has no credential store the app can use, so it isn't remembered."))
    size = (560, 300)
    window = toga.Window(title=f"Log in to {d.ip}", size=size, resizable=False, on_close=closing,
                         position=app._over_main(size))
    window.content = toga.Box(style=Pack(direction=COLUMN, margin=14, gap=8), children=[
        toga.Label(_label(d)),
        toga.Label(_fill(purpose, 72)),
        toga.Box(style=row, children=[toga.Label("Username", style=label), user_box]),
        toga.Box(style=row, children=[toga.Label("Password", style=label), password_box]),
        toga.Box(style=row, children=[toga.Label("Port", style=label), port_box, trouble]),
        remember,
        toga.Label(_fill(note, 72)),
        toga.Box(style=Pack(direction=ROW, gap=8), children=[
            toga.Box(style=Pack(flex=1)),
            toga.Button("Cancel", on_press=lambda w: finish(False)),
            toga.Button("Log in", on_press=lambda w: finish(True))])])
    app._show_over_main(window)
    (password_box if user_box.value else user_box).focus()
    app.cancel_ssh_login = lambda: finish(False)  # quitting must not leave it waiting
    try:
        return await answer
    finally:
        app.cancel_ssh_login = None


# ---------------------------------------------------------------------------
# Progress
# ---------------------------------------------------------------------------

class Progress:
    """A window showing what a long job is doing, with a bar and a log; Cancel while it may."""

    def __init__(self, app, title: str, heading: str):
        self.app = app
        self.stop = threading.Event()
        self.closed = False
        self.said = ""  # the step as it was said, before it was broken into lines
        self.heading = toga.Label(_fill(heading, 84))
        self.step = toga.Label("", style=Pack(flex=1))
        self.bar = toga.ProgressBar(max=100, value=0, style=Pack(flex=1))
        self.log = toga.MultilineTextInput(readonly=True, style=Pack(flex=1, font_family="monospace", font_size=11))
        self.button = toga.Button("Cancel", on_press=self._pressed)
        size = (640, 360)
        self.window = toga.Window(title=title, size=size, closable=False, position=app._over_main(size))
        self.window.content = toga.Box(style=Pack(direction=COLUMN, margin=14, gap=8), children=[
            self.heading, self.step, self.bar, self.log,
            toga.Box(style=Pack(direction=ROW, gap=8), children=[toga.Box(style=Pack(flex=1)), self.button])])
        app._show_over_main(self.window)

    def _pressed(self, widget, **kwargs):
        if self.button.text == "Cancel":
            self.stop.set()
            self.button.enabled = False
            self.show("Cancelling…")
        else:
            self.closed = True
            self.window.close()

    def show(self, text: str | None = None, percent: float | None = None) -> None:
        """From any thread."""
        self.app._from_worker(self._show, text, percent)

    def _show(self, text, percent):
        if text:
            if text.split("…")[0] != self.said.split("…")[0]:
                self.log.value += time.strftime("%H:%M:%S  ") + text.rstrip(" 0123456789s") + "\n"
                self.log.scroll_to_bottom()
            self.said, self.step.text = text, _fill(text, 84)
        if percent is not None:
            self.bar.value = max(0, min(100, percent))

    def no_cancel(self) -> None:
        self.app._from_worker(setattr, self.button, "enabled", False)

    def finish(self, text: str) -> None:
        self._show(text, None)
        self.button.text, self.button.enabled = "Close", True


# ---------------------------------------------------------------------------
# Scan from a device
# ---------------------------------------------------------------------------

async def scan_flow(app, d):
    """What the device knows of its neighbours, added to the table: its stations (airOS), LLDP
    neighbours and ARP table."""
    result = app.result
    if not result or _busy.get(d.key):
        return
    fam = devicetools.family(d)
    tools = "its ARP table and LLDP neighbours" + (" and the stations associated with it" if fam == "airos" else "")
    login = await ask_route(app, d, f"Log in to read what it sees: {tools}.")
    if not login:
        return
    _busy[d.key] = "scanning"
    app.spinner.start()
    app.status.text = f"Reading what {d.ip} sees…"
    try:
        def work():
            return devicetools.parse_scan(devicetools.read_scan(login, fam)), core.local_macs()

        try:
            sightings, local = await _work(work)
        except sshrun.SSHError as e:
            app.status.text = f"Scan from {d.ip}: {e}"
            return
    finally:
        _busy.pop(d.key, None)
        app.spinner.stop()
    if result is not app.result:  # a new scan started meanwhile
        app.status.text = f"Scan from {d.ip} finished after a new scan started: start it again."
        return
    seen, new = devicetools.merge_scan(result, d, sightings, local)
    app._show_devices(result.devices)
    _report_scan(app, d, sightings, seen, new)


def _report_scan(app, d, sightings, seen, new):
    """What a scan from a device found, in the log and the status line."""
    counts = ", ".join(f"{devicetools.SCAN_HOW[how]} {n}" for how in devicetools.SCAN_HOW
                       if (n := sum(1 for s in sightings if s.how == how)))
    lines = [f"Scan from {d.ip} ({d.name or d.model or d.mac}): {counts or 'nothing listed'}; "
             f"{len(seen)} device(s), {len(new)} new."]
    for dev in seen:
        how = sorted({devicetools.SCAN_HOW[s.how] for s in sightings
                      if (s.mac and dev.mac == core.norm_mac(s.mac)) or (s.ip and s.ip in dev.ips)})
        lines.append(f"  {dev.ip or '-':15} {dev.mac or '-':17} {dev.name or dev.model or dev.vendor or '':24} "
                     f"{', '.join(how)}{'  (new)' if dev in new else ''}")
    app._append_log("\n".join(lines))
    app.status.text = lines[0]
    selected = app._selected_device()
    if selected is not None:
        app.details.value = core.render_details(selected)


# ---------------------------------------------------------------------------
# Reaching a device through others: SSH, ping, web UI, ports
# ---------------------------------------------------------------------------

def _through(hops) -> str:
    return " → ".join(h.ip for h in hops)


async def routed_ssh(app, d):
    session = app.term.find(d.key, "ssh")
    if session:
        app._show_terminal(session)
        return
    login = await ask_route(app, d, "Log in for an SSH session.")
    if not login:
        return
    if login.nested:  # a device on the way doesn't forward: a session on the last hop's own client
        argv = sshrun.ssh_command(sshrun.last_hop(login), sshrun.nested_command(login, None), "-tt")
    else:
        argv = sshrun.ssh_command(login, None)
    title = f"{d.ip}  SSH {login.user}@ via {sshrun.route_text(login) or 'direct'}  {d.name or d.model or ''}".rstrip()
    if not login.via:
        title = f"{d.ip}  SSH {login.user}@port {login.port}  {d.name or d.model or ''}".rstrip()
    app._show_terminal(app.term.open(d.key, "ssh", title, argv, login.passwords))


async def routed_ping(app, d):
    session = app.term.find(d.key, "ping")
    if session:
        if not session.alive:
            session.type(b"\r")
        app._show_terminal(session)
        return
    hops = await ask_route(app, d, f"Log in to ping {d.ip} from the device before it.", hops_only=True)
    if hops is None:
        return
    if not hops:  # reachable from here
        app._open_ping(d)
        return
    last = _chain(hops)
    title = f"{d.ip}  ping from {last.ip}  {d.name or d.model or ''}".rstrip()
    app._show_terminal(app.term.open(d.key, "ping", title, sshrun.ssh_command(last, f"ping {d.ip}", "-tt"),
                                     last.passwords))


def _chain(hops) -> sshrun.Login:
    """The last device on the way, reached through the ones before it."""
    *before, last = hops
    return sshrun.Login(last.ip, last.port, last.user, last.password, last.alias, last.known_hosts, tuple(before))


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def routed_web(app, d):
    """The web UI through a local port forward from the last device on the way: the browser
    opens 127.0.0.1, and the forward runs as a Terminal session until it's closed."""
    url = urllib.parse.urlsplit(core.web_url(d, fallback=True))
    port = url.port or (443 if url.scheme == "https" else 80)
    session = app.term.find(d.key, "web")
    if session and session.alive:
        webbrowser.open(session.url)
        app.status.text = f"Opened {session.url} (forwarded to {d.ip}:{port})."
        return
    hops = await ask_route(app, d, f"Log in to forward {d.ip}'s web UI to this computer.",
                           hops_only=True)
    if hops is None:
        return
    if not hops:
        webbrowser.open(url.geturl())
        app.status.text = f"Opened {url.geturl()}"
        return
    last, local = _chain(hops), _free_port()
    if not any(kind in ("https", "http") for kind in d.services.values()):
        # This computer can't check its ports: the device before it looks for a web server.
        candidates = list(dict.fromkeys([port, 443, 80, 8443, 8080]))
        try:
            out = (await _work(lambda: sshrun.run(last, "for p in " + " ".join(map(str, candidates)) +
                                                  f"; do nc -z -w1 {d.ip} $p 2>/dev/null && echo $p && break; done"))).out
        except sshrun.SSHError as e:
            app.status.text = f"Web UI of {d.ip}: {e}"
            return
        found = next((int(p) for p in out.split() if p.isdigit()), None)
        if found and found != port:
            port, url = found, urllib.parse.urlsplit(f"{'http' if found in (80, 8080) else 'https'}://{d.ip}:{found}/")
    argv = sshrun.ssh_command(last, None, "-N", "-L", f"127.0.0.1:{local}:{d.ip}:{port}")
    target = f"{url.scheme}://127.0.0.1:{local}/"
    title = f"{d.ip}  web UI via {_through(hops)}  {target}"
    session = app.term.open(d.key, "web", title, argv, last.passwords)
    session.url = target
    app.status.text = f"Forwarding {target} to {d.ip}:{port} through {_through(hops)}…"
    if await _work(_wait_local, local, 30):
        webbrowser.open(target)
        app.status.text = (f"Opened {target}: forwarded to {d.ip}:{port} through {_through(hops)} for as long as its "
                           "session stays open in the Terminal tab. Each device on the way adds latency.")
    else:
        app._show_terminal(session)
        app.status.text = f"The forward to {d.ip}:{port} didn't start: its session in the Terminal tab says why."


def _wait_local(port: int, within: float) -> bool:
    start = time.monotonic()
    while time.monotonic() - start < within:
        if devicetools.answers("127.0.0.1", port, 1):
            return True
        time.sleep(0.5)
    return False


async def routed_find(app, d, kind: str):
    """A port search run on the last device on the way, with its nc: every connection through
    an SSH forward is a channel of its own, far too slow for 65,535 ports from here."""
    if not (app.settings.get("skip_port_warning") or app.port_warning_accepted or await app._port_warning(d)):
        return
    hops = await ask_route(app, d, f"Log in to search {d.ip}'s ports from the device before it.", hops_only=True)
    if hops is None:
        return
    if not hops:
        app._find(d, kind)
        return
    last, result = _chain(hops), app.result
    name = core.SERVICE_NAMES[kind]
    ports = core.search_order(kind, result.devices if result else ())
    app.finding = True
    app.start_button.enabled, app.stop_button.enabled = False, True
    app.spinner.start()
    core.STOP.clear()

    def work():
        if sshrun.run(last, f"nc -z -w1 127.0.0.1 {last.port}").code:
            raise devicetools.ToolError(f"{last.ip} has no nc that can check ports (nc -z), so {d.ip}'s ports "
                                        "can't be searched from it.")
        found = {}
        for start in range(0, len(ports), 600):
            if core.STOP.is_set():
                break
            chunk = " ".join(map(str, ports[start:start + 600]))
            out = sshrun.run(last, f"for p in {chunk}; do nc -z -w1 {d.ip} $p 2>/dev/null && echo $p; done",
                             timeout=900).out
            for port in (int(p) for p in out.split() if p.isdigit()):
                banner = sshrun.run(last, f"printf 'HEAD / HTTP/1.0\\r\\n\\r\\n' | nc -w2 {d.ip} {port} 2>/dev/null "
                                          "| head -c 80").out
                found[port] = ("ssh" if banner.startswith("SSH-") else "http" if banner.startswith("HTTP/")
                               else kind if kind != "all" and port in core.SEARCH_FIRST.get(kind, ()) else "open")
            done = min(start + 600, len(ports))
            app._from_worker(setattr, app.status, "text",
                             f"{d.ip} (from {last.ip}): checked {done:,} of {len(ports):,} TCP ports for {name}, "
                             f"{len(found)} open…")
            if kind != "all" and any(k == kind for k in found.values()):
                break
        return found

    error, found = None, {}
    try:
        found = await _work(work)
    except (devicetools.ToolError, sshrun.SSHError) as e:
        error = str(e)
    finally:
        app.finding = False
        app.spinner.stop()
        app.start_button.enabled, app.stop_button.enabled = True, False
    if error:
        app.status.text = f"Port search on {d.ip}: {error}"
        return
    d.ports = sorted(set(d.ports or []) | set(found))
    for port, what in found.items():
        d.services.setdefault(port, what)
    if result is app.result:
        app._show_devices(result.devices)
        if app._selected_device() is d:
            app.details.value = core.render_details(d)
    listed = ", ".join(f"{p} {k}" for p, k in sorted(found.items())) or "none"
    app.status.text = f"{d.ip}, checked from {last.ip}: open TCP ports {listed}."


# ---------------------------------------------------------------------------
# Firmware
# ---------------------------------------------------------------------------

async def _check(app, d) -> devicetools.Check | None:
    app.status.text = f"Asking Ubiquiti's firmware server about {d.ip or d.mac}…"
    try:
        check = await _work(devicetools.check_firmware, d)
    except devicetools.ToolError as e:
        app.status.text = str(e)
        await app.main_window.dialog(toga.ErrorDialog("Firmware check", str(e)))
        return None
    app.status.text = devicetools.summary(d, check).split("\n")[0]
    return check


async def check_flow(app, d):
    check = await _check(app, d)
    if check is None:
        return
    text = devicetools.summary(d, check)
    title = f"Firmware of {_label(d)}"
    can = (check.newer and devicetools.offers(d, "update")[0] and not devicetools.fits(d, check.release)
           and bool(d.ip) and sshrun.available() and not _busy.get(d.key))
    if can and await app.main_window.dialog(toga.QuestionDialog(title, text + "\n\nUpdate it now?")):
        await update_flow(app, d, check)
    elif not can:
        await app.main_window.dialog(toga.InfoDialog(title, text))


async def update_flow(app, d, check=None):
    if _busy.get(d.key):
        return
    check = check or await _check(app, d)
    if check is None:
        return
    if not check.newer:
        await app.main_window.dialog(toga.InfoDialog(f"Firmware of {_label(d)}", devicetools.summary(d, check)))
        return
    why = devicetools.fits(d, check.release)
    if why:
        await app.main_window.dialog(toga.ErrorDialog("Firmware update", why))
        return
    _busy[d.key] = "updating"
    try:
        login = await ask_route(app, d, f"Log in to install firmware {check.latest}.")
        if not login:
            return
        family = devicetools.FAMILY_NAMES[devicetools.family(d)]
        message = (f"Install {family} firmware {check.latest} on {_label(d)}? It runs {check.current} now.\n\n"
                   f"The app downloads it from Ubiquiti ({devicetools.fmt_size(check.size)}), checks it, copies it to "
                   "the device and starts the installation. The device restarts to install it and is offline for "
                   "a few minutes: don't unplug it or turn it off until it's back.")
        if devicetools.family(d) == "edgeos":
            app.status.text = f"Reading the firmware images of {d.ip}…"
            try:
                note = await _work(devicetools.edgeos_update_note, login, check.latest)
            except (devicetools.ToolError, sshrun.SSHError) as e:
                app.status.text = f"Firmware update of {d.ip}: {e}"
                await app.main_window.dialog(toga.ErrorDialog("Firmware update", str(e)))
                return
            message = (f"Install EdgeOS firmware {check.latest} on {_label(d)}? It runs {check.current} now.\n\n"
                       f"The app downloads it from Ubiquiti ({devicetools.fmt_size(check.size)}), checks it, copies it "
                       "to the router and adds it with EdgeOS's add system image. Once EdgeOS lists it as the image it "
                       "boots, the app restarts the router, which is offline for a few minutes: don't unplug it or "
                       f"turn it off until it's back.\n\n{note}")
        if devicetools.family(d) in ("unifi", "unifi-os"):
            message += ("\n\nUbiquiti's help center describes updating over SSH as a last resort, for when the UniFi "
                        "app can't update the device.")
        message += "\n\n" + terms.risk("firmware")
        if not await app.main_window.dialog(toga.QuestionDialog("Install firmware?", message)):
            return
        await _install(app, d, check, login)
    finally:
        _busy.pop(d.key, None)


async def _install(app, d, check, login):
    progress = Progress(app, f"Firmware update: {d.ip}", f"{_label(d)}: {check.current} → {check.latest}")
    folder = Path(app.paths.cache) / "firmware"
    outcome = {}

    def work():
        path = None
        try:
            progress.show(f"Downloading firmware {check.latest} from Ubiquiti…", 0)
            path = devicetools.download_release(
                check.release, folder, stop=progress.stop,
                progress=lambda done, total: progress.show(None, 100 * done / total if total else None))
            _in_use[path] = _in_use.get(path, 0) + 1
            progress.show(f"Downloaded and checked (SHA-256 {check.release['sha256_checksum'][:16]}…).", 100)

            def report(text, percent):
                if text and text.startswith("Starting the installation"):
                    progress.no_cancel()
                progress.show(text, percent)

            outcome["offline"] = devicetools.install_firmware(d, login, path, report, stop=progress.stop,
                                                              version=check.latest)
        except (devicetools.ToolError, sshrun.SSHError) as e:
            outcome["error"] = str(e)
        except Exception as e:
            outcome["error"] = f"{type(e).__name__}: {e}"
            app._from_worker(app._append_log, traceback.format_exc())
        finally:
            if path in _in_use:
                _in_use[path] -= 1
                if not _in_use[path] and "offline" in outcome:
                    _in_use.pop(path)
                    path.unlink(missing_ok=True)  # installed: no need to keep it

    await _work(work)
    if "error" in outcome:
        text = outcome["error"]
        if progress.stop.is_set() and "Cancelled" in text:
            text = "Cancelled. Nothing was installed."
        progress.finish(text)
        app.status.text = f"Firmware update of {d.ip}: {text}"
        return
    text = f"Back after {outcome['offline']:.0f} s."
    progress.finish(text + " Reading its firmware again…")
    now = await _reread(app, d)
    if now is None:
        text += " Rescan it to see the version it runs."
    elif devicetools.version_key(now) == devicetools.version_key(check.latest):
        text = f"Updated: it runs {now}. " + text
    else:
        text = f"It's back, but reports firmware {now or 'unknown'}, not {check.latest}. " + text
    progress.finish(text)
    app.status.text = f"{d.ip}: {text}"


async def _reread(app, d) -> str | None:
    """Rescan the device for the firmware it reports now; None when a scan is busy."""
    result = app.result
    if not result or app.running or app.rescanning or app.finding:
        return None
    app.rescanning = True
    app.spinner.start()
    error = None
    try:
        dev, answered = await _work(core.rescan_device, result, d,
                                    lambda m: app._from_worker(app._append_log, m))
    except Exception as e:
        dev, answered, error = d, False, f"{type(e).__name__}: {e}"
    app._rescanned(result, dev, answered, error)
    return devicetools.device_version(dev) if answered else None


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

async def config_flow(app, d):
    kind = devicetools.config_kind(d)
    login = await ask_route(app, d, f"Log in to read its configuration ({devicetools.CONFIG_FILES[kind]}).")
    if not login:
        return
    app.status.text = f"Reading the config of {d.ip}…"
    try:
        text, pending = await _work(devicetools.read_device_config, login, kind)
        tools = await _work(devicetools.config_tools, login, kind)
    except (sshrun.SSHError, devicetools.ToolError) as e:
        app.status.text = str(e)
        await app.main_window.dialog(toga.ErrorDialog("Config", str(e)))
        return
    app.status.text = f"Read the config of {d.ip}."
    ConfigEditor(app, d, login, text, pending, kind, tools)


ABOUT_CONFIG = {
    "airos": "{file} on {ip}: airOS's whole configuration, one setting per line.\nSave writes it to flash: it takes "
             "effect at the next reboot. Apply saves it and applies it now, the way the web UI's Apply does: the "
             "device restarts only what the changes affect, and the connection to it can drop for a moment.",
    "edgeos": "{file} on {ip}: EdgeOS's boot config (what it loads when it starts; changes committed since without "
              "saving aren't in it).\nSave checks that EdgeOS reads it and makes it the boot config: it takes effect "
              "at the next reboot. Apply loads it, commits and saves it, as configure; load; commit; save do: "
              "EdgeOS restarts what the changes affect, and the connection can drop for a moment.",
}
ABOUT_CONFIG["isp"] = ABOUT_CONFIG["airos"].replace("airOS's whole", "its whole")


class ConfigEditor:
    def __init__(self, app, d, login, text, pending, kind="airos", tools=None):
        self.app, self.d, self.login, self.kind = app, d, login, kind
        self.tools = tools or {"save": True, "apply": True, "why": ""}
        self.saved = text  # as the device has it
        self.box = toga.MultilineTextInput(value=text, style=Pack(flex=1, font_family="monospace", font_size=11))
        self.state = toga.Label("", style=Pack(flex=1))
        self.save_button = toga.Button("Save", on_press=self.save)
        self.apply_button = toga.Button("Apply", on_press=self.apply)
        self.buttons = [toga.Button("Reload", on_press=self.reload), self.save_button, self.apply_button]
        about = ABOUT_CONFIG[kind].format(file=devicetools.CONFIG_FILES[kind], ip=d.ip)
        if d.mac:
            about += " Before writing, the app keeps the config it read as a backup (Config backups…)."
        size = (900, 680)
        self.window = toga.Window(title=f"Config: {_label(d)}", size=size, on_close=self.closing,
                                  position=app._over_main(size))
        self.window.content = toga.Box(style=Pack(direction=COLUMN, margin=12, gap=8), children=[
            toga.Label(_fill(about, 118)), self.box,
            toga.Box(style=Pack(direction=ROW, align_items="center", gap=8), children=[
                self.state, *self.buttons, toga.Button("Close", on_press=lambda w: self.window.close())])])
        self._pending(pending)
        self._enable(True)
        app._show_over_main(self.window)

    def _pending(self, pending):
        self.state.text = _fill("It has changes that aren't applied yet (made in its web UI, or saved without "
                                "applying)." if pending else self.tools["why"], 64)

    def _enable(self, on: bool):
        for button in self.buttons:
            button.enabled = on
        self.save_button.enabled = on and self.tools["save"]
        self.apply_button.enabled = on and self.tools["apply"]

    def closing(self, widget, **kwargs):
        if self.box.value.replace("\r", "") == self.saved.replace("\r", ""):
            return True
        asyncio.create_task(self._close_unsaved())
        return False

    async def _close_unsaved(self):
        if await self.window.dialog(toga.QuestionDialog("Discard the changes?",
                                                        "The edits haven't been saved to the device.")):
            self.window.close()

    async def reload(self, widget, **kwargs):
        self._enable(False)
        self.state.text = "Reading…"
        try:
            text, pending = await _work(devicetools.read_device_config, self.login, self.kind)
        except (sshrun.SSHError, devicetools.ToolError) as e:
            self.state.text = _fill(e, 64)
        else:
            self.saved = self.box.value = text
            self._pending(pending)
        self._enable(True)

    async def save(self, widget, **kwargs):
        await self._write(False)

    async def apply(self, widget, **kwargs):
        await self._write(True)

    async def _write(self, apply: bool):
        text = self.box.value
        problems = devicetools.config_problems(text, self.kind)
        if problems:
            heading = ("EdgeOS wouldn't read it:\n" if self.kind == "edgeos"
                       else "airOS reads only key=value lines. These aren't:\n")
            await self.window.dialog(toga.ErrorDialog("Not a config", heading + "\n".join(problems[:10])))
            return
        changed = devicetools.lines_changed(self.saved, text)
        boot = "its boot config" if self.kind == "edgeos" else "flash"
        what = ("Apply the config on" if apply else f"Save the config to {boot} on") + f" {_label(self.d)}?"
        detail = (f"{changed} line(s) changed. " if changed else "Nothing changed in the editor. ") + (
            f"It's applied now and saved to {boot}; the device restarts what the changes affect." if apply
            else "It takes effect at the next reboot.") + "\n\n" + terms.risk("apply" if apply else "save")
        if not await self.window.dialog(toga.QuestionDialog(what, detail)):
            return
        self._enable(False)
        self.state.text = "Applying…" if apply else "Saving…"
        say = lambda m: self.app._from_worker(setattr, self.state, "text", _fill(m, 64))  # noqa: E731

        def work():
            if self.d.mac:  # what it had, kept before it's replaced
                devicetools.save_backup(self.d, self.saved, self.kind, "before edit")
                self.app._from_worker(_refresh_backups, self.d)
            return devicetools.push_config(self.login, self.kind, text, apply, report=say)

        try:
            message = await _work(work)
        except devicetools.LostConnection as e:  # what it means for the device, as far as it's known
            self.state.text = _fill(e, 64)
            self.app.status.text = f"{self.d.ip}: {e}"
            await self.window.dialog(toga.ErrorDialog("Connection lost", str(e)))
        except (devicetools.ToolError, sshrun.SSHError, OSError) as e:
            self.state.text = _fill(e, 64)
        else:
            self.saved = text
            self.state.text = _fill(message, 64)
            self.app.status.text = f"{self.d.ip}: {message}"
        self._enable(True)


# ---------------------------------------------------------------------------
# A new login
# ---------------------------------------------------------------------------

async def login_flow(app, d):
    if _busy.get(d.key):
        return
    login = await ask_route(app, d, "Log in with its current username and password first.")
    if not login:
        return
    kind = devicetools.config_kind(d)  # "airos" or "edgeos"
    if not login.password and kind == "airos":
        await app.main_window.dialog(toga.ErrorDialog(
            "Change login", "Changing the login needs the current password (an SSH key isn't enough): the app "
                            "checks it against the device's stored hash before writing a new one."))
        return
    _busy[d.key] = "changing login"
    try:
        app.status.text = f"Reading the config of {d.ip}…"
        try:
            if kind == "edgeos":
                text, _pending = await _work(devicetools.read_device_config, login, kind)
                pending = await _work(devicetools.edgeos_unsaved, login)
            else:
                text, pending = await _work(devicetools.read_config, login)
        except (sshrun.SSHError, devicetools.ToolError) as e:
            await app.main_window.dialog(toga.ErrorDialog("Change login", str(e)))
            return
        answer = await _new_login_window(app, d, login, text)
        if not answer:
            return
        new_text, new_user, new_password, scheme = answer
        what = (f"the password of {login.user} on {_label(d)}" if new_user == login.user
                else f"the login of {_label(d)} from {login.user} to {new_user} with the new password")
        if kind == "edgeos":
            message = (f"Change {what}? EdgeOS commits it right away and saves it to its boot config; the old "
                       f"{'password' if new_user == login.user else 'login'} stops working.")
            if new_user != login.user:
                message += (f"\n\nAs Ubiquiti's help center does it, {new_user} is made first, with {login.user}'s "
                            f"level and settings, and the app logs in with it; only then is {login.user} deleted, "
                            f"logged in as {new_user}.")
            message += "\n\nEdgeOS hashes the password itself and stores it so, never as plain text."
            if pending:
                message += ("\n\nIts config also has changes that are committed but not saved (in its CLI): saving "
                            "the new login saves them too.")
        else:
            message = (f"Change {what}? It's applied right away and saved to flash; the old login stops working.\n\n"
                       f"The password is stored on the device as an {scheme} hash, the format it uses now.")
            if pending:
                message += ("\n\nIts config also has changes that aren't applied yet (made in its web UI, or saved "
                            "without applying): they're applied with it.")
        message += "\n\n" + terms.risk("login")
        if not await app.main_window.dialog(toga.QuestionDialog("Change login?", message)):
            return
        new = sshrun.Login(login.ip, login.port, new_user, new_password, login.alias, login.known_hosts,
                           login.via, login.nested)
        progress = Progress(app, f"Changing login: {d.ip}", f"{_label(d)}: {login.user} → {new_user}")
        progress.no_cancel()
        outcome = {}

        def work():
            try:
                if d.mac:  # what it had, kept before it's replaced
                    devicetools.save_backup(d, text, kind, "before login change")
                    app._from_worker(_refresh_backups, d)
                if kind == "edgeos":  # new_text: the steps; it logs in with the new login itself
                    outcome["said"] = devicetools.change_edgeos_login(login, new, new_text, report=progress.show)
                    return
                outcome["said"] = devicetools.write_config(login, new_text, True, report=progress.show,
                                                           new_login=new)
                progress.show("Logging in with the new login…")
                sshrun.check_login(new)
            except (devicetools.ToolError, sshrun.SSHError, OSError) as e:
                outcome["error"] = str(e)

        await _work(work)
        if "error" in outcome:
            progress.finish(f"{outcome['error']}\nIf the device no longer takes either login, its web UI or a "
                            "reset to factory defaults gets it back.")
            return
        if _remembered(app, d):
            credstore.save(d.mac, new_user, new_password)
            _logins(app)[d.mac] = {"user": new_user, "port": login.port}
            app._save_settings()
        devicetools.forget_factory_login(d)
        app._save_settings()
        app._rediagnose()
        progress.finish(f"Done: {d.ip} takes the new login ({new_user}). {outcome['said']}" if kind == "edgeos"
                        else f"Done: {d.ip} takes the new login ({new_user}), applied and saved to flash.")
        app.status.text = f"{d.ip}: the login is now {new_user}."
    finally:
        _busy.pop(d.key, None)


async def _new_login_window(app, d, login, text):
    answer = app.loop.create_future()
    user_box = toga.TextInput(value=login.user, style=Pack(flex=1))
    first = toga.PasswordInput(style=Pack(flex=1))
    second = toga.PasswordInput(style=Pack(flex=1))
    trouble = toga.Label("", style=Pack(flex=1))

    def finish(ok):
        if answer.done():
            return
        if ok:
            if first.value != second.value:
                trouble.text = "The two passwords differ."
                return
            try:
                new_text, scheme = devicetools.new_login(d, login, text, user_box.value.strip(), first.value)
            except devicetools.ToolError as e:
                trouble.text = _fill(e, 76)
                return
            answer.set_result((new_text, user_box.value.strip(), first.value, scheme))
        else:
            answer.set_result(None)
        window.close()

    def closing(widget, **kwargs):
        if not answer.done():
            answer.set_result(None)
        return True

    second.on_confirm = lambda widget: finish(True)
    first.on_confirm = lambda widget: second.focus()
    label = Pack(width=120)
    row = Pack(direction=ROW, align_items="center", gap=8)
    size = (600, 300)
    window = toga.Window(title=f"New login: {d.ip}", size=size, resizable=False, on_close=closing,
                         position=app._over_main(size))
    window.content = toga.Box(style=Pack(direction=COLUMN, margin=14, gap=8), children=[
        toga.Label(_label(d)),
        toga.Label(_fill(devicetools.new_login_note(d), 76)),
        toga.Box(style=row, children=[toga.Label("Username", style=label), user_box]),
        toga.Box(style=row, children=[toga.Label("New password", style=label), first]),
        toga.Box(style=row, children=[toga.Label("Again", style=label), second]),
        trouble,
        toga.Box(style=Pack(direction=ROW, gap=8), children=[
            toga.Box(style=Pack(flex=1)),
            toga.Button("Cancel", on_press=lambda w: finish(False)),
            toga.Button("Change", on_press=lambda w: finish(True))])])
    app._show_over_main(window)
    first.focus()
    app.cancel_ssh_login = lambda: finish(False)
    try:
        return await answer
    finally:
        app.cancel_ssh_login = None


# ---------------------------------------------------------------------------
# Config backups
# ---------------------------------------------------------------------------

async def backup_flow(app, d):
    """Read the device's config and keep it in its backups folder."""
    if _busy.get(d.key):
        return
    kind = devicetools.config_kind(d)
    login = await ask_route(app, d, f"Log in to back up its config ({devicetools.CONFIG_FILES[kind]}).")
    if not login:
        return
    _busy[d.key] = "backing up"
    app.spinner.start()
    app.status.text = f"Reading the config of {d.ip}…"
    try:
        def work():
            text, _pending = devicetools.read_device_config(login, kind)
            return devicetools.save_backup(d, text, kind, "backup")

        try:
            backup = await _work(work)
        except (sshrun.SSHError, devicetools.ToolError, OSError) as e:
            app.status.text = f"Backup of {d.ip}: {e}"
            await app.main_window.dialog(toga.ErrorDialog("Config backup", str(e)))
            return
    finally:
        _busy.pop(d.key, None)
        app.spinner.stop()
    kept = len(devicetools.list_backups(d.mac))
    app._append_log(f"Config backup of {_label(d)}: {backup.path}")
    app.status.text = (f"Backed up the config of {d.ip} ({backup.date}); {kept} kept for it. Config backups… lists "
                       "them.")
    _refresh_backups(d)


async def backups_flow(app, d):
    window = _backup_windows.get(d.mac)
    if window is not None:
        window.window.show()
        return
    BackupsWindow(app, d)


def _refresh_backups(d):
    window = _backup_windows.get(d.mac)
    if window is not None:
        window.refresh()


def _show_folder(path: Path) -> None:
    """Open a folder in the Finder, Explorer or the desktop's file manager."""
    path.mkdir(parents=True, exist_ok=True)
    if sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    elif sys.platform.startswith("win"):
        os.startfile(str(path))  # noqa: S606 (a folder, opened as Explorer does)
    else:
        subprocess.Popen(["xdg-open", str(path)])


class BackupsWindow:
    """The configs kept for one device, the newest first, with the selected one's text; Restore
    uploads one (after a diff), Save a copy writes it elsewhere."""

    def __init__(self, app, d):
        self.app, self.d = app, d
        self.backups = []
        self.table = toga.Table(columns=["Taken", "Why", "Address", "Firmware", "Size"], on_select=self.selected,
                                style=Pack(flex=1))
        self.text = toga.MultilineTextInput(readonly=True, style=Pack(flex=2, font_family="monospace", font_size=11))
        self.state = toga.Label("", style=Pack(flex=1))
        offered = devicetools.offers(d, "backup")[0] and bool(d.ip) and sshrun.available()
        self.restore_button = toga.Button("Restore…", on_press=self.restore, enabled=False)
        self.copy_button = toga.Button("Save a copy…", on_press=self.save_copy, enabled=False)
        self.delete_button = toga.Button("Delete…", on_press=self.delete, enabled=False)
        kind = devicetools.config_kind(d)
        about = (f"Copies of {devicetools.CONFIG_FILES.get(kind, 'its config')} kept for {d.mac} in "
                 f"{devicetools.backup_folder(d.mac)}. Restore uploads one to it again (the same model only), "
                 "showing what changes first and keeping its current config as a backup.")
        size = (860, 620)
        self.window = toga.Window(title=f"Config backups: {_label(d)}", size=size, on_close=self.closing,
                                  position=app._over_main(size))
        self.window.content = toga.Box(style=Pack(direction=COLUMN, margin=12, gap=8), children=[
            toga.Label(_fill(about, 112)), self.table, self.text,
            toga.Box(style=Pack(direction=ROW, align_items="center", gap=8), children=[
                self.state,
                toga.Button("Back up now", on_press=self.backup_now, enabled=offered),
                self.restore_button, self.copy_button, self.delete_button,
                toga.Button("Show folder", on_press=lambda w: _show_folder(devicetools.backup_folder(d.mac))),
                toga.Button("Close", on_press=lambda w: self.window.close())])])
        _backup_windows[d.mac] = self
        self.refresh()
        app._show_over_main(self.window)

    def closing(self, widget, **kwargs):
        _backup_windows.pop(self.d.mac, None)
        return True

    def refresh(self):
        self.backups = devicetools.list_backups(self.d.mac)
        self.table.data = [{"taken": b.date, "why": b.reason or "backup", "address": b.meta.get("ip", ""),
                            "firmware": devicetools.device_version(_FirmwareOf(b.meta)) or b.meta.get("firmware", ""),
                            "size": f"{b.path.stat().st_size:,} B", "backup": b} for b in self.backups]
        self.text.value = ""
        self.state.text = f"{len(self.backups)} kept." if self.backups else "None kept yet."
        self.selected(self.table)

    def _current(self):
        row = self.table.selection
        return getattr(row, "backup", None) if row is not None else None

    def selected(self, widget, **kwargs):
        backup = self._current()
        can = devicetools.offers(self.d, "upload")[0] and bool(self.d.ip) and sshrun.available()
        self.restore_button.enabled = backup is not None and can and not _busy.get(self.d.key)
        self.copy_button.enabled = self.delete_button.enabled = backup is not None
        if backup is not None:
            try:
                self.text.value = backup.text()
            except OSError as e:
                self.text.value = f"Can't read {backup.path}: {e}"

    async def backup_now(self, widget, **kwargs):
        await _guarded(self.app, self.d, backup_flow)

    async def restore(self, widget, **kwargs):
        backup = self._current()
        if backup is not None:
            await _guarded(self.app, self.d, lambda app, d: upload_flow(app, d, backup))

    async def save_copy(self, widget, **kwargs):
        backup = self._current()
        if backup is None:
            return
        name = f"{(self.d.name or self.d.mac or 'device').replace(' ', '_')}_{backup.path.name}"
        path = await self.window.dialog(toga.SaveFileDialog("Save a copy of the config", suggested_filename=name))
        if path:
            try:
                Path(path).write_bytes(backup.path.read_bytes())
            except OSError as e:
                await self.window.dialog(toga.ErrorDialog("Save a copy", str(e)))
                return
            self.state.text = f"Saved a copy as {path}."

    async def delete(self, widget, **kwargs):
        backup = self._current()
        if backup is None or not await self.window.dialog(toga.QuestionDialog(
                "Delete this backup?", f"The config taken {backup.date} is deleted from {backup.path.parent}.")):
            return
        try:
            devicetools.delete_backup(backup)
        except OSError as e:
            await self.window.dialog(toga.ErrorDialog("Delete", str(e)))
        self.refresh()


class _FirmwareOf:
    """A backup's firmware string where device_version() looks for it."""

    def __init__(self, meta):
        self.info, self.firmware = {"firmware": str(meta.get("firmware") or "")}, ""


# ---------------------------------------------------------------------------
# Uploading a config: from a file or a backup, after a diff
# ---------------------------------------------------------------------------

async def upload_flow(app, d, backup=None):
    """Upload a config to the device: a file, or one of its backups (Restore). It must be the
    device's kind of config and from the same model; the app shows what changes, keeps the
    device's current config as a backup, then saves it (next boot) or applies it now."""
    if _busy.get(d.key):
        return
    kind = devicetools.config_kind(d)
    if backup is None:
        path = await app.main_window.dialog(toga.OpenFileDialog(
            f"Upload a config to {d.ip} ({devicetools.CONFIG_NAMES[kind]})"))
        if not path:
            return
        try:
            text, meta = devicetools.read_config_file(path)
        except (OSError, devicetools.ToolError) as e:
            await app.main_window.dialog(toga.ErrorDialog("Upload config", str(e)))
            return
        source = Path(path).name
    else:
        try:
            text, meta = backup.text(), backup.meta
        except OSError as e:
            await app.main_window.dialog(toga.ErrorDialog("Restore", str(e)))
            return
        source = f"the backup taken {backup.date}"
    refuse, warn = devicetools.upload_check(d, kind, text, meta)
    if refuse:
        await app.main_window.dialog(toga.ErrorDialog("Can't upload this config", refuse))
        return
    if warn and not await app.main_window.dialog(toga.QuestionDialog("Upload this config?", warn + "\n\nGo on?")):
        return
    login = await ask_route(app, d, f"Log in to upload {source}: what changes is shown first.")
    if not login:
        return
    _busy[d.key] = "uploading config"
    try:
        app.status.text = f"Reading the config of {d.ip} to compare…"
        try:
            current, _pending = await _work(devicetools.read_device_config, login, kind)
            tools = await _work(devicetools.config_tools, login, kind)
        except (sshrun.SSHError, devicetools.ToolError) as e:
            app.status.text = f"{d.ip}: {e}"
            await app.main_window.dialog(toga.ErrorDialog("Upload config", str(e)))
            return
        app.status.text = ""
        choice = await _diff_window(app, d, kind, current, text, source, tools)
        if not choice:
            return
        apply = choice == "apply"
        progress = Progress(app, f"Uploading a config: {d.ip}", f"{_label(d)}: {source}")
        progress.no_cancel()
        outcome = {}

        def work():
            try:
                kept = devicetools.save_backup(d, current, kind, "before upload")
                app._from_worker(_refresh_backups, d)
                progress.show(f"Kept its current config as a backup ({kept.date}).")
                outcome["said"] = devicetools.push_config(login, kind, text, apply, report=progress.show)
            except (devicetools.ToolError, sshrun.SSHError, OSError) as e:
                outcome["error"] = str(e)

        await _work(work)
        message = outcome.get("said") or outcome.get("error", "")
        progress.finish(message)
        app.status.text = f"{d.ip}: {message}"
    finally:
        _busy.pop(d.key, None)


async def _diff_window(app, d, kind, current, text, source, tools):
    """What uploading the config changes on the device; "save", "apply" or None (cancelled)."""
    answer = app.loop.create_future()
    diff, changed = devicetools.config_diff(current, text)
    boot = "its boot config" if kind == "edgeos" else "flash"
    heading = (f"{source} → {_label(d)}: {changed} line(s) change." if changed
               else f"{source} → {_label(d)}: no differences, the device has this config already.")
    note = (f"Save writes it to {boot}: it takes effect at the next reboot. Apply now also applies it: the device "
            "restarts what the changes affect, and the connection to it can drop for a moment. Either way the "
            "device's current config is kept as a backup first.")
    note += f"\n{terms.RISKS['upload']} {terms.RISKS['apply' if tools['apply'] else 'save']} {terms.TESTED}"
    if tools["why"]:
        note += f"\n{tools['why']}"

    def finish(choice):
        if not answer.done():
            answer.set_result(choice)
            window.close()

    def closing(widget, **kwargs):
        if not answer.done():
            answer.set_result(None)
        return True

    view = toga.MultilineTextInput(readonly=True, value=diff or "(no differences)",
                                   style=Pack(flex=1, font_family="monospace", font_size=11))
    size = (900, 640)
    window = toga.Window(title=f"Upload config: {d.ip}", size=size, on_close=closing, position=app._over_main(size))
    window.content = toga.Box(style=Pack(direction=COLUMN, margin=12, gap=8), children=[
        toga.Label(_fill(heading, 118)), view, toga.Label(_fill(note, 118)),
        toga.Box(style=Pack(direction=ROW, gap=8), children=[
            toga.Box(style=Pack(flex=1)),
            toga.Button("Cancel", on_press=lambda w: finish(None)),
            toga.Button(f"Save ({'next boot' if kind == 'edgeos' else 'to flash'})", on_press=lambda w: finish("save"),
                        enabled=tools["save"]),
            toga.Button("Apply now", on_press=lambda w: finish("apply"), enabled=tools["apply"])])])
    app._show_over_main(window)
    app.cancel_ssh_login = lambda: finish(None)
    try:
        return await answer
    finally:
        app.cancel_ssh_login = None


# ---------------------------------------------------------------------------
# Reboot and Locate
# ---------------------------------------------------------------------------

async def reboot_flow(app, d):
    if _busy.get(d.key):
        return
    hops = route(app, d)
    text = (f"{_label(d)} restarts and is offline for a minute or two, longer for some models: whatever goes "
            "through it stops meanwhile.")
    if hops:
        text += f" It's reached through {_through(hops)}."
    text += "\n\n" + terms.risk("reboot")
    if not await app.main_window.dialog(toga.QuestionDialog(f"Reboot {d.ip}?", text)):
        return
    login = await ask_route(app, d, "Log in to reboot it.")
    if not login:
        return
    _busy[d.key] = "rebooting"
    try:
        progress = Progress(app, f"Reboot: {d.ip}", _label(d))
        outcome = {}

        def work():
            try:
                outcome["took"] = devicetools.reboot(login, d, report=progress.show, stop=progress.stop)
            except (devicetools.ToolError, sshrun.SSHError) as e:
                outcome["error"] = str(e)

        await _work(work)
        message = outcome.get("error") or f"Rebooted: back after {outcome['took']:.0f} s."
        progress.finish(message)
        app.status.text = f"{d.ip}: {message}"
    finally:
        _busy.pop(d.key, None)


async def locate_flow(app, d):
    """Blink its LED until stopped: here, or later with Stop locating."""
    login = _locating.get(d.key)
    if login is not None:
        try:
            await _work(devicetools.locate, login, d, False)
        except (devicetools.ToolError, sshrun.SSHError) as e:
            app.status.text = f"Stop locating {d.ip}: {e}"
            return
        _locating.pop(d.key, None)
        app.status.text = f"{d.ip}: its LED is back to normal."
        return
    login = await ask_route(app, d, "Log in to blink its LED.")
    if not login:
        return
    try:
        state = await _work(devicetools.locate, login, d, True)
    except (devicetools.ToolError, sshrun.SSHError) as e:
        app.status.text = f"Locate {d.ip}: {e}"
        await app.main_window.dialog(toga.ErrorDialog("Locate", str(e)))
        return
    _locating[d.key] = login
    said = "" if state else (" It doesn't say it's locating: it may be busy (upgrading)." if state is False
                             else " It doesn't say whether it took.")
    app.status.text = f"{d.ip}: its LED is blinking.{said}"
    if await app.main_window.dialog(toga.QuestionDialog(
            "Locating", f"{_label(d)}'s LED is blinking.{said}\n\nStop it now? (No keeps it blinking: Stop locating, "
                        "in its menu, stops it later.)")):
        await locate_flow(app, d)


# ---------------------------------------------------------------------------
# Scan from a device given by its address
# ---------------------------------------------------------------------------

async def scan_address(app):
    """Scan from device with none selected: log in to a device by its address (one the scan
    didn't find, over a VPN say), list it, and what it sees under it."""
    if app.running or app.rescanning or app.finding:
        app.status.text = "Works once the scan has finished."
        return
    if not sshrun.available():
        app.status.text = "Scan from device needs ssh and scp."
        return
    ip, port = "", 22
    user, password, remember, problem = app.settings.get("ssh_user") or "", "", False, ""
    while True:
        answer = await _address_window(app, ip, port, user, password, remember, problem)
        if answer is None:
            return
        ip, port, user, password, remember = answer
        known = app.result.inv.find(ip=ip) if app.result else None
        login = sshrun.Login(ip, port, user, password, terminal.host_key_alias(known.mac if known else None, ip),
                             app.known_hosts)
        app.status.text = f"Logging in to {login.where}…"
        try:
            await _work(sshrun.check_login, login)
            break
        except sshrun.SSHError as e:
            app.status.text = problem = str(e)
    if app.running or app.rescanning or app.finding:
        app.status.text = "A scan started meanwhile: Scan from device again once it has finished."
        return
    result = app.result or _empty_result()
    app.spinner.start()
    app.status.text = f"Reading what {ip} sees…"
    try:
        def work():
            return devicetools.scan_from_address(result, login, core.local_macs())

        try:
            finder, sightings, seen, new = await _work(work)
        except (sshrun.SSHError, devicetools.ToolError) as e:
            app.status.text = f"Scan from {ip}: {e}"
            return
    finally:
        app.spinner.stop()
    if app.result is None and not app.running:
        app.result = result  # the table's devices from now on, as a scan's would be
        app.export_button.enabled = True
    elif result is not app.result:
        app.status.text = f"Scan from {ip} finished after a new scan started: start it again."
        return
    app._show_devices(result.devices)
    if not finder.ubnt_packets:  # what it is: UBNT discovery sent straight to it, as Rescan device does
        key = finder.key
        await _reread(app, finder)
        finder = (result.inv.find(mac=finder.mac) if finder.mac else None) or result.inv.find(ip=ip) or finder
        devicetools.relink(result, key, finder)
        app._show_devices(result.devices)
    app.settings["ssh_user"] = user
    if remember and credstore.available():
        if finder.mac and credstore.save(finder.mac, user, password):
            _logins(app)[finder.mac] = {"user": user, "port": port}
        elif not finder.mac:
            app._append_log(f"{ip}'s login isn't remembered: the app didn't learn its MAC address, which it's filed "
                            "under.")
    app._save_settings()
    _report_scan(app, finder, sightings, seen, new)
    await warn_factory_login(app, finder, login)


def _empty_result():
    """A scan result with nothing in it yet, for devices added before any scan has run."""
    return core.ScanResult(core.parse_args([]), [], [], [], [], [], [], core.Inventory(), None, 0.0)


async def _address_window(app, ip, port, user, password, remember, problem):
    answer = app.loop.create_future()
    ip_box = toga.TextInput(value=ip, placeholder="e.g. 10.20.0.1", style=Pack(flex=1))
    port_box = toga.TextInput(value=str(port), style=Pack(width=80))
    user_box = toga.TextInput(value=user, placeholder="e.g. ubnt or admin", style=Pack(flex=1))
    password_box = toga.PasswordInput(value=password, style=Pack(flex=1))
    trouble = toga.Label(_fill(problem, 46), style=Pack(flex=1))
    can_remember = credstore.available()
    keep = toga.Switch(f"Remember for this device (in {credstore.store_name()})", value=remember and can_remember,
                       enabled=can_remember)

    def finish(ok):
        if answer.done():
            return
        if ok:
            address, text = ip_box.value.strip(), port_box.value.strip()
            if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", address) or not core._usable_ip(address):
                trouble.text = _fill("The address is an IPv4 address, such as 10.20.0.1.", 46)
                return
            if not text.isdigit() or not 0 < int(text) < 65536:
                trouble.text = _fill("The port is a number from 1 to 65535.", 46)
                return
            if not user_box.value.strip():
                trouble.text = "Logging in needs a username."
                return
            answer.set_result((address, int(text), user_box.value.strip(), password_box.value, keep.value))
        else:
            answer.set_result(None)
        window.close()

    def closing(widget, **kwargs):
        if not answer.done():
            answer.set_result(None)
        return True

    password_box.on_confirm = lambda widget: finish(True)
    user_box.on_confirm = lambda widget: password_box.focus()
    ip_box.on_confirm = lambda widget: user_box.focus()
    label = Pack(width=80)
    row = Pack(direction=ROW, align_items="center", gap=8)
    size = (580, 340)
    window = toga.Window(title="Scan from a device", size=size, resizable=False, on_close=closing,
                         position=app._over_main(size))
    window.content = toga.Box(style=Pack(direction=COLUMN, margin=14, gap=8), children=[
        toga.Label(_fill("Log in to a device by its address, one the scan didn't find (over a VPN, say), to list "
                         "what it sees: its ARP table, LLDP neighbours and, on airOS, its stations. They're listed "
                         "under it, and the device tools reach them through it.", 74)),
        toga.Box(style=row, children=[toga.Label("Address", style=label), ip_box]),
        toga.Box(style=row, children=[toga.Label("Port", style=label), port_box, trouble]),
        toga.Box(style=row, children=[toga.Label("Username", style=label), user_box]),
        toga.Box(style=row, children=[toga.Label("Password", style=label), password_box]),
        keep,
        toga.Box(style=Pack(direction=ROW, gap=8), children=[
            toga.Box(style=Pack(flex=1)),
            toga.Button("Cancel", on_press=lambda w: finish(False)),
            toga.Button("Log in and scan", on_press=lambda w: finish(True))])])
    app._show_over_main(window)
    ip_box.focus()
    app.cancel_ssh_login = lambda: finish(False)
    try:
        return await answer
    finally:
        app.cancel_ssh_login = None
