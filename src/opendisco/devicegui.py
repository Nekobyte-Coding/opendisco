"""The device tools' windows (desktop only): firmware check and update, the config editor, config
backups (list, compare, restore, upload with a diff first, back up all), reboot, locate, the new
login, Scan from device (also from an address, for a device not in the table), link health
(airMAX: into Details), and the login window they share, which can remember a device's login in
the operating system's credential store. The work itself is opendisco.devicetools, run in worker
threads.

app.py only lists the actions in DEVICE_ACTIONS and calls menu_state(), act(), scan_address() and
back_up_all().
"""
import asyncio
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import webbrowser
from pathlib import Path

import toga
from toga.sources import AccessorColumn
from toga.style import Pack
from toga.style.pack import COLUMN, ROW

from opendisco import core, credstore, devicetools, i18n, linkhealth, terminal, terms
from opendisco.devicetools import sshrun  # the system's ssh and scp, or without them the app's own (phonessh)
from opendisco.i18n import N_, _, tr

ACTIONS = ("scan_from", "fw_check", "fw_update", "config", "login", "backup", "backups", "upload", "reboot", "locate",
           "forget_login", "link")
_busy: dict = {}  # device key -> what's running on it
_in_use: dict = {}  # downloaded firmware path -> updates using it
_locating: dict = {}  # device key -> the login its LED was set blinking with
_backup_windows: dict = {}  # MAC -> its open Config backups window
_backup_all = None  # the Back up all configs window, while it's open


ROUTED = ("ssh", "ping", "web", "rescan", "find_http", "find_https", "find_ssh", "all_ports")


def route(app, d) -> list:
    """The devices on the way to d, the nearest to this computer first (Inventory.route)."""
    return app.result.inv.route(d) if app.result else []


def handles(app, d, name: str) -> bool:
    """Whether this module does the action: the device tools, and for a device behind other
    devices, the app's own SSH, ping, web UI and port actions too."""
    return name in ACTIONS or (name in ROUTED and bool(route(app, d)))


def menu_state(app, d, titles: dict) -> dict:
    """{action: (title, enabled)} for the device tools, and for a device behind others, the
    app's own actions that reach it through them."""
    state = {}
    hops = route(app, d)  # (the parentheses stay outside the translations: app.py looks for "(")
    via = f"  ({tr('via {route}', route=' → '.join(h.ip or h.mac for h in hops))})" if hops else ""
    tools = not app.caps["mobile"] and sshrun.available()
    busy = _busy.get(d.key)
    ubiquiti = bool(d.info.get("firmware") or d.info.get("platform"))
    state["fw_check"] = (titles["fw_check"], ubiquiti and not busy)
    for name, action in (("scan_from", "scan"), ("fw_update", "update"), ("config", "edit"), ("login", "login"),
                         ("backup", "backup"), ("upload", "upload"), ("reboot", "reboot"), ("locate", "locate"),
                         ("link", "link")):
        offered, why = devicetools.offers(d, action)
        title = _("Stop locating (LED)") if name == "locate" and d.key in _locating else titles[name]
        if busy:
            title += f"  ({_(busy)})"
        elif not offered:
            title += f"  ({why})"
        elif not tools:
            title += f"  ({_('needs ssh and scp')})"
        if offered and not busy:
            title += via
        state[name] = (title, bool(d.ip) and offered and tools and not busy)
    if not hops and not ssh_here() and not (app.term and app.term.find(d.key, "ssh")):
        state["ssh"] = (titles["ssh"] + f"  ({_('needs ssh')})", False)
    idle = bool(app.result) and not (app.running or app.rescanning or app.finding)
    if hops:
        reach = bool(d.ip) and tools and all(h.ip for h in hops)
        for name in ("ssh", "ping", "web"):
            state[name] = (titles[name] + via, reach)
        for name in ("find_http", "find_https", "find_ssh", "all_ports"):
            state[name] = (titles[name] + via, reach and idle)
        state["rescan"] = (titles["rescan"] + "  (" + _("discovery can't travel over SSH") + ")", False)
    if state["scan_from"][1] and not idle:  # it adds to the scan's results
        state["scan_from"] = (titles["scan_from"], False)
    state["forget_login"] = (titles["forget_login"], bool(d.mac and _remembered(app, d)))
    kept = len(devicetools.list_backups(d.mac)) if d.mac else 0
    state["backups"] = (titles["backups"] + (f"  ({tr('{count} kept', count=kept)})" if kept else ""),
                        bool(d.mac and (kept or state["backup"][1])))  # filed by MAC: none without one
    return state


def ssh_here() -> bool:
    """Whether this computer can open SSH sessions: with its ssh, or the app's own SSH client."""
    return devicetools.OWN_SSH or bool(shutil.which("ssh"))


def act(app, d, name: str) -> None:
    flow = {"scan_from": scan_flow, "fw_check": check_flow, "fw_update": update_flow, "config": config_flow,
            "login": login_flow, "backup": backup_flow, "backups": backups_flow, "upload": upload_flow,
            "reboot": reboot_flow, "locate": locate_flow, "link": link_flow, "ssh": routed_ssh, "ping": routed_ping,
            "web": routed_web}.get(name)
    if name in ("find_http", "find_https", "find_ssh", "all_ports"):
        kind = {"find_http": "http", "find_https": "https", "find_ssh": "ssh", "all_ports": "all"}[name]
        flow = lambda app, d: routed_find(app, d, kind)  # noqa: E731
    if flow:
        asyncio.create_task(_guarded(app, d, flow))
    elif name == "forget_login":
        asyncio.create_task(forget_login(app, d))


async def _guarded(app, d, flow):
    try:
        await flow(app, d)
    except Exception as e:  # a bug, not the device: say so rather than fail silently
        app._append_log(traceback.format_exc())
        await app.main_window.dialog(toga.ErrorDialog(_("Something went wrong"), f"{type(e).__name__}: {e}"))


async def _work(fn, *args):
    return await asyncio.get_running_loop().run_in_executor(None, fn, *args)


def _label(d) -> str:
    return f"{d.ip}  {d.name or d.model or d.mac or ''}".strip()


def _fill(text: str, width: int) -> str:
    """Labels don't wrap by themselves (Windows' and macOS's alike): each paragraph broken to
    `width` characters, so it stays inside its window."""
    return "\n".join(i18n.fill(part, width) if part.strip() else "" for part in str(text).split("\n"))


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
        login = await ask_login(app, hop, i18n.sentences(tr("Device {number} of {total} on the way to {ip}.", number=n,
                                                            total=len(hops), ip=d.ip), purpose), via)
        if not login:
            return None
        via += (login,)
    if hops_only:
        return via
    if hops:
        purpose = i18n.sentences(purpose, tr("Through {route}: each device on the way adds latency.",
                                             route=" → ".join(h.ip for h in hops)))
    return await ask_login(app, d, purpose, via)


async def forget_login(app, d) -> None:
    _logins(app).pop(d.mac, None)
    app._save_settings()
    gone = await _work(credstore.forget, d.mac)
    app.status.text = (tr("Forgot the saved login for {device}.", device=d.ip or d.mac) if gone
                       else tr("Forgot the saved username for {device}; {store} had no password for it.",
                               device=d.ip or d.mac, store=credstore.store_name()))


async def ask_login(app, d, purpose: str, via: tuple = ()) -> sshrun.Login | None:
    """Ask for the username, password and port, then log in once to check them. Remembers or
    forgets the login as the checkbox says, once it has worked. None when cancelled. (The
    credential store is asked from a worker thread: it can wait up to a minute to be unlocked.)"""
    saved = _remembered(app, d)
    can_remember = await _work(credstore.available)  # (asked once; _login_window reads the answer kept)
    password = await _work(credstore.load, d.mac) if saved and can_remember else None
    user = (saved or {}).get("user") or app.settings.get("ssh_user") or ""
    port = int((saved or {}).get("port") or d.port("ssh"))
    problem, remember = "", bool(saved)
    while True:  # until it works or is cancelled, keeping what was typed and ticked
        answer = await _login_window(app, d, purpose, user, password or "", port, remember, problem)
        if answer is None:
            return None
        user, password, port, remember = answer
        login = _login(app, d, user, password, port, via)
        app.status.text = tr("Logging in to {where}…", where=login.where)
        try:
            await _work(sshrun.check_login, login)
        except sshrun.SSHError as e:
            app.status.text = str(e)
            problem = str(e)
            continue
        app.status.text = tr("Logged in to {ip} as {user}.", ip=d.ip, user=user)
        if remember and d.mac and can_remember:
            if await _work(credstore.save, d.mac, user, password):
                _logins(app)[d.mac] = {"user": user, "port": port}
            else:
                app.status.text = tr("Logged in, but {store} didn't take the password.", store=credstore.store_name())
        elif saved and not remember:
            _logins(app).pop(d.mac, None)
            await _work(credstore.forget, d.mac)
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
                _("Factory login"), f"{_label(d)}\n\n{core.factory_login_text(login.user, login.password)}"))


async def _login_window(app, d, purpose, user, password, port, remembered, problem):
    answer = app.loop.create_future()
    user_box = toga.TextInput(value=user, placeholder=_("e.g. ubnt or admin"), style=Pack(flex=1))
    password_box = toga.PasswordInput(value=password, style=Pack(flex=1))
    port_box = toga.TextInput(value=str(port), style=Pack(width=80))
    trouble = toga.Label(_fill(problem, 46), style=Pack(flex=1))
    can_remember = bool(d.mac) and credstore.available()
    remember = toga.Switch(tr("Remember for this device (in {store})", store=credstore.store_name()),
                           value=remembered and can_remember, enabled=can_remember)

    def finish(ok):
        if answer.done():
            return
        if ok:
            text = port_box.value.strip()
            if not user_box.value.strip():
                trouble.text = _("The device tools need a username.")
                return
            if not text.isdigit() or not 0 < int(text) < 65536:
                trouble.text = _fill(_("The port is a number from 1 to 65535."), 46)
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
    note = i18n.sentences(
        _("The password goes only to the device.") if devicetools.OWN_SSH
        else _("The password goes only to ssh and scp."),
        tr("Remembered logins are kept in {store}, never in a file.", store=credstore.store_name()) if can_remember
        else _("This computer has no credential store the app can use, so it isn't remembered."))
    size = (560, 300)
    window = toga.Window(title=tr("Log in to {ip}", ip=d.ip), size=size, resizable=False, on_close=closing,
                         position=app._over_main(size))
    window.content = toga.Box(style=Pack(direction=COLUMN, margin=14, gap=8), children=[
        toga.Label(_label(d)),
        toga.Label(_fill(purpose, 72)),
        toga.Box(style=row, children=[toga.Label(_("Username"), style=label), user_box]),
        toga.Box(style=row, children=[toga.Label(_("Password"), style=label), password_box]),
        toga.Box(style=row, children=[toga.Label(_("Port"), style=label), port_box, trouble]),
        remember,
        toga.Label(_fill(note, 72)),
        toga.Box(style=Pack(direction=ROW, gap=8), children=[
            toga.Box(style=Pack(flex=1)),
            toga.Button(_("Cancel"), on_press=lambda w: finish(False)),
            toga.Button(_("Log in"), on_press=lambda w: finish(True))])])
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
        self.button = toga.Button(_("Cancel"), on_press=self._pressed)
        size = (640, 360)
        self.window = toga.Window(title=title, size=size, closable=False, position=app._over_main(size))
        self.window.content = toga.Box(style=Pack(direction=COLUMN, margin=14, gap=8), children=[
            self.heading, self.step, self.bar, self.log,
            toga.Box(style=Pack(direction=ROW, gap=8), children=[toga.Box(style=Pack(flex=1)), self.button])])
        app._show_over_main(self.window)

    def _pressed(self, widget, **kwargs):
        if self.button.text == _("Cancel"):
            self.stop.set()
            self.button.enabled = False
            self.show(_("Cancelling…"))
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
        self.button.text, self.button.enabled = _("Close"), True


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
    login = await ask_route(app, d, _("Log in to read what it sees: its ARP table and LLDP neighbours and the stations "
                                      "associated with it.") if fam == "airos"
                            else _("Log in to read what it sees: its ARP table and LLDP neighbours."))
    if not login:
        return
    _busy[d.key] = N_("scanning")  # (shown translated; devicetools compares them in English)
    app.spinner.start()
    app.status.text = tr("Reading what {ip} sees…", ip=d.ip)
    try:
        def work():
            return devicetools.parse_scan(devicetools.read_scan(login, fam)), core.local_macs()

        try:
            sightings, local = await _work(work)
        except sshrun.SSHError as e:
            app.status.text = tr("Scan from {ip}: {error}", ip=d.ip, error=e)
            return
    finally:
        _busy.pop(d.key, None)
        app.spinner.stop()
    if result is not app.result:  # a new scan started meanwhile
        app.status.text = tr("Scan from {ip} finished after a new scan started: start it again.", ip=d.ip)
        return
    seen, new = devicetools.merge_scan(result, d, sightings, local)
    app._show_devices(result.devices)
    _report_scan(app, d, sightings, seen, new)


def _report_scan(app, d, sightings, seen, new):
    """What a scan from a device found, in the log and the status line."""
    counts = ", ".join(f"{_(devicetools.SCAN_HOW[how])} {n}" for how in devicetools.SCAN_HOW
                       if (n := sum(1 for s in sightings if s.how == how)))
    lines = [tr("Scan from {ip} ({name}): {counts}; {count} device(s), {new} new.", ip=d.ip,
                name=d.name or d.model or d.mac, counts=counts or _("nothing listed"), count=len(seen), new=len(new))]
    for dev in seen:
        how = sorted({_(devicetools.SCAN_HOW[s.how]) for s in sightings
                      if (s.mac and dev.mac == core.norm_mac(s.mac)) or (s.ip and s.ip in dev.ips)})
        lines.append(f"  {dev.ip or '-':15} {dev.mac or '-':17} {dev.name or dev.model or dev.vendor or '':24} "
                     f"{', '.join(how)}{'  ' + _('(new)') if dev in new else ''}")
    app._append_log("\n".join(lines))
    app.status.text = lines[0]
    selected = app._selected_device()
    if selected is not None:
        app.details.value = core.render_details(selected)


# ---------------------------------------------------------------------------
# Link health (airMAX)
# ---------------------------------------------------------------------------

async def link_flow(app, d):
    """Read a radio's link health (linkhealth): its own link, and each station's on an access
    point, into Details' Link section, with weak links flagged and said in the Log."""
    if _busy.get(d.key):
        return
    login = await ask_route(app, d, _("Log in to read its link health: signal, noise floor, SNR, capacity, airtime "
                                      "and distance, its own and, on an access point, each station's."))
    if not login:
        return
    _busy[d.key] = N_("reading its link")
    app.spinner.start()
    app.status.text = tr("Reading the link health of {ip}…", ip=d.ip)
    try:
        try:
            reading = await _work(devicetools.read_link, login)
        except (sshrun.SSHError, devicetools.ToolError) as e:
            app.status.text = tr("Link health of {ip}: {error}", ip=d.ip, error=e)
            return
    finally:
        _busy.pop(d.key, None)
        app.spinner.stop()
    linkhealth.keep(d, reading)
    app._rediagnose()  # its issues, in the list and Details (at the end of a scan that's running)
    if app._selected_device() is d:
        app.details.value = core.render_details(d)
        app.tabs.current_tab = _("Details")  # the tab's title, as app.py names it
    found = [f"  [{tag}] {msg}" for _, tag, msg in linkhealth.issues(d)]
    app._append_log("\n".join([linkhealth.summary(d)] + found), status=False)
    app.status.text = linkhealth.summary(d)


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
    login = await ask_route(app, d, _("Log in for an SSH session."))
    if not login:
        return
    title = tr("{ip}  SSH {user}@ via {route}  {name}", ip=d.ip, user=login.user,
               route=sshrun.route_text(login) or _("direct"), name=d.name or d.model or "").rstrip()
    if not login.via:
        title = tr("{ip}  SSH {user}@port {port}  {name}", ip=d.ip, user=login.user, port=login.port,
                   name=d.name or d.model or "").rstrip()
    if devicetools.OWN_SSH:  # (it goes through the last hop's own client by itself where it must)
        app._show_terminal(app.term.open_own(d.key, "ssh", title, login))
        return
    if login.nested:  # a device on the way doesn't forward: a session on the last hop's own client
        argv = sshrun.ssh_command(sshrun.last_hop(login), sshrun.nested_command(login, None), "-tt")
    else:
        argv = sshrun.ssh_command(login, None)
    app._show_terminal(app.term.open(d.key, "ssh", title, argv, login.passwords))


async def routed_ping(app, d):
    session = app.term.find(d.key, "ping")
    if session:
        if not session.alive:
            session.type(b"\r")
        app._show_terminal(session)
        return
    hops = await ask_route(app, d, tr("Log in to ping {ip} from the device before it.", ip=d.ip), hops_only=True)
    if hops is None:
        return
    if not hops:  # reachable from here
        app._open_ping(d)
        return
    last = hops[-1]  # the last device on the way, its login already through the ones before it
    title = tr("{ip}  ping from {via}  {name}", ip=d.ip, via=last.ip, name=d.name or d.model or "").rstrip()
    if devicetools.OWN_SSH:
        app._show_terminal(app.term.open_own(d.key, "ping", title, last, command=f"ping {d.ip}"))
        return
    app._show_terminal(app.term.open(d.key, "ping", title, sshrun.ssh_command(last, f"ping {d.ip}", "-tt"),
                                     last.passwords))


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
        app.status.text = tr("Opened {url} (forwarded to {ip}:{port}).", url=session.url, ip=d.ip, port=port)
        return
    hops = await ask_route(app, d, tr("Log in to forward {ip}'s web UI to this computer.", ip=d.ip),
                           hops_only=True)
    if hops is None:
        return
    if not hops:
        webbrowser.open(url.geturl())
        app.status.text = tr("Opened {url}", url=url.geturl())
        return
    last, local = hops[-1], _free_port()
    if not any(kind in ("https", "http") for kind in d.services.values()):
        # This computer can't check its ports: the device before it looks for a web server.
        candidates = list(dict.fromkeys([port, 443, 80, 8443, 8080]))
        try:
            out = (await _work(lambda: sshrun.run(last, "for p in " + " ".join(map(str, candidates)) +
                                                  f"; do nc -z -w1 {d.ip} $p 2>/dev/null && echo $p && break; done"))).out
        except sshrun.SSHError as e:
            app.status.text = tr("Web UI of {ip}: {error}", ip=d.ip, error=e)
            return
        found = next((int(p) for p in out.split() if p.isdigit()), None)
        if found and found != port:
            port, url = found, urllib.parse.urlsplit(f"{'http' if found in (80, 8080) else 'https'}://{d.ip}:{found}/")
    target = f"{url.scheme}://127.0.0.1:{local}/"
    title = tr("{ip}  web UI via {route}  {url}", ip=d.ip, route=_through(hops), url=target)
    if devicetools.OWN_SSH:
        session = app.term.open_own(d.key, "web", title, last, forward=(local, d.ip, port))
    else:
        argv = sshrun.ssh_command(last, None, "-N", "-L", f"127.0.0.1:{local}:{d.ip}:{port}")
        session = app.term.open(d.key, "web", title, argv, last.passwords)
    session.url = target
    app.status.text = tr("Forwarding {url} to {ip}:{port} through {route}…", url=target, ip=d.ip, port=port,
                         route=_through(hops))
    if await _work(_wait_local, local, 30):
        webbrowser.open(target)
        app.status.text = tr("Opened {url}: forwarded to {ip}:{port} through {route} for as long as its session stays "
                             "open in the Terminal tab. Each device on the way adds latency.", url=target, ip=d.ip,
                             port=port, route=_through(hops))
    else:
        app._show_terminal(session)
        app.status.text = tr("The forward to {ip}:{port} didn't start: its session in the Terminal tab says why.",
                             ip=d.ip, port=port)


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
    hops = await ask_route(app, d, tr("Log in to search {ip}'s ports from the device before it.", ip=d.ip),
                           hops_only=True)
    if hops is None:
        return
    if not hops:
        app._find(d, kind)
        return
    last, result = hops[-1], app.result
    name = _(core.SERVICE_NAMES[kind])  # ("services"; protocol names stay)
    ports = core.search_order(kind, result.devices if result else ())
    app.finding = True
    app.start_button.enabled, app.stop_button.enabled = False, True
    app.spinner.start()
    core.STOP.clear()

    def work():
        if sshrun.run(last, f"nc -z -w1 127.0.0.1 {last.port}").code:
            raise devicetools.ToolError(tr("{via} has no nc that can check ports (nc -z), so {ip}'s ports can't be "
                                           "searched from it.", via=last.ip, ip=d.ip))
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
                             tr("{ip} (from {via}): checked {done:,} of {total:,} TCP ports for {service}, {open} "
                                "open…", ip=d.ip, via=last.ip, done=done, total=len(ports), service=name,
                                open=len(found)))
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
        app.status.text = tr("Port search on {ip}: {error}", ip=d.ip, error=error)
        return
    d.ports = sorted(set(d.ports or []) | set(found))
    for port, what in found.items():
        d.services.setdefault(port, what)
    if result is app.result:
        app._show_devices(result.devices)
        if app._selected_device() is d:
            app.details.value = core.render_details(d)
    listed = ", ".join(f"{p} {k}" for p, k in sorted(found.items())) or _("none")
    app.status.text = tr("{ip}, checked from {via}: open TCP ports {ports}.", ip=d.ip, via=last.ip, ports=listed)


# ---------------------------------------------------------------------------
# Firmware
# ---------------------------------------------------------------------------

async def _check(app, d) -> devicetools.Check | None:
    app.status.text = tr("Asking Ubiquiti's firmware server about {device}…", device=d.ip or d.mac)
    try:
        check = await _work(devicetools.check_firmware, d)
    except devicetools.ToolError as e:
        app.status.text = str(e)
        await app.main_window.dialog(toga.ErrorDialog(_("Firmware check"), str(e)))
        return None
    app.status.text = devicetools.summary(d, check).split("\n")[0]
    return check


async def check_flow(app, d):
    check = await _check(app, d)
    if check is None:
        return
    text = devicetools.summary(d, check)
    title = tr("Firmware of {device}", device=_label(d))
    can = (check.newer and devicetools.offers(d, "update")[0] and not devicetools.fits(d, check.release)
           and bool(d.ip) and sshrun.available() and not _busy.get(d.key))
    if can and await app.main_window.dialog(toga.QuestionDialog(title, text + "\n\n" + _("Update it now?"))):
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
        await app.main_window.dialog(toga.InfoDialog(tr("Firmware of {device}", device=_label(d)),
                                                     devicetools.summary(d, check)))
        return
    why = devicetools.fits(d, check.release)
    if why:
        await app.main_window.dialog(toga.ErrorDialog(_("Firmware update"), why))
        return
    _busy[d.key] = N_("updating")
    try:
        login = await ask_route(app, d, tr("Log in to install firmware {version}.", version=check.latest))
        if not login:
            return
        family = devicetools.FAMILY_NAMES[devicetools.family(d)]
        message = tr("Install {family} firmware {version} on {device}? It runs {current} now.\n\nThe app downloads it "
                     "from Ubiquiti ({size}), checks it, copies it to the device and starts the installation. The "
                     "device restarts to install it and is offline for a few minutes: don't unplug it or turn it off "
                     "until it's back.", family=family, version=check.latest, device=_label(d), current=check.current,
                     size=devicetools.fmt_size(check.size))
        if devicetools.family(d) == "edgeos":
            app.status.text = tr("Reading the firmware images of {ip}…", ip=d.ip)
            try:
                note = await _work(devicetools.edgeos_update_note, login, check.latest)
            except (devicetools.ToolError, sshrun.SSHError) as e:
                app.status.text = tr("Firmware update of {ip}: {error}", ip=d.ip, error=e)
                await app.main_window.dialog(toga.ErrorDialog(_("Firmware update"), str(e)))
                return
            message = tr("Install EdgeOS firmware {version} on {device}? It runs {current} now.\n\nThe app downloads "
                         "it from Ubiquiti ({size}), checks it, copies it to the router and adds it with EdgeOS's add "
                         "system image. Once EdgeOS lists it as the image it boots, the app restarts the router, which "
                         "is offline for a few minutes: don't unplug it or turn it off until it's back.",
                         version=check.latest, device=_label(d), current=check.current,
                         size=devicetools.fmt_size(check.size)) + f"\n\n{note}"
        if devicetools.family(d) in ("unifi", "unifi-os"):
            message += "\n\n" + _("Ubiquiti's help center describes updating over SSH as a last resort, for when the "
                                  "UniFi app can't update the device.")
        message += "\n\n" + terms.risk("firmware")
        if not await app.main_window.dialog(toga.QuestionDialog(_("Install firmware?"), message)):
            return
        await _install(app, d, check, login)
    finally:
        _busy.pop(d.key, None)


async def _install(app, d, check, login):
    progress = Progress(app, tr("Firmware update: {ip}", ip=d.ip), f"{_label(d)}: {check.current} → {check.latest}")
    folder = Path(app.paths.cache) / "firmware"
    outcome = {}

    def work():
        path = None
        try:
            progress.show(tr("Downloading firmware {version} from Ubiquiti…", version=check.latest), 0)
            path = devicetools.download_release(
                check.release, folder, stop=progress.stop,
                progress=lambda done, total: progress.show(None, 100 * done / total if total else None))
            _in_use[path] = _in_use.get(path, 0) + 1
            progress.show(tr("Downloaded and checked (SHA-256 {checksum}…).",
                             checksum=check.release["sha256_checksum"][:16]), 100)

            def report(text, percent):
                if text and (text in map(_, devicetools.INSTALL_STARTS)):
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
        if progress.stop.is_set() and ("Cancelled" in text or _("Cancelled.") in text):  # (ToolError's, translated)
            text = _("Cancelled. Nothing was installed.")
        progress.finish(text)
        app.status.text = tr("Firmware update of {ip}: {error}", ip=d.ip, error=text)
        return
    text = tr("Back after {seconds:.0f} s.", seconds=outcome["offline"])
    progress.finish(i18n.sentences(text, _("Reading its firmware again…")))
    now = await _reread(app, d)
    if now is None:
        text = i18n.sentences(text, _("Rescan it to see the version it runs."))
    elif devicetools.version_key(now) == devicetools.version_key(check.latest):
        text = i18n.sentences(tr("Updated: it runs {version}.", version=now), text)
    else:
        text = i18n.sentences(tr("It's back, but reports firmware {version}, not {latest}.",
                                 version=now or _("unknown"), latest=check.latest), text)
    progress.finish(text)
    app.status.text = f"{d.ip}: {text}"


async def _reread(app, d) -> str | None:
    """Rescan the device for the firmware it reports now; None when a scan is busy or it didn't answer."""
    found = await app.reread(d)
    return devicetools.device_version(found[0]) if found and found[1] else None


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

async def config_flow(app, d):
    kind = devicetools.config_kind(d)
    login = await ask_route(app, d, tr("Log in to read its configuration ({file}).",
                                       file=devicetools.CONFIG_FILES[kind]))
    if not login:
        return
    app.status.text = tr("Reading the config of {ip}…", ip=d.ip)
    try:
        text, pending = await _work(devicetools.read_device_config, login, kind)
        tools = await _work(devicetools.config_tools, login, kind)
    except (sshrun.SSHError, devicetools.ToolError) as e:
        app.status.text = str(e)
        await app.main_window.dialog(toga.ErrorDialog(_("Config"), str(e)))
        return
    app.status.text = tr("Read the config of {ip}.", ip=d.ip)
    ConfigEditor(app, d, login, text, pending, kind, tools)


# Each kind of config's note, filled in with its file and the device's address (translated where it's shown)
ABOUT_CONFIG = {
    "airos": N_("{file} on {ip}: airOS's whole configuration, one setting per line.\nSave writes it to flash: it "
                "takes effect at the next reboot. Apply saves it and applies it now, the way the web UI's Apply does: "
                "the device restarts only what the changes affect, and the connection to it can drop for a moment."),
    "isp": N_("{file} on {ip}: its whole configuration, one setting per line.\nSave writes it to flash: it takes "
              "effect at the next reboot. Apply saves it and applies it now, the way the web UI's Apply does: the "
              "device restarts only what the changes affect, and the connection to it can drop for a moment."),
    "edgeos": N_("{file} on {ip}: EdgeOS's boot config (what it loads when it starts; changes committed since "
                 "without saving aren't in it).\nSave checks that EdgeOS reads it and makes it the boot config: it "
                 "takes effect at the next reboot. Apply loads it, commits and saves it, as configure; load; commit; "
                 "save do: EdgeOS restarts what the changes affect, and the connection can drop for a moment."),
}


class ConfigEditor:
    def __init__(self, app, d, login, text, pending, kind="airos", tools=None):
        self.app, self.d, self.login, self.kind = app, d, login, kind
        self.tools = tools or {"save": True, "apply": True, "why": ""}
        self.saved = text  # as the device has it
        self.box = toga.MultilineTextInput(value=text, style=Pack(flex=1, font_family="monospace", font_size=11))
        self.state = toga.Label("", style=Pack(flex=1))
        self.save_button = toga.Button(_("Save"), on_press=self.save)
        self.apply_button = toga.Button(_("Apply"), on_press=self.apply)
        self.buttons = [toga.Button(_("Reload"), on_press=self.reload), self.save_button, self.apply_button]
        about = _(ABOUT_CONFIG[kind]).format(file=devicetools.CONFIG_FILES[kind], ip=d.ip)
        if d.mac:
            about = i18n.sentences(about, _("Before writing, the app keeps the config it read as a backup (Config "
                                            "backups…)."))
        size = (900, 680)
        self.window = toga.Window(title=tr("Config: {device}", device=_label(d)), size=size, on_close=self.closing,
                                  position=app._over_main(size))
        self.window.content = toga.Box(style=Pack(direction=COLUMN, margin=12, gap=8), children=[
            toga.Label(_fill(about, 118)), self.box,
            toga.Box(style=Pack(direction=ROW, align_items="center", gap=8), children=[
                self.state, *self.buttons, toga.Button(_("Close"), on_press=lambda w: self.window.close())])])
        self._pending(pending)
        self._enable(True)
        app._show_over_main(self.window)

    def _pending(self, pending):
        self.state.text = _fill(_("It has changes that aren't applied yet (made in its web UI, or saved without "
                                  "applying).") if pending else self.tools["why"], 64)

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
        if await self.window.dialog(toga.QuestionDialog(_("Discard the changes?"),
                                                        _("The edits haven't been saved to the device."))):
            self.window.close()

    async def reload(self, widget, **kwargs):
        self._enable(False)
        self.state.text = _("Reading…")
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
            heading = (_("EdgeOS wouldn't read it:") if self.kind == "edgeos"
                       else _("airOS reads only key=value lines. These aren't:")) + "\n"
            await self.window.dialog(toga.ErrorDialog(_("Not a config"), heading + "\n".join(problems[:10])))
            return
        changed = devicetools.lines_changed(self.saved, text)
        edgeos, device = self.kind == "edgeos", _label(self.d)
        what = (tr("Apply the config on {device}?", device=device) if apply
                else tr("Save the config to its boot config on {device}?", device=device) if edgeos
                else tr("Save the config to flash on {device}?", device=device))
        detail = i18n.sentences(
            tr("{count} line(s) changed.", count=changed) if changed else _("Nothing changed in the editor."),
            (_("It's applied now and saved to its boot config; the device restarts what the changes affect.") if edgeos
             else _("It's applied now and saved to flash; the device restarts what the changes affect.")) if apply
            else _("It takes effect at the next reboot.")) + "\n\n" + terms.risk("apply" if apply else "save")
        if not await self.window.dialog(toga.QuestionDialog(what, detail)):
            return
        self._enable(False)
        self.state.text = _("Applying…") if apply else _("Saving…")
        say = lambda m: self.app._from_worker(setattr, self.state, "text", _fill(m, 64))  # noqa: E731

        def work():
            if self.d.mac:  # what it had, kept before it's replaced
                devicetools.save_backup(self.d, self.saved, self.kind, N_("before edit"))  # (shown translated)
                self.app._from_worker(_refresh_backups, self.d)
            return devicetools.push_config(self.login, self.kind, text, apply, report=say)

        try:
            message = await _work(work)
        except devicetools.LostConnection as e:  # what it means for the device, as far as it's known
            self.state.text = _fill(e, 64)
            self.app.status.text = f"{self.d.ip}: {e}"
            await self.window.dialog(toga.ErrorDialog(_("Connection lost"), str(e)))
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
    login = await ask_route(app, d, _("Log in with its current username and password first."))
    if not login:
        return
    kind = devicetools.config_kind(d)  # "airos" or "edgeos"
    if not login.password and kind == "airos":
        await app.main_window.dialog(toga.ErrorDialog(
            _("Change login"), _("Changing the login needs the current password (an SSH key isn't enough): the app "
                                 "checks it against the device's stored hash before writing a new one.")))
        return
    _busy[d.key] = N_("changing login")
    try:
        app.status.text = tr("Reading the config of {ip}…", ip=d.ip)
        try:
            if kind == "edgeos":
                text, _pending = await _work(devicetools.read_device_config, login, kind)
                pending = await _work(devicetools.edgeos_unsaved, login)
            else:
                text, pending = await _work(devicetools.read_config, login)
        except (sshrun.SSHError, devicetools.ToolError) as e:
            await app.main_window.dialog(toga.ErrorDialog(_("Change login"), str(e)))
            return
        answer = await _new_login_window(app, d, login, text)
        if not answer:
            return
        new_text, new_user, new_password, scheme = answer
        same, names = new_user == login.user, {"device": _label(d), "user": login.user, "new_user": new_user}
        if kind == "edgeos":
            message = (tr("Change the password of {user} on {device}? EdgeOS commits it right away and saves it to "
                          "its boot config; the old password stops working.", **names) if same
                       else tr("Change the login of {device} from {user} to {new_user} with the new password? EdgeOS "
                               "commits it right away and saves it to its boot config; the old login stops working.",
                               **names))
            if new_user != login.user:
                message += "\n\n" + tr("As Ubiquiti's help center does it, {new_user} is made first, with {user}'s "
                                       "level and settings, and the app logs in with it; only then is {user} deleted, "
                                       "logged in as {new_user}.", **names)
            message += "\n\n" + _("EdgeOS hashes the password itself and stores it so, never as plain text.")
            if pending:
                message += "\n\n" + _("Its config also has changes that are committed but not saved (in its CLI): "
                                      "saving the new login saves them too.")
        else:
            message = (tr("Change the password of {user} on {device}? It's applied right away and saved to flash; the "
                          "old login stops working.", **names) if same
                       else tr("Change the login of {device} from {user} to {new_user} with the new password? It's "
                               "applied right away and saved to flash; the old login stops working.", **names))
            message += "\n\n" + tr("The password is stored on the device as an {scheme} hash, the format it uses now.",
                                   scheme=scheme)
            if pending:
                message += "\n\n" + _("Its config also has changes that aren't applied yet (made in its web UI, or "
                                      "saved without applying): they're applied with it.")
        message += "\n\n" + terms.risk("login")
        if not await app.main_window.dialog(toga.QuestionDialog(_("Change login?"), message)):
            return
        new = sshrun.Login(login.ip, login.port, new_user, new_password, login.alias, login.known_hosts,
                           login.via, login.nested)
        progress = Progress(app, tr("Changing login: {ip}", ip=d.ip), f"{_label(d)}: {login.user} → {new_user}")
        progress.no_cancel()
        outcome = {}

        def work():
            try:
                if d.mac:  # what it had, kept before it's replaced
                    devicetools.save_backup(d, text, kind, N_("before login change"))
                    app._from_worker(_refresh_backups, d)
                if kind == "edgeos":  # new_text: the steps; it logs in with the new login itself
                    outcome["said"] = devicetools.change_edgeos_login(login, new, new_text, report=progress.show)
                    return
                outcome["said"] = devicetools.write_config(login, new_text, True, report=progress.show,
                                                           new_login=new)
                progress.show(_("Logging in with the new login…"))
                sshrun.check_login(new)
            except (devicetools.ToolError, sshrun.SSHError, OSError) as e:
                outcome["error"] = str(e)

        await _work(work)
        if "error" in outcome:
            progress.finish(outcome["error"] + "\n" + _("If the device no longer takes either login, its web UI or a "
                                                        "reset to factory defaults gets it back."))
            return
        if _remembered(app, d):
            await _work(credstore.save, d.mac, new_user, new_password)
            _logins(app)[d.mac] = {"user": new_user, "port": login.port}
            app._save_settings()
        devicetools.forget_factory_login(d)
        app._save_settings()
        app._rediagnose()
        progress.finish(i18n.sentences(tr("Done: {ip} takes the new login ({user}).", ip=d.ip, user=new_user),
                                       outcome["said"]) if kind == "edgeos"
                        else tr("Done: {ip} takes the new login ({user}), applied and saved to flash.", ip=d.ip,
                                user=new_user))
        app.status.text = tr("{ip}: the login is now {user}.", ip=d.ip, user=new_user)
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
                trouble.text = _("The two passwords differ.")
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
    window = toga.Window(title=tr("New login: {ip}", ip=d.ip), size=size, resizable=False, on_close=closing,
                         position=app._over_main(size))
    window.content = toga.Box(style=Pack(direction=COLUMN, margin=14, gap=8), children=[
        toga.Label(_label(d)),
        toga.Label(_fill(devicetools.new_login_note(d), 76)),
        toga.Box(style=row, children=[toga.Label(_("Username"), style=label), user_box]),
        toga.Box(style=row, children=[toga.Label(_("New password"), style=label), first]),
        toga.Box(style=row, children=[toga.Label(_("Again"), style=label), second]),
        trouble,
        toga.Box(style=Pack(direction=ROW, gap=8), children=[
            toga.Box(style=Pack(flex=1)),
            toga.Button(_("Cancel"), on_press=lambda w: finish(False)),
            toga.Button(_("Change"), on_press=lambda w: finish(True))])])
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
    login = await ask_route(app, d, tr("Log in to back up its config ({file}).", file=devicetools.CONFIG_FILES[kind]))
    if not login:
        return
    _busy[d.key] = N_("backing up")
    app.spinner.start()
    app.status.text = tr("Reading the config of {ip}…", ip=d.ip)
    try:
        def work():
            text, _pending = devicetools.read_device_config(login, kind)
            return devicetools.save_backup(d, text, kind, N_("backup"))

        try:
            backup = await _work(work)
        except (sshrun.SSHError, devicetools.ToolError, OSError) as e:
            app.status.text = tr("Backup of {ip}: {error}", ip=d.ip, error=e)
            await app.main_window.dialog(toga.ErrorDialog(_("Config backup"), str(e)))
            return
    finally:
        _busy.pop(d.key, None)
        app.spinner.stop()
    kept = len(devicetools.list_backups(d.mac))
    app._append_log(tr("Config backup of {device}: {detail}", device=_label(d), detail=backup.path))
    app.status.text = tr("Backed up the config of {ip} ({date}); {count} kept for it. Config backups… lists them.",
                         ip=d.ip, date=backup.date, count=kept)
    _refresh_backups(d)


async def compare_flow(app, d, backup, other=None):
    """What differs between two of the device's backups (the older first), or, with one, between
    it and the config the device has now, read over SSH; that one can then be kept as a backup."""
    kind = devicetools.config_kind(d) or str(backup.meta.get("kind") or "")
    try:
        old, new = backup.text(), other.text() if other is not None else None
    except OSError as e:
        await app.main_window.dialog(toga.ErrorDialog(_("Compare"), str(e)))
        return
    # The diff's own labels (in its --- and +++ lines) stay as they are
    names = (f"backup {backup.date}", f"backup {other.date}" if other is not None else "on the device now")
    if other is None:
        if _busy.get(d.key):
            app.status.text = tr("{ip} is {doing}: compare once that's done.", ip=d.ip, doing=_(_busy[d.key]))
            return
        login = await ask_route(app, d, tr("Log in to read its config ({file}) and compare it with the backup taken "
                                           "{date}.", file=devicetools.CONFIG_FILES[kind], date=backup.date))
        if not login:
            return
        _busy[d.key] = N_("reading its config")
        app.spinner.start()
        app.status.text = tr("Reading the config of {ip} to compare…", ip=d.ip)
        try:
            new = await _work(devicetools.read_current, login, kind)
        except (sshrun.SSHError, devicetools.ToolError) as e:
            app.status.text = f"{d.ip}: {e}"
            await app.main_window.dialog(toga.ErrorDialog(_("Compare"), str(e)))
            return
        finally:
            _busy.pop(d.key, None)
            app.spinner.stop()
        app.status.text = ""
    diff, changed = devicetools.config_diff(old, new, *names)
    dates = {"device": _label(d), "count": changed, "date": backup.date,
             "other": other.date if other is not None else ""}
    if other is None:
        heading = (tr("{device}: {count} line(s) differ between the backup {date} and the config on the device now.",
                      **dates) if changed else
                   tr("{device}: no differences between the backup {date} and the config on the device now.", **dates))
        note = tr("Lines marked - are only in the first (backup {date}), lines marked + only in the second (on the "
                  "device now); the ones around them are in both, for context.", **dates)
    else:
        heading = (tr("{device}: {count} line(s) differ between the backup {date} and the backup {other}.", **dates)
                   if changed else
                   tr("{device}: no differences between the backup {date} and the backup {other}.", **dates))
        note = tr("Lines marked - are only in the first (backup {date}), lines marked + only in the second (backup "
                  "{other}); the ones around them are in both, for context.", **dates)
    buttons = [(_("Close"), None, True)]
    if other is None:  # the config now can be kept, unless the last backup has it already
        latest = devicetools.list_backups(d.mac)
        same = bool(latest) and latest[0].holds(new)
        buttons.insert(0, (_("Same as its last backup") if same else _("Keep it as a backup"), "keep", not same))
    if await _diff_view(app, tr("Compare configs: {ip}", ip=d.ip), heading, diff, note, buttons) != "keep":
        return
    try:
        kept = devicetools.save_backup(d, new, kind, N_("backup"))
    except (OSError, devicetools.ToolError) as e:
        await app.main_window.dialog(toga.ErrorDialog(_("Config backup"), str(e)))
        return
    app._append_log(tr("Config backup of {device}: {detail}", device=_label(d), detail=kept.path))
    _refresh_backups(d)


async def backups_flow(app, d):
    window = _backup_windows.get(d.mac)
    if window is not None and not window.window.closed:
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
    """The configs kept for one device, the newest first, with the selected one's text; Compare
    shows what differs between two selected, or between one and the device's config now; Restore
    uploads one (after a diff), Save a copy writes it elsewhere."""

    def __init__(self, app, d):
        self.app, self.d = app, d
        self.backups = []
        # (headings translated; each column's accessor stays as the rows name it)
        self.table = toga.Table(columns=[AccessorColumn(_("Taken"), "taken"), AccessorColumn(_("Why"), "why"),
                                         AccessorColumn(_("Address"), "address"),
                                         AccessorColumn(_("Firmware"), "firmware"), AccessorColumn(_("Size"), "size")],
                                on_select=self.selected, multiple_select=True, style=Pack(flex=1))
        self.text = toga.MultilineTextInput(readonly=True, style=Pack(flex=2, font_family="monospace", font_size=11))
        self.state = toga.Label("", style=Pack(flex=1))
        offered = devicetools.offers(d, "backup")[0] and bool(d.ip) and sshrun.available()
        self.compare_button = toga.Button(_("Compare…"), on_press=self.compare, enabled=False)
        self.restore_button = toga.Button(_("Restore…"), on_press=self.restore, enabled=False)
        self.copy_button = toga.Button(_("Save a copy…"), on_press=self.save_copy, enabled=False)
        self.delete_button = toga.Button(_("Delete…"), on_press=self.delete, enabled=False)
        kind = devicetools.config_kind(d)
        about = tr("Copies of {file} kept for {mac} in {folder}. Compare shows what differs between two selected, or "
                   "between one and its config now. Restore uploads one to it again (the same model only), showing "
                   "what changes first and keeping its current config as a backup.",
                   file=devicetools.CONFIG_FILES.get(kind, _("its config")), mac=d.mac,
                   folder=devicetools.backup_folder(d.mac))
        size = (860, 620)
        self.window = toga.Window(title=tr("Config backups: {device}", device=_label(d)), size=size,
                                  on_close=self.closing, position=app._over_main(size))
        self.window.content = toga.Box(style=Pack(direction=COLUMN, margin=12, gap=8), children=[
            toga.Label(_fill(about, 112)), self.table, self.text,
            toga.Box(style=Pack(direction=ROW, align_items="center", gap=8), children=[
                self.state,
                toga.Button(_("Back up now"), on_press=self.backup_now, enabled=offered),
                self.compare_button, self.restore_button, self.copy_button, self.delete_button,
                toga.Button(_("Show folder"), on_press=lambda w: _show_folder(devicetools.backup_folder(d.mac))),
                toga.Button(_("Close"), on_press=lambda w: self.closing(w) and self.window.close())])])
        _backup_windows[d.mac] = self
        self.refresh()
        app._show_over_main(self.window)

    def closing(self, widget, **kwargs):
        _backup_windows.pop(self.d.mac, None)
        return True

    def refresh(self):
        self.backups = devicetools.list_backups(self.d.mac)
        self.table.data = [{"taken": b.date, "why": _(b.reason or "backup"), "address": b.meta.get("ip", ""),
                            "firmware": b.version,
                            "size": f"{b.path.stat().st_size:,} B", "backup": b} for b in self.backups]
        self.text.value = ""
        self.state.text = tr("{count} kept.", count=len(self.backups)) if self.backups else _("None kept yet.")
        self.selected(self.table)

    def _chosen(self) -> list:
        """The backups selected (several can be)."""
        return [row.backup for row in self.table.selection or [] if getattr(row, "backup", None) is not None]

    def _current(self):
        chosen = self._chosen()
        return chosen[0] if len(chosen) == 1 else None

    def selected(self, widget, **kwargs):
        chosen = self._chosen()
        backup = self._current()
        can = devicetools.offers(self.d, "upload")[0] and bool(self.d.ip) and sshrun.available()
        self.restore_button.enabled = backup is not None and can and not _busy.get(self.d.key)
        self.copy_button.enabled = self.delete_button.enabled = backup is not None
        reads = devicetools.offers(self.d, "backup")[0] and bool(self.d.ip) and sshrun.available()
        self.compare_button.text = (_("Compare the two…") if len(chosen) == 2 else _("Compare with its config now…")
                                    if len(chosen) == 1 and reads else _("Compare…"))
        self.compare_button.enabled = len(chosen) == 2 or (backup is not None and reads and not _busy.get(self.d.key))
        if backup is not None:
            try:
                self.text.value = backup.text()
            except OSError as e:
                self.text.value = tr("Can't read {path}: {error}", path=backup.path, error=e)
        else:
            self.text.value = (_("Two backups selected: Compare the two shows what differs between them.")
                               if len(chosen) == 2 else "")

    async def compare(self, widget, **kwargs):
        chosen = sorted(self._chosen(), key=lambda b: b.when)  # the older first
        if len(chosen) in (1, 2):
            await _guarded(self.app, self.d, lambda app, d: compare_flow(app, d, *chosen))

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
        path = await self.window.dialog(toga.SaveFileDialog(_("Save a copy of the config"), suggested_filename=name))
        if path:
            try:
                Path(path).write_bytes(backup.path.read_bytes())
            except OSError as e:
                await self.window.dialog(toga.ErrorDialog(_("Save a copy"), str(e)))
                return
            self.state.text = tr("Saved a copy as {path}.", path=path)

    async def delete(self, widget, **kwargs):
        backup = self._current()
        if backup is None or not await self.window.dialog(toga.QuestionDialog(
                _("Delete this backup?"), tr("The config taken {date} is deleted from {folder}.", date=backup.date,
                                             folder=backup.path.parent))):
            return
        try:
            devicetools.delete_backup(backup)
        except OSError as e:
            await self.window.dialog(toga.ErrorDialog(_("Delete"), str(e)))
        self.refresh()


# ---------------------------------------------------------------------------
# Back up all configs
# ---------------------------------------------------------------------------

def _saved_login(app, d, via: tuple = ()) -> sshrun.Login | None:
    """d's remembered login: its username and port from the settings, its password from the
    credential store. None when there's none. (It asks the store: from a worker thread.)"""
    saved = _remembered(app, d)
    if not saved or not saved.get("user") or not credstore.available():
        return None
    password = credstore.load(d.mac)
    if password is None:
        return None
    return _login(app, d, saved["user"], password, int(saved.get("port") or d.port("ssh")), via)


async def back_up_all(app):
    """Device > Back up all configs…: every device in the table that keeps a config, with the
    login remembered for it (BackupAllWindow). While a run goes on, its window shows again; one
    that's over makes way for a new run."""
    last = _backup_all
    if last is not None and not last.window.closed:
        if last.running:
            last.window.show()
            return
        last.closing(last.window) and last.window.close()
    if not sshrun.available():
        app.status.text = _("Back up all configs needs ssh and scp.")
        return
    devices = [d for d in (app._device(getattr(row, "key", None)) for row in app.table.data) if d is not None]
    if not any(devicetools.config_kind(d) for d in devices):
        await app.main_window.dialog(toga.InfoDialog(
            _("Back up all configs"), _("No device in the table keeps a config the app can back up (airMAX, "
                                        "airFiber, LTU, GigaBeam, EdgeOS).") if devices
            else _("Scan first: the table is empty.")))
        return
    app.status.text = _("Looking up the saved logins…")
    jobs = await _work(devicetools.backup_jobs, devices, lambda d, via: _saved_login(app, d, via),
                       lambda d: route(app, d))
    app.status.text = ""
    BackupAllWindow(app, jobs, searched=bool((app.search.value or "").strip()))


class BackupAllWindow:
    """Back up all configs: a line for each device saying how its backup went, as it goes,
    BACKUP_AT_ONCE at a time; Stop starts no more and cancels those running. The devices without
    a saved login come last, skipped; once the run is over they, and any that failed, have a
    Back up… button of their own, which asks for the login. Closed while it runs, it carries on
    (the status line follows it) and the menu item shows it again."""

    def __init__(self, app, jobs, searched=False):
        global _backup_all
        self.app, self.jobs = app, jobs
        self.stop = threading.Event()
        self.running = False
        self.lines = {}  # id(job) -> (the label saying how it went, its Back up… button)
        rows = []
        for job in jobs:
            state = toga.Label(_fill(job.text, 50), style=Pack(flex=1))
            button = toga.Button(_("Back up…"), style=Pack(visibility="hidden"),
                                 on_press=lambda w, job=job: asyncio.create_task(_guarded(app, job.d, self._one(job))))
            self.lines[id(job)] = (state, button)
            rows.append(toga.Box(style=Pack(direction=ROW, align_items="center", gap=8), children=[
                toga.Label(_fill(_label(job.d), 36), style=Pack(width=270)), state, button]))
        if searched:
            about = tr("Backs up the config of each device in the table (the ones the search shows) that keeps one "
                       "(airMAX, airFiber, LTU, GigaBeam, EdgeOS), with the login remembered for it, {count} at a "
                       "time; one the same as the device's last backup isn't kept again. Devices without a saved "
                       "login are skipped and listed at the end, each with a Back up… button that asks for its "
                       "login.",
                       count=devicetools.BACKUP_AT_ONCE)
        else:
            about = tr("Backs up the config of each device in the table that keeps one (airMAX, airFiber, LTU, "
                       "GigaBeam, EdgeOS), with the login remembered for it, {count} at a time; one the same as the "
                       "device's last backup isn't kept again. Devices without a saved login are skipped and listed "
                       "at the end, each with a Back up… button that asks for its login.",
                       count=devicetools.BACKUP_AT_ONCE)
        self.bar = toga.ProgressBar(max=100, value=0, style=Pack(flex=1))
        self.summary = toga.Label("", style=Pack(flex=1))
        self.stop_button = toga.Button(_("Stop"), on_press=self.stopping, enabled=False)
        size = (860, 560)
        self.window = toga.Window(title=_("Back up all configs"), size=size, on_close=self.closing,
                                  position=app._over_main(size))
        self.window.content = toga.Box(style=Pack(direction=COLUMN, margin=12, gap=8), children=[
            toga.Label(_fill(about, 112)),
            toga.ScrollContainer(horizontal=False, style=Pack(flex=1), content=toga.Box(
                style=Pack(direction=COLUMN, margin=4, gap=6), children=rows)),
            self.bar,
            toga.Box(style=Pack(direction=ROW, align_items="center", gap=8), children=[
                self.summary, self.stop_button,
                toga.Button(_("Show folder"), on_press=lambda w: _show_folder(devicetools.backup_root())),
                toga.Button(_("Close"), on_press=lambda w: self.closing(w) and self.window.close())])])
        _backup_all = self
        app._show_over_main(self.window)
        asyncio.create_task(self.run())

    def closing(self, widget, **kwargs):
        global _backup_all
        if self.running:  # it carries on; the menu item shows it again
            self.window.hide()
            return False
        _backup_all = None
        return True

    def stopping(self, widget, **kwargs):
        self.stop.set()
        self.stop_button.enabled = False
        self.summary.text = _("Stopping…")

    async def run(self):
        app = self.app
        self.running = True
        self.stop_button.enabled = True
        app.spinner.start()
        try:
            await _work(devicetools.back_up_all, self.jobs, lambda job: app._from_worker(self.show, job), self.stop,
                        devicetools.BACKUP_AT_ONCE, _busy)
        finally:
            self.running = False
            app.spinner.stop()
        self.stop_button.enabled = False
        for job in self.jobs:
            self.show(job)
        said = devicetools.backup_summary(self.jobs)
        self.summary.text = tr("Done: {summary}.", summary=said)
        app._append_log(_("Back up all configs:") + "\n" + "".join(f"  {_label(job.d)}: {job.text}\n"
                                                                   for job in self.jobs) + f"  {said}.", status=False)
        app.status.text = i18n.sentences(tr("Back up all configs: {summary}.", summary=said), "" if self.window.visible
                                         else _("Device > Back up all configs… shows how each went."))

    def show(self, job):
        """How a job went, in its line; with the counts under the lines and in the status line."""
        state, button = self.lines[id(job)]
        state.text = _fill(job.text, 50)
        retry = job.can_retry and not self.running
        button.style.visibility = "visible" if retry else "hidden"
        button.enabled = retry
        if job.state == "backed up":
            _refresh_backups(job.d)
        if self.running:
            done = sum(j.state not in ("waiting", "backing up") for j in self.jobs)
            self.bar.value = 100 * done / max(1, len(self.jobs))
            self.summary.text = devicetools.backup_summary(self.jobs) + "…"
            self.app.status.text = tr("Back up all configs: {done} of {total} done…", done=done, total=len(self.jobs))
        else:
            self.bar.value = 100

    def _one(self, job):
        return lambda app, d: self.one(job)

    async def one(self, job):
        """A device's own Back up… button: its login asked for, then backed up as the run does."""
        app, d = self.app, job.d
        if _busy.get(d.key):
            app.status.text = tr("{ip} is {doing}: back it up once that's done.", ip=d.ip, doing=_(_busy[d.key]))
            return
        _state, button = self.lines[id(job)]
        login = await ask_route(app, d, tr("Log in to back up its config ({file}).",
                                           file=devicetools.CONFIG_FILES[job.kind]))
        if not login:
            return
        button.enabled = False
        _busy[d.key] = N_("backing up")
        job.state, job.said = "backing up", ""  # (the job's state: devicetools says it)
        self.show(job)
        try:
            job.state, job.backup = await _work(devicetools.back_up, login, d, job.kind)
        except (sshrun.SSHError, devicetools.ToolError, OSError) as e:
            job.state, job.said = "failed", str(e)
        finally:
            _busy.pop(d.key, None)
        self.show(job)
        self.summary.text = tr("Done: {summary}.", summary=devicetools.backup_summary(self.jobs))
        app._append_log(tr("Config backup of {device}: {detail}", device=_label(d), detail=job.text))


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
            tr("Upload a config to {ip} ({file})", ip=d.ip, file=devicetools.CONFIG_NAMES[kind])))
        if not path:
            return
        try:
            text, meta = devicetools.read_config_file(path)
        except (OSError, devicetools.ToolError) as e:
            await app.main_window.dialog(toga.ErrorDialog(_("Upload config"), str(e)))
            return
        source = Path(path).name
    else:
        try:
            text, meta = backup.text(), backup.meta
        except OSError as e:
            await app.main_window.dialog(toga.ErrorDialog(_("Restore"), str(e)))
            return
        source = tr("the backup taken {date}", date=backup.date)
    refuse, warn = devicetools.upload_check(d, kind, text, meta)
    if refuse:
        await app.main_window.dialog(toga.ErrorDialog(_("Can't upload this config"), refuse))
        return
    if warn and not await app.main_window.dialog(toga.QuestionDialog(_("Upload this config?"),
                                                                     warn + "\n\n" + _("Go on?"))):
        return
    login = await ask_route(app, d, tr("Log in to upload {source}: what changes is shown first.", source=source))
    if not login:
        return
    _busy[d.key] = N_("uploading config")
    try:
        app.status.text = tr("Reading the config of {ip} to compare…", ip=d.ip)
        try:
            current, _pending = await _work(devicetools.read_device_config, login, kind)
            tools = await _work(devicetools.config_tools, login, kind)
        except (sshrun.SSHError, devicetools.ToolError) as e:
            app.status.text = f"{d.ip}: {e}"
            await app.main_window.dialog(toga.ErrorDialog(_("Upload config"), str(e)))
            return
        app.status.text = ""
        choice = await _diff_window(app, d, kind, current, text, source, tools)
        if not choice:
            return
        apply = choice == "apply"
        progress = Progress(app, tr("Uploading a config: {ip}", ip=d.ip), f"{_label(d)}: {source}")
        progress.no_cancel()
        outcome = {}

        def work():
            try:
                kept = devicetools.save_backup(d, current, kind, N_("before upload"))
                app._from_worker(_refresh_backups, d)
                progress.show(tr("Kept its current config as a backup ({date}).", date=kept.date))
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
    diff, changed = devicetools.config_diff(current, text)
    edgeos = kind == "edgeos"
    heading = (tr("{source} → {device}: {count} line(s) change.", source=source, device=_label(d), count=changed)
               if changed else tr("{source} → {device}: no differences, the device has this config already.",
                                  source=source, device=_label(d)))
    note = (_("Save writes it to its boot config: it takes effect at the next reboot. Apply now also applies it: the "
              "device restarts what the changes affect, and the connection to it can drop for a moment. Either way "
              "the device's current config is kept as a backup first.") if edgeos else
            _("Save writes it to flash: it takes effect at the next reboot. Apply now also applies it: the device "
              "restarts what the changes affect, and the connection to it can drop for a moment. Either way the "
              "device's current config is kept as a backup first."))
    note += "\n" + i18n.sentences(_(terms.RISKS["upload"]), _(terms.RISKS["apply" if tools["apply"] else "save"]),
                                  _(terms.TESTED))
    if tools["why"]:
        note += f"\n{tools['why']}"
    return await _diff_view(app, tr("Upload config: {ip}", ip=d.ip), heading, diff, note, [
        (_("Cancel"), None, True), (_("Save (next boot)") if edgeos else _("Save (to flash)"), "save", tools["save"]),
        (_("Apply now"), "apply", tools["apply"])])


async def _diff_view(app, title, heading, diff, note, buttons):
    """A diff in a window of its own, under its heading and over a note, with a button for each
    (text, answer, enabled) in buttons. Returns the answer of the one pressed; None when it's
    closed."""
    answer = app.loop.create_future()

    def finish(choice):
        if not answer.done():
            answer.set_result(choice)
            window.close()

    def closing(widget, **kwargs):
        if not answer.done():
            answer.set_result(None)
        return True

    view = toga.MultilineTextInput(readonly=True, value=diff or _("(no differences)"),
                                   style=Pack(flex=1, font_family="monospace", font_size=11))
    size = (900, 640)
    window = toga.Window(title=title, size=size, on_close=closing, position=app._over_main(size))
    window.content = toga.Box(style=Pack(direction=COLUMN, margin=12, gap=8), children=[
        toga.Label(_fill(heading, 118)), view, toga.Label(_fill(note, 118)),
        toga.Box(style=Pack(direction=ROW, gap=8), children=[
            toga.Box(style=Pack(flex=1)),
            *(toga.Button(text, on_press=lambda w, choice=choice: finish(choice), enabled=enabled)
              for text, choice, enabled in buttons)])])
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
    text = tr("{device} restarts and is offline for a minute or two, longer for some models: whatever goes through it "
              "stops meanwhile.", device=_label(d))
    if hops:
        text = i18n.sentences(text, tr("It's reached through {route}.", route=_through(hops)))
    text += "\n\n" + terms.risk("reboot")
    if not await app.main_window.dialog(toga.QuestionDialog(tr("Reboot {ip}?", ip=d.ip), text)):
        return
    login = await ask_route(app, d, _("Log in to reboot it."))
    if not login:
        return
    _busy[d.key] = N_("rebooting")
    try:
        progress = Progress(app, tr("Reboot: {ip}", ip=d.ip), _label(d))
        outcome = {}

        def work():
            try:
                outcome["took"] = devicetools.reboot(login, d, report=progress.show, stop=progress.stop)
            except (devicetools.ToolError, sshrun.SSHError) as e:
                outcome["error"] = str(e)

        await _work(work)
        message = outcome.get("error") or tr("Rebooted: back after {seconds:.0f} s.", seconds=outcome["took"])
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
            app.status.text = tr("Stop locating {ip}: {error}", ip=d.ip, error=e)
            return
        _locating.pop(d.key, None)
        app.status.text = tr("{ip}: its LED is back to normal.", ip=d.ip)
        return
    login = await ask_route(app, d, _("Log in to blink its LED."))
    if not login:
        return
    try:
        state = await _work(devicetools.locate, login, d, True)
    except (devicetools.ToolError, sshrun.SSHError) as e:
        app.status.text = tr("Locate {ip}: {error}", ip=d.ip, error=e)
        await app.main_window.dialog(toga.ErrorDialog(_("Locate"), str(e)))
        return
    _locating[d.key] = login
    said = "" if state else (_("It doesn't say it's locating: it may be busy (upgrading).") if state is False
                             else _("It doesn't say whether it took."))
    app.status.text = i18n.sentences(tr("{ip}: its LED is blinking.", ip=d.ip), said)
    if await app.main_window.dialog(toga.QuestionDialog(
            _("Locating"), i18n.sentences(tr("{device}'s LED is blinking.", device=_label(d)), said) + "\n\n" +
            _("Stop it now? (No keeps it blinking: Stop locating, in its menu, stops it later.)"))):
        await locate_flow(app, d)


# ---------------------------------------------------------------------------
# Scan from a device given by its address
# ---------------------------------------------------------------------------

async def scan_address(app):
    """Scan from device with none selected: log in to a device by its address (one the scan
    didn't find, over a VPN say), list it, and what it sees under it."""
    if app.running or app.rescanning or app.finding:
        app.status.text = _("Works once the scan has finished.")
        return
    if not sshrun.available():
        app.status.text = _("Scan from device needs ssh and scp.")
        return
    ip, port = "", 22
    user, password, remember, problem = app.settings.get("ssh_user") or "", "", False, ""
    can_remember = await _work(credstore.available)  # (asked once; _address_window reads the answer kept)
    while True:
        answer = await _address_window(app, ip, port, user, password, remember, problem)
        if answer is None:
            return
        ip, port, user, password, remember = answer
        known = app.result.inv.find(ip=ip) if app.result else None
        login = sshrun.Login(ip, port, user, password, terminal.host_key_alias(known.mac if known else None, ip),
                             app.known_hosts)
        app.status.text = tr("Logging in to {where}…", where=login.where)
        try:
            await _work(sshrun.check_login, login)
            break
        except sshrun.SSHError as e:
            app.status.text = problem = str(e)
    if app.running or app.rescanning or app.finding:
        app.status.text = _("A scan started meanwhile: Scan from device again once it has finished.")
        return
    result = app.result or _empty_result()
    app.spinner.start()
    app.status.text = tr("Reading what {ip} sees…", ip=ip)
    try:
        def work():
            return devicetools.scan_from_address(result, login, core.local_macs())

        try:
            finder, sightings, seen, new = await _work(work)
        except (sshrun.SSHError, devicetools.ToolError) as e:
            app.status.text = tr("Scan from {ip}: {error}", ip=ip, error=e)
            return
    finally:
        app.spinner.stop()
    if app.result is None and not app.running:
        app.result = result  # the table's devices from now on, as a scan's would be
        app.export_button.enabled = True
    elif result is not app.result:
        app.status.text = tr("Scan from {ip} finished after a new scan started: start it again.", ip=ip)
        return
    app._show_devices(result.devices)
    if not finder.ubnt_packets:  # what it is: UBNT discovery sent straight to it, as Rescan device does
        key = finder.key
        await _reread(app, finder)
        finder = (result.inv.find(mac=finder.mac) if finder.mac else None) or result.inv.find(ip=ip) or finder
        devicetools.relink(result, key, finder)
        app._show_devices(result.devices)
    app.settings["ssh_user"] = user
    if remember and can_remember:
        if finder.mac and await _work(credstore.save, finder.mac, user, password):
            _logins(app)[finder.mac] = {"user": user, "port": port}
        elif not finder.mac:
            app._append_log(tr("{ip}'s login isn't remembered: the app didn't learn its MAC address, which it's filed "
                               "under.", ip=ip))
    app._save_settings()
    _report_scan(app, finder, sightings, seen, new)
    await warn_factory_login(app, finder, login)


def _empty_result():
    """A scan result with nothing in it yet, for devices added before any scan has run."""
    return core.ScanResult(core.parse_args([]), [], [], [], [], [], [], core.Inventory(), None, 0.0)


async def _address_window(app, ip, port, user, password, remember, problem):
    answer = app.loop.create_future()
    ip_box = toga.TextInput(value=ip, placeholder=_("e.g. 10.20.0.1"), style=Pack(flex=1))
    port_box = toga.TextInput(value=str(port), style=Pack(width=80))
    user_box = toga.TextInput(value=user, placeholder=_("e.g. ubnt or admin"), style=Pack(flex=1))
    password_box = toga.PasswordInput(value=password, style=Pack(flex=1))
    trouble = toga.Label(_fill(problem, 46), style=Pack(flex=1))
    can_remember = credstore.available()
    keep = toga.Switch(tr("Remember for this device (in {store})", store=credstore.store_name()),
                       value=remember and can_remember, enabled=can_remember)

    def finish(ok):
        if answer.done():
            return
        if ok:
            address, text = ip_box.value.strip(), port_box.value.strip()
            if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", address) or not core._usable_ip(address):
                trouble.text = _fill(_("The address is an IPv4 address, such as 10.20.0.1."), 46)
                return
            if not text.isdigit() or not 0 < int(text) < 65536:
                trouble.text = _fill(_("The port is a number from 1 to 65535."), 46)
                return
            if not user_box.value.strip():
                trouble.text = _("Logging in needs a username.")
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
    window = toga.Window(title=_("Scan from a device"), size=size, resizable=False, on_close=closing,
                         position=app._over_main(size))
    window.content = toga.Box(style=Pack(direction=COLUMN, margin=14, gap=8), children=[
        toga.Label(_fill(_("Log in to a device by its address, one the scan didn't find (over a VPN, say), to list "
                           "what it sees: its ARP table, LLDP neighbours and, on airOS, its stations. They're listed "
                           "under it, and the device tools reach them through it."), 74)),
        toga.Box(style=row, children=[toga.Label(_("Address"), style=label), ip_box]),
        toga.Box(style=row, children=[toga.Label(_("Port"), style=label), port_box, trouble]),
        toga.Box(style=row, children=[toga.Label(_("Username"), style=label), user_box]),
        toga.Box(style=row, children=[toga.Label(_("Password"), style=label), password_box]),
        keep,
        toga.Box(style=Pack(direction=ROW, gap=8), children=[
            toga.Box(style=Pack(flex=1)),
            toga.Button(_("Cancel"), on_press=lambda w: finish(False)),
            toga.Button(_("Log in and scan"), on_press=lambda w: finish(True))])])
    app._show_over_main(window)
    ip_box.focus()
    app.cancel_ssh_login = lambda: finish(False)
    try:
        return await answer
    finally:
        app.cancel_ssh_login = None
