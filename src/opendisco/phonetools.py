"""The device tools on the phones, as devicegui does them on the desktop, from the Tools tab
(phone.py): firmware check and update, the config editor (airMAX, airFiber, LTU, EdgeOS), config
backups (back up, restore, upload a file, share, delete), a new login, Reboot, Locate, Link health
(airMAX: into Details), and Scan from a device given by its address (the title bar's +).

The work is devicetools', over phonessh (devicetools uses it on phones). What the desktop shows
in windows is a page here (the config, the backups, what an upload changes, a new login, an
address) or lines in the Tools console (progress), and its questions are the phone's alerts. One
job runs at a time (app.device_job); a firmware download can be stopped until the installation
starts, and waiting for a reboot can be stopped too. Shared by iOS and Android.
"""
import re
import shutil
import threading
import traceback
from pathlib import Path

import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW

from opendisco import core, devicetools, linkhealth, phone, phonessh, terms


def _label(d) -> str:
    return f"{d.ip}  {d.name or d.model or d.mac or ''}".strip()


async def _work(app, fn, *args):
    return await app.loop.run_in_executor(None, fn, *args)


def _say(app, text: str, begins: bool = False):
    app._tool_said(text, begins=begins)


def update_buttons(app, d):
    """Enable the device tools for what the open device can do. The button of what can be stopped
    reads Stop (a firmware download, waiting for a reboot); Locate reads Stop locating while the
    LED blinks."""
    job = app.device_job
    idle = bool(d and d.ip and app.result) and not (app.running or app.rescanning or app.finding or job)
    ubiquiti = bool(d and (d.info.get("firmware") or d.info.get("platform")))
    stoppable = job["name"] if job and job["stop"] and d and job["key"] == d.key else ""
    retitle, ssh = phone.native(app).retitle, phonessh.available()
    retitle(app.firmware_button, "Stop" if stoppable == "firmware" else "Firmware")
    app.firmware_button.enabled = (idle and ubiquiti) or stoppable == "firmware"
    for button, action in ((app.config_button, "edit"), (app.login_button, "login"), (app.reboot_button, "reboot")):
        button.enabled = idle and devicetools.offers(d, action)[0] and ssh
    retitle(app.reboot_button, "Stop" if stoppable == "reboot" else "Reboot")
    app.reboot_button.enabled = app.reboot_button.enabled or stoppable == "reboot"
    kept = bool(d and d.mac and devicetools.list_backups(d.mac))
    app.backups_button.enabled = bool(d and d.mac) and not job and (
        kept or (idle and devicetools.offers(d, "backup")[0] and ssh))
    locating = bool(d and d.key in app.phone_locating)
    retitle(app.locate_button, "Stop locating" if locating else "Locate")
    app.locate_button.enabled = locating or (idle and devicetools.offers(d, "locate")[0] and ssh)
    app.link_button.enabled = idle and devicetools.offers(d, "link")[0] and ssh


def _begin(app, d, name: str, stop: threading.Event | None = None):
    app.device_job = {"key": d.key, "name": name, "stop": stop}
    app.spinner.start()
    phone.update_tools(app)


def _end(app):
    app.device_job = None
    app.spinner.stop()
    phone.update_tools(app)


def _reporter(app):
    """report(text, percent=None) from a worker thread: a console line for each new step, the
    step (with its seconds or percentage) in the status line."""
    shown = {"step": ""}

    def show(text, percent):
        if text and text.split("…")[0] != shown["step"].split("…")[0]:
            phone.say(app, text.rstrip(" 0123456789s"))
        shown["step"] = text or shown["step"]
        app.status.text = shown["step"] + (f"  {percent:.0f}%" if percent is not None else "")

    return lambda text, percent=None: app._from_worker(show, text, percent)


async def _alert(app, title: str, text: str, question: bool = False):
    dialog = toga.QuestionDialog(title, text) if question else toga.InfoDialog(title, text)
    return await app.main_window.dialog(dialog)


def _offered(app, d, action: str) -> bool:
    ok, why = devicetools.offers(d, action)
    if not ok:
        _say(app, f"{_label(d)}: {why}.")
    return ok


# -- firmware ----------------------------------------------------------------------------
async def firmware(app):
    """Ask Ubiquiti's firmware server about the open device, then offer to update it; Stop
    while a download runs."""
    job = app.device_job
    if job:
        if job["name"] == "firmware" and job["stop"]:
            job["stop"].set()
            _say(app, "Stopping…")
        return
    d = app._selected_device()
    if d is None:
        return
    _say(app, f"Asking Ubiquiti's firmware server about {d.ip or d.mac}…", begins=True)
    try:
        check = await _work(app, devicetools.check_firmware, d)
    except devicetools.ToolError as e:
        _say(app, str(e))
        return
    text = devicetools.summary(d, check)
    phone.say(app, text)
    app.status.text = text.split("\n")[0]
    if not check.newer:
        return
    why = devicetools.fits(d, check.release)
    if why:
        _say(app, why)
        return
    if not _offered(app, d, "update") or not d.ip:
        return
    if await _alert(app, f"Firmware {check.latest}", f"{_label(d)} runs {check.current}. Install {check.latest} "
                    "now?", question=True):
        await _update(app, d, check)


async def _update(app, d, check):
    login = await phone.ask_route(app, d, f"Log in to install firmware {check.latest}.")
    if not login:
        return
    family = devicetools.FAMILY_NAMES[devicetools.family(d)]
    message = (f"Install {family} firmware {check.latest} on {_label(d)}? It runs {check.current} now.\n\n"
               f"OpenDisco downloads it from Ubiquiti ({devicetools.fmt_size(check.size)}), checks it, copies it "
               "to the device and starts the installation. The device restarts to install it and is offline for a "
               "few minutes: don't unplug it or turn it off until it's back.")
    if devicetools.family(d) == "edgeos":
        _say(app, f"Reading the firmware images of {d.ip}…")
        try:
            note = await _work(app, devicetools.edgeos_update_note, login, check.latest)
        except (devicetools.ToolError, phonessh.SSHError) as e:
            _say(app, f"Firmware update of {d.ip}: {e}")
            return
        message = (f"Install EdgeOS firmware {check.latest} on {_label(d)}? It runs {check.current} now.\n\n"
                   f"OpenDisco downloads it from Ubiquiti ({devicetools.fmt_size(check.size)}), checks it, copies it "
                   "to the router and adds it with EdgeOS's add system image. Once EdgeOS lists it as the image it "
                   "boots, OpenDisco restarts the router, which is offline for a few minutes: don't unplug it or turn "
                   f"it off until it's back.\n\n{note}")
    if devicetools.family(d) in ("unifi", "unifi-os"):
        message += ("\n\nUbiquiti's help center describes updating over SSH as a last resort, for when the UniFi app "
                    "can't update the device.")
    message += "\n\n" + terms.risk("firmware")
    if not await _alert(app, "Install firmware?", message, question=True):
        return
    stop = threading.Event()
    _begin(app, d, "firmware", stop)
    folder = Path(app.paths.cache) / "firmware"
    outcome, report = {}, _reporter(app)

    def no_stop():
        app.device_job["stop"] = None  # past the point where stopping leaves the device as it was
        phone.update_tools(app)

    def work():
        path = None
        try:
            report(f"Downloading firmware {check.latest} from Ubiquiti…", 0)
            path = devicetools.download_release(
                check.release, folder, stop=stop,
                progress=lambda done, total: report(None, 100 * done / total if total else None))
            report(f"Downloaded and checked (SHA-256 {check.release['sha256_checksum'][:16]}…).", 100)

            def step(text, percent=None):
                if text and text.startswith("Starting the installation"):
                    app._from_worker(no_stop)
                report(text, percent)

            outcome["offline"] = devicetools.install_firmware(d, login, path, step, stop=stop, version=check.latest)
        except (devicetools.ToolError, phonessh.SSHError) as e:
            outcome["error"] = str(e)
        except Exception as e:
            outcome["error"] = f"{type(e).__name__}: {e}"
            app._from_worker(app._append_log, traceback.format_exc())
        if path is not None and "offline" in outcome:
            path.unlink(missing_ok=True)  # installed: no need to keep it

    try:
        await _work(app, work)
    finally:
        _end(app)
    if "error" in outcome:
        text = outcome["error"]
        if stop.is_set() and "Cancelled" in text:
            text = "Stopped. Nothing was installed."
        _say(app, f"Firmware update of {d.ip}: {text}")
        return
    _say(app, f"Back after {outcome['offline']:.0f} s. Reading its firmware again…")
    now = await _reread(app, d)
    if now is None:
        _say(app, f"{d.ip} is back: rescan it to see the version it runs.")
    elif devicetools.version_key(now) == devicetools.version_key(check.latest):
        _say(app, f"Updated: {d.ip} runs {now}.")
    else:
        _say(app, f"{d.ip} is back, but reports firmware {now or 'unknown'}, not {check.latest}.")


async def _reread(app, d) -> str | None:
    """Rescan the device for the firmware it reports now; None when a scan is busy."""
    result = app.result
    if not result or app.running or app.rescanning or app.finding:
        return None
    app.rescanning = True
    app.spinner.start()
    error = None
    try:
        dev, answered = await _work(app, core.rescan_device, result, d,
                                    lambda m: app._from_worker(app._append_log, m))
    except Exception as e:
        dev, answered, error = d, False, f"{type(e).__name__}: {e}"
    app._rescanned(result, dev, answered, error)
    return devicetools.device_version(dev) if answered else None


# -- the config editor -----------------------------------------------------------------
async def config(app):
    d = app._selected_device()
    if d is None or app.device_job or not _offered(app, d, "edit"):
        return
    kind = devicetools.config_kind(d)
    login = await phone.ask_route(app, d, f"Log in to read its configuration ({devicetools.CONFIG_FILES[kind]}).")
    if not login:
        return
    _say(app, f"Reading the config of {d.ip}…", begins=True)
    try:
        text, pending = await _work(app, devicetools.read_device_config, login, kind)
        tools = await _work(app, devicetools.config_tools, login, kind)
    except (phonessh.SSHError, devicetools.ToolError) as e:
        _say(app, str(e))
        return
    _say(app, f"Read the config of {d.ip}.")
    ConfigPage(app, d, login, text, pending, kind, tools)


ABOUT_CONFIG = {
    "airos": "{file}, one setting per line. Save writes it to flash for the next reboot; Apply saves it and applies "
             "it now, as the web UI's Apply does (the connection can drop for a moment).",
    "edgeos": "{file}, EdgeOS's boot config. Save checks that EdgeOS reads it and makes it the boot config, for the "
              "next reboot; Apply loads, commits and saves it now (the connection can drop for a moment).",
}
ABOUT_CONFIG["isp"] = ABOUT_CONFIG["airos"]


class ConfigPage:
    """The device's config as text on a page of its own (airMAX, airFiber and LTU: system.cfg;
    EdgeOS: config.boot): Reload, Save or Apply, where the device has the tools for them. The
    config read is kept as a backup before each write. Leaving with changes not saved asks
    first."""

    def __init__(self, app, d, login, text, pending, kind="airos", tools=None):
        self.app, self.d, self.login, self.saved, self.kind = app, d, login, text, kind
        self.tools = tools or {"save": True, "apply": True, "why": ""}
        ui = phone.native(app)
        self.box = toga.MultilineTextInput(value=text, style=Pack(flex=1, font_family="monospace", font_size=10))
        self.state = toga.Label("")
        self.buttons = [toga.Button("Reload", on_press=self.reload, style=Pack(flex=1)),
                        toga.Button("Save", on_press=lambda w, **kw: app.loop.create_task(self._write(False)),
                                    style=Pack(flex=1)),
                        toga.Button("Apply", on_press=lambda w, **kw: app.loop.create_task(self._write(True)),
                                    style=Pack(flex=1))]
        about = ABOUT_CONFIG[kind].format(file=devicetools.CONFIG_FILES[kind])
        if d.mac:
            about += " What it has is kept as a backup before each write."
        about = app._wrap(about)
        content = toga.Box(style=Pack(direction=COLUMN, flex=1, margin=12, gap=8), children=[
            toga.Label(about), self.box, self.state,
            toga.Box(style=Pack(direction=ROW, gap=8), children=self.buttons)])
        for button, kind in zip(self.buttons, ("gray", "tinted", "filled")):
            ui.style_button(button, kind)
        ui.monospaced(self.box, 10)
        phone.hook(app, "plain_entry")(self.box)
        phone.hook(app, "watch_keyboard")(app, self.box, follow=False)
        phone.hook(app, "done_bar")(app, self.box)
        self.page = ui.Page(app, content, on_back=self.leaving)
        self._pending(pending)
        self._enable(True)
        self.page.show("Config", _label(d))

    def _pending(self, pending):
        self.state.text = self.app._wrap("It has changes that aren't applied yet (made in its web UI, or saved "
                                         "without applying)." if pending else self.tools["why"])

    def _changed(self) -> bool:
        return self.box.value.replace("\r", "") != self.saved.replace("\r", "")

    def leaving(self):
        """Back: with edits not saved, ask; keeping them shows the page again."""
        if self._changed():
            self.app.loop.create_task(self._discard_or_keep())

    async def _discard_or_keep(self):
        if not await _alert(self.app, "Discard the changes?", "The edits haven't been saved to the device.",
                            question=True):
            self.page.show("Config", _label(self.d))

    def _enable(self, on: bool):
        reload, save, apply = self.buttons
        reload.enabled = on
        save.enabled = on and self.tools["save"]
        apply.enabled = on and self.tools["apply"]

    async def reload(self, widget, **kwargs):
        self._enable(False)
        self.state.text = "Reading…"
        try:
            text, pending = await _work(self.app, devicetools.read_device_config, self.login, self.kind)
        except (phonessh.SSHError, devicetools.ToolError) as e:
            self.state.text = self.app._wrap(str(e))
        else:
            self.saved = self.box.value = text
            self._pending(pending)
        self._enable(True)

    async def _write(self, apply: bool):
        app = self.app
        phone.hook(app, "end_editing")(app)
        text = self.box.value
        problems = devicetools.config_problems(text, self.kind)
        if problems:
            heading = ("EdgeOS wouldn't read it:\n" if self.kind == "edgeos"
                       else "airOS reads only key=value lines. These aren't:\n")
            await app.main_window.dialog(toga.ErrorDialog("Not a config", heading + "\n".join(problems[:10])))
            return
        changed = devicetools.lines_changed(self.saved, text)
        boot = "boot config" if self.kind == "edgeos" else "flash"
        what = ("Apply the config on" if apply else f"Save the config to {boot} on") + f" {_label(self.d)}?"
        detail = (f"{changed} line(s) changed. " if changed else "Nothing changed here. ") + (
            f"It's applied now and saved to {boot}; the device restarts what the changes affect." if apply
            else "It takes effect at the next reboot.") + "\n\n" + terms.risk("apply" if apply else "save")
        if not await _alert(app, what, detail, question=True):
            return
        self._enable(False)
        self.state.text = "Applying…" if apply else "Saving…"
        def work():
            if self.d.mac:  # what it had, kept before it's replaced
                devicetools.save_backup(self.d, self.saved, self.kind, "before edit")
            return devicetools.push_config(self.login, self.kind, text, apply,
                                           report=lambda m: app._from_worker(setattr, self.state, "text", app._wrap(m)))

        try:
            message = await _work(app, work)
        except devicetools.LostConnection as e:  # what it means for the device, as far as it's known
            self.state.text = app._wrap(str(e))
            await app.main_window.dialog(toga.ErrorDialog("Connection lost", str(e)))
        except (devicetools.ToolError, phonessh.SSHError, OSError) as e:
            self.state.text = app._wrap(str(e))
        else:
            self.saved = text
            self.state.text = app._wrap(message)
            _say(app, f"{self.d.ip}: {message}")
        self._enable(True)


# -- a new login -----------------------------------------------------------------------
async def change_login(app):
    d = app._selected_device()
    if d is None or app.device_job or not _offered(app, d, "login"):
        return
    login = await phone.ask_route(app, d, "Log in with its current username and password first.")
    if not login:
        return
    kind = devicetools.config_kind(d)  # "airos" or "edgeos"
    _say(app, f"Reading the config of {d.ip}…", begins=True)
    try:
        if kind == "edgeos":
            text, _pending = await _work(app, devicetools.read_device_config, login, kind)
            pending = await _work(app, devicetools.edgeos_unsaved, login)
        else:
            text, pending = await _work(app, devicetools.read_config, login)
    except (phonessh.SSHError, devicetools.ToolError) as e:
        _say(app, str(e))
        return
    answer = await _new_login_page(app, d, login, text)
    if not answer:
        _say(app, "The login wasn't changed.")
        return
    new_text, new_user, new_password, scheme = answer
    what = (f"the password of {login.user} on {_label(d)}" if new_user == login.user
            else f"the login of {_label(d)} from {login.user} to {new_user} with the new password")
    if kind == "edgeos":
        message = (f"Change {what}? EdgeOS commits it right away and saves it to its boot config; the old "
                   f"{'password' if new_user == login.user else 'login'} stops working.")
        if new_user != login.user:
            message += (f"\n\nAs Ubiquiti's help center does it, {new_user} is made first, with {login.user}'s level "
                        f"and settings, and OpenDisco logs in with it; only then is {login.user} deleted, logged in "
                        f"as {new_user}.")
        message += "\n\nEdgeOS hashes the password itself and stores it so, never as plain text."
        if pending:
            message += ("\n\nIts config also has changes that are committed but not saved (in its CLI): saving the "
                        "new login saves them too.")
    else:
        message = (f"Change {what}? It's applied right away and saved to flash; the old login stops working.\n\n"
                   f"The password is stored on the device as an {scheme} hash, the format it uses now.")
        if pending:
            message += ("\n\nIts config also has changes that aren't applied yet (made in its web UI, or saved without "
                        "applying): they're applied with it.")
    message += "\n\n" + terms.risk("login")
    if not await _alert(app, "Change login?", message, question=True):
        _say(app, "The login wasn't changed.")
        return
    new = phonessh.Login(login.ip, login.port, new_user, new_password, login.alias, login.known_hosts, login.via,
                         login.nested)
    _begin(app, d, "login")
    outcome = {}

    def work():
        report = lambda m: app._from_worker(_say, app, m)  # noqa: E731
        try:
            if d.mac:  # what it had, kept before it's replaced
                devicetools.save_backup(d, text, kind, "before login change")
            if kind == "edgeos":  # new_text: the steps; it logs in with the new login itself
                outcome["said"] = devicetools.change_edgeos_login(login, new, new_text, report=report)
                return
            outcome["said"] = devicetools.write_config(login, new_text, True, new_login=new, report=report)
            app._from_worker(_say, app, "Logging in with the new login…")
            phonessh.check_login(new)
        except (devicetools.ToolError, phonessh.SSHError, OSError) as e:
            outcome["error"] = str(e)

    try:
        await _work(app, work)
    finally:
        _end(app)
    if "error" in outcome:
        _say(app, f"{outcome['error']} If the device takes neither login now, its web UI or a reset to factory "
                  "defaults gets it back.")
        return
    app.phone_passwords[d.key] = new_password
    devicetools.forget_factory_login(d)
    if d.mac:
        app.settings.setdefault("device_logins", {})[d.mac] = {"user": new_user, "port": login.port}
    app._save_settings()
    app._rediagnose()
    _say(app, f"Done: {d.ip} takes the new login ({new_user}). {outcome['said']}" if kind == "edgeos"
         else f"Done: {d.ip} takes the new login ({new_user}), applied and saved to flash.")


async def _new_login_page(app, d, login, text):
    """A page for the new username and password (twice); (config, user, password, scheme) or None."""
    answer = app.loop.create_future()
    ui = phone.native(app)
    user = toga.TextInput(value=login.user, style=Pack(flex=1))
    first = toga.PasswordInput(style=Pack(flex=1))
    second = toga.PasswordInput(style=Pack(flex=1))
    trouble = toga.Label("")
    label = Pack(width=110)
    row = Pack(direction=ROW, align_items="center", gap=8)

    def finish(result):
        if not answer.done():
            answer.set_result(result)

    def change(*args, **kwargs):
        phone.hook(app, "end_editing")(app)
        if first.value != second.value:
            trouble.text = "The two passwords differ."
            return
        if not first.value:
            trouble.text = "The new password is empty."
            return
        try:
            new_text, scheme = devicetools.new_login(d, login, text, user.value.strip(), first.value)
        except devicetools.ToolError as e:
            trouble.text = app._wrap(str(e))
            return
        close()
        finish((new_text, user.value.strip(), first.value, scheme))

    def cancel(*args, **kwargs):
        close()
        finish(None)

    note = (devicetools.new_login_note(d) if devicetools.config_kind(d) == "edgeos" else
            "The new password is stored on the device hashed the way it hashes the current one, never as plain text.")
    go = toga.Button("Change", on_press=change)
    second.on_confirm = change
    first.on_confirm = lambda widget, **kwargs: second.focus()
    content = toga.Box(style=Pack(direction=COLUMN, margin=14, gap=10), children=[
        toga.Label(app._wrap(f"{_label(d)}\n{note}")),
        toga.Box(style=row, children=[toga.Label("Username", style=label), user]),
        toga.Box(style=row, children=[toga.Label("New password", style=label), first]),
        toga.Box(style=row, children=[toga.Label("Again", style=label), second]),
        trouble,
        toga.Box(style=Pack(direction=ROW, gap=8), children=[
            toga.Box(style=Pack(flex=1)), toga.Button("Cancel", on_press=cancel), go])])
    ui.style_button(go)
    phone.hook(app, "plain_entry")(user)
    for entry in (first, second):
        phone.hook(app, "plain_entry")(entry, new_password=True)
    close = phone.push_panel(app, "New login", content, on_back=lambda: finish(None))
    first.focus()
    return await answer


# -- config backups --------------------------------------------------------------------
async def backups(app):
    d = app._selected_device()
    if d is None or app.device_job or not d.mac:
        return
    BackupsPage(app, d)


class BackupsPage:
    """The configs kept for the open device, the newest first: Back up now and Upload a file (from
    Files), and for the one picked, Restore (an upload: what changes is shown first), Share and
    Delete."""

    def __init__(self, app, d):
        self.app, self.d, self.backups = app, d, []
        ui = phone.native(app)
        kind = devicetools.config_kind(d)
        grow = Pack(flex=1)
        self.list = toga.DetailedList(accessors=("title", "subtitle", "icon"), on_select=self.picked, style=grow)
        self.state = toga.Label("")
        can = devicetools.offers(d, "backup")[0] and bool(d.ip) and phonessh.available()
        self.opener = phone.hook(app, "open_file")
        self.backup_button = toga.Button("Back up now", on_press=self.backup_now, enabled=can, style=grow)
        self.upload_button = toga.Button("Upload a file", on_press=self.upload_file,
                                         enabled=can and self.opener is not None, style=grow)
        self.restore_button = toga.Button("Restore", on_press=self.restore, enabled=False, style=grow)
        self.share_button = toga.Button("Share", on_press=self.share, enabled=False, style=grow)
        self.delete_button = toga.Button("Delete", on_press=self.delete, enabled=False, style=grow)
        about = app._wrap(f"Copies of {devicetools.CONFIG_FILES.get(kind, 'its config')} kept for {d.mac} on "
                          f"{phone.hook(app, 'here')(app)}. Restore uploads one to it again (the same model only), "
                          "showing what changes first and keeping its current config as a backup.")
        row = Pack(direction=ROW, gap=8)
        content = toga.Box(style=Pack(direction=COLUMN, flex=1, margin=12, gap=8), children=[
            toga.Label(about), self.list, self.state,
            toga.Box(style=row, children=[self.backup_button, self.upload_button]),
            toga.Box(style=row, children=[self.restore_button, self.share_button, self.delete_button])])
        for button, look in ((self.backup_button, ("tinted",)), (self.upload_button, ("tinted",)),
                             (self.restore_button, ("tinted",)), (self.share_button, ("gray",)),
                             (self.delete_button, ("tinted", "systemRedColor"))):
            ui.style_button(button, *look)
        self.page = ui.Page(app, content, on_back=self.closed)
        app.phone_backups = self
        self.refresh()
        self.page.show("Config backups", _label(d))

    def closed(self):
        if getattr(self.app, "phone_backups", None) is self:
            self.app.phone_backups = None

    def refresh(self):
        self.backups = devicetools.list_backups(self.d.mac)
        rows = []
        for b in self.backups:
            version = devicetools.device_version(_FirmwareOf(b.meta)) or b.meta.get("firmware", "")
            size = b.path.stat().st_size if b.path.exists() else 0
            rows.append({"title": b.date, "subtitle": "  ·  ".join(x for x in (b.reason or "backup", version,
                                                                               f"{size:,} bytes") if x),
                         "icon": None, "backup": b})
        self.list.data = rows
        self.state.text = f"{len(self.backups)} kept." if self.backups else "None kept yet."
        self.picked(self.list)

    def _picked(self):
        row = self.list.selection
        return getattr(row, "backup", None) if row is not None else None

    def picked(self, widget, **kwargs):
        backup = self._picked()
        can = devicetools.offers(self.d, "upload")[0] and bool(self.d.ip) and phonessh.available()
        self.restore_button.enabled = backup is not None and can and not self.app.device_job
        self.share_button.enabled = self.delete_button.enabled = backup is not None

    async def backup_now(self, widget, **kwargs):
        app, d = self.app, self.d
        kind = devicetools.config_kind(d)
        login = await phone.ask_route(app, d, f"Log in to back up its config ({devicetools.CONFIG_FILES[kind]}).")
        if not login:
            return
        self.state.text = f"Reading the config of {d.ip}…"
        self.backup_button.enabled = False

        def work():
            text, _pending = devicetools.read_device_config(login, kind)
            return devicetools.save_backup(d, text, kind, "backup")

        try:
            backup = await _work(app, work)
        except (phonessh.SSHError, devicetools.ToolError, OSError) as e:
            self.state.text = app._wrap(f"Backup of {d.ip}: {e}")
            return
        finally:
            self.backup_button.enabled = True
        self.refresh()
        self.state.text = app._wrap(f"Backed up the config of {d.ip} ({backup.date}); {len(self.backups)} kept.")
        app._append_log(f"Config backup of {_label(d)}: {backup.path}", status=False)

    async def upload_file(self, widget, **kwargs):
        path = await self.opener(self.app)
        if path:
            await upload(self.app, self.d, path=path)

    async def restore(self, widget, **kwargs):
        backup = self._picked()
        if backup is not None:
            await upload(self.app, self.d, backup=backup)

    async def share(self, widget, **kwargs):
        backup = self._picked()
        if backup is None:
            return
        name = f"{(self.d.name or self.d.mac or 'device').replace(' ', '_')}_{backup.path.name}"
        await self.app._save_export(name, "Save a copy of the config", [backup.path.suffix.lstrip(".") or "txt"],
                                    lambda path: shutil.copyfile(backup.path, path))

    async def delete(self, widget, **kwargs):
        backup = self._picked()
        if backup is None or not await _alert(self.app, "Delete this backup?",
                                              f"The config taken {backup.date} is deleted from "
                                              f"{phone.hook(self.app, 'here')(self.app)}.", question=True):
            return
        try:
            devicetools.delete_backup(backup)
        except OSError as e:
            self.state.text = self.app._wrap(f"Couldn't delete it: {e.strerror or e}")
            return
        self.refresh()
        phone.update_tools(self.app)


class _FirmwareOf:
    """A backup's firmware string where device_version() looks for it."""

    def __init__(self, meta):
        self.info, self.firmware = {"firmware": str(meta.get("firmware") or "")}, ""


async def upload(app, d, backup=None, path=None):
    """Upload a config to the device: one of its backups (Restore) or a file. It must be the
    device's kind of config and from the same model; what changes is shown first, the device's
    current config is kept as a backup, then the new one is saved (next boot) or applied now."""
    if app.device_job:
        return
    kind = devicetools.config_kind(d)
    try:
        text, meta = (backup.text(), backup.meta) if backup is not None else devicetools.read_config_file(path)
    except (OSError, devicetools.ToolError) as e:
        await _alert(app, "Upload config", str(e))
        return
    source = f"the backup taken {backup.date}" if backup is not None else Path(path).name
    refuse, warn = devicetools.upload_check(d, kind, text, meta)
    if refuse:
        await _alert(app, "Can't upload this config", refuse)
        return
    if warn and not await _alert(app, "Upload this config?", warn + "\n\nGo on?", question=True):
        return
    login = await phone.ask_route(app, d, f"Log in to upload {source}: what changes is shown first.")
    if not login:
        return
    _say(app, f"Reading the config of {d.ip} to compare…", begins=True)
    try:
        current, _pending = await _work(app, devicetools.read_device_config, login, kind)
        tools = await _work(app, devicetools.config_tools, login, kind)
    except (phonessh.SSHError, devicetools.ToolError) as e:
        _say(app, str(e))
        return
    choice = await _changes_page(app, d, kind, current, text, source, tools)
    if not choice:
        _say(app, "Nothing was uploaded.")
        return
    page = getattr(app, "phone_backups", None)
    if page is not None:  # back to Tools, whose console follows the upload
        page.page.close()
        page.closed()
    app.tabs.current_tab = "Tools"
    _begin(app, d, "upload")
    outcome = {}

    def work():
        try:
            kept = devicetools.save_backup(d, current, kind, "before upload")
            app._from_worker(_say, app, f"Kept its current config as a backup ({kept.date}).")
            outcome["said"] = devicetools.push_config(login, kind, text, choice == "apply",
                                                      report=lambda m: app._from_worker(_say, app, m))
        except (devicetools.ToolError, phonessh.SSHError, OSError) as e:
            outcome["error"] = str(e)

    try:
        await _work(app, work)
    finally:
        _end(app)
    _say(app, f"{d.ip}: {outcome.get('said') or outcome.get('error', '')}")


async def _changes_page(app, d, kind, current, text, source, tools):
    """What uploading the config changes on the device, on a page: "save", "apply" or None."""
    answer = app.loop.create_future()
    ui = phone.native(app)
    diff, changed = devicetools.config_diff(current, text)
    boot = "boot config" if kind == "edgeos" else "flash"
    if source.startswith("the "):  # "The backup taken...", a file's name as it is
        source = "The" + source[3:]
    heading = (f"{source}: {changed} line(s) change." if changed
               else f"{source}: no differences, the device has this config already.")
    note = (f"Save writes it to {boot}, for the next reboot. Apply now also applies it: the device restarts what the "
            "changes affect, and the connection can drop for a moment. Either way its current config is kept as a "
            "backup first.") + (f" {terms.RISKS['upload']} {terms.RISKS['apply' if tools['apply'] else 'save']} "
                                f"{terms.TESTED}") + (f" {tools['why']}" if tools["why"] else "")
    view = toga.MultilineTextInput(readonly=True, value=diff or "(no differences)",
                                   style=Pack(flex=1, font_family="monospace", font_size=10))

    def finish(choice):
        if not answer.done():
            answer.set_result(choice)
            close()

    save = toga.Button("Save", on_press=lambda w, **kw: finish("save"), enabled=tools["save"], style=Pack(flex=1))
    apply = toga.Button("Apply now", on_press=lambda w, **kw: finish("apply"), enabled=tools["apply"],
                        style=Pack(flex=1))
    cancel = toga.Button("Cancel", on_press=lambda w, **kw: finish(None), style=Pack(flex=1))
    content = toga.Box(style=Pack(direction=COLUMN, flex=1, margin=12, gap=8), children=[
        toga.Label(app._wrap(heading)), view, toga.Label(app._wrap(note)),
        toga.Box(style=Pack(direction=ROW, gap=8), children=[cancel, save, apply])])
    for button, look in ((cancel, "gray"), (save, "tinted"), (apply, "filled")):
        ui.style_button(button, look)
    ui.monospaced(view, 10)
    close = phone.push_panel(app, "Upload config", content, on_back=lambda: answer.done() or answer.set_result(None))
    return await answer


# -- reboot and locate -------------------------------------------------------------------
async def reboot(app):
    """Restart the open device (asked first) and wait until it's back; Stop stops the waiting."""
    job = app.device_job
    if job:
        if job["name"] == "reboot" and job["stop"]:
            job["stop"].set()
            _say(app, "Stopping…")
        return
    d = app._selected_device()
    if d is None or not _offered(app, d, "reboot"):
        return
    hops = phone.route(app, d)
    text = (f"{_label(d)} restarts and is offline for a minute or two, longer for some models: whatever goes "
            "through it stops meanwhile.")
    if hops:
        text += f" It's reached through {', '.join(h.ip or h.mac for h in hops)}."
    text += "\n\n" + terms.risk("reboot")
    if not await _alert(app, f"Reboot {d.ip}?", text, question=True):
        return
    login = await phone.ask_route(app, d, "Log in to reboot it.")
    if not login:
        return
    stop = threading.Event()
    _begin(app, d, "reboot", stop)
    _say(app, f"Rebooting {d.ip}…", begins=True)
    outcome, report = {}, _reporter(app)

    def work():
        try:
            outcome["took"] = devicetools.reboot(login, d, report=report, stop=stop)
        except (devicetools.ToolError, phonessh.SSHError) as e:
            outcome["error"] = str(e)

    try:
        await _work(app, work)
    finally:
        _end(app)
    _say(app, f"{d.ip}: {outcome.get('error') or 'Rebooted: back after %.0f s.' % outcome['took']}")


async def locate(app):
    """Blink the open device's LED (UniFi access points and switches); again stops it."""
    d = app._selected_device()
    if d is None:
        return
    login = app.phone_locating.get(d.key)
    if login is not None:
        try:
            await _work(app, devicetools.locate, login, d, False)
        except (devicetools.ToolError, phonessh.SSHError) as e:
            _say(app, f"Stop locating {d.ip}: {e}")
            return
        app.phone_locating.pop(d.key, None)
        _say(app, f"{d.ip}: its LED is back to normal.")
        phone.update_tools(app)
        return
    if app.device_job or not _offered(app, d, "locate"):
        return
    login = await phone.ask_route(app, d, "Log in to blink its LED.")
    if not login:
        return
    try:
        state = await _work(app, devicetools.locate, login, d, True)
    except (devicetools.ToolError, phonessh.SSHError) as e:
        _say(app, f"Locate {d.ip}: {e}")
        return
    app.phone_locating[d.key] = login
    said = "" if state else (" It doesn't say it's locating: it may be busy (upgrading)." if state is False
                             else " It doesn't say whether it took.")
    _say(app, f"{d.ip}: its LED is blinking.{said} Stop locating stops it.", begins=True)
    phone.update_tools(app)


# -- link health (airMAX) ------------------------------------------------------------
async def link(app):
    """Read the open radio's link health (linkhealth): its own link, and each station's on an
    access point, into Details, with what's flagged in the console."""
    d = app._selected_device()
    if d is None or app.device_job or not _offered(app, d, "link"):
        return
    login = await phone.ask_route(app, d, "Log in to read its link health: signal, noise floor, SNR, capacity, "
                                          "airtime and distance, its own and each station's on an access point.")
    if not login:
        return
    _begin(app, d, "link")
    _say(app, f"Reading the link health of {d.ip}…", begins=True)
    try:
        reading = await _work(app, devicetools.read_link, login)
    except (devicetools.ToolError, phonessh.SSHError) as e:
        _say(app, f"Link health of {d.ip}: {e}")
        return
    finally:
        _end(app)
    linkhealth.keep(d, reading)
    app._rediagnose()  # its issues, in the list and Details
    if app._selected_device() is d:
        app.details.value = core.render_details(d)
    found = [msg.split(". ")[0] + "." for _, _, msg in linkhealth.issues(d)]  # what, without the advice
    if found:
        phone.say(app, "\n".join(found))
    _say(app, linkhealth.summary(d) + " Details has every number.")


# -- scan from a device given by its address -----------------------------------------
async def scan_address(app):
    """Log in to a device by its address (one the scan didn't find, over a VPN, say), list it,
    and what it sees under it, as Scan from device does."""
    if app.running or app.rescanning or app.finding or app.device_job:
        app.status.text = "Works once the scan has finished."
        return
    if not phonessh.available():
        app.status.text = "Scan from an address needs the app's SSH, which didn't load."
        return
    login = await _address_page(app)
    if not login:
        return
    if app.running or app.rescanning or app.finding:
        app.status.text = "A scan started meanwhile: scan from the address again once it has finished."
        return
    result = app.result or core.ScanResult(core.parse_args([]), [], [], [], [], [], [], core.Inventory(), None, 0.0)
    app.rescanning = True
    app.spinner.start()
    app.status.text = f"Reading what {login.ip} sees…"
    try:
        finder, sightings, seen, new = await _work(app, devicetools.scan_from_address, result, login,
                                                   core.local_macs())
    except (phonessh.SSHError, devicetools.ToolError) as e:
        app.status.text = f"Scan from {login.ip}: {e}"
        return
    finally:
        app.rescanning = False
        app.spinner.stop()
    if app.result is None and not app.running:
        app.result = result  # the list's devices from now on, as a scan's would be
        app.export_button.enabled = True
    elif result is not app.result:
        app.status.text = f"Scan from {login.ip} finished after a new scan started: start it again."
        return
    app._show_devices(result.devices)
    if not finder.ubnt_packets:  # what it is: UBNT discovery sent straight to it, as Rescan does
        key = finder.key
        await _reread(app, finder)
        finder = (result.inv.find(mac=finder.mac) if finder.mac else None) or result.inv.find(ip=login.ip) or finder
        devicetools.relink(result, key, finder)
        app._show_devices(result.devices)
    app.phone_passwords[finder.key] = login.password
    if finder.mac:
        app.settings.setdefault("device_logins", {})[finder.mac] = {"user": login.user, "port": login.port}
    app.settings["ssh_user"] = login.user
    app._save_settings()
    counts = ", ".join(f"{devicetools.SCAN_HOW[how]} {n}" for how in devicetools.SCAN_HOW
                       if (n := sum(1 for s in sightings if s.how == how)))
    lines = [f"Scan from {login.ip}: {counts or 'nothing listed'}; {len(seen)} device(s), {len(new)} new."]
    for dev in seen:
        lines.append(f"  {dev.ip or '-':15} {dev.name or dev.model or dev.mac or ''}{'  (new)' if dev in new else ''}")
    app._append_log("\n".join(lines), status=False)
    app.status.text = lines[0]
    await phone.warn_factory_login(app, finder, login)


async def _address_page(app):
    """A page asking for a device's address, port and login; it logs in once to check them and
    closes when that works: the login, or None when cancelled."""
    answer = app.loop.create_future()
    ui = phone.native(app)
    address = toga.TextInput(placeholder="e.g. 10.20.0.1", style=Pack(flex=1))
    port = toga.TextInput(value="22", style=Pack(flex=1))
    user = toga.TextInput(value=app.settings.get("ssh_user") or "", placeholder="e.g. ubnt or admin",
                          style=Pack(flex=1))
    password = toga.PasswordInput(style=Pack(flex=1))
    trouble = toga.Label("")
    label = Pack(width=90)
    row = Pack(direction=ROW, align_items="center", gap=8)

    def finish(login):
        if not answer.done():
            answer.set_result(login)

    async def log_in(*args, **kwargs):
        phone.hook(app, "end_editing")(app)
        ip, text = address.value.strip(), port.value.strip()
        if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip) or not core._usable_ip(ip):
            trouble.text = "The address is an IPv4 address, such as 10.20.0.1."
            return
        if not text.isdigit() or not 0 < int(text) < 65536:
            trouble.text = "The port is a number from 1 to 65535."
            return
        if not user.value.strip():
            trouble.text = "Logging in needs a username."
            return
        known = app.result.inv.find(ip=ip) if app.result else None
        login = phonessh.Login(ip, int(text), user.value.strip(), password.value,
                               phonessh.host_key_alias(known.mac if known else None, ip), app.known_hosts)
        go.enabled = False
        trouble.text = f"Logging in to {ip}…"
        try:
            await _work(app, phonessh.check_login, login)
        except phonessh.SSHError as e:
            trouble.text = app._wrap(str(e))
            go.enabled = True
            return
        close()
        finish(login)

    def cancel(*args, **kwargs):
        close()
        finish(None)

    go = toga.Button("Log in and scan", on_press=lambda w, **kw: app.loop.create_task(log_in()))
    password.on_confirm = lambda w, **kw: app.loop.create_task(log_in())
    cancel_button = toga.Button("Cancel", on_press=cancel)
    content = toga.Box(style=Pack(direction=COLUMN, margin=14, gap=10), children=[
        toga.Label(app._wrap("Log in to a device by its address, one the scan didn't find (over a VPN, say), to list "
                             "what it sees: its ARP table, LLDP neighbours and, on airOS, its stations. They're "
                             "listed under it, and the device tools reach them through it.")),
        toga.Box(style=row, children=[toga.Label("Address", style=label), address]),
        toga.Box(style=row, children=[toga.Label("Port", style=label), port]),
        toga.Box(style=row, children=[toga.Label("Username", style=label), user]),
        toga.Box(style=row, children=[toga.Label("Password", style=label), password]),
        trouble,
        toga.Box(style=Pack(direction=ROW, gap=8), children=[toga.Box(style=Pack(flex=1)), cancel_button, go])])
    ui.style_button(go)
    ui.style_button(cancel_button, "gray")
    for entry in (address, port, user, password):
        phone.hook(app, "plain_entry")(entry)
    close = phone.push_panel(app, "Scan from an address", content, on_back=lambda: finish(None))
    address.focus()
    return await answer
