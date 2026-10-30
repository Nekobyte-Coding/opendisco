"""The device tools on the phones, as devicegui does them on the desktop, from the Tools tab
(phone.py): firmware check and update, the config editor (airMAX, airFiber, LTU, EdgeOS), config
backups (back up, compare, restore, upload a file, share, delete; back up all), a new login,
Reboot, Locate, Link health (airMAX: into Details), and Scan from a device given by its address
(the title bar's +).

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

from opendisco import core, devicetools, i18n, linkhealth, phone, phonessh, terms
from opendisco.i18n import N_, _, tr


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
    retitle(app.firmware_button, _("Stop") if stoppable == "firmware" else _("Firmware"))
    app.firmware_button.enabled = (idle and ubiquiti) or stoppable == "firmware"
    for button, action in ((app.config_button, "edit"), (app.login_button, "login"), (app.reboot_button, "reboot")):
        button.enabled = idle and devicetools.offers(d, action)[0] and ssh
    retitle(app.reboot_button, _("Stop") if stoppable == "reboot" else _("Reboot"))
    app.reboot_button.enabled = app.reboot_button.enabled or stoppable == "reboot"
    kept = bool(d and d.mac and devicetools.list_backups(d.mac))
    app.backups_button.enabled = bool(d and d.mac) and not job and (
        kept or (idle and devicetools.offers(d, "backup")[0] and ssh))
    locating = bool(d and d.key in app.phone_locating)
    retitle(app.locate_button, _("Stop locating") if locating else _("Locate"))
    app.locate_button.enabled = locating or (idle and devicetools.offers(d, "locate")[0] and ssh)
    app.link_button.enabled = idle and devicetools.offers(d, "link")[0] and ssh
    backing_up = bool(job and job["name"] == "backup_all")
    retitle(app.backup_all_button, _("Stop") if backing_up else _("Back up all"))
    app.backup_all_button.enabled = backing_up or (ssh and bool(app.result) and not (
        app.running or app.rescanning or app.finding or job))


def _begin(app, d, name: str, stop: threading.Event | None = None) -> dict | None:
    """Take the one job a phone runs at a time. None (and it says so) when another took it
    meanwhile: a flow checks on its first tap, then waits for questions and the network, and a
    second tap could get there too (two firmware installs on one radio)."""
    if app.device_job:
        _say(app, tr("{device}: wait for what's running to finish.", device=_label(d)))
        return None
    job = app.device_job = {"key": d.key, "name": name, "stop": stop}
    app.spinner.start()
    phone.update_tools(app)
    return job


def _end(app, job=None):
    """Give the job back: that one only (job), when given."""
    if job is not None and app.device_job is not job:
        return
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
        _say(app, tr("{device}: {reason}.", device=_label(d), reason=why))
    return ok


# -- firmware ----------------------------------------------------------------------------
async def firmware(app):
    """Ask Ubiquiti's firmware server about the open device, then offer to update it; Stop
    while a download runs."""
    job = app.device_job
    if job:
        if job["name"] == "firmware" and job["stop"]:
            job["stop"].set()
            _say(app, _("Stopping…"))
        return
    d = app._selected_device()
    if d is None:
        return
    _say(app, tr("Asking Ubiquiti's firmware server about {device}…", device=d.ip or d.mac), begins=True)
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
    if await _alert(app, tr("Firmware {version}", version=check.latest),
                    tr("{device} runs {current}. Install {latest} now?", device=_label(d), current=check.current,
                       latest=check.latest), question=True):
        await _update(app, d, check)


async def _update(app, d, check):
    login = await phone.ask_route(app, d, tr("Log in to install firmware {version}.", version=check.latest))
    if not login:
        return
    family = devicetools.FAMILY_NAMES[devicetools.family(d)]
    size = devicetools.fmt_size(check.size)
    message = tr("Install {family} firmware {version} on {device}? It runs {current} now.\n\n"
                 "OpenDisco downloads it from Ubiquiti ({size}), checks it, copies it to the device and starts the "
                 "installation. The device restarts to install it and is offline for a few minutes: don't unplug it "
                 "or turn it off until it's back.", family=family, version=check.latest, device=_label(d),
                 current=check.current, size=size)
    if devicetools.family(d) == "edgeos":
        _say(app, tr("Reading the firmware images of {ip}…", ip=d.ip))
        try:
            note = await _work(app, devicetools.edgeos_update_note, login, check.latest)
        except (devicetools.ToolError, phonessh.SSHError) as e:
            _say(app, tr("Firmware update of {ip}: {error}", ip=d.ip, error=e))
            return
        message = tr("Install EdgeOS firmware {version} on {device}? It runs {current} now.\n\n"
                     "OpenDisco downloads it from Ubiquiti ({size}), checks it, copies it to the router and adds it "
                     "with EdgeOS's add system image. Once EdgeOS lists it as the image it boots, OpenDisco restarts "
                     "the router, which is offline for a few minutes: don't unplug it or turn it off until it's back."
                     "\n\n{note}", version=check.latest, device=_label(d), current=check.current, size=size, note=note)
    if devicetools.family(d) in ("unifi", "unifi-os"):
        message += "\n\n" + _("Ubiquiti's help center describes updating over SSH as a last resort, for when the "
                               "UniFi app can't update the device.")
    message += "\n\n" + terms.risk("firmware")
    if not await _alert(app, _("Install firmware?"), message, question=True):
        return
    stop = threading.Event()
    job = _begin(app, d, "firmware", stop)
    if job is None:
        return
    folder = Path(app.paths.cache) / "firmware"
    outcome, report = {}, _reporter(app)

    def no_stop():
        job["stop"] = None  # past the point where stopping leaves the device as it was
        phone.update_tools(app)

    def work():
        path = None
        try:
            report(tr("Downloading firmware {version} from Ubiquiti…", version=check.latest), 0)
            path = devicetools.download_release(
                check.release, folder, stop=stop,
                progress=lambda done, total: report(None, 100 * done / total if total else None))
            report(tr("Downloaded and checked (SHA-256 {checksum}…).",
                      checksum=check.release['sha256_checksum'][:16]), 100)

            def step(text, percent=None):
                if text and text in map(_, devicetools.INSTALL_STARTS):  # (past cancelling)
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
        _end(app, job)
    if "error" in outcome:
        text = outcome["error"]
        if stop.is_set() and ("Cancelled" in text or _("Cancelled.") in text):
            text = _("Stopped. Nothing was installed.")
        _say(app, tr("Firmware update of {ip}: {error}", ip=d.ip, error=text))
        return
    _say(app, tr("Back after {seconds:.0f} s. Reading its firmware again…", seconds=outcome['offline']))
    now = await _reread(app, d)
    if now is None:
        _say(app, tr("{ip} is back: rescan it to see the version it runs.", ip=d.ip))
    elif devicetools.version_key(now) == devicetools.version_key(check.latest):
        _say(app, tr("Updated: {ip} runs {version}.", ip=d.ip, version=now))
    else:
        _say(app, tr("{ip} is back, but reports firmware {version}, not {latest}.", ip=d.ip,
                     version=now or _("unknown"), latest=check.latest))


async def _reread(app, d) -> str | None:
    """Rescan the device for the firmware it reports now; None when a scan is busy or it didn't answer."""
    found = await app.reread(d)
    return devicetools.device_version(found[0]) if found and found[1] else None


# -- the config editor -----------------------------------------------------------------
async def config(app):
    d = app._selected_device()
    if d is None or app.device_job or not _offered(app, d, "edit"):
        return
    kind = devicetools.config_kind(d)
    login = await phone.ask_route(app, d, tr("Log in to read its configuration ({file}).",
                                             file=devicetools.CONFIG_FILES[kind]))
    if not login:
        return
    _say(app, tr("Reading the config of {ip}…", ip=d.ip), begins=True)
    try:
        text, pending = await _work(app, devicetools.read_device_config, login, kind)
        tools = await _work(app, devicetools.config_tools, login, kind)
    except (phonessh.SSHError, devicetools.ToolError) as e:
        _say(app, str(e))
        return
    _say(app, tr("Read the config of {ip}.", ip=d.ip))
    ConfigPage(app, d, login, text, pending, kind, tools)


ABOUT_CONFIG = {  # (templates: _() and .format(file=...) where shown)
    "airos": N_("{file}, one setting per line. Save writes it to flash for the next reboot; Apply saves it and "
                "applies it now, as the web UI's Apply does (the connection can drop for a moment)."),
    "edgeos": N_("{file}, EdgeOS's boot config. Save checks that EdgeOS reads it and makes it the boot config, for "
                 "the next reboot; Apply loads, commits and saves it now (the connection can drop for a moment)."),
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
        self.writing = False  # Save or Apply on its way to the device
        ui = phone.native(app)
        self.box = toga.MultilineTextInput(value=text, style=Pack(flex=1, font_family="monospace", font_size=10))
        self.state = toga.Label("")
        self.buttons = [toga.Button(_("Reload"), on_press=self.reload, style=Pack(flex=1)),
                        toga.Button(_("Save"), on_press=lambda w, **kw: app.loop.create_task(self._write(False)),
                                    style=Pack(flex=1)),
                        toga.Button(_("Apply"), on_press=lambda w, **kw: app.loop.create_task(self._write(True)),
                                    style=Pack(flex=1))]
        about = _(ABOUT_CONFIG[kind]).format(file=devicetools.CONFIG_FILES[kind])
        if d.mac:
            about = i18n.sentences(about, _("What it has is kept as a backup before each write."))
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
        self.page.show(_("Config"), _label(d))

    def _pending(self, pending):
        self.state.text = self.app._wrap(_("It has changes that aren't applied yet (made in its web UI, or saved "
                                           "without applying).") if pending else self.tools["why"])

    def _changed(self) -> bool:
        return self.box.value.replace("\r", "") != self.saved.replace("\r", "")

    def leaving(self):
        """Back: with edits not saved, ask; keeping them shows the page again. (Not while they're
        being written: they're on their way.)"""
        if self._changed() and not self.writing:
            self.app.loop.create_task(self._discard_or_keep())

    async def _discard_or_keep(self):
        if not await _alert(self.app, _("Discard the changes?"), _("The edits haven't been saved to the device."),
                            question=True):
            self.page.show(_("Config"), _label(self.d))

    def _enable(self, on: bool):
        reload, save, apply = self.buttons
        reload.enabled = on
        save.enabled = on and self.tools["save"]
        apply.enabled = on and self.tools["apply"]

    async def reload(self, widget, **kwargs):
        self._enable(False)
        self.state.text = _("Reading…")
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
            heading = (_("EdgeOS wouldn't read it:") if self.kind == "edgeos"
                       else _("airOS reads only key=value lines. These aren't:"))
            await app.main_window.dialog(toga.ErrorDialog(_("Not a config"), heading + "\n" + "\n".join(problems[:10])))
            return
        changed = devicetools.lines_changed(self.saved, text)
        edgeos, device = self.kind == "edgeos", _label(self.d)
        if apply:
            what = tr("Apply the config on {device}?", device=device)
            then = (_("It's applied now and saved to boot config; the device restarts what the changes affect.")
                    if edgeos else
                    _("It's applied now and saved to flash; the device restarts what the changes affect."))
        else:
            what = (tr("Save the config to boot config on {device}?", device=device) if edgeos
                    else tr("Save the config to flash on {device}?", device=device))
            then = _("It takes effect at the next reboot.")
        changes = tr("{count} line(s) changed.", count=changed) if changed else _("Nothing changed here.")
        detail = i18n.sentences(changes, then) + "\n\n" + terms.risk("apply" if apply else "save")
        if not await _alert(app, what, detail, question=True):
            return
        job = _begin(app, self.d, "config")  # (the one job: no reboot or second write meanwhile)
        if job is None:
            return
        self.writing = True
        self._enable(False)
        self.state.text = _("Applying…") if apply else _("Saving…")
        def work():
            if self.d.mac:  # what it had, kept before it's replaced
                devicetools.save_backup(self.d, self.saved, self.kind, N_("before edit"))  # (kept in English)
            return devicetools.push_config(self.login, self.kind, text, apply,
                                           report=lambda m: app._from_worker(setattr, self.state, "text", app._wrap(m)))

        try:
            message = await _work(app, work)
        except devicetools.LostConnection as e:  # what it means for the device, as far as it's known
            self.state.text = app._wrap(str(e))
            await app.main_window.dialog(toga.ErrorDialog(_("Connection lost"), str(e)))
        except (devicetools.ToolError, phonessh.SSHError, OSError) as e:
            self.state.text = app._wrap(str(e))
            _say(app, f"{self.d.ip}: {e}")  # (also when the page was left meanwhile)
        else:
            self.saved = text
            self.state.text = app._wrap(message)
            _say(app, f"{self.d.ip}: {message}")
        finally:
            self.writing = False
            _end(app, job)
        self._enable(True)


# -- a new login -----------------------------------------------------------------------
async def change_login(app):
    d = app._selected_device()
    if d is None or app.device_job or not _offered(app, d, "login"):
        return
    login = await phone.ask_route(app, d, _("Log in with its current username and password first."))
    if not login:
        return
    kind = devicetools.config_kind(d)  # "airos" or "edgeos"
    _say(app, tr("Reading the config of {ip}…", ip=d.ip), begins=True)
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
        _say(app, _("The login wasn't changed."))
        return
    new_text, new_user, new_password, scheme = answer
    same = new_user == login.user
    what = (tr("Change the password of {user} on {device}?", user=login.user, device=_label(d)) if same
            else tr("Change the login of {device} from {user} to {new_user} with the new password?", device=_label(d),
                    user=login.user, new_user=new_user))
    if kind == "edgeos":
        message = i18n.sentences(what, _("EdgeOS commits it right away and saves it to its boot config; the old "
                                         "password stops working.") if same else
                                 _("EdgeOS commits it right away and saves it to its boot config; the old login "
                                   "stops working."))
        if not same:
            message += "\n\n" + tr("As Ubiquiti's help center does it, {new_user} is made first, with {user}'s level "
                                    "and settings, and OpenDisco logs in with it; only then is {user} deleted, logged "
                                    "in as {new_user}.", new_user=new_user, user=login.user)
        message += "\n\n" + _("EdgeOS hashes the password itself and stores it so, never as plain text.")
        if pending:
            message += "\n\n" + _("Its config also has changes that are committed but not saved (in its CLI): saving "
                                   "the new login saves them too.")
    else:
        message = (i18n.sentences(what, _("It's applied right away and saved to flash; the old login stops working."))
                   + "\n\n" + tr("The password is stored on the device as an {scheme} hash, the format it uses now.",
                                  scheme=scheme))
        if pending:
            message += "\n\n" + _("Its config also has changes that aren't applied yet (made in its web UI, or saved "
                                   "without applying): they're applied with it.")
    message += "\n\n" + terms.risk("login")
    if not await _alert(app, _("Change login?"), message, question=True):
        _say(app, _("The login wasn't changed."))
        return
    new = phonessh.Login(login.ip, login.port, new_user, new_password, login.alias, login.known_hosts, login.via,
                         login.nested)
    job = _begin(app, d, "login")
    if job is None:
        return
    outcome = {}

    def work():
        report = lambda m: app._from_worker(_say, app, m)  # noqa: E731
        try:
            if d.mac:  # what it had, kept before it's replaced
                devicetools.save_backup(d, text, kind, N_("before login change"))  # (kept in English)
            if kind == "edgeos":  # new_text: the steps; it logs in with the new login itself
                outcome["said"] = devicetools.change_edgeos_login(login, new, new_text, report=report)
                return
            outcome["said"] = devicetools.write_config(login, new_text, True, new_login=new, report=report)
            app._from_worker(_say, app, _("Logging in with the new login…"))
            phonessh.check_login(new)
        except (devicetools.ToolError, phonessh.SSHError, OSError) as e:
            outcome["error"] = str(e)

    try:
        await _work(app, work)
    finally:
        _end(app, job)
    if "error" in outcome:
        _say(app, tr("{error} If the device takes neither login now, its web UI or a reset to factory defaults gets "
                     "it back.", error=outcome['error']))
        return
    app.phone_passwords[d.key] = new_password
    devicetools.forget_factory_login(d)
    if d.mac:
        app.settings.setdefault("device_logins", {})[d.mac] = {"user": new_user, "port": login.port}
    app._save_settings()
    app._rediagnose()
    _say(app, tr("Done: {ip} takes the new login ({user}). {said}", ip=d.ip, user=new_user, said=outcome['said'])
         if kind == "edgeos" else tr("Done: {ip} takes the new login ({user}), applied and saved to flash.", ip=d.ip,
                                     user=new_user))


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
            trouble.text = _("The two passwords differ.")
            return
        if not first.value:
            trouble.text = _("The new password is empty.")
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
            _("The new password is stored on the device hashed the way it hashes the current one, never as plain "
              "text."))
    go = toga.Button(_("Change"), on_press=change)
    second.on_confirm = change
    first.on_confirm = lambda widget, **kwargs: second.focus()
    content = toga.Box(style=Pack(direction=COLUMN, margin=14, gap=10), children=[
        toga.Label(app._wrap(f"{_label(d)}\n{note}")),
        toga.Box(style=row, children=[toga.Label(_("Username"), style=label), user]),
        toga.Box(style=row, children=[toga.Label(_("New password"), style=label), first]),
        toga.Box(style=row, children=[toga.Label(_("Again"), style=label), second]),
        trouble,
        toga.Box(style=Pack(direction=ROW, gap=8), children=[
            toga.Box(style=Pack(flex=1)), toga.Button(_("Cancel"), on_press=cancel), go])])
    ui.style_button(go)
    phone.hook(app, "plain_entry")(user)
    for entry in (first, second):
        phone.hook(app, "plain_entry")(entry, new_password=True)
    close = phone.push_panel(app, _("New login"), content, on_back=lambda: finish(None))
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
    Files), and for the one picked, Compare (with another backup, or with its config now), Restore
    (an upload: what changes is shown first), Share and Delete."""

    def __init__(self, app, d):
        self.app, self.d, self.backups = app, d, []
        ui = phone.native(app)
        kind = devicetools.config_kind(d)
        grow = Pack(flex=1)
        self.list = toga.DetailedList(accessors=("title", "subtitle", "icon"), on_select=self.picked, style=grow)
        self.state = toga.Label("")
        can = devicetools.offers(d, "backup")[0] and bool(d.ip) and phonessh.available()
        self.opener = phone.hook(app, "open_file")
        self.backup_button = toga.Button(_("Back up now"), on_press=self.backup_now, enabled=can, style=grow)
        self.upload_button = toga.Button(_("Upload a file"), on_press=self.upload_file,
                                         enabled=can and self.opener is not None, style=grow)
        self.compare_button = toga.Button(_("Compare"), on_press=self.compare, enabled=False, style=grow)
        self.restore_button = toga.Button(_("Restore"), on_press=self.restore, enabled=False, style=grow)
        self.share_button = toga.Button(_("Share"), on_press=self.share, enabled=False, style=grow)
        self.delete_button = toga.Button(_("Delete"), on_press=self.delete, enabled=False, style=grow)
        about = app._wrap(tr("Copies of {file} kept for {mac} on {device}. Compare shows what differs from another "
                             "backup or its config now. Restore uploads one to it again (the same model only), showing "
                             "what changes first and keeping its current config as a backup.",
                             file=devicetools.CONFIG_FILES.get(kind) or _("its config"), mac=d.mac,
                             device=phone.hook(app, "here")(app)))
        row = Pack(direction=ROW, gap=8)
        content = toga.Box(style=Pack(direction=COLUMN, flex=1, margin=12, gap=8), children=[
            toga.Label(about), self.list, self.state,
            toga.Box(style=row, children=[self.backup_button, self.upload_button]),
            toga.Box(style=row, children=[self.compare_button, self.restore_button]),
            toga.Box(style=row, children=[self.share_button, self.delete_button])])
        for button, look in ((self.backup_button, ("tinted",)), (self.upload_button, ("tinted",)),
                             (self.compare_button, ("tinted",)), (self.restore_button, ("tinted",)),
                             (self.share_button, ("gray",)), (self.delete_button, ("tinted", "systemRedColor"))):
            ui.style_button(button, *look)
        self.page = ui.Page(app, content, on_back=self.closed)
        app.phone_backups = self
        self.refresh()
        self.page.show(_("Config backups"), _label(d))

    def closed(self):
        if getattr(self.app, "phone_backups", None) is self:
            self.app.phone_backups = None

    def refresh(self):
        self.backups = devicetools.list_backups(self.d.mac)
        self.list.data = [_backup_row(b) for b in self.backups]
        self.state.text = tr("{count} kept.", count=len(self.backups)) if self.backups else _("None kept yet.")
        self.picked(self.list)

    def _picked(self):
        row = self.list.selection
        return getattr(row, "backup", None) if row is not None else None

    def picked(self, widget, **kwargs):
        backup = self._picked()
        can = devicetools.offers(self.d, "upload")[0] and bool(self.d.ip) and phonessh.available()
        self.restore_button.enabled = backup is not None and can and not self.app.device_job
        self.share_button.enabled = self.delete_button.enabled = backup is not None
        self.compare_button.enabled = backup is not None and (len(self.backups) > 1 or self._reads())

    def _reads(self) -> bool:
        """Whether its config now can be read, to compare."""
        return (devicetools.offers(self.d, "backup")[0] and bool(self.d.ip) and phonessh.available()
                and not self.app.device_job)

    async def compare(self, widget, **kwargs):
        """What differs between the backup picked and another one, or its config now: the other
        is picked on a page of its own."""
        backup = self._picked()
        if backup is None:
            return
        others = [b for b in self.backups if b.path != backup.path]
        other = await _compare_with(self.app, self.d, backup, others, self._reads())
        if other is None:
            return
        app, d = self.app, self.d
        kind = devicetools.config_kind(d) or str(backup.meta.get("kind") or "")
        try:
            if other != "now":
                backup, other = sorted((backup, other), key=lambda b: b.when)  # the older first
            old, new = backup.text(), other.text() if other != "now" else None
        except OSError as e:
            self.state.text = app._wrap(tr("Can't read it: {error}", error=e.strerror or e))
            return
        names = (tr("backup {date}", date=backup.date),
                 _("on the device now") if other == "now" else tr("backup {date}", date=other.date))
        if other == "now":
            login = await phone.ask_route(app, d, tr("Log in to read its config ({file}) and compare it with the "
                                                     "backup taken {date}.", file=devicetools.CONFIG_FILES[kind],
                                                     date=backup.date))
            if not login:
                return
            self.state.text = tr("Reading the config of {ip}…", ip=d.ip)
            self.compare_button.enabled = False
            try:
                new = await _work(app, devicetools.read_current, login, kind)
            except (phonessh.SSHError, devicetools.ToolError) as e:
                self.state.text = app._wrap(f"{d.ip}: {e}")
                return
            finally:
                self.picked(self.list)
            self.state.text = ""
        diff, changed = devicetools.config_diff(old, new, *names)
        if other == "now":
            heading = (tr("{count} line(s) differ between the backup {date} and the config on the device now.",
                          count=changed, date=backup.date) if changed
                       else tr("No differences between the backup {date} and the config on the device now.",
                               date=backup.date))
        else:
            heading = (tr("{count} line(s) differ between the backup {date} and the backup {other}.", count=changed,
                          date=backup.date, other=other.date) if changed
                       else tr("No differences between the backup {date} and the backup {other}.", date=backup.date,
                               other=other.date))
        note = tr("Lines marked - are only in the first ({first}), + only in the second ({second}); the ones around "
                  "them are in both, for context.", first=names[0], second=names[1])
        buttons = [(_("Done"), None, True, "gray")]
        if other == "now":  # the config now can be kept, unless the last backup has it already
            same = bool(self.backups) and self.backups[0].holds(new)
            buttons.append((_("Same as last backup") if same else _("Keep as a backup"), "keep", not same, "filled"))
        if await _diff_page(app, _("Compare configs"), heading, diff, note, buttons) != "keep":
            return
        try:
            kept = devicetools.save_backup(d, new, kind, N_("backup"))
        except (OSError, devicetools.ToolError) as e:
            self.state.text = app._wrap(tr("Couldn't keep it: {error}", error=getattr(e, 'strerror', None) or e))
            return
        self.refresh()
        self.state.text = app._wrap(tr("Kept its config now as a backup ({date}); {count} kept.", date=kept.date,
                                       count=len(self.backups)))
        app._append_log(tr("Config backup of {device}: {path}", device=_label(d), path=kept.path), status=False)

    async def backup_now(self, widget, **kwargs):
        app, d = self.app, self.d
        kind = devicetools.config_kind(d)
        login = await phone.ask_route(app, d, tr("Log in to back up its config ({file}).",
                                                 file=devicetools.CONFIG_FILES[kind]))
        if not login:
            return
        job = _begin(app, d, "backup")  # (the one job: the demo, say, doesn't end under it)
        if job is None:
            return
        self.state.text = tr("Reading the config of {ip}…", ip=d.ip)
        self.backup_button.enabled = False

        def work():
            text, _pending = devicetools.read_device_config(login, kind)
            return devicetools.save_backup(d, text, kind, N_("backup"))

        try:
            backup = await _work(app, work)
        except (phonessh.SSHError, devicetools.ToolError, OSError) as e:
            self.state.text = app._wrap(tr("Backup of {ip}: {error}", ip=d.ip, error=e))
            return
        finally:
            self.backup_button.enabled = True
            _end(app, job)
        self.refresh()
        self.state.text = app._wrap(tr("Backed up the config of {ip} ({date}); {count} kept.", ip=d.ip,
                                       date=backup.date, count=len(self.backups)))
        app._append_log(tr("Config backup of {device}: {path}", device=_label(d), path=backup.path), status=False)

    async def upload_file(self, widget, **kwargs):
        try:
            path = await self.opener(self.app)
        except Exception as e:  # too big, not available offline, refused by its app: said, not lost
            self.state.text = self.app._wrap(tr("Couldn't open the file: {error}", error=getattr(e, "strerror", None)
                                                or e))
            return
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
        await self.app._save_export(name, _("Save a copy of the config"), [backup.path.suffix.lstrip(".") or "txt"],
                                    lambda path: shutil.copyfile(backup.path, path))

    async def delete(self, widget, **kwargs):
        backup = self._picked()
        if backup is None or not await _alert(self.app, _("Delete this backup?"),
                                              tr("The config taken {date} is deleted from {device}.", date=backup.date,
                                                 device=phone.hook(self.app, "here")(self.app)), question=True):
            return
        try:
            devicetools.delete_backup(backup)
        except OSError as e:
            self.state.text = self.app._wrap(tr("Couldn't delete it: {error}", error=e.strerror or e))
            return
        self.refresh()
        phone.update_tools(self.app)


def _backup_row(b) -> dict:
    """A backup's row in a list: when it was taken; why, the firmware it ran and its size."""
    version = b.version
    size = b.path.stat().st_size if b.path.exists() else 0
    reason = _(b.reason) if b.reason else _("backup")  # (kept in English: "before edit"...)
    return {"title": b.date, "subtitle": "  ·  ".join(x for x in (reason, version, tr("{size:,} bytes", size=size))
                                                      if x), "icon": None, "backup": b}


async def _compare_with(app, d, backup, others, reads: bool):
    """A page listing what the backup can be compared with: the device's config now (when it can
    be read), then its other backups. Returns "now", a Backup, or None when it's left."""
    answer = app.loop.create_future()
    rows = ([{"title": _("Its config now"), "subtitle": tr("Read from {ip} over SSH", ip=d.ip), "icon": None,
              "backup": "now"}] if reads else []) + [_backup_row(b) for b in others]

    def picked(widget, **kwargs):
        row = widget.selection
        if row is not None and not answer.done():
            answer.set_result(row.backup)
            close()

    chooser = toga.DetailedList(accessors=("title", "subtitle", "icon"), data=rows, on_select=picked,
                                style=Pack(flex=1))
    content = toga.Box(style=Pack(direction=COLUMN, flex=1, margin=12, gap=8), children=[
        toga.Label(app._wrap(tr("Compare the backup taken {date} with:", date=backup.date))), chooser])
    close = phone.push_panel(app, _("Compare with"), content,
                             on_back=lambda: answer.done() or answer.set_result(None))
    return await answer


# -- back up all -----------------------------------------------------------------------------
def _saved_login(app, d, via: tuple = ()):
    """d's login as the phone keeps it: the username and port by its MAC in the settings, the
    password only while the app runs (app.phone_passwords). None without both."""
    saved = app.settings.get("device_logins", {}).get(d.mac) if d.mac else None
    password = app.phone_passwords.get(d.key)
    if not saved or not saved.get("user") or password is None:
        return None
    return phonessh.Login(d.ip, int(saved.get("port") or d.port("ssh")), saved["user"], password,
                          phonessh.host_key_alias(d.mac, d.ip), app.known_hosts, via)


async def back_up_all(app):
    """Tools > Back up all: every device in the list that keeps a config, with the login given
    for it since the app opened (BackupAllPage); Stop while it runs."""
    job = app.device_job
    if job:
        if job["name"] == "backup_all" and job["stop"]:
            job["stop"].set()
            _say(app, _("Stopping: no more are started, and those under way are cancelled…"))
        return
    devices = [d for d in (app._device(getattr(row, "key", None)) for row in app.table.data) if d is not None]
    if not any(devicetools.config_kind(d) for d in devices):
        await _alert(app, _("Back up all"), _("No device in the list keeps a config the app can back up (airMAX, "
                                              "airFiber, LTU, GigaBeam, EdgeOS)."))
        return
    jobs = devicetools.backup_jobs(devices, lambda d, via: _saved_login(app, d, via), lambda d: phone.route(app, d),
                                   _("no login given yet"))
    BackupAllPage(app, jobs)


class BackupAllPage:
    """Back up all: a line for each device saying how its backup went, as it goes,
    BACKUP_AT_ONCE at a time (the Tools console says it too). The devices without a login given
    since the app opened come last, skipped; once the run is over they, and any that failed, have
    a Back up button of their own, which asks for the login. Leaving the page doesn't stop it:
    Tools' Back up all reads Stop meanwhile."""

    def __init__(self, app, jobs):
        self.app, self.jobs = app, jobs
        self.stop = threading.Event()
        self.lines = {}  # id(job) -> (the label saying how it went, its Back up button)
        ui = phone.native(app)
        rows = []
        for job in jobs:
            state = toga.Label(self._text(job))
            button = toga.Button(_("Back up"), on_press=lambda w, job=job, **kw: app.loop.create_task(self.one(job)),
                                 style=Pack(visibility="hidden"))
            ui.style_button(button, "tinted")
            self.lines[id(job)] = (state, button)
            rows.append(toga.Box(style=Pack(direction=ROW, align_items="center", gap=8), children=[
                toga.Box(style=Pack(flex=1), children=[state]), button]))
        about = app._wrap(tr("Backs up each device in the list that keeps a config, with the login given for it since "
                             "the app opened, {count} at a time; one the same as the device's last backup isn't kept "
                             "again. Those without one are listed at the end, each with a Back up button that asks "
                             "for it.", count=devicetools.BACKUP_AT_ONCE))
        self.summary = toga.Label("")
        self.stop_button = toga.Button(_("Stop"), on_press=self.stopping, style=Pack(flex=1))
        ui.style_button(self.stop_button, "tinted", "systemRedColor")
        content = toga.Box(style=Pack(direction=COLUMN, flex=1, margin=12, gap=8), children=[
            toga.Label(about),
            toga.ScrollContainer(horizontal=False, style=Pack(flex=1), content=toga.Box(
                style=Pack(direction=COLUMN, gap=10), children=rows)),
            self.summary, toga.Box(style=Pack(direction=ROW), children=[self.stop_button])])
        self.page = ui.Page(app, content)
        self.page.show(_("Back up all"), tr("{count} device(s)", count=len(jobs)))
        app.loop.create_task(self.run())

    def _text(self, job) -> str:
        """The device and how it went, in lines that leave room for its button."""
        return "\n".join(i18n.fill(part, 30) for part in (_label(job.d), job.text))

    def stopping(self, widget=None, **kwargs):
        self.stop.set()
        self.stop_button.enabled = False
        self.summary.text = _("Stopping…")

    async def run(self):
        app = self.app
        if app.device_job:  # (taken while its page was being made)
            _say(app, _("Back up all: wait for what's running to finish."))
            return
        app.device_job = taken = {"key": None, "name": "backup_all", "stop": self.stop}
        app.spinner.start()
        phone.update_tools(app)
        _say(app, tr("Back up all: {waiting} of {count} device(s), {at_once} at a time…",
                     waiting=sum(j.state == 'waiting' for j in self.jobs), count=len(self.jobs),
                     at_once=devicetools.BACKUP_AT_ONCE), begins=True)
        try:
            await _work(app, devicetools.back_up_all, self.jobs, lambda job: app._from_worker(self.show, job),
                        self.stop)
        finally:
            _end(app, taken)
        self.stop_button.enabled = False
        for job in self.jobs:
            self.show(job)
        for job in self.jobs:
            if job.state in ("skipped", "stopped"):
                phone.say(app, f"{_label(job.d)}: {job.text}")
        said = devicetools.backup_summary(self.jobs)
        self.summary.text = app._wrap(tr("Done: {summary}.", summary=said))
        _say(app, tr("Back up all: {summary}.", summary=said))
        app._append_log(_("Back up all configs:") + "\n"
                        + "".join(f"  {_label(job.d)}: {job.text}\n" for job in self.jobs) + f"  {said}.", status=False)

    def show(self, job):
        """How a job went, in its line (and the console, once it's done); the counts under the lines."""
        state, button = self.lines[id(job)]
        state.text = self._text(job)
        running = bool(self.app.device_job and self.app.device_job["name"] == "backup_all")
        retry = job.can_retry and not running
        button.style.visibility = "visible" if retry else "hidden"
        button.enabled = retry and not self.app.device_job
        if running:
            if job.state in ("backed up", "unchanged", "failed"):
                phone.say(self.app, f"{_label(job.d)}: {job.text}")
            self.summary.text = self.app._wrap(devicetools.backup_summary(self.jobs) + "…")

    async def one(self, job):
        """A device's own Back up button: its login asked for, then backed up as the run does."""
        app, d = self.app, job.d
        if app.device_job:
            return
        login = await phone.ask_route(app, d, tr("Log in to back up its config ({file}).",
                                                 file=devicetools.CONFIG_FILES[job.kind]))
        if not login:
            return
        taken = _begin(app, d, "backup")
        if taken is None:
            return
        job.state, job.said = "backing up", ""
        self.show(job)
        try:
            job.state, job.backup = await _work(app, devicetools.back_up, login, d, job.kind)
        except (phonessh.SSHError, devicetools.ToolError, OSError) as e:
            job.state, job.said = "failed", str(e)
        finally:
            _end(app, taken)
        for other in self.jobs:  # the other buttons were off meanwhile
            self.show(other)
        self.summary.text = app._wrap(tr("Done: {summary}.", summary=devicetools.backup_summary(self.jobs)))
        _say(app, f"{_label(d)}: {job.text}")
        app._append_log(tr("Config backup of {device}: {result}", device=_label(d), result=job.text), status=False)


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
        await _alert(app, _("Upload config"), str(e))
        return
    if backup is not None:  # what's uploaded, heading what it changes; and the login's purpose
        source = tr("The backup taken {date}", date=backup.date)
        purpose = tr("Log in to upload the backup taken {date}: what changes is shown first.", date=backup.date)
    else:
        source = Path(path).name
        purpose = tr("Log in to upload {file}: what changes is shown first.", file=source)
    refuse, warn = devicetools.upload_check(d, kind, text, meta)
    if refuse:
        await _alert(app, _("Can't upload this config"), refuse)
        return
    if warn and not await _alert(app, _("Upload this config?"), warn + "\n\n" + _("Go on?"), question=True):
        return
    login = await phone.ask_route(app, d, purpose)
    if not login:
        return
    _say(app, tr("Reading the config of {ip} to compare…", ip=d.ip), begins=True)
    try:
        current, _pending = await _work(app, devicetools.read_device_config, login, kind)
        tools = await _work(app, devicetools.config_tools, login, kind)
    except (phonessh.SSHError, devicetools.ToolError) as e:
        _say(app, str(e))
        return
    choice = await _changes_page(app, d, kind, current, text, source, tools)
    if not choice:
        _say(app, _("Nothing was uploaded."))
        return
    page = getattr(app, "phone_backups", None)
    if page is not None:  # back to Tools, whose console follows the upload
        page.page.close()
        page.closed()
    app.tabs.current_tab = _("Tools")
    job = _begin(app, d, "upload")
    if job is None:
        return
    outcome = {}

    def work():
        try:
            kept = devicetools.save_backup(d, current, kind, N_("before upload"))  # (kept in English)
            app._from_worker(_say, app, tr("Kept its current config as a backup ({date}).", date=kept.date))
            outcome["said"] = devicetools.push_config(login, kind, text, choice == "apply",
                                                      report=lambda m: app._from_worker(_say, app, m))
        except (devicetools.ToolError, phonessh.SSHError, OSError) as e:
            outcome["error"] = str(e)

    try:
        await _work(app, work)
    finally:
        _end(app, job)
    _say(app, f"{d.ip}: {outcome.get('said') or outcome.get('error', '')}")


async def _changes_page(app, d, kind, current, text, source, tools):
    """What uploading the config changes on the device, on a page: "save", "apply" or None. source:
    what's uploaded ("The backup taken...", a file's name as it is)."""
    diff, changed = devicetools.config_diff(current, text)
    heading = (tr("{source}: {count} line(s) change.", source=source, count=changed) if changed
               else tr("{source}: no differences, the device has this config already.", source=source))
    note = i18n.sentences(
        _("Save writes it to boot config, for the next reboot.") if kind == "edgeos"
        else _("Save writes it to flash, for the next reboot."),
        _("Apply now also applies it: the device restarts what the changes affect, and the connection can drop for a "
          "moment."), _("Either way its current config is kept as a backup first."),
        _(terms.RISKS['upload']), _(terms.RISKS['apply' if tools['apply'] else 'save']), _(terms.TESTED), tools["why"])
    return await _diff_page(app, _("Upload config"), heading, diff, note, [
        (_("Cancel"), None, True, "gray"), (_("Save"), "save", tools["save"], "tinted"),
        (_("Apply now"), "apply", tools["apply"], "filled")])


async def _diff_page(app, title, heading, diff, note, buttons):
    """A diff on a page, under its heading and over a note, with a button for each (text, answer,
    enabled, look) in buttons. Returns the answer of the one tapped; None when it's left."""
    answer = app.loop.create_future()
    ui = phone.native(app)
    view = toga.MultilineTextInput(readonly=True, value=diff or _("(no differences)"),
                                   style=Pack(flex=1, font_family="monospace", font_size=10))

    def finish(choice):
        if not answer.done():
            answer.set_result(choice)
            close()

    row = toga.Box(style=Pack(direction=ROW, gap=8))
    for text, choice, enabled, look in buttons:
        button = toga.Button(text, on_press=lambda w, choice=choice, **kw: finish(choice), enabled=enabled,
                             style=Pack(flex=1))
        row.add(button)
        ui.style_button(button, look)
    content = toga.Box(style=Pack(direction=COLUMN, flex=1, margin=12, gap=8), children=[
        toga.Label(app._wrap(heading)), view, toga.Label(app._wrap(note)), row])
    ui.monospaced(view, 10)
    close = phone.push_panel(app, title, content, on_back=lambda: answer.done() or answer.set_result(None))
    return await answer


# -- reboot and locate -------------------------------------------------------------------
async def reboot(app):
    """Restart the open device (asked first) and wait until it's back; Stop stops the waiting."""
    job = app.device_job
    if job:
        if job["name"] == "reboot" and job["stop"]:
            job["stop"].set()
            _say(app, _("Stopping…"))
        return
    d = app._selected_device()
    if d is None or not _offered(app, d, "reboot"):
        return
    hops = phone.route(app, d)
    text = tr("{device} restarts and is offline for a minute or two, longer for some models: whatever goes through "
              "it stops meanwhile.", device=_label(d))
    if hops:
        text = i18n.sentences(text, tr("It's reached through {devices}.",
                                       devices=", ".join(h.ip or h.mac for h in hops)))
    text += "\n\n" + terms.risk("reboot")
    if not await _alert(app, tr("Reboot {ip}?", ip=d.ip), text, question=True):
        return
    login = await phone.ask_route(app, d, _("Log in to reboot it."))
    if not login:
        return
    stop = threading.Event()
    job = _begin(app, d, "reboot", stop)
    if job is None:
        return
    _say(app, tr("Rebooting {ip}…", ip=d.ip), begins=True)
    outcome, report = {}, _reporter(app)

    def work():
        try:
            outcome["took"] = devicetools.reboot(login, d, report=report, stop=stop)
        except (devicetools.ToolError, phonessh.SSHError) as e:
            outcome["error"] = str(e)

    try:
        await _work(app, work)
    finally:
        _end(app, job)
    said = outcome.get("error") or tr("Rebooted: back after {seconds:.0f} s.", seconds=outcome["took"])
    _say(app, f"{d.ip}: {said}")


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
            if getattr(e, "kind", "") in ("auth", "key"):  # its login changed meanwhile: asked for again
                login = await phone.ask_route(app, d, _("Log in to stop its LED blinking."))
                try:
                    if login is None:
                        raise e
                    await _work(app, devicetools.locate, login, d, False)
                except (devicetools.ToolError, phonessh.SSHError) as again:
                    e = again
                else:
                    e = None
            if e is not None:
                app.phone_locating.pop(d.key, None)  # (not stuck at Stop locating: Locate tries again)
                _say(app, tr("Stop locating {ip}: {error}", ip=d.ip, error=e))
                phone.update_tools(app)
                return
        app.phone_locating.pop(d.key, None)
        _say(app, tr("{ip}: its LED is back to normal.", ip=d.ip))
        phone.update_tools(app)
        return
    if app.device_job or not _offered(app, d, "locate"):
        return
    login = await phone.ask_route(app, d, _("Log in to blink its LED."))
    if not login:
        return
    try:
        state = await _work(app, devicetools.locate, login, d, True)
    except (devicetools.ToolError, phonessh.SSHError) as e:
        _say(app, tr("Locate {ip}: {error}", ip=d.ip, error=e))
        return
    app.phone_locating[d.key] = login
    said = "" if state else (_("It doesn't say it's locating: it may be busy (upgrading).") if state is False
                             else _("It doesn't say whether it took."))
    _say(app, i18n.sentences(tr("{ip}: its LED is blinking.", ip=d.ip), said, _("Stop locating stops it.")),
         begins=True)
    phone.update_tools(app)


# -- link health (airMAX) ------------------------------------------------------------
async def link(app):
    """Read the open radio's link health (linkhealth): its own link, and each station's on an
    access point, into Details, with what's flagged in the console."""
    d = app._selected_device()
    if d is None or app.device_job or not _offered(app, d, "link"):
        return
    login = await phone.ask_route(app, d, _("Log in to read its link health: signal, noise floor, SNR, capacity, "
                                            "airtime and distance, its own and each station's on an access point."))
    if not login:
        return
    job = _begin(app, d, "link")
    if job is None:
        return
    _say(app, tr("Reading the link health of {ip}…", ip=d.ip), begins=True)
    try:
        reading = await _work(app, devicetools.read_link, login)
    except (devicetools.ToolError, phonessh.SSHError) as e:
        _say(app, tr("Link health of {ip}: {error}", ip=d.ip, error=e))
        return
    finally:
        _end(app, job)
    linkhealth.keep(d, reading)
    app._rediagnose()  # its issues, in the list and Details
    if app._selected_device() is d:
        app.details.value = core.render_details(d)
    found = [_without_advice(msg) for _level, _tag, msg in linkhealth.issues(d)]  # what, without the advice
    if found:
        phone.say(app, "\n".join(found))
    _say(app, i18n.sentences(linkhealth.summary(d), _("Details has every number.")))


def _without_advice(message: str) -> str:
    """An issue's first sentence: what's found, without the advice after it (a Japanese one ends in 。)."""
    end = re.search(r"\. |。", message)
    if end is None:
        return i18n.stop(message)
    return message[:end.start()] + ("。" if end.group() == "。" else ".")


# -- scan from a device given by its address -----------------------------------------
async def scan_address(app):
    """Log in to a device by its address (one the scan didn't find, over a VPN, say), list it,
    and what it sees under it, as Scan from device does."""
    if app.running or app.rescanning or app.finding or app.device_job:
        app.status.text = _("Works once the scan has finished.")
        return
    if not phonessh.available():
        app.status.text = _("Scan from an address needs the app's SSH, which didn't load.")
        return
    login = await _address_page(app)
    if not login:
        return
    if app.running or app.rescanning or app.finding:
        app.status.text = _("A scan started meanwhile: scan from the address again once it has finished.")
        return
    result = app.result or core.ScanResult(core.parse_args([]), [], [], [], [], [], [], core.Inventory(), None, 0.0)
    app.rescanning = True
    app.spinner.start()
    app.status.text = tr("Reading what {ip} sees…", ip=login.ip)
    try:
        finder, sightings, seen, new = await _work(app, devicetools.scan_from_address, result, login,
                                                   core.local_addresses())
    except (phonessh.SSHError, devicetools.ToolError) as e:
        app.status.text = tr("Scan from {ip}: {error}", ip=login.ip, error=e)
        return
    finally:
        app.rescanning = False
        app.spinner.stop()
    if app.result is None and not app.running:
        app.result = result  # the list's devices from now on, as a scan's would be
        app.export_button.enabled = True
    elif result is not app.result:
        app.status.text = tr("Scan from {ip} finished after a new scan started: start it again.", ip=login.ip)
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
    counts = ", ".join(f"{_(devicetools.SCAN_HOW[how])} {n}" for how in devicetools.SCAN_HOW
                       if (n := sum(1 for s in sightings if s.how == how)))
    lines = [tr("Scan from {ip}: {counts}; {count} device(s), {new} new.", ip=login.ip,
                counts=counts or _("nothing listed"), count=len(seen), new=len(new))]
    for dev in seen:
        lines.append(f"  {dev.ip or '-':15} {dev.name or dev.model or dev.mac or ''}"
                     f"{'  ' + _('(new)') if dev in new else ''}")
    app._append_log("\n".join(lines), status=False)
    app.status.text = lines[0]
    await phone.warn_factory_login(app, finder, login)


async def _address_page(app):
    """A page asking for a device's address, port and login; it logs in once to check them and
    closes when that works: the login, or None when cancelled."""
    answer = app.loop.create_future()
    ui = phone.native(app)
    address = toga.TextInput(placeholder=_("e.g. 10.20.0.1"), style=Pack(flex=1))
    port = toga.TextInput(value="22", style=Pack(flex=1))
    user = toga.TextInput(value=app.settings.get("ssh_user") or "", placeholder=_("e.g. ubnt or admin"),
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
            trouble.text = _("The address is an IPv4 address, such as 10.20.0.1.")
            return
        if not text.isdigit() or not 0 < int(text) < 65536:
            trouble.text = _("The port is a number from 1 to 65535.")
            return
        if not user.value.strip():
            trouble.text = _("Logging in needs a username.")
            return
        known = app.result.inv.find(ip=ip) if app.result else None
        login = phonessh.Login(ip, int(text), user.value.strip(), password.value,
                               phonessh.host_key_alias(known.mac if known else None, ip), app.known_hosts)
        go.enabled = False
        trouble.text = tr("Logging in to {ip}…", ip=ip)
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

    go = toga.Button(_("Log in and scan"), on_press=lambda w, **kw: app.loop.create_task(log_in()))
    password.on_confirm = lambda w, **kw: app.loop.create_task(log_in())
    cancel_button = toga.Button(_("Cancel"), on_press=cancel)
    content = toga.Box(style=Pack(direction=COLUMN, margin=14, gap=10), children=[
        toga.Label(app._wrap(_("Log in to a device by its address, one the scan didn't find (over a VPN, say), to "
                               "list what it sees: its ARP table, LLDP neighbours and, on airOS, its stations. They're "
                               "listed under it, and the device tools reach them through it."))),
        toga.Box(style=row, children=[toga.Label(_("Address"), style=label), address]),
        toga.Box(style=row, children=[toga.Label(_("Port"), style=label), port]),
        toga.Box(style=row, children=[toga.Label(_("Username"), style=label), user]),
        toga.Box(style=row, children=[toga.Label(_("Password"), style=label), password]),
        trouble,
        toga.Box(style=Pack(direction=ROW, gap=8), children=[toga.Box(style=Pack(flex=1)), cancel_button, go])])
    ui.style_button(go)
    ui.style_button(cancel_button, "gray")
    for entry in (address, port, user, password):
        phone.hook(app, "plain_entry")(entry)
    close = phone.push_panel(app, _("Scan from an address"), content, on_back=lambda: finish(None))
    address.focus()
    return await answer
