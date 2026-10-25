"""The device tools on the phones: firmware check and update, the airOS config editor and a new
login, as devicegui does them on the desktop, from the Tools tab (phone.py).

The work is devicetools', over phonessh (devicetools uses it on phones). What the desktop shows
in windows is a page here (the config, a new login) or lines in the Tools console (progress), and
its questions are the phone's alerts. One job runs at a time (app.device_job); a firmware
download can be stopped until the installation starts. Shared by iOS and Android.
"""
import threading
import traceback
from pathlib import Path

import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW

from opendisco import core, devicetools, phone, phonessh


def _label(d) -> str:
    return f"{d.ip}  {d.name or d.model or d.mac or ''}".strip()


async def _work(app, fn, *args):
    return await app.loop.run_in_executor(None, fn, *args)


def _say(app, text: str, begins: bool = False):
    app._tool_said(text, begins=begins)


def update_buttons(app, d):
    """Enable Firmware, Config and Login for what the open device can do; a firmware download's
    button reads Stop."""
    job = app.device_job
    idle = bool(d and d.ip and app.result) and not (app.running or app.rescanning or app.finding or job)
    ubiquiti = bool(d and (d.info.get("firmware") or d.info.get("platform")))
    stoppable = bool(job and job["name"] == "firmware" and job["stop"] and d and job["key"] == d.key)
    phone.native(app).retitle(app.firmware_button, "Stop" if stoppable else "Firmware")
    app.firmware_button.enabled = (idle and ubiquiti) or stoppable
    for button, action in ((app.config_button, "config"), (app.login_button, "login")):
        button.enabled = idle and devicetools.offers(d, action)[0] and phonessh.available()


def _begin(app, d, name: str, stop: threading.Event | None = None):
    app.device_job = {"key": d.key, "name": name, "stop": stop}
    app.spinner.start()
    phone.update_tools(app)


def _end(app):
    app.device_job = None
    app.spinner.stop()
    phone.update_tools(app)


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
    if devicetools.family(d) in ("unifi", "unifi-os"):
        message += ("\n\nUbiquiti's help center describes updating over SSH as a last resort, for when the UniFi app "
                    "can't update the device.")
    if not await _alert(app, "Install firmware?", message, question=True):
        return
    stop = threading.Event()
    _begin(app, d, "firmware", stop)
    folder = Path(app.paths.cache) / "firmware"
    outcome, shown = {}, {"step": ""}

    def show(text, percent):  # on the UI thread: a console line for each step, the percentage in the status
        if text and text.split("…")[0] != shown["step"].split("…")[0]:
            phone.say(app, text.rstrip(" 0123456789s"))
        shown["step"] = text or shown["step"]
        app.status.text = shown["step"] + (f"  {percent:.0f}%" if percent is not None else "")

    def report(text, percent=None):
        app._from_worker(show, text, percent)

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

            outcome["offline"] = devicetools.install_firmware(d, login, path, step, stop=stop)
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
    if d is None or app.device_job or not _offered(app, d, "config"):
        return
    login = await phone.ask_route(app, d, f"Log in to read its configuration ({devicetools.AIROS_CONFIG}).")
    if not login:
        return
    _say(app, f"Reading the config of {d.ip}…", begins=True)
    try:
        text, pending = await _work(app, devicetools.read_config, login)
    except phonessh.SSHError as e:
        _say(app, str(e))
        return
    _say(app, f"Read the config of {d.ip}.")
    ConfigPage(app, d, login, text, pending)


class ConfigPage:
    """airOS's config as text on a page of its own: Reload, Save (to flash) or Apply (save and
    apply now). Leaving it with changes not saved asks first."""

    def __init__(self, app, d, login, text, pending):
        self.app, self.d, self.login, self.saved = app, d, login, text
        ui = phone.native(app)
        self.box = toga.MultilineTextInput(value=text, style=Pack(flex=1, font_family="monospace", font_size=10))
        self.state = toga.Label("")
        self.buttons = [toga.Button("Reload", on_press=self.reload, style=Pack(flex=1)),
                        toga.Button("Save", on_press=lambda w, **kw: app.loop.create_task(self._write(False)),
                                    style=Pack(flex=1)),
                        toga.Button("Apply", on_press=lambda w, **kw: app.loop.create_task(self._write(True)),
                                    style=Pack(flex=1))]
        about = app._wrap(f"{devicetools.AIROS_CONFIG}, one setting per line. Save writes it to flash for the next "
                          "reboot; Apply saves it and applies it now, as the web UI's Apply does (the connection "
                          "can drop for a moment).")
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
        self.page.show("Config", _label(d))

    def _pending(self, pending):
        self.state.text = self.app._wrap("It has changes that aren't applied yet (made in its web UI, or saved "
                                         "without applying).") if pending else ""

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
        for button in self.buttons:
            button.enabled = on

    async def reload(self, widget, **kwargs):
        self._enable(False)
        self.state.text = "Reading…"
        try:
            text, pending = await _work(self.app, devicetools.read_config, self.login)
        except phonessh.SSHError as e:
            self.state.text = self.app._wrap(str(e))
        else:
            self.saved = self.box.value = text
            self._pending(pending)
        self._enable(True)

    async def _write(self, apply: bool):
        app = self.app
        phone.hook(app, "end_editing")(app)
        text = self.box.value
        problems = devicetools.config_problems(text)
        if problems:
            await app.main_window.dialog(toga.ErrorDialog(
                "Not a config", "airOS reads only key=value lines. These aren't:\n" + "\n".join(problems[:10])))
            return
        changed = devicetools.lines_changed(self.saved, text)
        what = ("Apply the config on" if apply else "Save the config to flash on") + f" {_label(self.d)}?"
        detail = (f"{changed} line(s) changed. " if changed else "Nothing changed here. ") + (
            "It's saved to flash and applied now; the device restarts what the changes affect." if apply
            else "It takes effect at the next reboot.")
        if not await _alert(app, what, detail, question=True):
            return
        self._enable(False)
        self.state.text = "Applying…" if apply else "Saving…"
        try:
            message = await _work(app, lambda: devicetools.write_config(
                self.login, text, apply, report=lambda m: app._from_worker(setattr, self.state, "text", app._wrap(m))))
        except devicetools.LostConnection as e:  # what it means for the device, as far as it's known
            self.state.text = app._wrap(str(e))
            await app.main_window.dialog(toga.ErrorDialog("Connection lost", str(e)))
        except (devicetools.ToolError, phonessh.SSHError) as e:
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
    _say(app, f"Reading the config of {d.ip}…", begins=True)
    try:
        text, pending = await _work(app, devicetools.read_config, login)
    except phonessh.SSHError as e:
        _say(app, str(e))
        return
    answer = await _new_login_page(app, d, login, text)
    if not answer:
        _say(app, "The login wasn't changed.")
        return
    new_text, new_user, new_password, scheme = answer
    what = (f"the password of {login.user} on {_label(d)}" if new_user == login.user
            else f"the login of {_label(d)} from {login.user} to {new_user} with the new password")
    message = (f"Change {what}? It's applied right away and saved to flash; the old login stops working.\n\n"
               f"The password is stored on the device as an {scheme} hash, the format it uses now.")
    if pending:
        message += ("\n\nIts config also has changes that aren't applied yet (made in its web UI, or saved without "
                    "applying): they're applied with it.")
    if not await _alert(app, "Change login?", message, question=True):
        _say(app, "The login wasn't changed.")
        return
    new = phonessh.Login(login.ip, login.port, new_user, new_password, login.alias, login.known_hosts, login.via,
                         login.nested)
    _begin(app, d, "login")
    outcome = {}

    def work():
        try:
            outcome["said"] = devicetools.write_config(login, new_text, True, new_login=new,
                                                       report=lambda m: app._from_worker(_say, app, m))
            app._from_worker(_say, app, "Logging in with the new login…")
            phonessh.check_login(new)
        except (devicetools.ToolError, phonessh.SSHError) as e:
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
    if d.mac:
        app.settings.setdefault("device_logins", {})[d.mac] = {"user": new_user, "port": login.port}
        app._save_settings()
    _say(app, f"Done: {d.ip} takes the new login ({new_user}), applied and saved to flash.")


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
            new_text, scheme = devicetools.change_login(text, login.user, login.password, user.value.strip(),
                                                        first.value)
        except devicetools.ToolError as e:
            trouble.text = app._wrap(str(e))
            return
        close()
        finish((new_text, user.value.strip(), first.value, scheme))

    def cancel(*args, **kwargs):
        close()
        finish(None)

    go = toga.Button("Change", on_press=change)
    second.on_confirm = change
    first.on_confirm = lambda widget, **kwargs: second.focus()
    content = toga.Box(style=Pack(direction=COLUMN, margin=14, gap=10), children=[
        toga.Label(app._wrap(f"{_label(d)}\nThe new password is stored on the device hashed the way it hashes the "
                             "current one, never as plain text.")),
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
