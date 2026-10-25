"""The device tools' windows (desktop only): firmware check and update, the config editor, the new
login, and the login window they share, which can remember a device's login in the operating
system's credential store. The work itself is opendisco.devicetools, run in worker threads.

app.py only lists the actions in DEVICE_ACTIONS and calls menu_state() and act().
"""
import asyncio
import difflib
import threading
import time
import traceback
from pathlib import Path

import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW

from opendisco import core, credstore, devicetools, sshrun, terminal

ACTIONS = ("fw_check", "fw_update", "config", "login", "forget_login")
_busy: dict = {}  # device key -> what's running on it
_in_use: dict = {}  # downloaded firmware path -> updates using it


def menu_state(app, d, titles: dict) -> dict:
    """{action: (title, enabled)} for the device tools."""
    state = {}
    tools = not app.caps["mobile"] and sshrun.available()
    busy = _busy.get(d.key)
    ubiquiti = bool(d.info.get("firmware") or d.info.get("platform"))
    state["fw_check"] = (titles["fw_check"], ubiquiti and not busy)
    for name, action in (("fw_update", "update"), ("config", "config"), ("login", "login")):
        offered, why = devicetools.offers(d, action)
        title = titles[name]
        if busy:
            title += f"  ({busy})"
        elif not offered:
            title += f"  ({why})"
        elif not tools:
            title += "  (needs ssh and scp)"
        state[name] = (title, bool(d.ip) and offered and tools and not busy)
    state["forget_login"] = (titles["forget_login"], bool(d.mac and _remembered(app, d)))
    return state


def act(app, d, name: str) -> None:
    flow = {"fw_check": check_flow, "fw_update": update_flow, "config": config_flow, "login": login_flow}.get(name)
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


# ---------------------------------------------------------------------------
# Logins
# ---------------------------------------------------------------------------

def _logins(app) -> dict:
    return app.settings.setdefault("device_logins", {})  # MAC -> {"user", "port"}; passwords in the store


def _remembered(app, d) -> dict | None:
    return _logins(app).get(d.mac) if d.mac else None


def _login(app, d, user: str, password: str, port: int) -> sshrun.Login:
    return sshrun.Login(d.ip, port, user, password, terminal.host_key_alias(d.mac, d.ip), app.known_hosts)


def forget_login(app, d) -> None:
    _logins(app).pop(d.mac, None)
    app._save_settings()
    gone = credstore.forget(d.mac)
    app.status.text = (f"Forgot the saved login for {d.ip or d.mac}." if gone
                       else f"Forgot the saved username for {d.ip or d.mac}; {credstore.store_name()} had no password for it.")


async def ask_login(app, d, purpose: str) -> sshrun.Login | None:
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
        login = _login(app, d, user, password, port)
        app.status.text = f"Logging in to {d.ip}…"
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
        return login


async def _login_window(app, d, purpose, user, password, port, remembered, problem):
    answer = app.loop.create_future()
    user_box = toga.TextInput(value=user, placeholder="e.g. ubnt or admin", style=Pack(flex=1))
    password_box = toga.PasswordInput(value=password, style=Pack(flex=1))
    port_box = toga.TextInput(value=str(port), style=Pack(width=80))
    trouble = toga.Label(problem, style=Pack(flex=1))
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
                trouble.text = "The port is a number from 1 to 65535."
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
        toga.Label(purpose),
        toga.Box(style=row, children=[toga.Label("Username", style=label), user_box]),
        toga.Box(style=row, children=[toga.Label("Password", style=label), password_box]),
        toga.Box(style=row, children=[toga.Label("Port", style=label), port_box, trouble]),
        remember,
        toga.Label(note),
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
        self.heading = toga.Label(heading)
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
            if text.split("…")[0] != self.step.text.split("…")[0]:
                self.log.value += time.strftime("%H:%M:%S  ") + text.rstrip(" 0123456789s") + "\n"
                self.log.scroll_to_bottom()
            self.step.text = text
        if percent is not None:
            self.bar.value = max(0, min(100, percent))

    def no_cancel(self) -> None:
        self.app._from_worker(setattr, self.button, "enabled", False)

    def finish(self, text: str) -> None:
        self._show(text, None)
        self.button.text, self.button.enabled = "Close", True


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
        login = await ask_login(app, d, f"Log in to install firmware {check.latest}.")
        if not login:
            return
        family = devicetools.FAMILY_NAMES[devicetools.family(d)]
        message = (f"Install {family} firmware {check.latest} on {_label(d)}? It runs {check.current} now.\n\n"
                   f"The app downloads it from Ubiquiti ({devicetools.fmt_size(check.size)}), checks it, copies it to "
                   "the device and starts the installation. The device restarts to install it and is offline for "
                   "a few minutes: don't unplug it or turn it off until it's back.")
        if devicetools.family(d) in ("unifi", "unifi-os"):
            message += ("\n\nUbiquiti's help center describes updating over SSH as a last resort, for when the UniFi "
                        "app can't update the device.")
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

            outcome["offline"] = devicetools.install_firmware(d, login, path, report, stop=progress.stop)
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
    login = await ask_login(app, d, f"Log in to read its configuration ({devicetools.AIROS_CONFIG}).")
    if not login:
        return
    app.status.text = f"Reading the config of {d.ip}…"
    try:
        text, pending = await _work(devicetools.read_config, login)
    except sshrun.SSHError as e:
        app.status.text = str(e)
        await app.main_window.dialog(toga.ErrorDialog("Config", str(e)))
        return
    app.status.text = f"Read the config of {d.ip}."
    ConfigEditor(app, d, login, text, pending)


class ConfigEditor:
    def __init__(self, app, d, login, text, pending):
        self.app, self.d, self.login = app, d, login
        self.saved = text  # as the device has it
        self.box = toga.MultilineTextInput(value=text, style=Pack(flex=1, font_family="monospace", font_size=11))
        self.state = toga.Label("", style=Pack(flex=1))
        self.buttons = [toga.Button("Reload", on_press=self.reload), toga.Button("Save", on_press=self.save),
                        toga.Button("Apply", on_press=self.apply)]
        about = (f"{devicetools.AIROS_CONFIG} on {d.ip}: airOS's whole configuration, one setting per line.\n"
                 "Save writes it to flash: it takes effect at the next reboot. Apply saves it and applies it now, "
                 "the way the web UI's Apply does: the device restarts only what the changes affect, and the "
                 "connection to it can drop for a moment.")
        size = (900, 680)
        self.window = toga.Window(title=f"Config: {_label(d)}", size=size, on_close=self.closing,
                                  position=app._over_main(size))
        self.window.content = toga.Box(style=Pack(direction=COLUMN, margin=12, gap=8), children=[
            toga.Label(about), self.box,
            toga.Box(style=Pack(direction=ROW, align_items="center", gap=8), children=[
                self.state, *self.buttons, toga.Button("Close", on_press=lambda w: self.window.close())])])
        self._pending(pending)
        app._show_over_main(self.window)

    def _pending(self, pending):
        self.state.text = ("It has changes that aren't applied yet (made in its web UI, or saved without applying)."
                           if pending else "")

    def _enable(self, on: bool):
        for button in self.buttons:
            button.enabled = on

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
            text, pending = await _work(devicetools.read_config, self.login)
        except sshrun.SSHError as e:
            self.state.text = str(e)
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
        problems = devicetools.config_problems(text)
        if problems:
            await self.window.dialog(toga.ErrorDialog(
                "Not a config", "airOS reads only key=value lines. These aren't:\n" + "\n".join(problems[:10])))
            return
        changed = sum(1 for line in difflib.unified_diff(self.saved.replace("\r", "").splitlines(),
                                                         text.replace("\r", "").splitlines(), lineterm="", n=0)
                      if line[:1] in "+-" and line[:3] not in ("+++", "---"))
        what = ("Apply the config on" if apply else "Save the config to flash on") + f" {_label(self.d)}?"
        detail = (f"{changed} line(s) changed. " if changed else "Nothing changed in the editor. ") + (
            "It's saved to flash and applied now; the device restarts what the changes affect." if apply
            else "It takes effect at the next reboot.")
        if not await self.window.dialog(toga.QuestionDialog(what, detail)):
            return
        self._enable(False)
        self.state.text = "Applying…" if apply else "Saving…"
        try:
            message = await _work(lambda: devicetools.write_config(
                self.login, text, apply, report=lambda m: self.app._from_worker(setattr, self.state, "text", m)))
        except (devicetools.ToolError, sshrun.SSHError) as e:
            self.state.text = str(e)
        else:
            self.saved = text
            self.state.text = message
            self.app.status.text = f"{self.d.ip}: {message}"
        self._enable(True)


# ---------------------------------------------------------------------------
# A new login
# ---------------------------------------------------------------------------

async def login_flow(app, d):
    if _busy.get(d.key):
        return
    login = await ask_login(app, d, "Log in with its current username and password first.")
    if not login:
        return
    if not login.password:
        await app.main_window.dialog(toga.ErrorDialog(
            "Change login", "Changing the login needs the current password (an SSH key isn't enough): the app "
                            "checks it against the device's stored hash before writing a new one."))
        return
    _busy[d.key] = "changing login"
    try:
        app.status.text = f"Reading the config of {d.ip}…"
        try:
            text, pending = await _work(devicetools.read_config, login)
        except sshrun.SSHError as e:
            await app.main_window.dialog(toga.ErrorDialog("Change login", str(e)))
            return
        answer = await _new_login_window(app, d, login, text)
        if not answer:
            return
        new_text, new_user, new_password, scheme = answer
        message = (f"Change the login of {_label(d)} from {login.user} to {new_user} with the new password? "
                   f"It's applied right away and saved to flash; the old login stops working.\n\n"
                   f"The password is stored on the device as an {scheme} hash, the format it uses now.")
        if pending:
            message += ("\n\nIts config also has changes that aren't applied yet (made in its web UI, or saved "
                        "without applying): they're applied with it.")
        if not await app.main_window.dialog(toga.QuestionDialog("Change login?", message)):
            return
        new = sshrun.Login(login.ip, login.port, new_user, new_password, login.alias, login.known_hosts)
        progress = Progress(app, f"Changing login: {d.ip}", f"{_label(d)}: {login.user} → {new_user}")
        progress.no_cancel()
        outcome = {}

        def work():
            try:
                outcome["said"] = devicetools.write_config(login, new_text, True, report=progress.show,
                                                           new_login=new)
                progress.show("Logging in with the new login…")
                sshrun.check_login(new)
            except (devicetools.ToolError, sshrun.SSHError) as e:
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
        progress.finish(f"Done: {d.ip} takes the new login ({new_user}), applied and saved to flash.")
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
                new_text, scheme = devicetools.change_login(text, login.user, login.password, user_box.value.strip(),
                                                            first.value)
            except devicetools.ToolError as e:
                trouble.text = str(e)
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
        toga.Label("The new password is stored on the device hashed the way it hashes the current one, never as "
                   "plain text; the app checks its hashing against the current password first."),
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
