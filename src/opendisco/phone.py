"""OpenDisco's screens on phones, for app.OpenDiscoApp: the same layout on iOS and Android.

A phone has no menus, no second windows and no room for a twelve-column table, and lets an app
run no other program. So there the app opens on its device list, under Quick Scan, Full Scan and
Stop and a search, with Export (the scan report and the other reports), the scan's Notes and Log
and Settings in the title bar. Tapping a device opens
its own page, titled with its name and address, with its tabs along the bottom: Details,
Packets, Tools, Notes and Log. Tools pings the device (core.ping: the app's own ICMP), opens an
SSH session to it (phonessh: the app's own SSH), finds its ports, opens its web UI, rescans it,
reads what it sees of its neighbours (Scan from device, as on the desktop: devicetools), checks
and updates its firmware, edits its config, keeps backups of it and uploads one, changes its
login, reboots it, blinks its LED (phonetools), keeps a note on it, exports its own report and
copies its addresses, with what they find, and the SSH session, in a console underneath. The
title bar's + scans from a device given by its address (one the scan didn't find). On a tablet
(wide), the device's page sits beside the list instead of over it, turned either way.

This module is what both phones share. What each does natively is in phone_<platform>.py
(phone_ios.py: UIKit through rubicon-objc; phone_android.py), which provides:
    Page(app, content, on_back=None)   a page over the device list, holding Toga content:
                                .show(title, subtitle) opens it, .close() closes it; Back (button,
                                gesture) closes it too and then calls on_back
    fit(app, export, notes, settings)   once the window exists: title-bar buttons calling those
                                (app.export_button: anything with .enabled), the list's and the
                                tabs' looks
    style_button(button, kind, color=None)   kind "filled", "tinted" or "gray"
    retitle(button, text)       a button's text, styled or not
    monospaced(widget, size)    the platform's monospaced font for a text view
    copy_text(text)
    export(app, name)           save the report (export_file) and offer it (iOS: the share sheet)
    keep_selection(app, key)    select the device's row again after the list reloaded
    fit_safe_area(app)          keep the content clear of the screen's edges after a resize
    and, where the platform has its own (hook() falls back to plain ones otherwise):
    Picker(app, items)          a drop-down choice, styled: .widget to lay out, .value the item chosen
    watch_keyboard(app, widget) keep a text view's last lines above the on-screen keyboard
    plain_entry(widget, send=False, new_password=False)   a text field without auto-capitals or
                                corrections (logins, commands); send: its return key reads "send";
                                new_password: no password manager taking it over
    end_editing(app)            finish typing, so a field's value has its last character
    done_bar(app, widget)       a way to put the keyboard away from a many-line text view
    wide(app)                   True on a tablet: the list and the device page side by side, laid
                                out here (Detail)
    side_by_side(app)           True while the platform's own layout keeps the list in view beside
                                the pages (iOS: an iPad at a regular width, in a split view)
    clear_selection(app)        a tablet: no row marked as the one beside the list (the scan's
                                Notes and Log are showing there)
    search_field(app, widget)   the search above the list, looking like the platform's own
    export_menu(app, choices, pick)   Export offers a choice of reports: choices() lists them as
                                (kind, title, detail, enabled) when it's tapped; pick(kind) saves one
                                (without it, Export saves the scan report)
    here(app)                   what the app's text calls the device it runs on ("this phone")
    text_box(widget)            a text view for typing many lines into, drawn so it can be seen
    menu_button(app, title, items)   a button that opens a menu: items() lists (title, enabled,
                                action) when it's tapped (None where there's none: phone.py lays
                                out a button for each instead)
    bar_button(app, symbol, title, action)   one more title-bar button (the + for Scan from an
                                address)
    open_file(app)              (async) a file the user picks (iOS: from Files), as a local path;
                                None when cancelled
app.py makes the widgets every platform shares and calls in here; it all runs on the UI thread.
"""
import importlib
import importlib.util
import re
import shutil
import threading
from pathlib import Path

import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW

from opendisco import core, phonessh

DEVICE_TABS = ("Details", "Packets", "Tools")  # hidden while the page shows the scan's Notes and Log
FIND_KINDS = {"HTTP": "find_http", "HTTPS": "find_https", "SSH": "find_ssh", "All ports": "all_ports"}
CONSOLE_KEEP = 200_000  # characters of console output kept
SHELL_COLUMNS = 64  # what the console shows in a line on an iPhone
LIST_WIDTH = 320  # a tablet's device list, beside the device page


def supported(platform: str) -> bool:
    """True where these screens are used: a platform with a phone_<platform>.py."""
    return importlib.util.find_spec(f"opendisco.phone_{platform}") is not None


def native(app):
    """The platform's phone_<platform> module."""
    return importlib.import_module(f"opendisco.phone_{app.caps['platform']}")


class _SelectionPicker:
    """A drop-down where the platform has none of its own: Toga's Selection."""

    def __init__(self, app, items):
        self.widget = toga.Selection(items=list(items), style=Pack(flex=1))

    @property
    def value(self):
        return self.widget.value


def _nothing(*args, **kwargs):
    pass


FALLBACKS = {"Picker": _SelectionPicker, "watch_keyboard": _nothing, "plain_entry": _nothing,
             "end_editing": _nothing, "done_bar": _nothing, "wide": lambda app: False,
             "side_by_side": lambda app: False, "clear_selection": _nothing, "search_field": _nothing,
             "export_menu": _nothing, "here": lambda app: "this phone", "text_box": _nothing,
             "menu_button": _nothing, "bar_button": _nothing, "open_file": None}


def hook(app, name: str):
    """A phone_<platform> function that not every platform has, or its plain fallback."""
    return getattr(native(app), name, None) or FALLBACKS[name]


def beside(app) -> bool:
    """True while the list is in view beside the device page: a tablet, laid out here (wide) or
    by the platform (side_by_side)."""
    return app.wide or hook(app, "side_by_side")(app)


class Mirror:
    """Widgets that show one thing in two places: setting an attribute sets it on each, reading
    one reads the first. (The status line on the device list and on Tools; Quick Scan and Full
    Scan standing in for Start.)"""

    def __init__(self, *widgets):
        object.__setattr__(self, "widgets", widgets)

    def __getattr__(self, name):
        return getattr(self.widgets[0], name)

    def __setattr__(self, name, value):
        for widget in self.widgets:
            setattr(widget, name, value)


# -- the device list ---------------------------------------------------------------
def main_screen(app) -> toga.Box:
    """Quick Scan, Full Scan and Stop across the top, the devices under them, the status line at
    the bottom; on a tablet, the device page (Detail) to their right."""
    quick = toga.Button("Quick Scan", on_press=lambda w, **kw: _scan(app, "Quick"), style=Pack(flex=1))
    full = toga.Button("Full Scan", on_press=lambda w, **kw: _scan(app, "Full scan"), style=Pack(flex=1))
    status_here = app.status
    app.status = Mirror(status_here, app.tool_status)
    app.start_button = Mirror(quick, full)
    app.search.placeholder = "Search: IP, MAC, model, name, note…"  # (and firmware, status, via)
    app.search.on_confirm = lambda w, **kw: hook(app, "end_editing")(app)
    app.search_count.style.update(color="#8a8a8e", font_size=13)
    content = toga.Box(style=Pack(direction=COLUMN, margin=10, gap=10), children=[
        toga.Box(style=Pack(direction=ROW, gap=8), children=[quick, full, app.stop_button]),
        toga.Box(style=Pack(direction=ROW, align_items="center", gap=8), children=[app.search, app.search_count]),
        app.table,
        toga.Box(style=Pack(direction=ROW, align_items="center", gap=8), children=[app.spinner, status_here]),
    ])
    style = native(app).style_button
    style(quick)
    style(full)
    style(app.stop_button, "tinted", "systemRedColor")
    hook(app, "search_field")(app, app.search)
    app.wide = hook(app, "wide")(app)
    if not app.wide:
        return content
    content.style.update(width=LIST_WIDTH)
    app.tool_status.parent.remove(app.tool_status)  # the list's, beside Tools, says it already
    app.page = Detail(app)
    return toga.Box(style=Pack(direction=ROW, flex=1), children=[
        content, toga.Divider(direction=toga.Divider.VERTICAL), app.page.box])


class Detail:
    """A tablet's device page, beside the list rather than over it: the title and subtitle a
    page shows in the title bar, over the tabs. With no device showing, it shows the scan's
    Notes and Log (show_scan). Shows and closes like the phones' Page."""

    def __init__(self, app):
        self.app = app
        self.title = toga.Label("", style=Pack(font_size=20, font_weight="bold", color="#1c1c1e"))
        self.subtitle = toga.Label("", style=Pack(font_size=14, color="#8a8a8e"))
        self.box = toga.Box(style=Pack(direction=COLUMN, flex=1), children=[
            toga.Box(style=Pack(direction=COLUMN, gap=2, margin=(12, 16, 4, 16)),
                     children=[self.title, self.subtitle]),
            app.tabs])

    def show(self, title: str, subtitle: str = ""):
        self.title.text, self.subtitle.text = title, subtitle

    def close(self):
        show_scan(self.app)


def _scan(app, mode: str):
    app.mode.value = mode
    if beside(app):  # the new scan clears the shown device's tabs; its Log shows how it goes
        show_scan(app)
    app.loop.create_task(app.on_start(None))


def fit(app):
    """After the window exists: the device page, the title bar's buttons, the looks."""
    ui = native(app)
    for text in (app.details, app.packets, app.notes, app.log):
        text.style.update(margin_left=8, margin_right=8)
        ui.monospaced(text, 10)
    ui.monospaced(app.console, 10)
    if not app.wide:  # (a tablet's is beside the list: Detail)
        app.page = ui.Page(app, toga.Box(style=Pack(direction=COLUMN, flex=1), children=[app.tabs]))
    ui.fit(app, export=lambda: app.loop.create_task(app.on_export(None)), notes=lambda: show_scan(app),
           settings=app.preferences)
    for button in (app.ping_button, app.ssh_button, app.web_button, app.rescan_button, app.scan_from_button,
                   app.firmware_button, app.config_button, app.login_button, app.backups_button, app.reboot_button,
                   app.locate_button, app.find_button):
        ui.style_button(button, "tinted")
    for button in (app.note_button, app.export_device_button, app.copy_ip_button, app.copy_mac_button,
                   *app.ssh_row.children[1:]):
        ui.style_button(button, "gray")
    hook(app, "export_menu")(app, lambda: export_choices(app), lambda kind: app.loop.create_task(app._export(kind)))
    hook(app, "bar_button")(app, "plus", "Scan from an address", lambda: app.loop.create_task(_tool(app, "scan_address")))
    hook(app, "watch_keyboard")(app, app.console)
    hook(app, "plain_entry")(app.ssh_input, send=True)
    if app.wide:  # beside the list until a device is tapped
        show_scan(app)
    update_tools(app)


def push_panel(app, title: str, content, on_back=None, fit=False):
    """A small page (Settings, a login) over what's showing; returns what closes it. Back closes
    it too, then calls on_back. fit: app.py's panels, made for every platform, get this one's looks
    (fit_panel)."""
    if fit:
        fit_panel(app, content)
    page = native(app).Page(app, toga.Box(style=Pack(direction=COLUMN, flex=1), children=[content]), on_back)
    page.show(title, "")
    return page.close


EDITOR_HEIGHT = 170  # a panel's many-line text box (a note, the subnets to sweep)
PRIMARY = ("Save", "Log in", "OK")  # a panel's buttons that go ahead: filled (Done just closes, as Back does)
DANGER = ("Delete", "Reboot", "Restore", "Upload")  # what changes or loses something on a device: red


def fit_panel(app, box):
    """A panel app.py made for every platform, made to look at home on a phone: its buttons
    styled (going ahead filled, deleting red, the rest gray) and a row of them at the right; its
    one-line fields and monospaced text (addresses, logins) without auto-capitals or corrections,
    in the platform's monospaced font; a many-line one in a box of its own size, with a way to
    put the keyboard away and kept clear of it; and "this computer" in its text named for this
    device."""
    ui = native(app)
    for widget in box.children:
        if isinstance(widget, toga.Button):
            text = widget.text or ""  # (one styled already has none: it keeps its looks)
            if not text:
                continue
            if text in PRIMARY:
                ui.style_button(widget)
            elif text.startswith(DANGER):
                ui.style_button(widget, "tinted", "systemRedColor")
            else:
                ui.style_button(widget, "gray")
        elif isinstance(widget, toga.MultilineTextInput):
            if "monospace" in str(widget.style.font_family):  # (a note stays prose, corrected as typed)
                ui.monospaced(widget, 12)
                hook(app, "plain_entry")(widget)
            if not widget.readonly:  # a box of its own size, the buttons under it above the keyboard
                widget.style.update(flex=0, height=EDITOR_HEIGHT)
                hook(app, "text_box")(widget)
                hook(app, "done_bar")(app, widget)
                hook(app, "watch_keyboard")(app, widget, follow=False)
        elif isinstance(widget, toga.TextInput):  # PasswordInput too
            hook(app, "plain_entry")(widget)
        elif isinstance(widget, toga.Label) and re.search(r"this\s+computer", widget.text):
            noun = hook(app, "here")(app).split(" ", 1)[-1]  # (a wrapped label may break the line between)
            widget.text = re.sub(r"this(\s+)computer", lambda m: f"this{m.group(1)}{noun}", widget.text)
        elif isinstance(widget, toga.Box):
            fit_panel(app, widget)
    if box.children and isinstance(box.children[-1], toga.Box) and all(
            isinstance(w, toga.Button) for w in box.children[-1].children):  # a row of buttons: at the right
        box.children[-1].insert(0, toga.Box(style=Pack(flex=1)))


def export_choices(app) -> list:
    """What Export offers on a phone: the scan report, then the other reports (records.SITE_EXPORTS),
    as (kind, title, detail, enabled)."""
    from opendisco import records
    backups = records.all_backups()
    notes = len(app.device_notes.items)
    details = {"scan": "Every device, with diagnostics: HTML",
               "security": "Known CVEs and outdated firmware: HTML",
               "backups": f"{sum(len(p) for _, p in backups)} file(s) from {len(backups)} device(s): .zip"
                          if backups else "None saved yet",
               "notes": f"{notes} note(s): HTML" if notes else "None written yet",
               "log": "The Log, as text"}
    enabled = {"scan": bool(app.result), "security": bool(app.result), "backups": bool(backups), "notes": bool(notes)}
    choices = [("scan", "Scan report", details["scan"], enabled["scan"])]
    for kind, button, _text, _types in records.SITE_EXPORTS:
        choices.append((kind, button.rstrip("…"), details.get(kind, ""), enabled.get(kind, True)))
    return choices


# -- the device page ------------------------------------------------------------------
def _device_tabs(app, shown: bool):
    """Show or hide Details, Packets and Tools (the scan's Notes and Log need none of them)."""
    tabs = app.tabs.content
    if shown:
        for name in DEVICE_TABS:
            tabs[name].enabled = True
        if app.tabs.current_tab.text not in DEVICE_TABS:
            app.tabs.current_tab = "Details"
    else:
        if app.tabs.current_tab.text in DEVICE_TABS:
            app.tabs.current_tab = "Notes"
        for name in DEVICE_TABS:
            tabs[name].enabled = False


def show_device(app, d):
    """Open a device's page (app.on_select has filled Details and Packets)."""
    if app.pinging is not None and app.pinging[0] != d.key:  # a ping or SSH session of another device ends
        app.pinging[1].set()
    if app.ssh is not None and app.ssh[0] != d.key:
        app.ssh[1].close()
    _device_tabs(app, True)
    title = d.name or d.model or d.ip or d.mac or "Device"
    subtitle = " · ".join(x for x in (d.ip, d.model if d.name else "") if x)
    app.page.show(title, subtitle)
    update_tools(app)


def _showing_scan(app) -> bool:
    return not app.tabs.content["Details"].enabled


def _scan_summary(app) -> str:
    if app.running:
        return f"{app.mode.value}: scanning"
    if app.result:
        return f"{app.mode.value}: {len(app.result.devices)} device(s), {app.result.elapsed:.0f}s"
    return "No scan yet"


def show_scan(app):
    """Open the page on the scan's Notes and Log, with no device (a tablet: beside the list,
    with no device's row marked)."""
    _device_tabs(app, False)
    if beside(app):
        hook(app, "clear_selection")(app)
    app.page.show("Scan", _scan_summary(app))


# -- Tools -------------------------------------------------------------------------------
def tools(app) -> toga.Box:
    """The Tools tab: buttons over a console for what they find. While an SSH session is open,
    a line to type commands into sits above the console, which shows the session."""
    def action(name):
        return lambda w, **kw: app._device_action(name)

    def later(flow):
        return lambda w, **kw: app.loop.create_task(flow(app))

    grow = Pack(flex=1)
    app.ping_button = toga.Button("Ping", on_press=lambda w, **kw: toggle_ping(app), style=grow)
    app.ssh_button = toga.Button("SSH", on_press=later(toggle_ssh), style=grow)
    app.web_button = toga.Button("Web UI", on_press=action("web"), style=grow)
    app.rescan_button = toga.Button("Rescan", on_press=action("rescan"), style=grow)
    app.scan_from_button = toga.Button("Scan from device", on_press=later(scan_from), style=grow)

    def tool(name):
        return lambda w, **kw: app.loop.create_task(_tool(app, name))

    app.firmware_button = toga.Button("Firmware", on_press=tool("firmware"), style=grow)
    app.config_button = toga.Button("Config", on_press=tool("config"), style=grow)
    app.login_button = toga.Button("Login", on_press=tool("change_login"), style=grow)
    app.backups_button = toga.Button("Backups", on_press=tool("backups"), style=grow)
    app.reboot_button = toga.Button("Reboot", on_press=tool("reboot"), style=grow)
    app.locate_button = toga.Button("Locate", on_press=tool("locate"), style=grow)
    app.port_picker = hook(app, "Picker")(app, list(FIND_KINDS))
    app.find_button = toga.Button("Find", on_press=lambda w, **kw: find_port(app), style=grow)
    app.note_button = toga.Button("Note", on_press=action("note"), style=grow)
    app.export_device_button = toga.Button("Export device", on_press=action("export_device"), style=grow)
    app.copy_ip_button = toga.Button("Copy IP", on_press=action("copy_ip"), style=grow)
    app.copy_mac_button = toga.Button("Copy MAC", on_press=action("copy_mac"), style=grow)
    app.copy_menu = hook(app, "menu_button")(app, "Copy", lambda: _copy_items(app))
    app.tool_status = toga.Label("", style=Pack(margin_left=2))
    app.console = toga.MultilineTextInput(readonly=True, placeholder="What the tools find shows here.",
                                          style=Pack(flex=1, font_family="monospace", font_size=10,
                                                     color="#e8e8e8", background_color="#16181d"))
    # A command goes when the keyboard's send key is tapped; Ctrl-C stops the one running.
    app.ssh_input = toga.TextInput(placeholder="Command (send to run it)", on_confirm=lambda w, **kw: send_ssh(app),
                                   style=Pack(flex=1))
    app.ssh_row = toga.Box(style=Pack(direction=ROW, align_items="center", gap=8), children=[
        app.ssh_input,
        toga.Button("Ctrl-C", on_press=lambda w, **kw: app.ssh and app.ssh[1].send("\x03"))])
    app.pinging = None  # (device key, Event that stops it) while a ping runs
    app.ssh = None  # (device key, phonessh.Shell) while an SSH session is open
    app.find_from = None  # app.py's; the phone has one Find button
    app.device_job = None  # phonetools: {"key", "name", "stop"} while a firmware update, reboot... runs
    app.phone_locating = {}  # device key -> the login its LED was set blinking with (phonetools.locate)
    app.phone_passwords = {}  # device key -> its SSH password, for this run only: phones keep none
    if app.copy_menu is not None:  # three to a row: the short name
        app.export_device_button.text = "Export"
    row = Pack(direction=ROW, gap=8)
    app.tools_box = toga.Box(style=Pack(direction=COLUMN, margin=12, gap=8), children=[
        toga.Box(style=row, children=[app.ping_button, app.ssh_button, app.web_button]),
        toga.Box(style=row, children=[app.rescan_button, app.scan_from_button]),
        toga.Box(style=row, children=[app.firmware_button, app.config_button, app.login_button]),
        toga.Box(style=row, children=[app.backups_button, app.reboot_button, app.locate_button]),
        toga.Box(style=Pack(direction=ROW, align_items="center", gap=8), children=[
            toga.Label("Find port", style=Pack(font_weight="bold", margin_left=2)), app.port_picker.widget,
            app.find_button]),
        *([toga.Box(style=row, children=[app.note_button, app.export_device_button, app.copy_menu])]
          if app.copy_menu is not None else
          [toga.Box(style=row, children=[app.note_button, app.export_device_button]),
           toga.Box(style=row, children=[app.copy_ip_button, app.copy_mac_button])]),
        app.tool_status,
        app.console,
    ])
    return app.tools_box


async def _tool(app, name: str):
    """One of phonetools' device tools (devicetools' work), loaded when first used."""
    from opendisco import phonetools
    await getattr(phonetools, name)(app)


def _copy_items(app) -> list:
    """The Copy menu: the open device's IP and MAC address."""
    d = app._selected_device()
    return [(f"IP address  {d.ip}" if d and d.ip else "IP address", bool(d and d.ip),
             lambda: app._device_action("copy_ip")),
            (f"MAC address  {d.mac}" if d and d.mac else "MAC address", bool(d and d.mac),
             lambda: app._device_action("copy_mac"))]


def say(app, text: str):
    """Add lines to the console."""
    _append(app, text.rstrip("\n") + "\n")


def _append(app, text: str):
    """Add text to the console as it comes, keeping its last CONSOLE_KEEP characters."""
    value = app.console.value + text
    if len(value) > CONSOLE_KEEP:
        value = value[value.index("\n", len(value) - CONSOLE_KEEP) + 1:]
    app.console.value = value
    app.console.scroll_to_bottom()


def toggle_ping(app):
    """Ping the device whose page is open, a line a second into the console; again stops it."""
    if app.pinging is not None:
        app.pinging[1].set()
        return
    d = app._selected_device()
    if d is None or not d.ip:
        app.status.text = "Select a device first."
        return
    stop = threading.Event()
    app.pinging = (d.key, stop)
    retitle = native(app).retitle
    retitle(app.ping_button, "Stop")
    if app.console.value:
        say(app, "")

    def work():
        try:
            core.ping(d.ip, lambda line: app._from_worker(say, app, line), stop.is_set)
        except Exception as e:  # never leave the button saying Stop
            app._from_worker(say, app, f"ping: {type(e).__name__}: {e}")
        app._from_worker(stopped)

    def stopped():
        app.pinging = None
        retitle(app.ping_button, "Ping")

    threading.Thread(target=work, daemon=True).start()


def find_port(app):
    """Look for the port the picker names (app._find: the deep check, then every TCP port); the
    button reads Stop while it runs."""
    if app.finding:
        app.on_stop(None)
        return
    app._device_action(FIND_KINDS[app.port_picker.value])


def update_tools(app):
    """Enable what the open device can do; the buttons of what's running read Stop or Disconnect."""
    retitle = native(app).retitle
    d = app._selected_device()
    state = app._menu_state(d)
    if beside(app) and _showing_scan(app):  # a scan started or ended beside it
        app.page.show("Scan", _scan_summary(app))
    idle = bool(d and d.ip and app.result) and not (app.running or app.rescanning or app.finding or app.device_job)
    retitle(app.find_button, "Stop" if app.finding else "Find")
    app.find_button.enabled = idle or app.finding
    app.ping_button.enabled = bool(d and d.ip) or app.pinging is not None
    retitle(app.ssh_button, "Disconnect" if app.ssh else "SSH")
    app.ssh_button.enabled = app.ssh is not None or (phonessh.available() and bool(d and d.ip))
    app.scan_from_button.enabled = phonessh.available() and idle
    for button, name in ((app.web_button, "web"), (app.rescan_button, "rescan"), (app.copy_ip_button, "copy_ip"),
                         (app.copy_mac_button, "copy_mac"), (app.note_button, "note"),
                         (app.export_device_button, "export_device")):
        button.enabled = state[name][1]
    retitle(app.note_button, "Edit note" if d and d.note else "Note")
    if app.device_job:
        app.rescan_button.enabled = False
    if phonessh.available():
        from opendisco import phonetools
        phonetools.update_buttons(app, d)
    else:
        for button in (app.firmware_button, app.config_button, app.login_button, app.backups_button,
                       app.reboot_button, app.locate_button):
            button.enabled = False


# -- logging in (SSH) -------------------------------------------------------------------
async def _work(app, fn, *args):
    return await app.loop.run_in_executor(None, fn, *args)


def route(app, d) -> list:
    """The devices on the way to d, the nearest first: the ones it was found through (as
    devicegui.route on the desktop). Empty for a device found directly."""
    devices = app.result.inv.devices if app.result else {}
    chain, seen, current = [], {d.key}, d
    while current.found_by.get("key") in devices and current.found_by["key"] not in seen:
        current = devices[current.found_by["key"]]
        seen.add(current.key)
        chain.insert(0, current)
    return chain


async def ask_route(app, d, purpose: str):
    """The login for d, through the devices on its route, each asked for in turn, nearest first
    (a device this phone can reach itself is logged in to directly). None when cancelled."""
    from opendisco import devicetools
    hops = route(app, d)
    if hops and await _work(app, devicetools.answers, d.ip, d.port("ssh"), 2):
        hops = []
    via = ()
    for n, hop in enumerate(hops, 1):
        login = await ask_login(app, hop, f"Device {n} of {len(hops)} on the way to {d.ip}. {purpose}", via)
        if not login:
            return None
        via += (login,)
    return await ask_login(app, d, purpose, via)


async def ask_login(app, d, purpose: str, via: tuple = ()):
    """A page asking for the username, password and port; it logs in once to check them and
    closes when that works. None when cancelled. The username and port are kept for the device;
    the password only until the app quits."""
    logins = app.settings.setdefault("device_logins", {})
    saved = logins.get(d.mac) if d.mac else None
    answer = app.loop.create_future()
    user = toga.TextInput(value=(saved or {}).get("user") or app.settings.get("ssh_user") or "",
                          placeholder="e.g. ubnt or admin", style=Pack(flex=1))
    password = toga.PasswordInput(value=app.phone_passwords.get(d.key, ""), style=Pack(flex=1))
    port = toga.TextInput(value=str((saved or {}).get("port") or d.port("ssh")), style=Pack(flex=1))
    trouble = toga.Label("")
    label = Pack(width=90)
    alias = phonessh.host_key_alias(d.mac, d.ip)

    def finish(login):
        if not answer.done():
            answer.set_result(login)

    async def log_in(*args, **kwargs):
        hook(app, "end_editing")(app)
        text = port.value.strip()
        if not text.isdigit() or not 0 < int(text) < 65536:
            trouble.text = "The port is a number from 1 to 65535."
            return
        login = phonessh.Login(d.ip, int(text), user.value.strip(), password.value, alias, app.known_hosts, via)
        go.enabled = False
        trouble.text = f"Logging in to {d.ip}…"
        try:
            await _work(app, phonessh.check_login, login)
        except phonessh.SSHError as e:
            trouble.text = app._wrap(str(e))
            if e.kind == "key" and forget not in buttons.children:
                buttons.insert(0, forget)
            go.enabled = True
            return
        app.phone_passwords[d.key] = login.password
        if d.mac:
            logins[d.mac] = {"user": login.user, "port": login.port}
        app.settings["ssh_user"] = login.user
        app._save_settings()
        close()
        finish(login)

    def forget_key(*args, **kwargs):
        phonessh.forget_host_key(alias, app.known_hosts)
        buttons.remove(forget)
        trouble.text = app._wrap(f"Forgot {d.ip}'s SSH key: the next login trusts the one it shows.")

    def cancel(*args, **kwargs):
        close()
        finish(None)

    go = toga.Button("Log in", on_press=lambda w, **kw: app.loop.create_task(log_in()))
    forget = toga.Button("Forget SSH key", on_press=forget_key)
    password.on_confirm = lambda w, **kw: app.loop.create_task(log_in())
    buttons = toga.Box(style=Pack(direction=ROW, gap=8), children=[
        toga.Box(style=Pack(flex=1)), toga.Button("Cancel", on_press=cancel), go])
    name = f"{d.ip}  {d.name or d.model or ''}".strip()
    content = toga.Box(style=Pack(direction=COLUMN, margin=14, gap=10), children=[
        toga.Label(app._wrap(f"{name}\n{purpose}")),
        toga.Box(style=Pack(direction=ROW, align_items="center", gap=8),
                 children=[toga.Label("Username", style=label), user]),
        toga.Box(style=Pack(direction=ROW, align_items="center", gap=8),
                 children=[toga.Label("Password", style=label), password]),
        toga.Box(style=Pack(direction=ROW, align_items="center", gap=8),
                 children=[toga.Label("Port", style=label), port]),
        trouble,
        buttons,
    ])
    ui = native(app)
    ui.style_button(go)
    for entry in (user, password, port):
        hook(app, "plain_entry")(entry)
    close = push_panel(app, "Log in", content, on_back=lambda: finish(None))
    (password if user.value else user).focus()
    return await answer


# -- the SSH session ---------------------------------------------------------------------
async def toggle_ssh(app):
    """Open an SSH session to the device in the console, or end the one that's open."""
    if app.ssh is not None:
        app.ssh[1].close()
        return
    d = app._selected_device()
    if d is None or not d.ip:
        app.status.text = "Select a device first."
        return
    login = await ask_route(app, d, "Log in for an SSH session.")
    if not login:
        return
    key = d.key
    app._tool_said(f"SSH to {login.where} as {login.user}…", begins=True)
    # It starts in the background; a failure arrives as the reason it closed.
    session = phonessh.Shell(login, lambda text: app._from_worker(_append, app, phonessh.plain(text)),
                             lambda reason: app._from_worker(_ssh_ended, app, key, reason), cols=SHELL_COLUMNS)
    app.ssh = (key, session)
    app.tools_box.insert(len(app.tools_box.children) - 1, app.ssh_row)
    app.status.text = f"SSH session with {d.ip} as {login.user}: commands go in the line below."
    update_tools(app)
    app.ssh_input.focus()


def send_ssh(app):
    if app.ssh is not None:
        app.ssh[1].send(app.ssh_input.value + "\r")
        app.ssh_input.value = ""


def _ssh_ended(app, key, reason: str):
    if app.ssh is None or app.ssh[0] != key:
        return
    app.ssh = None
    if app.ssh_row in app.tools_box.children:
        app.tools_box.remove(app.ssh_row)
    say(app, "")
    app._tool_said("SSH session closed" + (f": {reason}" if reason else "."))
    update_tools(app)


# -- Scan from device ------------------------------------------------------------------
async def scan_from(app):
    """What the device knows of its neighbours (its stations on airOS, LLDP neighbours and ARP
    table), added to the scan as on the desktop, then back to the list (unless it's in view
    beside the page already), where the devices found through it are listed under it."""
    from opendisco import devicetools
    d, result = app._selected_device(), app.result
    if d is None or not result:
        return
    fam = devicetools.family(d)
    tools_used = "its ARP table and LLDP neighbours" + (" and the stations associated with it" if fam == "airos"
                                                        else "")
    login = await ask_route(app, d, f"Log in to read what it sees: {tools_used}.")
    if not login:
        return
    app.rescanning = True  # nothing else on the device meanwhile
    app.spinner.start()
    update_tools(app)
    app._tool_said(f"Reading what {d.ip} sees…", begins=True)
    try:
        sightings = await _work(app, lambda: devicetools.parse_scan(devicetools.read_scan(login, fam)))
    except phonessh.SSHError as e:
        app._tool_said(f"Scan from {d.ip}: {e}")
        return
    finally:
        app.rescanning = False
        app.spinner.stop()
        update_tools(app)
    if result is not app.result:
        app._tool_said(f"Scan from {d.ip} finished after a new scan started: start it again.")
        return
    own = {i.ip for i in core.local_interfaces()}  # this phone is in the device's ARP table too
    sightings = [s for s in sightings if s.ip not in own]
    seen, new = devicetools.merge_scan(result, d, sightings, core.local_macs())
    app._show_devices(result.devices)
    counts = ", ".join(f"{devicetools.SCAN_HOW[how]} {n}" for how in devicetools.SCAN_HOW
                       if (n := sum(1 for s in sightings if s.how == how)))
    lines = [f"Scan from {d.ip}: {counts or 'nothing listed'}; {len(seen)} device(s), {len(new)} new."]
    for dev in seen:
        lines.append(f"  {dev.ip or '-':15} {dev.name or dev.model or dev.mac or ''}{'  (new)' if dev in new else ''}")
    app._append_log("\n".join(lines), status=False)
    app._tool_said(lines[0])
    if lines[1:]:
        say(app, "\n".join(lines[1:]))
    if not beside(app):  # (a tablet shows the list already)
        app.page.close()  # back to the list


# -- export -----------------------------------------------------------------------------
def export_file(app, name: str) -> Path:
    """Write the report into the app's own folder, in place of the last one (shared already, or
    not wanted)."""
    folder = Path(app.paths.cache) / "exports"
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir(parents=True)
    path = folder / name
    core.write_export(app.result, str(path))
    return path
