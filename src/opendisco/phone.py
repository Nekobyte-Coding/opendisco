"""OpenDisco's screens on phones, for app.OpenDiscoApp: the same layout on iOS and Android.

A phone has no menus, no second windows and no room for a twelve-column table, and lets an app
run no other program. So there the app opens on its device list, under Quick Scan, Full Scan and
Stop, with Export, the scan's Notes and Log and Settings in the title bar. Tapping a device opens
its own page, titled with its name and address, with its tabs along the bottom: Details,
Packets, Tools, Notes and Log. Tools pings the device (core.ping: the app's own ICMP), finds its
ports, opens its web UI, rescans it and copies its addresses, with what they find in a console
underneath.

This module is what both phones share. What each does natively is in phone_<platform>.py
(phone_ios.py: UIKit through rubicon-objc; phone_android.py), which provides:
    Page(app, content)          a page over the device list, holding Toga content: .show(title,
                                subtitle) opens it, .close() closes it; Back returns to the list
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
app.py makes the widgets every platform shares and calls in here; it all runs on the UI thread.
"""
import importlib
import importlib.util
import shutil
import threading
from pathlib import Path

import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW

from opendisco import core

DEVICE_TABS = ("Details", "Packets", "Tools")  # hidden while the page shows the scan's Notes and Log
FIND_TITLES = {"find_http": "HTTP", "find_https": "HTTPS", "find_ssh": "SSH", "all_ports": "All ports"}
CONSOLE_KEEP = 200_000  # characters of console output kept


def supported(platform: str) -> bool:
    """True where these screens are used: a platform with a phone_<platform>.py."""
    return importlib.util.find_spec(f"opendisco.phone_{platform}") is not None


def native(app):
    """The platform's phone_<platform> module."""
    return importlib.import_module(f"opendisco.phone_{app.caps['platform']}")


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
    the bottom."""
    quick = toga.Button("Quick Scan", on_press=lambda w, **kw: _scan(app, "Quick"), style=Pack(flex=1))
    full = toga.Button("Full Scan", on_press=lambda w, **kw: _scan(app, "Full scan"), style=Pack(flex=1))
    status_here = app.status
    app.status = Mirror(status_here, app.tool_status)
    app.start_button = Mirror(quick, full)
    content = toga.Box(style=Pack(direction=COLUMN, margin=10, gap=10), children=[
        toga.Box(style=Pack(direction=ROW, gap=8), children=[quick, full, app.stop_button]),
        app.table,
        toga.Box(style=Pack(direction=ROW, align_items="center", gap=8), children=[app.spinner, status_here]),
    ])
    style = native(app).style_button
    style(quick)
    style(full)
    style(app.stop_button, "tinted", "systemRedColor")
    return content


def _scan(app, mode: str):
    app.mode.value = mode
    app.loop.create_task(app.on_start(None))


def fit(app):
    """After the window exists: the device page, the title bar's buttons, the looks."""
    ui = native(app)
    for text in (app.details, app.packets, app.notes, app.log):
        text.style.update(margin_left=8, margin_right=8)
        ui.monospaced(text, 10)
    ui.monospaced(app.console, 10)
    app.page = ui.Page(app, toga.Box(style=Pack(direction=COLUMN, flex=1), children=[app.tabs]))
    ui.fit(app, export=lambda: app.loop.create_task(app.on_export(None)), notes=lambda: show_scan(app),
           settings=app.preferences)
    for button in (app.ping_button, app.web_button, app.rescan_button, *app.find_buttons):
        ui.style_button(button, "tinted")
    for button in (app.copy_ip_button, app.copy_mac_button):
        ui.style_button(button, "gray")
    update_tools(app)


def push_panel(app, title: str, content):
    """A small page (Settings) over the device list; returns what closes it."""
    page = native(app).Page(app, toga.Box(style=Pack(direction=COLUMN, flex=1), children=[content]))
    page.show(title, "")
    return page.close


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
    if app.pinging is not None and app.pinging[0] != d.key:  # a ping of another device stops
        app.pinging[1].set()
    _device_tabs(app, True)
    title = d.name or d.model or d.ip or d.mac or "Device"
    subtitle = " · ".join(x for x in (d.ip, d.model if d.name else "") if x)
    app.page.show(title, subtitle)
    update_tools(app)


def show_scan(app):
    """Open the page on the scan's Notes and Log, with no device."""
    _device_tabs(app, False)
    if app.running:
        summary = f"{app.mode.value}: scanning"
    elif app.result:
        summary = f"{app.mode.value}: {len(app.result.devices)} device(s), {app.result.elapsed:.0f}s"
    else:
        summary = "No scan yet"
    app.page.show("Scan", summary)


# -- Tools -------------------------------------------------------------------------------
def tools(app) -> toga.Box:
    """The Tools tab: buttons over a console for what they find."""
    def action(name):
        return lambda w, **kw: app._device_action(name)

    app.ping_button = toga.Button("Ping", on_press=lambda w, **kw: toggle_ping(app), style=Pack(flex=1))
    app.web_button = toga.Button("Web UI", on_press=action("web"), style=Pack(flex=1))
    app.rescan_button = toga.Button("Rescan", on_press=action("rescan"), style=Pack(flex=1))
    app.copy_ip_button = toga.Button("Copy IP", on_press=action("copy_ip"), style=Pack(flex=1))
    app.copy_mac_button = toga.Button("Copy MAC", on_press=action("copy_mac"), style=Pack(flex=1))
    app.tool_status = toga.Label("", style=Pack(margin_left=2))
    app.console = toga.MultilineTextInput(readonly=True, placeholder="What the tools find shows here.",
                                          style=Pack(flex=1, font_family="monospace", font_size=10,
                                                     color="#e8e8e8", background_color="#16181d"))
    app.pinging = None  # (device key, Event that stops it) while a ping runs
    app.find_from = None  # the Find button that started the port search running
    row = Pack(direction=ROW, gap=8)
    return toga.Box(style=Pack(direction=COLUMN, margin=12, gap=8), children=[
        toga.Box(style=row, children=[app.ping_button, app.web_button, app.rescan_button]),
        toga.Label("Find port", style=Pack(font_weight="bold", margin_top=4, margin_left=2)),
        toga.Box(style=row, children=app.find_buttons),
        toga.Box(style=row, children=[app.copy_ip_button, app.copy_mac_button]),
        app.tool_status,
        app.console,
    ])


def say(app, text: str):
    """Add lines to the console, keeping its last CONSOLE_KEEP characters."""
    value = app.console.value + text.rstrip("\n") + "\n"
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


def update_tools(app):
    """Enable what the open device can do; the Find button of a search that's running reads Stop."""
    retitle = native(app).retitle
    d = app._selected_device()
    state = app._menu_state(d)
    idle = bool(d and d.ip and app.result) and not (app.running or app.rescanning or app.finding)
    for button in app.find_buttons:
        running = app.finding and button.id == app.find_from
        retitle(button, "Stop" if running else FIND_TITLES[button.id])
        button.enabled = idle or running
    app.ping_button.enabled = bool(d and d.ip) or app.pinging is not None
    for button, name in ((app.web_button, "web"), (app.rescan_button, "rescan"), (app.copy_ip_button, "copy_ip"),
                         (app.copy_mac_button, "copy_mac")):
        button.enabled = state[name][1]


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
