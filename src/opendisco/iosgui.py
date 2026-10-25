"""OpenDisco's screens on iOS (iPhone and iPad), for app.OpenDiscoApp.

iOS has no menus, no second windows and no table, and lets an app run no other program. So
there the app opens on its device list, with Quick Scan, Full Scan and Stop across the top,
Export (the share sheet) at the top left and the scan's Notes and Log and Settings at the top
right. Tapping a device opens its own page, titled with its name and address, with its tabs
along the bottom: Details, Packets, Tools, Notes and Log. Tools pings the device (core.ping, the
app's own ICMP), finds its ports, opens its web UI, rescans it and copies its addresses, with
what they find in a console underneath.

app.py makes the widgets every platform shares and calls these for the iOS layout. Everything
here runs on the UI thread.
"""
import shutil
import threading
from pathlib import Path

import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW

from opendisco import core

# SF Symbols for the device page's tabs, in place of Toga's star on every one
TAB_SYMBOLS = {"Details": "info.circle", "Packets": "doc.text.magnifyingglass", "Tools": "wrench.and.screwdriver",
               "Notes": "text.bubble", "Log": "list.bullet.rectangle"}
DEVICE_TABS = ("Details", "Packets", "Tools")  # hidden while the page shows the scan's Notes and Log
FIND_TITLES = {"find_http": "HTTP", "find_https": "HTTPS", "find_ssh": "SSH", "all_ports": "All ports"}
CONSOLE_KEEP = 200_000  # characters of console output kept


def _objc(name):
    from rubicon.objc import ObjCClass
    return ObjCClass(name)


def _class_value(cls, name):
    """A class property (UIColor.systemRedColor...), however rubicon hands it over."""
    from rubicon.objc import ObjCInstance
    value = getattr(cls, name)
    return value if isinstance(value, ObjCInstance) else value()


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


class BarItem:
    """A title-bar button that app.py enables and disables like a Toga one (Export)."""

    def __init__(self, native):
        self.native = native

    @property
    def enabled(self) -> bool:
        return bool(self.native.isEnabled())

    @enabled.setter
    def enabled(self, value):
        self.native.enabled = bool(value)


class Page:
    """A page pushed over the device list, holding Toga content, with the title bar's back
    button (and the swipe from the left edge) to return."""

    def __init__(self, app, content):
        from toga_iOS.container import ControlledContainer
        self.app, self.content, self.laid_out = app, content, None
        self.container = ControlledContainer(on_refresh=lambda container: None, on_native_layout=self._layout)
        content.app = app
        self.container.content = content._impl
        self.controller = self.container.controller
        self.controller.view.backgroundColor = _class_value(_objc("UIColor"), "systemBackgroundColor")

    def _layout(self, container):
        """Lay the content out below the title bar whenever the page changes size (rotation)."""
        bar = self.app.main_window._impl.container.controller.navigationBar
        top = bar.frame.origin.y + bar.frame.size.height
        size = (container.native.bounds.size.width, container.native.bounds.size.height, top)
        if size != self.laid_out:
            self.laid_out = size
            container.top_inset = top
            self.content.refresh()

    def show(self, title: str, subtitle: str):
        from rubicon.objc import SEL
        item = self.controller.navigationItem
        if item.respondsToSelector(SEL("setSubtitle:")):  # iOS 26 and later
            item.title, item.subtitle = title, subtitle
        else:
            item.title = f"{title}  {subtitle}" if subtitle and subtitle != title else title
        nav = self.app.main_window._impl.container.controller
        if nav.topViewController != self.controller:
            nav.pushViewController(self.controller, animated=True)


def push_panel(app, title: str, content) -> "callable":
    """A small page (Settings) pushed over the device list; returns what closes it."""
    page = Page(app, toga.Box(style=Pack(direction=COLUMN, flex=1), children=[content]))
    page.show(title, "")

    def close():
        nav = app.main_window._impl.container.controller
        if nav.topViewController == page.controller:
            nav.popViewControllerAnimated(True)
    return close


def style_button(button, kind="filled", color=None):
    """A rounded, filled or tinted iOS button (UIButton.Configuration) in place of plain text."""
    try:
        Config = _objc("UIButtonConfiguration")
        config = {"filled": Config.filledButtonConfiguration, "tinted": Config.tintedButtonConfiguration,
                  "gray": Config.grayButtonConfiguration}[kind]()
        config.cornerStyle = 4  # capsule
        config.title = button.text
        if color:
            tint = _class_value(_objc("UIColor"), color)
            config.baseForegroundColor = tint
            config.baseBackgroundColor = tint
        native = button._impl.native
        native.setTitle(None, forState=0)  # Toga's title would keep its own colour: blue on the blue fill
        native.configuration = config
        button.refresh()
    except Exception:
        pass  # cosmetic: a plain button still works


def _monospaced(text, size: float):
    """The system's monospaced font (SF Mono), which reads better than the Courier Toga picks."""
    try:
        text._impl.native.font = _objc("UIFont").monospacedSystemFontOfSize(size, weight=0.0)
    except Exception:
        pass  # cosmetic


def retitle(button, text: str):
    """Change a button's text, styled or not."""
    native = button._impl.native
    config = native.configuration
    if config is None:
        button.text = text
    elif str(config.title) != text:
        config.title = text
        native.configuration = config
        button.refresh()


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
    style_button(quick)
    style_button(full)
    style_button(app.stop_button, "tinted", "systemRedColor")
    return content


def _scan(app, mode: str):
    app.mode.value = mode
    app.loop.create_task(app.on_start(None))


def fit(app):
    """After the window exists: the title bar's buttons, the device page, lines between devices."""
    from rubicon.objc import Block, objc_id
    app._ios_blocks = []  # the buttons' handlers, kept alive

    def item(symbol, title, action):
        def tapped(_action) -> None:
            try:
                action()
            except Exception as e:  # UIKit would drop it silently
                app.status.text = f"{title}: {type(e).__name__}: {e}"

        block = Block(tapped, None, objc_id)
        app._ios_blocks.append(block)
        act = _objc("UIAction").actionWithTitle(title, image=_objc("UIImage").systemImageNamed(symbol),
                                                identifier=None, handler=block)
        return _objc("UIBarButtonItem").alloc().initWithPrimaryAction(act)

    bar = app.main_window._impl.container.content_controller.navigationItem
    export = item("square.and.arrow.up", "Export", lambda: app.loop.create_task(app.on_export(None)))
    bar.leftBarButtonItem = export
    bar.rightBarButtonItems = _objc("NSArray").arrayWithArray([
        item("gearshape", "Settings", app.preferences),
        item("list.bullet.rectangle", "Notes and Log", lambda: show_scan(app))])
    bar.backButtonTitle = "Devices"
    app.export_button = BarItem(export)
    app.export_button.enabled = False
    for text in (app.details, app.packets, app.notes, app.log):
        text.style.update(margin_left=8, margin_right=8)
        _monospaced(text, 10)
    _monospaced(app.console, 10)
    app.page = Page(app, toga.Box(style=Pack(direction=COLUMN, flex=1), children=[app.tabs]))
    try:
        app.table._impl.native.separatorStyle = 1  # UITableViewCellSeparatorStyleSingleLine
        UIImage = _objc("UIImage")
        for tab in app.tabs._impl.sub_containers:
            image = UIImage.systemImageNamed(TAB_SYMBOLS.get(str(tab.controller.tabBarItem.title), ""))
            if image:
                tab.controller.tabBarItem.image = image
    except Exception:
        pass  # cosmetic
    for button in (app.ping_button, app.web_button, app.rescan_button, *app.find_buttons):
        style_button(button, "tinted")
    for button in (app.copy_ip_button, app.copy_mac_button):
        style_button(button, "gray")
    update_tools(app)


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


def copy_text(text: str):
    _class_value(_objc("UIPasteboard"), "generalPasteboard").string = text


# -- export -----------------------------------------------------------------------------
def export_file(app, name: str) -> Path:
    """Write the report into the app's own folder for the share sheet, in place of the last one
    (shared already, or not wanted)."""
    folder = Path(app.paths.cache) / "exports"
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir(parents=True)
    path = folder / name
    core.write_export(app.result, str(path))
    return path


def share(app, path: Path):
    """Offer a file to the share sheet: Save to Files, Mail, AirDrop, Messages…"""
    from rubicon.objc import Block, objc_id
    url = _objc("NSURL").fileURLWithPath(str(path))
    sheet = _objc("UIActivityViewController").alloc().initWithActivityItems(
        _objc("NSArray").arrayWithObject(url), applicationActivities=None)
    popover = sheet.popoverPresentationController  # iPad: the sheet points at the Export button
    if popover:
        popover.barButtonItem = app.export_button.native

    def done(activity, completed: bool, items, error) -> None:
        app.status.text = f"Shared {path.name}" if completed else "Export not shared."

    app._share_done = Block(done, None, objc_id, bool, objc_id, objc_id)  # kept alive while it's up
    sheet.completionWithItemsHandler = app._share_done
    shown = app.main_window._impl.native.rootViewController
    while shown.presentedViewController:
        shown = shown.presentedViewController
    shown.presentViewController(sheet, animated=True, completion=None)
    app.status.text = f"Saved {path.name}: share it to Files, Mail or AirDrop."
