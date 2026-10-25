"""OpenDisco's GUI (Toga): native on macOS, Windows, Linux, iOS and Android.

The scanning is opendisco.core; this module only builds the window, runs scans in a
worker thread and shows what they find. Each platform offers the modes it allows: phones and
Windows can't capture traffic, add addresses or tag VLANs. The iOS app doesn't update itself
(Apple allows installs from the App Store, TestFlight or Xcode only) and has no SSH tools.
"""
import asyncio
import json
import shutil
import textwrap
import threading
import time
import traceback
import webbrowser
from pathlib import Path

import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW

from opendisco import FULL_NAME, __version__, core, health, phone, records, vulns

if core.platform_name() != "ios":  # left out of the iOS app (packaging/ios/build_ios.py)
    from opendisco import update

# (name, description, command-line flags, needs) where needs is a capability from core.capabilities()
MODES = [
    ("Quick", "Broadcast and multicast discovery only, like Ubiquiti's old Java tool.", ["--quick"], None),
    ("Full scan", "Discovery plus a sweep of the local subnets, mDNS, SSDP and the ARP table.", [], None),
    ("Sniff the wire", "Listen on every port for gear on any subnet (ARP, LLDP, CDP, broadcasts).",
     ["--sniff"], "listen"),
    ("Trunk VLANs", "Find the VLANs on a trunk port, then probe each one through a temporary tagged interface.",
     ["--vlans"], "vlans"),
    ("Direct to a device", "Wired straight into one radio: find its IP and VLAN from what it says, then probe it.",
     ["--direct"], "vlans"),
]
COLUMNS = list(core.EXPORT_COLUMNS)
ACCESSORS = [c.lower() for c in COLUMNS]
# Phones: Android's table doesn't scroll sideways, so twelve columns ran off the screen. Three
# larger ones instead; tapping a device shows the rest in Details.
PHONE_COLUMNS = ["IP", "Model", "Name"]
ANY_PORT = "Any port"
# What a device's right-click menu (and the Device menu) offers; None separates groups.
DEVICE_ACTIONS = [("web", "Open Web UI"), ("ssh", "Open SSH…"), ("ping", "Ping"), ("latency", "Measure latency"),
                  ("rescan", "Rescan device"),
                  ("scan_from", "Scan from device…"), ("issues", "Show issues…"), None,
                  ("find_http", "Find HTTP port"), ("find_https", "Find HTTPS port"), ("find_ssh", "Find SSH port"),
                  ("all_ports", "Scan all ports"), None,
                  ("fw_check", "Check for firmware update"), ("fw_update", "Update firmware…"),
                  ("config", "Edit config…"), ("login", "Change login…"), None,
                  ("backup", "Back up config"), ("backups", "Config backups…"), ("upload", "Upload config…"), None,
                  ("reboot", "Reboot…"), ("locate", "Locate (blink LED)"), None,
                  ("copy_ip", "Copy IP address"), ("copy_mac", "Copy MAC address"), None,
                  ("note", "Note…"), ("export_device", "Export device…"), None,
                  ("forget", "Forget SSH key"), ("forget_login", "Forget saved login"), ("hide", "Hide device")]
FINDS = {"find_http": "http", "find_https": "https", "find_ssh": "ssh", "all_ports": "all"}
# Said before a port search, until switched off: to intrusion prevention it looks like a port scan.
PORT_SEARCH_WARNING = ("A port search connects to {ip}'s TCP ports: all 65,535 of them when the service isn't on a "
                       "usual one. Intrusion prevention on the network (UniFi's IPS / Threat Management, a "
                       "firewall's port-scan detection) can take that for a port scan from this computer: it may "
                       "raise an alert, a false alarm here, or block this computer for a while.")
NO_SESSION = "Right-click a device to get started: Open SSH or Ping."
# The Settings window's checkboxes: settings.json key -> text. All are on until turned off.
SETTINGS = {"check_app_updates": "Check for OpenDisco updates when opening",
            "check_cve_updates": "Check for new CVEs when opening",
            "check_firmware": "Check firmware versions during scans"}
# What settings.json keeps; "update" remembers an update while the app restarts into it,
# "deep_checks" is iOS's Deep checks switch (in Settings there) and "sweep_subnets" Settings' list
# of subnets every scan also sweeps (records.SWEEP_KEY).
SAVED_SETTINGS = ("hidden", "ssh_user", "skip_port_warning", "device_logins", *SETTINGS, "update", "deep_checks",
                  records.SWEEP_KEY)
# Where earlier versions kept their data, by the parts of the data folder's path that changed:
# folder name now -> patterns for its earlier names. macOS names the folder after the app ID
# (earlier IDs ended .opendisco or .ubnt-discover); Windows after the publisher (until 1.4.1,
# "Unknown") and the app's name; Linux after the app's name.
LEGACY_FOLDERS = {"com.michaelfroehlke.opendisco": ("*.opendisco", "*.ubnt-discover"),
                  "Nekobyte-Coding": ("Unknown",),
                  "OpenDisco": ("UBNT Discovery Reloaded", "UBNT Discover"),
                  "opendisco": ("ubnt-discover", "ubnt_discover")}

# Windows keeps an app's files in %LOCALAPPDATA%\<publisher>\<app>; Toga would use the author's
# name as the publisher.
WINDOWS_PUBLISHER = "Nekobyte-Coding"

_MENU_TARGET = None
_TIP_TABLE = None


def _menu_target_class():
    """The Objective-C object a device's right-click menu reports to (macOS)."""
    global _MENU_TARGET
    if _MENU_TARGET is None:
        from rubicon.objc import NSObject, objc_method, objc_property

        class OpenDiscoDeviceMenuTarget(NSObject):
            app = objc_property(object, weak=True)

            @objc_method
            def menuNeedsUpdate_(self, menu) -> None:
                self.app._context_menu_opening()

            @objc_method
            def pick_(self, sender) -> None:
                self.app._device_action(DEVICE_ACTIONS[int(sender.tag)][0])

        _MENU_TARGET = OpenDiscoDeviceMenuTarget
    return _MENU_TARGET


class OpenDiscoApp(toga.App):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        paths = getattr(self.paths, "_impl", None)
        if core.IS_WINDOWS and hasattr(paths, "platformdirs_args"):
            toga_args = paths.platformdirs_args
            paths.platformdirs_args = lambda: {**toga_args(), "appauthor": WINDOWS_PUBLISHER}
            paths.__dict__.pop("_dirs", None)  # in case the folders were looked up already

    def startup(self):
        self.caps = core.capabilities()
        self.caps["vlans"] = self.caps["aliases"] and self.caps["listen"]
        self.caps["updates"] = self.caps["platform"] != "ios"  # OpenDisco updates itself
        offered = dict(self.caps)
        if self.caps["platform"] == "windows":  # listed before Npcap is installed: starting one offers it
            offered.update(listen=True, vlans=self.caps["aliases"])
        self.modes = [m for m in MODES if m[3] is None or offered.get(m[3])]
        self.offers_listening = offered["listen"]
        self.result = None  # the last finished scan
        self.live_inv = None  # the inventory of the scan that's running
        self.running = False
        self.rescanning = False
        self.finding = False  # a port search on one device
        self.holding = False
        self.cancel_password = None
        self.cancel_ssh_login = None
        self.cancel_port_warning = None
        self.port_warning_accepted = False  # phones: asked once per run
        self.updating = False  # checking for, downloading or installing an update
        self.update_cancel = None  # stops a download
        self.close_settings = None
        self._panels = []  # Android: (page, what Back does, title, subtitle) over the device list, newest last
        self.back_callback = None  # Android: takes Back while a page is open
        self._move_old_data()
        self.networks_path = self._networks_file()
        self.settings_path = Path(self.paths.data) / "settings.json"
        self.known_hosts = Path(self.paths.data) / "known_hosts"  # SSH host keys, filed by MAC
        vulns.CACHE_DIR = Path(self.paths.data)  # where a downloaded CVE list is kept (vulns.refresh)
        from opendisco import devicetools  # its SSH parts load only when used
        devicetools.BACKUP_ROOT = Path(self.paths.data) / devicetools.BACKUP_FOLDER  # config backups, by MAC
        self.settings = self._load_settings()
        self.hidden = self.settings.setdefault("hidden", {})  # device key (its MAC) -> what it was
        self.device_notes = records.Notes(self.paths.data)  # a note per device, by MAC (notes.json)
        if not self.caps["mobile"]:
            core.SUDO_ASKPASS = self._ask_password  # no terminal here, so the GUI asks
        self.multicast_lock = self._android_multicast_lock()

        mobile = self.caps["mobile"]
        # Phones get screens of their own (phone.py) where a phone_<platform>.py gives the native parts.
        self.phone_ui = phone_ui = phone.supported(self.caps["platform"])
        self.mode = toga.Selection(items=[m[0] for m in self.modes], on_change=self.on_mode,
                                   style=Pack(flex=1) if mobile else Pack(width=190))
        self.port_names = self._ports()  # what the Port list shows -> the interface name
        self.port = toga.Selection(items=list(self.port_names), style=Pack(width=230))
        self.start_button = toga.Button("Start", on_press=self.on_start, style=Pack(width=90))
        self.stop_button = toga.Button("Stop", on_press=self.on_stop, enabled=False,
                                       style=Pack(flex=1) if phone_ui else Pack(width=90))
        self.aliases = toga.Switch("Probe listed networks (temporary addresses)", enabled=self.caps["aliases"])
        self.aliases_choice = None  # the switch as it was set, while a mode that needs it on is picked
        self.deep = toga.Switch("Deep checks (ports, console API)",
                                value=phone_ui and bool(self.settings.get("deep_checks")))  # phones: in Settings
        # GTK draws − and + beside the number, so on Linux the box takes its own width (for "300")
        # instead of a fixed one, which pushed the + outside the box.
        gtk = self.caps["platform"] == "linux"
        self.listen = toga.NumberInput(min=5, max=300, step=5, value=20, style=Pack() if gtk else Pack(width=70))
        if gtk:
            self.listen._impl.native.set_width_chars(3)
        # Android sizes a label to its text on one line and never wraps it, so on phones the
        # description gets its own line and on_mode wraps it by hand.
        self.mode_help = toga.Label("", style=Pack(margin_left=2) if mobile else Pack(flex=1, margin_left=8))
        self.hidden_button = toga.Button("", on_press=self.on_hidden)
        self._update_hidden_button()
        # The search over the device list (records.filter_tree), above it; phones lay it out themselves.
        self.search = toga.TextInput(placeholder="Search: IP, MAC, model, name, firmware, status, via, note",
                                     on_change=self.on_search, style=Pack(flex=1))
        self.search_count = toga.Label("")  # "3 of 25 shown" while searching

        self.find_buttons = []
        if mobile:
            if phone_ui:  # the address over the model and name, a row per device
                self.table = toga.DetailedList(accessors=("ip", "summary", "icon"), on_select=self.on_select,
                                               style=Pack(flex=1))
            else:
                self.table = toga.Table(columns=PHONE_COLUMNS, on_select=self.on_select,
                                        style=Pack(flex=1, font_size=16))
            # No right-click on a phone: the port finder's buttons act on the device last tapped.
            self.find_buttons = [toga.Button(text, id=action, on_press=self.on_find_button, enabled=False,
                                             style=Pack(flex=1))
                                 for action, text in (("find_http", "HTTP"), ("find_https", "HTTPS"),
                                                      ("find_ssh", "SSH"), ("all_ports", "All ports"))]
        else:
            self.table = toga.Table(columns=COLUMNS, on_select=self.on_select, on_activate=self.on_activate,
                                    style=Pack(flex=1))
        mono = Pack(flex=1, font_family="monospace", font_size=12 if mobile else 11)
        self.details = toga.MultilineTextInput(readonly=True, placeholder="Select a device to see everything "
                                               "it reported and what to check.", style=mono)
        self.wire = toga.MultilineTextInput(readonly=True, placeholder="Sniff, Trunk VLANs and Direct show what "
                                            "they heard on the wire here.", style=mono)
        self.packets = toga.MultilineTextInput(readonly=True, placeholder="Select a device to see the packets it "
                                               "sent, decoded and checked for damage.", style=mono)
        self.shown_packets = None  # (device, packets received) the Packets tab shows
        self.notes = toga.MultilineTextInput(readonly=True, style=mono)
        self.log = toga.MultilineTextInput(readonly=True, style=mono)
        tabs = [("Details", self.details), ("Packets", self.packets)]
        self.term = None
        self.console = None  # iOS: the Tools tab's output
        if phone_ui:  # ping, the port finder and more, in place of On the wire (a phone hears no wire)
            tabs.append(("Tools", phone.tools(self)))
        elif not mobile:  # SSH and ping sessions to devices
            from opendisco import terminal
            self.term = terminal.TerminalPane(toga, Pack)
            tabs.append(("Terminal", self.term.box))
        if not phone_ui:
            tabs.append(("On the wire", self.wire))
        tabs += [("Notes", self.notes), ("Log", self.log)]
        self.networks = None  # the networks file's editor, in Settings while it's open
        self.tabs = toga.OptionContainer(content=tabs, style=Pack(flex=1))

        self.spinner = toga.ActivityIndicator()
        self.status = toga.Label("Ready.", style=Pack(flex=1, margin_left=6))
        self.export_button = toga.Button("Export…", on_press=self.on_export, enabled=False)
        self.hold_button = toga.Button("Keep addresses", on_press=self.on_hold, enabled=False)

        # Phones' title bars have room for the short name only.
        title = f"{self.formal_name if mobile else FULL_NAME} {__version__}"
        self.main_window = toga.MainWindow(title=title, size=(1250, 780))
        if phone_ui:  # the device list; each device gets a page of its own
            self.main_window.content = phone.main_screen(self)
        else:
            controls = [toga.Label("Mode"), self.mode]
            if not mobile:
                controls += [toga.Label("Port"), self.port]
            controls += [self.start_button, self.stop_button] + ([] if mobile else [self.mode_help])
            options = [self.aliases, self.deep] if not mobile else [self.deep]
            if self.offers_listening:
                options += [toga.Label("Listen (s)"), self.listen]
            if not mobile:
                options += [toga.Box(style=Pack(flex=1)), self.hidden_button]
            footer = [self.spinner, self.status, self.export_button]
            if self.caps["aliases"]:
                footer.append(self.hold_button)

            row = Pack(direction=ROW, align_items="center", gap=8)
            searching = toga.Box(style=row, children=[self.search, self.search_count])
            if mobile:  # phones: one column, no splitter
                finder = toga.Box(style=Pack(direction=ROW, align_items="center", gap=4),
                                  children=[toga.Label("Find port"), *self.find_buttons])
                body = toga.Box(style=Pack(direction=COLUMN, flex=1, gap=6),
                                children=[searching, self.table, finder, self.tabs])
            else:
                listed = toga.Box(style=Pack(direction=COLUMN, gap=6), children=[searching, self.table])
                body = toga.SplitContainer(content=[listed, self.tabs], direction=toga.SplitContainer.HORIZONTAL,
                                           style=Pack(flex=1))
            self.main_window.content = toga.Box(style=Pack(direction=COLUMN, margin=10, gap=8), children=[
                toga.Box(style=row, children=controls),
                *([self.mode_help] if mobile else []),
                toga.Box(style=row, children=options),
                body,
                toga.Box(style=row, children=footer),
            ])
        self.main_content = self.main_window.content
        self.on_exit = self.handle_exit
        if phone_ui:  # Settings, Export and the scan's Notes and Log are in the title bar
            phone.fit(self)
        if self.caps["platform"] != "ios":  # iOS shows no menus
            self._add_app_commands()
        if self.caps["platform"] == "android":
            if not phone_ui:
                self._fit_phone_table()
            self.back_callback = self._android_back()
        self.on_mode(self.mode)
        if not mobile:
            self._add_device_menu()
        self.main_window.show()
        if not mobile:
            self._install_context_menu()
            self._install_status_tips()
        # macOS re-centres the tab labels whenever it re-tiles the tab view (window resizes,
        # dragging the divider, tab changes, moving to another display), so snap a moment later.
        self.main_window.on_resize = lambda *args, **kwargs: (self.loop.call_later(0.05, self._align_tab_labels),
                                                              self.loop.call_later(0.05, self._size_columns),
                                                              self.loop.call_later(0.05, self._fit_safe_area))
        self.tabs.on_select = lambda *args, **kwargs: self.loop.call_later(0.05, self._align_tab_labels)
        self._watch_tab_labels()
        self.loop.call_later(0.3, self._align_tab_labels)
        self.loop.call_later(0.3, self._fit_safe_area)
        self.loop.call_later(0.5, self._size_columns)
        self.loop.call_later(1.0, self._launch_checks)

    # -- set-up helpers -----------------------------------------------------
    def _load_settings(self) -> dict:
        try:
            return json.loads(self.settings_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save_settings(self):
        try:
            self.settings_path.parent.mkdir(parents=True, exist_ok=True)
            self.settings_path.write_text(json.dumps({k: v for k, v in self.settings.items()
                                                      if k in SAVED_SETTINGS}, indent=1), encoding="utf-8")
        except OSError:
            pass

    def _move_old_data(self):
        """Earlier versions kept the networks file, hidden devices and SSH keys in a folder named
        after the app's earlier names or app ID (and on Windows, no author): bring them over once.
        The portable Linux version keeps its Python environment in the folder too: not data."""
        new = Path(self.paths.data)
        try:
            if new.is_dir() and any(p.name != "python" for p in new.iterdir()):
                return
            # Every earlier spelling of the path, current names first, so the newest data wins.
            found = [Path(new.anchor)]
            for part in new.parts[1:]:
                found = [match for folder in found for pattern in (part, *LEGACY_FOLDERS.get(part, ()))
                         for match in ([folder / part] if pattern == part else sorted(folder.glob(pattern)))]
            old = next((p for p in found if p != new and p.is_dir() and any(p.iterdir())), None)
            if old:
                shutil.copytree(old, new, dirs_exist_ok=True, ignore=shutil.ignore_patterns("python"))
        except OSError:
            pass

    def _networks_file(self) -> Path:
        """The editable networks file lives in the app's data folder (the bundle is read-only)."""
        path = Path(self.paths.data) / "networks.txt"
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(core.DEFAULT_NETWORKS_FILE, path)
        return path

    def _ports(self) -> dict:
        """The Port list: {what it shows: interface name}. Windows adapter names can have spaces
        ("Ethernet 2"), so the name is looked up rather than cut from what's shown."""
        try:
            links = core.hardware_links(core.local_interfaces())
        except Exception:
            links = []
        links = [l for l in links if l.active or not l.label.startswith("Ethernet Adapter (")]  # Apple's virtual ports
        return {ANY_PORT: None, **{f"{l.name} ({l.label})" + ("" if l.active else ", no link"): l.name
                                   for l in links}}

    def _align_tab_labels(self, *args, **kwargs):
        """macOS centres the tab labels inside the tab view, which can leave them half a pixel
        off the Retina grid and blurry; snap them back onto whole pixels."""
        if self.caps["platform"] != "macos":
            return
        try:
            from rubicon.objc import NSPoint
            view = self.tabs._impl.native
            scale = view.window.backingScaleFactor if view.window else 2.0
            for sub in view.subviews:
                if "Segmented" not in str(sub.className):
                    continue
                origin = view.convertPoint_toView_(sub.frame.origin, None)  # in window coordinates
                dx = round(origin.x * scale) / scale - origin.x
                dy = round(origin.y * scale) / scale - origin.y
                if dx or dy:
                    dy = -dy if view.isFlipped else dy
                    sub.setFrameOrigin(NSPoint(sub.frame.origin.x + dx, sub.frame.origin.y + dy))
        except Exception:
            pass  # purely cosmetic

    COLUMN_WEIGHTS = (1.1, 0.5, 0.9, 1.3, 1.0, 1.4, 1.3, 0.8, 0.6, 0.7, 0.6, 0.7, 1.1, 1.3)  # IP ... Status

    def _size_columns(self, *args, **kwargs):
        """Windows: toga sizes the table's columns once, before the window has its width, which left
        them as slivers with no headings. Spread them over the table's width instead."""
        if self.caps["platform"] != "windows":
            return
        try:
            view = self.table._impl.native
            width = view.ClientSize.Width
            if width < 200:
                return
            weights = self.COLUMN_WEIGHTS[:view.Columns.Count]
            for column, weight in zip(view.Columns, weights):
                column.Width = int(width * weight / sum(weights))
        except Exception:
            pass  # cosmetic

    def _watch_tab_labels(self):
        """Snap the tab labels after every frame change of the tab view or its label strip, and
        after the window moves to a display with another scale, whatever caused it."""
        if self.caps["platform"] != "macos":
            return
        try:
            from rubicon.objc import Block, ObjCClass, ObjCInstance
            center = ObjCClass("NSNotificationCenter").defaultCenter
            view = self.tabs._impl.native
            pending = []

            def changed(note: ObjCInstance) -> None:
                if not pending:  # one snap per burst of layout changes
                    pending.append(self.loop.call_soon(snapped))

            def snapped():
                pending.clear()
                self._align_tab_labels()

            self._tab_label_block = Block(changed)  # keep the block and the observers alive
            strips = [sub for sub in view.subviews if "Segmented" in str(sub.className)]
            watched = [("NSViewFrameDidChangeNotification", v) for v in [view, *strips]]
            watched.append(("NSWindowDidChangeBackingPropertiesNotification", view.window))
            self._tab_label_observers = []
            for name, obj in watched:
                if name == "NSViewFrameDidChangeNotification":
                    obj.postsFrameChangedNotifications = True
                self._tab_label_observers.append(
                    center.addObserverForName(name, object=obj, queue=None, usingBlock=self._tab_label_block))
        except Exception:
            pass  # purely cosmetic; the resize and tab-change hooks still snap

    def _android_multicast_lock(self):
        """Android drops broadcasts and multicast in Wi-Fi power save unless an app holds this."""
        if self.caps["platform"] != "android":
            return None
        try:
            from java import jclass  # Chaquopy, part of Briefcase's Android support
            context = self._impl.native.getApplicationContext()
            wifi = context.getSystemService(jclass("android.content.Context").WIFI_SERVICE)
            lock = wifi.createMulticastLock("opendisco")
            lock.setReferenceCounted(False)
            lock.acquire()
            return lock
        except Exception:
            return None

    def _android_back(self):
        """Android: the Back button and back gesture close the page on top (Settings, an update)
        the way a window's close button would, rather than leaving the app. With no page open,
        Back does what it always does."""
        try:
            from java import dynamic_proxy, jclass
            app = self

            class Pressed(dynamic_proxy(jclass("kotlin.jvm.functions.Function1"))):
                def invoke(self, callback):
                    app._back()

            activity = self._impl.native
            return jclass("androidx.activity.OnBackPressedDispatcherKt").addCallback(
                activity.getOnBackPressedDispatcher(), activity, False, Pressed())
        except Exception:
            self._append_log("Couldn't take over the Back button:\n" + traceback.format_exc(), status=False)
            return None

    def _back(self):
        if self._panels:
            self._panels[-1][1]()

    def _fit_phone_table(self):
        """Android: spread the columns over the screen's width and wrap a long name rather than
        push it off the edge, with a thin line between devices."""
        try:
            from java import jclass
            line = jclass("android.graphics.drawable.GradientDrawable")()
            line.setColor(0x33808080)
            line.setSize(1, 2)
            gap = jclass("android.graphics.drawable.InsetDrawable")(line, 0, 6, 0, 6)
            layout = self.table._impl.table_layout
            layout.setStretchAllColumns(True)
            layout.setShrinkAllColumns(True)
            layout.setDividerDrawable(gap)
            layout.setShowDividers(jclass("android.widget.LinearLayout").SHOW_DIVIDER_MIDDLE)
        except Exception:
            pass  # cosmetic

    def _fit_safe_area(self, *args, **kwargs):
        """Phones: keep the content clear of the screen's rounded corners, home bar and cutouts."""
        if self.phone_ui:
            phone.native(self).fit_safe_area(self)

    def _over_main(self, size):
        """Where a window of this size sits centred over the main window, on whatever screen
        that's on (a new window otherwise opens on the primary screen)."""
        try:
            (x, y), (width, height) = self.main_window.position, self.main_window.size
        except Exception:
            return None
        return int(x + (width - size[0]) / 2), int(y + max(40, (height - size[1]) / 3))

    def _show_over_main(self, window):
        window.show()
        position = self._over_main(tuple(window.size))  # its real size, now its content is laid out
        if position:
            window.position = position

    # -- talking to the worker thread ------------------------------------------
    def _from_worker(self, fn, *args):
        self.loop.call_soon_threadsafe(fn, *args)

    def _append_log(self, msg, status=True):
        self.log.value += msg.rstrip("\n") + "\n"
        self.log.scroll_to_bottom()
        if msg.strip() and status:
            self.status.text = msg.strip().splitlines()[-1][:140]

    def _ask_password(self, reason: str):
        """Called from the worker thread by core.authorize_sudo: ask on the UI thread and wait."""
        answer, done = {}, threading.Event()

        def show():
            box = toga.PasswordInput(style=Pack(flex=1))

            def finish(value):
                if done.is_set():
                    return
                self.cancel_password = None
                answer["password"] = value
                window.close()
                done.set()

            box.on_confirm = lambda widget: finish(box.value)
            window = toga.Window(title="Administrator password", size=(460, 170), resizable=False, closable=False,
                                 position=self._over_main((460, 170)))
            window.content = toga.Box(style=Pack(direction=COLUMN, margin=14, gap=10), children=[
                toga.Label(reason),
                toga.Label("It's passed straight to sudo and not stored."),
                box,
                toga.Box(style=Pack(direction=ROW, gap=8), children=[
                    toga.Box(style=Pack(flex=1)),
                    toga.Button("Cancel", on_press=lambda w: finish(None)),
                    toga.Button("OK", on_press=lambda w: finish(box.value))])])
            self._show_over_main(window)
            box.focus()
            self.cancel_password = lambda: finish(None)  # quitting must not leave the scan waiting

        self._from_worker(show)
        done.wait()
        return answer.get("password")

    # -- scanning --------------------------------------------------------------
    def _selected_mode(self):
        return next(m for m in self.modes if m[0] == self.mode.value)

    def on_mode(self, widget, **kwargs):
        name, description, flags, needs = self._selected_mode()
        self.mode_help.text = textwrap.fill(description, 44) if self.caps["mobile"] else description
        forced = needs == "vlans"  # these always probe through temporary addresses
        if self.caps["aliases"]:
            # Turned on for these modes only: leaving them sets the switch back, or the next Full
            # scan would add addresses (and ask for a password) nobody asked for.
            if forced and self.aliases_choice is None:
                self.aliases_choice = self.aliases.value
            elif not forced and self.aliases_choice is not None:
                self.aliases.value, self.aliases_choice = self.aliases_choice, None
            self.aliases.enabled = not forced and name != "Quick"
            if forced:
                self.aliases.value = True
        if self.listen.value in (20, 45):  # a time set by hand stays
            self.listen.value = 45 if name == "Direct to a device" else 20

    def _args(self) -> list:
        name, _description, flags, needs = self._selected_mode()
        args = list(flags) + ["--networks", str(self.networks_path), "--no-color"]
        if self.aliases.value and self.caps["aliases"] and name != "Quick" and needs != "vlans":
            args.append("-a")
        if self.deep.value:
            args.append("--deep")
        if needs in ("listen", "vlans"):
            args += ["--vlan-listen", str(int(self.listen.value or 20))]
        port = self.port_names.get(self.port.value)
        if port:
            args += ["-i", port]
        if self.caps["mobile"]:  # a phone app can't read the ARP table; mDNS and SSDP work (iOS: the
            args.append("--no-arp")  # multicast entitlement; Android: the multicast lock, and unicast replies)
        if name != "Direct to a device":  # Settings' routed and VPN subnets (Direct is about one device)
            args += records.sweep_targets(self.settings.get(records.SWEEP_KEY))
        return args

    async def _windows_ready(self) -> bool:
        """Windows: Npcap for the listening modes, administrator rights for temporary addresses.
        Offers to get each; False when the scan can't start yet."""
        from opendisco import winnet
        _name, _description, _flags, needs = self._selected_mode()
        if needs in ("listen", "vlans") and not self.caps["listen"]:
            if not await self.main_window.dialog(toga.QuestionDialog(
                    "Npcap is needed",
                    "Sniffing, Trunk VLANs and Direct capture packets through Npcap, which isn't installed. "
                    "Install it now? This downloads the official installer from npcap.com, checks that it's "
                    "signed by the Nmap Project, and starts it (Windows asks for permission first). "
                    "Npcap's free license covers 5 computers.")):
                return False
            self.status.text = "Installing Npcap: follow its installer…"
            self.spinner.start()
            error = await asyncio.get_running_loop().run_in_executor(None, winnet.install_npcap)
            self.spinner.stop()
            self.caps["listen"] = winnet.npcap() is not None
            self.caps["vlans"] = self.caps["aliases"] and self.caps["listen"]
            if error:
                self.status.text = f"Npcap: {error}"
                return False
            self.status.text = "Npcap is installed."
        if ("-a" in self._args() or needs == "vlans") and not winnet.is_admin():
            if await self.main_window.dialog(toga.QuestionDialog(
                    "Administrator rights needed",
                    "Temporary addresses change a network adapter's settings, which Windows only lets "
                    "administrators do. Restart OpenDisco as administrator? Windows asks first; then "
                    "start the scan again.")):
                if winnet.relaunch_as_admin(["-m", "opendisco"]):
                    self.request_exit()
            return False
        return True

    async def on_start(self, widget, **kwargs):
        if self.running:
            return
        if self.caps["platform"] == "windows" and not await self._windows_ready():
            return
        try:
            opts = core.parse_args(self._args())
        except SystemExit as e:
            await self.main_window.dialog(toga.ErrorDialog("Can't start", str(e.code)))
            return
        await self._release_hold()
        self.running, self.result, self.live_inv = True, None, None
        self.shown_packets = None
        self.table.data = []
        self.details.value = self.packets.value = self.wire.value = self.notes.value = ""
        self.log.value = f"{time.strftime('%H:%M:%S')}  {self.mode.value}: {' '.join(self._args())}\n"
        self.start_button.enabled, self.stop_button.enabled = False, True
        self.export_button.enabled = self.hold_button.enabled = False
        self.spinner.start()
        self._update_find_buttons()
        threading.Thread(target=self._scan, args=(opts,), daemon=True).start()
        asyncio.create_task(self._refresh_while_running())

    def on_stop(self, widget, **kwargs):
        core.STOP.set()
        self.status.text = "Stopping…"

    def _scan(self, opts):
        """The worker thread."""
        def progress(elapsed, total, inv=None):
            if elapsed is not None:
                self._from_worker(setattr, self.status, "text", f"Scanning… {elapsed:.0f}/{total:.0f}s")

        def keep(inv):
            self.live_inv = inv

        result, error = None, None
        try:
            result = core.run_scan(opts, lambda m: self._from_worker(self._append_log, m), progress, keep)
        except SystemExit as e:
            error = str(e.code)
        except Exception as e:
            error = f"{type(e).__name__}: {e}"
            self._from_worker(self._append_log, traceback.format_exc())
        self._from_worker(self._finished, result, error)

    async def _refresh_while_running(self):
        while self.running:
            if self.live_inv is not None:
                self._show_devices(core.sorted_devices(self.live_inv))
                if self.shown_packets:
                    self._show_packets(self.shown_packets[0])
            await asyncio.sleep(1.0)

    def _show_packets(self, d, force=False):
        """Fill the Packets tab for a device; while scanning, only when it has sent more."""
        if force or self.shown_packets != (d, d.ubnt_packets):
            self.shown_packets = (d, d.ubnt_packets)
            res = self.result
            self.packets.value = core.render_packets(d, res.inv if res else self.live_inv,
                                                     res.counters if res else None)

    def _show_devices(self, devices):
        """Fill the table, minus hidden devices and those the search leaves out. Rows change in
        place when the same devices are listed, so the selection stays put while a scan or a rescan
        updates them."""
        self._check_firmware(devices)
        row = self._phone_row if self.caps["mobile"] else (lambda d: dict(zip(ACCESSORS, core.device_row(d))))
        self.device_notes.apply(devices)
        listed = [d for d in devices if d.key not in self.hidden]
        rows = []
        # Found through another device: indented under it, which a search keeps in view
        for d, depth in records.filter_tree(listed, self.search.value or ""):
            values = row(d)
            values["ip"] = core.nested_ip(d, depth)
            if d.note:
                for attr in ("name", "summary"):
                    if attr in values:
                        values[attr] = f"{values[attr]} {records.NOTE_MARK}".lstrip()
            rows.append((d.key, values))
        self.search_count.text = f"{len(rows)} of {len(listed)} shown" if (self.search.value or "").strip() else ""
        data = self.table.data
        selected = getattr(self.table.selection, "key", None)
        if [key for key, _ in rows] == [getattr(row, "key", None) for row in data]:
            for row, (_, values) in zip(data, rows):
                for attr, value in values.items():
                    if getattr(row, attr) != value:
                        setattr(row, attr, value)
        else:
            self.table.data = [dict(values, key=key) for key, values in rows]
        if self.phone_ui:  # iOS forgets the tapped row whenever a row changes
            phone.keep_selection(self, selected)

    def on_search(self, widget, **kwargs):
        self._show_devices(self._all_devices())

    @staticmethod
    def _phone_row(d) -> dict:
        """A device as a phone lists it: address, model and name (Details has the rest). iOS
        lists the model and name under the address, then the newer firmware that's out and its
        latency, once known (what doesn't fit ends in …)."""
        model, name = d.model or "?", d.name or d.mac or ""
        fw = d.health.get("firmware") or {}
        extra = [f"update {fw['latest']}" if fw.get("newer") else "", health.latency_cell(d)]
        return {"ip": d.ip or "-", "model": model, "name": name,
                "summary": " · ".join(x for x in (model, name, *extra) if x)}

    def _all_devices(self) -> list:
        if self.result:
            return self.result.devices
        return core.sorted_devices(self.live_inv) if self.live_inv else []

    def _finished(self, result, error):
        self.running = False
        self.spinner.stop()
        self.start_button.enabled, self.stop_button.enabled = True, False
        if error:
            self.status.text = error.removeprefix("error: ")
            asyncio.create_task(self.main_window.dialog(toga.ErrorDialog("Scan failed", self.status.text)))
            return
        if not isinstance(result, core.ScanResult):
            self.status.text = "Done."
            return
        self.result = result
        self._show_devices(result.devices)
        self.wire.value = result.wire_text(verbose=True)
        self.notes.value = "\n\n".join(f"[{level}] {msg}" for level, msg in result.notes)
        heard = sum(1 for d in result.devices if d.ubnt_packets)
        hidden = sum(1 for d in result.devices if d.key in self.hidden)
        self.status.text = (f"{len(result.devices) - hidden} device(s), {heard} answered UBNT discovery, "
                            f"{result.elapsed:.0f}s" + (f", {hidden} hidden" if hidden else "")
                            + (" (stopped early)" if result.interrupted else ""))
        self.export_button.enabled = bool(result.devices or result.trunks)
        self._update_find_buttons()
        self.hold_button.enabled = bool(result.mgr) and any(d.alias for d in result.devices)
        if self.shown_packets:  # now with the interface counters and the final checks
            self.details.value = core.render_details(self.shown_packets[0])
            self._show_packets(self.shown_packets[0], force=True)
        if result.trunks:
            self.tabs.current_tab = "On the wire"
        self._measure_latency()

    def _device(self, key):
        return next((d for d in self._all_devices() if d.key == key), None)

    def _selected_device(self):
        row = self.table.selection
        return self._device(getattr(row, "key", None)) if row is not None else None

    def on_select(self, widget, **kwargs):
        d = self._selected_device()
        self._update_find_buttons()
        if d is not None:
            self.details.value = core.render_details(d)
            self._show_packets(d, force=True)
            if self.term:  # its session, if it has one; the others keep running
                self.term.show_device(d.key, d.ip or d.mac or "this device")
            if self.phone_ui:  # its own page
                phone.show_device(self, d)
            elif self.tabs.current_tab.text not in ("Details", "Packets", "Terminal"):
                self.tabs.current_tab = "Details"

    # -- device actions: right-click menu and the Device menu --------------------
    def _add_device_menu(self):
        group = toga.Group("Device", order=50)
        section = 0
        for order, entry in enumerate(DEVICE_ACTIONS):
            if entry is None:
                section += 1
                continue
            name, title = entry
            self.commands.add(toga.Command(lambda command, name=name, **kwargs: self._device_action(name),
                                           text=title, group=group, section=section, order=order))
        self.commands.add(toga.Command(lambda command, **kwargs: self._measure_latency(),
                                       text="Measure latency to all devices", group=group, section=section + 1))

    def _install_context_menu(self):
        try:
            if self.caps["platform"] == "macos":
                self._context_menu_macos()
            elif self.caps["platform"] == "windows":
                self._context_menu_windows()
            elif self.caps["platform"] == "linux":
                self._context_menu_gtk()
        except Exception:  # the Device menu still offers everything
            self._append_log("Couldn't add the right-click menu:\n" + traceback.format_exc())

    def _context_menu_macos(self):
        from rubicon.objc import SEL, ObjCClass
        NSMenu, NSMenuItem = ObjCClass("NSMenu"), ObjCClass("NSMenuItem")
        self._menu_target = _menu_target_class().alloc().init()  # the menu holds it weakly
        self._menu_target.app = self
        menu = NSMenu.alloc().initWithTitle("Device")
        menu.autoenablesItems = False
        menu.delegate = self._menu_target
        self._menu_items = {}
        for tag, entry in enumerate(DEVICE_ACTIONS):
            if entry is None:
                menu.addItem(NSMenuItem.separatorItem())
                continue
            item = NSMenuItem.alloc().initWithTitle(entry[1], action=SEL("pick:"), keyEquivalent="")
            item.target, item.tag = self._menu_target, tag
            menu.addItem(item)
            self._menu_items[entry[0]] = item
        self.table._impl.native_table.menu = menu

    def _context_menu_windows(self):
        import System.Windows.Forms as WinForms
        view = self.table._impl.native
        strip = WinForms.ContextMenuStrip()
        self._menu_items = {}
        for entry in DEVICE_ACTIONS:
            if entry is None:
                strip.Items.Add(WinForms.ToolStripSeparator())
                continue
            item = WinForms.ToolStripMenuItem(entry[1])
            item.Click += lambda sender, event, name=entry[0]: self._device_action(name)
            strip.Items.Add(item)
            self._menu_items[entry[0]] = item

        def opening(sender, event):
            hit = view.HitTest(view.PointToClient(WinForms.Cursor.Position)).Item
            if hit is None:
                event.Cancel = True
                return
            view.SelectedIndices.Clear()
            view.SelectedIndices.Add(hit.Index)
            self._update_menu_items(self._device(getattr(self.table.data[hit.Index], "key", None)))

        strip.Opening += opening
        view.ContextMenuStrip = strip
        self._menu_strip = strip

    def _context_menu_gtk(self):
        from gi.repository import Gdk, GLib, Gtk
        view = self.table._impl.native_table  # a Gtk.TreeView
        menu = Gtk.Menu()
        self._menu_items = {}
        for entry in DEVICE_ACTIONS:
            if entry is None:
                menu.append(Gtk.SeparatorMenuItem())
                continue
            item = Gtk.MenuItem(label=entry[1])
            item.connect("activate", lambda widget, name=entry[0]: self._device_action(name))
            menu.append(item)
            self._menu_items[entry[0]] = item
        menu.show_all()

        def pressed(widget, event):
            if event.type != Gdk.EventType.BUTTON_PRESS or event.button != Gdk.BUTTON_SECONDARY:
                return False
            hit = widget.get_path_at_pos(int(event.x), int(event.y))
            if hit is None:
                return True
            index, trigger = hit[0].get_indices()[0], event.copy()

            def show():
                # Not in the press handler itself: selecting refreshes Details, and Toga flushes
                # GTK's pending events while it does, which would include this press, forever.
                widget.get_selection().select_path(Gtk.TreePath.new_from_indices([index]))
                self._update_menu_items(self._device(getattr(self.table.data[index], "key", None)))
                menu.popup_at_pointer(trigger)
                return False

            GLib.idle_add(show)
            return True

        view.connect("button-press-event", pressed)
        self._menu_gtk = menu

    def _context_menu_opening(self):
        """macOS, just before the menu shows: select the row that was right-clicked."""
        from rubicon.objc import ObjCClass
        view = self.table._impl.native_table
        row = int(view.clickedRow)
        if 0 <= row != int(view.selectedRow):
            view.selectRowIndexes(ObjCClass("NSIndexSet").indexSetWithIndex(row), byExtendingSelection=False)
        d = self._device(getattr(self.table.data[row], "key", None)) if row >= 0 else None
        self._update_menu_items(d)

    def _update_menu_items(self, d):
        """Name each item for this device (the URL, the SSH port) and grey out what it can't do."""
        for name, (title, enabled) in self._menu_state(d).items():
            item = self._menu_items.get(name)
            if item is None:
                continue
            if self.caps["platform"] == "windows":
                item.Text, item.Enabled = title, enabled
            elif self.caps["platform"] == "linux":
                item.set_label(title)
                item.set_sensitive(enabled)
            else:
                item.title, item.enabled = title, enabled

    def _menu_state(self, d) -> dict:
        titles = dict(entry for entry in DEVICE_ACTIONS if entry)
        if d is None:
            return {name: (title, False) for name, title in titles.items()}
        ip = bool(d.ip)
        ssh = self.term.find(d.key, "ssh") if self.term else None
        ping = self.term.find(d.key, "ping") if self.term else None
        idle = ip and bool(self.result) and not (self.running or self.rescanning or self.finding)
        finds = {}
        for name, kind in FINDS.items():
            ports = ", ".join(str(p) for p, k in sorted(d.services.items()) if k == kind)
            finds[name] = (titles[name] + (f"  (answers on {ports})" if ports else ""), idle)
        return {
            "web": (f"Open Web UI  ({core.web_url(d, fallback=True)})" if ip else titles["web"], ip),
            "ssh": ("Show SSH session" if ssh else f"Open SSH…  (port {d.port('ssh')})", ip),
            "ping": ("Show ping" if ping and ping.alive else titles["ping"], ip),
            "latency": (titles["latency"] + (f"  ({health.latency_cell(d)})" if health.latency_cell(d) else ""), ip),
            "rescan": (titles["rescan"], idle),
            "issues": (f"Show issues ({len(d.issues)})…" if d.issues else titles["issues"], bool(d.issues)),
            **finds,
            "note": ("Edit note…" if d.note else titles["note"], True) if d.mac
                    else (titles["note"] + "  (no MAC to keep it under)", False),
            "export_device": (titles["export_device"], True),
            "copy_ip": (f"Copy IP address  ({d.ip})" if ip else titles["copy_ip"], ip),
            "copy_mac": (f"Copy MAC address  ({d.mac})" if d.mac else titles["copy_mac"], bool(d.mac)),
            "forget": (titles["forget"], ip),
            "hide": (titles["hide"], True),
            **self._device_tools_state(d, titles),
        }

    def _device_tools_state(self, d, titles) -> dict:
        """The SSH device tools, and devices behind others (desktop only: phones have no ssh)."""
        if self.caps["mobile"]:
            return {}
        from opendisco import devicegui
        return devicegui.menu_state(self, d, titles)

    def _device_action(self, name):
        d = self._selected_device()
        if d is None and name == "scan_from" and not self.caps["mobile"]:  # from a device given by its address
            from opendisco import devicegui
            asyncio.create_task(devicegui.scan_address(self))
            return
        if d is None:
            self.status.text = "Select a device first."
            return
        title, enabled = self._menu_state(d)[name]
        if enabled and not self.caps["mobile"]:
            from opendisco import devicegui
            if devicegui.handles(self, d, name):  # the device tools, and devices behind others
                devicegui.act(self, d, name)
                return
        if not enabled:
            waits = name == "rescan" or name in FINDS or (name == "scan_from" and "(" not in title)
            self.status.text = ("Works once a scan has finished, one device at a time." if waits
                                else f"{title}: not available for this device.")
            return
        if name == "web":
            url = core.web_url(d, fallback=True)
            webbrowser.open(url)
            self.status.text = f"Opened {url}"
        elif name == "ssh":
            asyncio.create_task(self._open_ssh(d))
        elif name == "ping":
            self._open_ping(d)
        elif name == "latency":
            self._measure_latency([d])
        elif name == "rescan":
            self._rescan(d)
        elif name in FINDS:
            asyncio.create_task(self._find_after_warning(d, FINDS[name]))
        elif name == "issues":
            self._show_issues(d)
        elif name == "note":
            self._edit_note(d)
        elif name == "export_device":
            asyncio.create_task(self._export_device(d))
        elif name == "copy_ip":
            self._copy(d.ip, "IP address")
        elif name == "copy_mac":
            self._copy(d.mac, "MAC address")
        elif name == "forget":
            from opendisco import terminal
            alias = terminal.host_key_alias(d.mac, d.ip)
            gone = terminal.forget_host_key(alias, self.known_hosts)
            self.status.text = (f"Forgot the saved SSH key for {d.ip}: the next connection trusts its new one."
                                if gone else f"No SSH key saved for {d.ip}.")
        elif name == "hide":
            self.hidden[d.key] = {"mac": d.mac or "", "ip": d.ip, "vendor": d.vendor, "model": d.model,
                                  "name": d.name}
            self._save_settings()
            self._update_hidden_button()
            self._show_devices(self._all_devices())
            self.status.text = f"Hid {d.ip or d.mac}. Hidden devices… brings it back."

    # -- a device's note and its own export ------------------------------------------
    def _edit_note(self, d):
        """Write or change a device's note (where it's mounted, the site, who looks after it): kept
        by its MAC through rescans, restarts and updates, until deleted."""
        who = f"{d.ip or d.mac}  {d.name or d.model or ''}".strip()
        text = toga.MultilineTextInput(value=d.note, placeholder="Where it's mounted, the site, who looks after it…",
                                       style=Pack(flex=1))

        def finish(keep):
            close()
            if keep is None:
                return
            try:
                self.device_notes.set(d, text.value if keep else "")
            except OSError as e:
                self.status.text = f"Couldn't save the note: {e.strerror or e}"
                return
            self._notes_changed(d)
            self.status.text = f"Saved the note on {d.ip or d.mac}." if d.note else f"No note on {d.ip or d.mac} now."

        buttons = [toga.Button("Cancel", on_press=lambda w, **kw: finish(None)),
                   toga.Button("Save", on_press=lambda w, **kw: finish(True))]
        if d.note:
            buttons.insert(0, toga.Button("Delete note", on_press=lambda w, **kw: finish(False)))
        if not self.caps["mobile"]:
            buttons.insert(1 if d.note else 0, toga.Box(style=Pack(flex=1)))
        content = toga.Box(style=Pack(direction=COLUMN, flex=1, margin=14, gap=8), children=[
            toga.Label(self._wrap(f"Kept with {d.mac} in OpenDisco's data on {self._here()}, through rescans, "
                                  "restarts and updates; Details, the search and the exports include it.")),
            text, toga.Box(style=Pack(direction=ROW, gap=8), children=buttons)])
        close = self._show_panel(f"Note: {who}", content, (560, 300), resizable=True)
        text.focus()

    def _here(self) -> str:
        """What the app's text calls the device it runs on: this computer, or on phones the platform's
        own word where phone_<platform> has here() ("this iPhone", "this iPad"), else "this phone"."""
        if not self.caps["mobile"]:
            return "this computer"
        here = getattr(phone.native(self), "here", None) if self.phone_ui else None
        return here(self) if here else "this phone"

    def _notes_changed(self, d):
        """After a note changed: its ✎ in the list, and Details if it's the device shown."""
        self._show_devices(self._all_devices())
        if self._selected_device() is d:
            self.details.value = core.render_details(d)
        if self.phone_ui:
            phone.update_tools(self)

    async def _export_device(self, d):
        """Save one device's report (records.device_report): HTML, or with its saved config
        backups a .zip."""
        who = f"{d.ip or d.mac}  {d.name or d.model or ''}".strip()
        backups = records.backups_for(d)
        packed = bool(backups) and await self.main_window.dialog(toga.QuestionDialog(
            "Export device", f"{who} has {len(backups)} saved config backup(s). Include them? Yes saves a .zip with "
                             "the report and the backups; No saves the report alone (.html)."))
        ext = ".zip" if packed else ".html"
        noted = self.device_notes.entry(d).get("updated", "")
        await self._save_export(records.device_file_name(d, ext), f"Export {who}", [ext[1:]],
                                lambda path: records.write_device_export(path, d, self.result,
                                                                         backups if packed else (), noted))

    # -- SSH and ping ----------------------------------------------------------------
    def _show_terminal(self, session):
        self.tabs.current_tab = "Terminal"
        self.term.show(session)

    async def _open_ssh(self, d):
        from opendisco import terminal
        session = self.term.find(d.key, "ssh")
        if session:  # already logged in: just show it
            self._show_terminal(session)
            return
        login = await self._ssh_login(d)
        if not login:
            return
        user, password, port = login
        self.settings["ssh_user"] = user
        self._save_settings()
        argv = terminal.ssh_argv(d.ip, port, user, terminal.host_key_alias(d.mac, d.ip), self.known_hosts)
        if not terminal.in_app_terminals():
            terminal.open_console_window(argv)
            self.status.text = f"SSH to {d.ip} opened in its own window."
            return
        who = f"{user}@" if user else ""
        title = f"{d.ip}  SSH {who}port {port}" + (f"  {d.name or d.model}" if d.name or d.model else "")
        self._show_terminal(self.term.open(d.key, "ssh", title, argv, password))

    async def _ssh_login(self, d):
        """Ask for the username and password (and confirm the port); None when cancelled."""
        answer = self.loop.create_future()
        said = d.said_ports("ssh")
        found = sorted(p for p, k in d.services.items() if k == "ssh")
        where = ("It says SSH is on " + ", ".join(f"{p} ({core.PORT_SOURCES[s]})" for s, p in said.items())
                 if said else "It doesn't say which port SSH is on")
        if found:
            where += f"; SSH answers on {', '.join(map(str, found))}."
        elif d.ports is not None:
            where += "; a deep check found no SSH answering."
        else:
            where += "."
        user = toga.TextInput(value=self.settings.get("ssh_user", ""), placeholder="e.g. ubnt or admin",
                              style=Pack(flex=1))
        password = toga.PasswordInput(placeholder="empty: type it in the terminal, or use an SSH key",
                                      style=Pack(flex=1))
        port = toga.TextInput(value=str(d.port("ssh")), style=Pack(width=80))
        problem = toga.Label("", style=Pack(flex=1))

        def finish(ok):
            if answer.done():
                return
            if ok:
                text = port.value.strip()
                if not text.isdigit() or not 0 < int(text) < 65536:
                    problem.text = "The port is a number from 1 to 65535."
                    return
                answer.set_result((user.value.strip(), password.value, int(text)))
            else:
                answer.set_result(None)
            window.close()

        def closing(widget, **kwargs):
            if not answer.done():
                answer.set_result(None)
            return True

        password.on_confirm = lambda widget: finish(True)
        user.on_confirm = lambda widget: password.focus()
        label = Pack(width=80)
        window = toga.Window(title=f"SSH to {d.ip}", size=(520, 250), resizable=False, on_close=closing,
                             position=self._over_main((520, 250)))
        window.content = toga.Box(style=Pack(direction=COLUMN, margin=14, gap=8), children=[
            toga.Label(f"{d.ip}  {d.name or d.model or d.mac or ''}".strip()),
            toga.Label(where),
            toga.Box(style=Pack(direction=ROW, align_items="center", gap=8),
                     children=[toga.Label("Username", style=label), user]),
            toga.Box(style=Pack(direction=ROW, align_items="center", gap=8),
                     children=[toga.Label("Password", style=label), password]),
            toga.Box(style=Pack(direction=ROW, align_items="center", gap=8),
                     children=[toga.Label("Port", style=label), port, problem]),
            toga.Label("The password goes only to ssh, and is kept in memory to log in again if the "
                       "connection drops. It isn't stored."),
            toga.Box(style=Pack(direction=ROW, gap=8), children=[
                toga.Box(style=Pack(flex=1)),
                toga.Button("Cancel", on_press=lambda w: finish(False)),
                toga.Button("Connect", on_press=lambda w: finish(True))])])
        self._show_over_main(window)
        (password if user.value else user).focus()
        self.cancel_ssh_login = lambda: finish(False)
        try:
            return await answer
        finally:
            self.cancel_ssh_login = None

    def _open_ping(self, d):
        from opendisco import terminal
        session = self.term.find(d.key, "ping")
        if session:
            if not session.alive:
                session.type(b"\r")  # start it again
            self._show_terminal(session)
            return
        argv = terminal.ping_argv(d.ip)
        if not terminal.in_app_terminals():
            terminal.open_console_window(argv)
            self.status.text = f"Pinging {d.ip} in its own window."
            return
        title = f"{d.ip}  ping" + (f"  {d.name or d.model}" if d.name or d.model else "")
        self._show_terminal(self.term.open(d.key, "ping", title, argv))

    # -- rescanning one device -------------------------------------------------------
    def _rescan(self, d):
        self.rescanning = True
        self._update_find_buttons()
        self.spinner.start()
        self._tool_said(f"Rescanning {d.ip}…", begins=True)
        result = self.result

        def work():
            error = None
            try:
                dev, answered = core.rescan_device(result, d, lambda m: self._from_worker(self._append_log, m))
            except Exception as e:
                dev, answered, error = d, False, f"{type(e).__name__}: {e}"
            self._from_worker(self._rescanned, result, dev, answered, error)

        threading.Thread(target=work, daemon=True).start()

    def _rescanned(self, result, d, answered, error):
        self.rescanning = False
        self.spinner.stop()
        self._update_find_buttons()
        if result is not self.result:  # a new scan started meanwhile
            return
        self._show_devices(result.devices)
        if self._selected_device() is d:
            self.details.value = core.render_details(d)
            self._show_packets(d, force=True)
        if error:
            self._tool_said(f"Rescan of {d.ip} failed: {error}")
            return
        ports = ", ".join(f"{p} {k}" for p, k in sorted(d.services.items())) or "no management ports open"
        self._tool_said(f"Rescanned {d.ip}: " + ("answered discovery" if answered else "no discovery reply")
                        + f"; {ports}.")

    # -- health: the latest firmware and latency (health.py) ---------------------------
    firmware = None  # health.Firmware: the latest releases for the platforms found
    measuring = None  # the scan whose devices' latency is being measured

    def _check_firmware(self, devices):
        """Give each device the latest firmware for its platform, as far as it's known, and look up
        the rest in the background (Settings: "Check firmware versions during scans")."""
        if not self.settings.get("check_firmware", True):
            return
        if self.firmware is None:
            self.firmware = health.Firmware(self.paths.data, on_found=lambda: self._from_worker(self._health_changed),
                                            log=lambda m: self._from_worker(self._append_log, m, False))
        self.firmware.add(devices)

    def _health_changed(self):
        """New firmware answers or latency: shown in the list and in Details."""
        self._show_devices(self._all_devices())
        d = self._selected_device()
        if d is not None:
            self.details.value = core.render_details(d)

    def _measure_latency(self, devices=None):
        """Ping devices a few times each, in the background: all of them after a scan (or from
        Device > Measure latency to all devices), or the ones given."""
        res = self.result
        if res is None:
            self.status.text = "Latency is measured once a scan has finished."
            return
        if self.measuring is res:
            self.status.text = "Measuring latency already…"
            return
        asked = devices is not None
        devices = [d for d in (devices if asked else res.devices)
                   if d.ip and (asked or (d.key not in self.hidden and health.pingable(d, self.holding)))]
        if not devices:
            return
        self.measuring = res
        what = devices[0].ip if len(devices) == 1 else f"{len(devices)} devices"
        self._append_log(f"Measuring latency to {what}…", status=asked)

        def work():
            error = None
            try:
                health.measure(devices)
            except OSError as e:
                error = str(e)
            except Exception as e:
                error = f"{type(e).__name__}: {e}"
                self._from_worker(self._append_log, traceback.format_exc(), False)
            self._from_worker(self._measured, res, devices, asked, error)

        threading.Thread(target=work, daemon=True).start()

    def _measured(self, res, devices, asked, error):
        if self.measuring is res:
            self.measuring = None
        if res is not self.result:  # a new scan started meanwhile
            return
        if error:
            self._append_log(f"Latency not measured: {error}", status=asked)
            return
        if res.diag_args:  # flags high latency and loss
            core.diagnose(res.inv, *res.diag_args)
            res.devices = core.sorted_devices(res.inv)
        self._health_changed()
        self._append_log(health.summary(devices), status=asked)

    # -- chasing one device's ports ---------------------------------------------------
    async def _find_after_warning(self, d, kind):
        if self.settings.get("skip_port_warning") or self.port_warning_accepted or await self._port_warning(d):
            self._find(d, kind)

    async def _port_warning(self, d) -> bool:
        """Say what a port search can set off, and ask to go ahead (phones once a run; elsewhere
        until "Don't warn again" is ticked)."""
        text = PORT_SEARCH_WARNING.format(ip=d.ip)
        if self.caps["mobile"]:  # phones have no extra windows: a plain question
            text = text.replace("this computer", phone.hook(self, "here")(self) if self.phone_ui else "this phone")
            ok = await self.main_window.dialog(toga.QuestionDialog("Port search", text + " Go ahead?"))
            self.port_warning_accepted = bool(ok)
            return bool(ok)
        answer = self.loop.create_future()
        quiet = toga.Switch("Don't warn again")

        def finish(ok):
            if not answer.done():
                answer.set_result(ok)
                window.close()

        def closing(widget, **kwargs):
            if not answer.done():
                answer.set_result(False)
            return True

        window = toga.Window(title=f"Port search on {d.ip}", size=(540, 240), resizable=False, on_close=closing,
                             position=self._over_main((540, 240)))
        window.content = toga.Box(style=Pack(direction=COLUMN, margin=14, gap=10), children=[
            toga.Label(textwrap.fill(text, 78)),
            quiet,
            toga.Box(style=Pack(direction=ROW, gap=8), children=[
                toga.Box(style=Pack(flex=1)),
                toga.Button("Cancel", on_press=lambda w: finish(False)),
                toga.Button("Search ports", on_press=lambda w: finish(True))])])
        self._show_over_main(window)
        self.cancel_port_warning = lambda: finish(False)
        try:
            ok = await answer
        finally:
            self.cancel_port_warning = None
        if ok and quiet.value:
            self.settings["skip_port_warning"] = True
            self._save_settings()
        return ok

    def _find(self, d, kind):
        """Look for one device's SSH, HTTPS or HTTP port, or every open port ("all"): the deep
        check, then all 65535 TCP ports until it turns up. Stop ends it."""
        self.finding = True
        self.start_button.enabled, self.stop_button.enabled = False, True
        self._update_find_buttons()
        self.spinner.start()
        name = core.SERVICE_NAMES[kind]
        self._tool_said(f"Looking for {'every open port' if kind == 'all' else name} on {d.ip}…", begins=True)
        result = self.result

        def progress(done, total, found):
            self._from_worker(setattr, self.status, "text",
                              f"{d.ip}: checked {done:,} of {total:,} TCP ports for {name}, {found} open…")

        def work():
            error, ports = None, []
            try:
                ports = core.find_ports(result, d, kind, lambda m: self._from_worker(self._append_log, m), progress)
            except Exception as e:
                error = f"{type(e).__name__}: {e}"
            self._from_worker(self._found_ports, result, d, kind, ports, error)

        threading.Thread(target=work, daemon=True).start()

    def _found_ports(self, result, d, kind, ports, error):
        self.finding = False
        self.spinner.stop()
        self.start_button.enabled, self.stop_button.enabled = True, False
        self._update_find_buttons()
        if result is not self.result:
            return
        self._show_devices(result.devices)
        if self._selected_device() is d:
            self.details.value = core.render_details(d)
            self._show_packets(d, force=True)
        if error:
            self._tool_said(f"Port search on {d.ip} failed: {error}")
            return
        name = core.SERVICE_NAMES[kind]
        search = d.port_search
        everything = ", ".join(f"{p} {d.services[p]}" for p in d.ports or []) or "none"
        if kind == "all":
            self._tool_said(f"{d.ip}: open TCP ports: {everything}" + (" (stopped early)" if search.get("stopped") else ""))
        elif ports:
            self._tool_said(f"{name} on {d.ip}: port {', '.join(map(str, ports))}.")
        else:
            where = ("any of the 65,535 TCP ports" if not search.get("stopped")
                     else f"the {search['checked']:,} ports checked before stopping")
            self._tool_said(f"No {name} on {d.ip} in {where}. Open: {everything}.")

    def _tool_said(self, text, begins=False):
        """The status line; on iOS also the Tools console, which keeps what the tools found (a
        blank line before each tool's run)."""
        self.status.text = text
        if self.console is not None:
            phone.say(self, ("\n" if begins and self.console.value else "") + text)

    def _update_find_buttons(self):
        """Phones: the Find buttons act on the device last tapped, once a scan has finished. (iOS:
        all of Tools.)"""
        if self.phone_ui:
            phone.update_tools(self)
            return
        if not self.find_buttons:
            return
        d = self._selected_device()
        idle = bool(d and d.ip and self.result) and not (self.running or self.rescanning or self.finding)
        for button in self.find_buttons:
            button.enabled = idle

    def on_find_button(self, widget, **kwargs):
        if self.finding and self.phone_ui:  # the button of the search reads Stop
            self.on_stop(widget)
            return
        d = self._selected_device()
        if d is not None:
            self.find_from = widget.id
            self._device_action(widget.id)

    # -- a device's issues: the Status column's hover text and list ------------------
    @staticmethod
    def _issue_text(d, width=None) -> str:
        lines = []
        for level, tag, msg in d.issues:
            line = f"{core.status_label(tag)} ({level}): {msg}"
            lines.append(textwrap.fill(line, width, subsequent_indent="    ") if width else line)
        return "\n".join(lines)

    def on_activate(self, widget, row=None, **kwargs):
        d = self._device(getattr(row, "key", None)) if row is not None else None
        if d is not None and d.issues:
            self._show_issues(d)

    def _show_issues(self, d):
        """Every finding for one device, with its public write-ups (CVE pages) one click away."""
        links = core.issue_links(d)
        text = toga.MultilineTextInput(readonly=True, value=self._issue_text(d),
                                       style=Pack(flex=1, font_family="monospace", font_size=11))
        rows = [toga.Box(style=Pack(flex=1)), toga.Button("Close", on_press=lambda w: window.close())]
        if links:
            pick = toga.Selection(items=[name for name, _ in links], style=Pack(width=200))
            rows[:0] = [toga.Label("Read about"), pick,
                        toga.Button("Open", on_press=lambda w: webbrowser.open(dict(links)[pick.value]))]
        title = f"{d.ip or d.mac}  {d.name or d.model or ''}".strip()
        window = toga.Window(title=f"Issues: {title}", size=(720, 360), position=self._over_main((720, 360)))
        window.content = toga.Box(style=Pack(direction=COLUMN, margin=12, gap=8), children=[
            text, toga.Box(style=Pack(direction=ROW, align_items="center", gap=8), children=rows)])
        self._show_over_main(window)

    def _tip(self, index) -> str:
        """Hover text for a table row: its device's issues, or nothing."""
        try:
            d = self._device(getattr(self.table.data[index], "key", None))
        except IndexError:
            return ""
        if d is None or not d.issues:
            return ""
        return self._issue_text(d, 90) + ("\n\nDouble-click for the list" + (" and CVE pages." if core.issue_links(d) else "."))

    def _install_status_tips(self):
        """Hovering over a device lists its issues (Toga's tables have no tooltips of their own)."""
        try:
            if self.caps["platform"] == "macos":
                self._status_tips_macos()
            elif self.caps["platform"] == "windows":
                view = self.table._impl.native
                view.ShowItemToolTips = True

                def retrieve(sender, e):  # runs after Toga's own handler has made the row
                    if e.Item is not None:
                        e.Item.ToolTipText = self._tip(e.ItemIndex)

                view.RetrieveVirtualItem += retrieve
                self._tip_handler = retrieve
            elif self.caps["platform"] == "linux":
                view = self.table._impl.native_table

                def query(widget, x, y, keyboard, tooltip):
                    found, _x, _y, _model, path, _iter = widget.get_tooltip_context(x, y, keyboard)
                    text = self._tip(path.get_indices()[0]) if found and path else ""
                    if not text:
                        return False
                    tooltip.set_text(text)
                    widget.set_tooltip_row(tooltip, path)
                    return True

                view.set_has_tooltip(True)
                view.connect("query-tooltip", query)
        except Exception:  # cosmetic: Show issues… and Details still have it all
            self._append_log("Couldn't add the hover lists:\n" + traceback.format_exc())

    def _status_tips_macos(self):
        """macOS: each row's cells carry the hover text, set as the table makes them."""
        from rubicon.objc import NSInteger, ObjCInstance, objc_id, objc_method, send_super
        from rubicon.objc.runtime import libobjc
        native = self.table._impl.native_table
        table_class = native.objc_class
        app = self

        global _TIP_TABLE
        if _TIP_TABLE is None:
            class OpenDiscoTipTable(table_class):
                @objc_method
                def tableView_viewForTableColumn_row_(self, table, column, row: int):
                    view = send_super(__class__, self, "tableView:viewForTableColumn:row:", table, column, row,
                                      argtypes=[objc_id, objc_id, NSInteger], restype=objc_id)
                    if not view:
                        return None
                    view = ObjCInstance(view)
                    view.toolTip = app._tip(row) or None
                    return view

            _TIP_TABLE = OpenDiscoTipTable
        libobjc.object_setClass(native, _TIP_TABLE)

    # -- clipboard and hidden devices -----------------------------------------------
    def _copy(self, text, what):
        try:
            if self.caps["platform"] == "macos":
                from rubicon.objc import ObjCClass
                board = ObjCClass("NSPasteboard").generalPasteboard
                board.clearContents()
                board.setString(text, forType="public.utf8-plain-text")
            elif self.caps["platform"] == "windows":
                import System.Windows.Forms as WinForms
                WinForms.Clipboard.SetText(text)
            elif self.caps["platform"] == "linux":
                from gi.repository import Gdk, Gtk
                board = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
                board.set_text(text, -1)
                board.store()
            elif self.phone_ui:
                phone.native(self).copy_text(text)
            else:
                raise NotImplementedError
            self.status.text = f"Copied {what} {text}"
        except Exception:
            self.status.text = f"{what}: {text} (copying isn't supported here)"

    def _update_hidden_button(self):
        self.hidden_button.text = f"Hidden devices ({len(self.hidden)})…"

    def on_hidden(self, widget, **kwargs):
        def rows():
            return [{"mac": info.get("mac") or "(no MAC)", "ip": info.get("ip", ""), "vendor": info.get("vendor", ""),
                     "model": info.get("model", ""), "name": info.get("name", ""), "key": key}
                    for key, info in sorted(self.hidden.items(), key=lambda kv: kv[1].get("ip", ""))]

        table = toga.Table(columns=["MAC", "IP", "Vendor", "Model", "Name"], data=rows(), multiple_select=True,
                           style=Pack(flex=1))

        def unhide(keys):
            for key in keys:
                self.hidden.pop(key, None)
            self._save_settings()
            self._update_hidden_button()
            self._show_devices(self._all_devices())
            table.data = rows()

        window = toga.Window(title="Hidden devices", size=(700, 380), position=self._over_main((700, 380)))
        window.content = toga.Box(style=Pack(direction=COLUMN, margin=12, gap=8), children=[
            toga.Label("These are left out of the table, by MAC address, in every scan until unhidden. "
                       "Exports still include them."),
            table,
            toga.Box(style=Pack(direction=ROW, gap=8), children=[
                toga.Box(style=Pack(flex=1)),
                toga.Button("Unhide selected", on_press=lambda w: unhide([r.key for r in table.selection])),
                toga.Button("Unhide all", on_press=lambda w: unhide(list(self.hidden))),
                toga.Button("Close", on_press=lambda w: window.close())])])
        self._show_over_main(window)

    # -- exports and holding addresses ---------------------------------------------
    async def on_export(self, widget, **kwargs):
        """The scan report; on desktops, first a choice of it or the extras (records.SITE_EXPORTS).
        (Phones: the scan report as before; their Export offers the extras through _export.)"""
        if not self.result:
            return
        if self.caps["mobile"]:
            await self._export("scan")
            return
        self._export_chooser()

    def _export_chooser(self):
        """Export: the scan report first, as it always was, then the site-wide extras."""
        backups = records.all_backups()
        notes = len(self.device_notes.items)
        state = {"backups": (bool(backups), f"{sum(len(p) for _, p in backups)} file(s) from {len(backups)} device(s)"
                             if backups else "none saved yet"),
                 "notes": (bool(notes), f"{notes} note(s)" if notes else "none written yet")}
        choices = []
        for kind, button, text, types in [records.SCAN_EXPORT, *records.SITE_EXPORTS]:
            enabled, extra = state.get(kind, (True, ""))
            saved = types[:1] if self.caps["mobile"] else types  # phones save the first type only
            choices.append((kind, button, records.choice_text(text, saved, extra), enabled))

        def pick(kind):
            close()
            asyncio.create_task(self._export(kind))

        rows = [toga.Box(style=Pack(direction=ROW, align_items="center", gap=10), children=[
                    toga.Button(button, enabled=enabled, on_press=lambda w, kind=kind, **kw: pick(kind),
                                style=Pack(width=170)),
                    toga.Label(textwrap.fill(text, 58), style=Pack(flex=1))])
                for kind, button, text, enabled in choices]
        content = toga.Box(style=Pack(direction=COLUMN, margin=14, gap=10), children=[
            *rows, toga.Box(style=Pack(direction=ROW), children=[
                toga.Box(style=Pack(flex=1)), toga.Button("Close", on_press=lambda w, **kw: close())])])
        close = self._show_panel("Export", content, (640, 290))

    async def _export(self, kind: str):
        """Save the scan report ("scan") or one of records.SITE_EXPORTS, named for now."""
        stamp = time.strftime("%Y%m%d-%H%M")
        devices = self._all_devices()
        if kind == "scan":
            res = self.result
            if self.phone_ui:  # the phones' own: iOS's share sheet, Android's Downloads
                try:
                    phone.native(self).export(self, f"opendisco-scan-{stamp}.html")
                except Exception as e:
                    self.status.text = f"Couldn't save the export: {getattr(e, 'strerror', None) or e}"
                return
            await self._save_export(f"opendisco-scan-{stamp}.html",
                                    "Export results (.html opens on any phone; .csv, .json)", records.SCAN_EXPORT[3],
                                    lambda path: core.write_export(res, path))
            return
        _kind, button, _text, types = next(e for e in records.SITE_EXPORTS if e[0] == kind)
        names = {"security": "security", "backups": "config-backups", "notes": "notes", "log": "log"}
        log = self.log.value
        await self._save_export(f"opendisco-{names[kind]}-{stamp}.{types[0]}", f"Export: {button.rstrip('…')}", types,
                                lambda path: records.write_site_export(kind, path, devices, self.device_notes, log))

    async def _save_export(self, name: str, title: str, file_types: list, write):
        """Save an export where this platform keeps files: a save dialog on desktops; on phones, the
        share sheet (iOS) or Downloads (Android). write(path) writes it in the format its
        extension names."""
        try:
            if self.caps["mobile"]:  # Toga has no save dialog there
                folder = Path(self.paths.cache) / "exports"  # in place of the last one: shared already, or not wanted
                shutil.rmtree(folder, ignore_errors=True)
                folder.mkdir(parents=True)
                path = folder / name
                write(str(path))
                share = getattr(phone.native(self), "share", None) if self.phone_ui else None
                if share is not None:  # iOS: Files, Mail, AirDrop…
                    share(self, path)
                    return
                if self.caps["platform"] == "android":
                    self.status.text = f"Saved {self._save_to_downloads(name, path.read_bytes())}"
                    return
                self.status.text = f"Saved {path}"
                return
            path = await self.main_window.dialog(toga.SaveFileDialog(title, name, file_types=file_types))
            if not path:
                return
            write(str(path))
        except Exception as e:  # a read-only folder, a full disk, Android refusing...
            self.status.text = f"Couldn't save the export: {getattr(e, 'strerror', None) or e}"
            return
        self.status.text = f"Saved {path}"

    def _save_to_downloads(self, name: str, text) -> str:
        """Android: save a report (text, or a file's bytes) where a file manager or browser can
        open it, the Downloads folder (Android 10 and later; earlier, the app's folder on shared
        storage)."""
        import mimetypes
        from java import jclass
        data = text.encode("utf-8") if isinstance(text, str) else bytes(text)
        context = self._impl.native.getApplicationContext()
        if jclass("android.os.Build$VERSION").SDK_INT < 29:
            path = Path(str(context.getExternalFilesDir(None))) / name
            path.write_bytes(data)
            return str(path)
        columns = jclass("android.provider.MediaStore$MediaColumns")
        values = jclass("android.content.ContentValues")()
        values.put(columns.DISPLAY_NAME, name)
        values.put(columns.MIME_TYPE, mimetypes.guess_type(name)[0] or "application/octet-stream")
        values.put(columns.RELATIVE_PATH, jclass("android.os.Environment").DIRECTORY_DOWNLOADS)
        resolver = context.getContentResolver()
        uri = resolver.insert(jclass("android.provider.MediaStore$Downloads").EXTERNAL_CONTENT_URI, values)
        stream = resolver.openOutputStream(uri)
        try:
            stream.write(data)
        finally:
            stream.close()
        try:  # Android adds " (1)" when the folder already has that name: say what it's called
            cursor = resolver.query(uri, [columns.DISPLAY_NAME], None, None, None)
            if cursor is not None:
                if cursor.moveToFirst():
                    name = cursor.getString(0) or name
                cursor.close()
        except Exception:
            pass
        return f"{name} in Downloads"

    async def on_hold(self, widget, **kwargs):
        if self.holding:
            await self._release_hold()
            return
        res = self.result
        # Until the addresses are in place: a scan started meanwhile would replace this result
        # and lose track of them.
        self.hold_button.enabled = self.start_button.enabled = False

        def work():
            try:
                res.mgr.authorize()  # sudo on macOS and Linux; on Windows the app already runs as administrator
                lines = core.hold_start(res.mgr, res.inv, lambda m: self._from_worker(self._append_log, m))
            except SystemExit as e:
                lines = [f"[error] {str(e.code).removeprefix('error: ')}"]
            except Exception as e:
                lines = [f"[error] {type(e).__name__}: {e}"]
            self._from_worker(self._held, res, lines)

        threading.Thread(target=work, daemon=True).start()

    def _held(self, res, lines):
        self.hold_button.enabled = self.start_button.enabled = True
        if not res.mgr.active:
            self.notes.value += "\n\n" + ("\n".join(lines) or "Nothing was reached through an address to keep.")
            return
        self.holding = True
        self.hold_button.text = "Release addresses"
        self.notes.value = "Keeping these addresses for working on the gear (Release addresses removes them):\n" + "\n".join(lines) + \
                           "\n\n" + self.notes.value
        self.tabs.current_tab = "Notes"
        asyncio.create_task(self._keepalive())

    async def _keepalive(self):
        while self.holding:
            await asyncio.sleep(60)
            if self.holding:
                await asyncio.get_running_loop().run_in_executor(None, self.result.mgr.keepalive)

    async def _release_hold(self):
        if not self.holding:
            return
        self.holding = False
        mgr = self.result.mgr
        await asyncio.get_running_loop().run_in_executor(None, mgr.remove_all)
        self.hold_button.text = "Keep addresses"
        self.status.text = "Temporary addresses removed."

    # -- networks file (in Settings) ---------------------------------------------------
    def on_save_networks(self, widget=None, **kwargs) -> bool:
        """Check Settings' networks list and save it; False, with the line that's wrong on the
        status line, when it can't be used."""
        try:
            for n, line in enumerate(self.networks.value.splitlines(), 1):
                line = line.split("#", 1)[0].strip()
                if line:
                    core.parse_alias_spec(line)
        except ValueError as e:
            self.status.text = f"Networks line {n}: {e}"
            return False
        try:
            self.networks_path.write_text(self.networks.value, encoding="utf-8")
        except OSError as e:
            self.status.text = f"Couldn't save {self.networks_path}: {e.strerror or e}"
            return False
        self.status.text = f"Saved {self.networks_path}"
        return True

    def on_reset_networks(self, widget=None, **kwargs):
        self.networks.value = Path(core.DEFAULT_NETWORKS_FILE).read_text(encoding="utf-8")

    # -- settings and updates -------------------------------------------------------
    def _add_app_commands(self):
        """Settings… where each system keeps it (macOS: the app menu; Windows: File; Linux: the
        app's menu) and a check for updates (macOS: under About; Windows, Linux: Help). Android
        has no standard place for either: the check goes in its ⋮ menu, and Settings too unless
        it's in the title bar (phone_android)."""
        platform = self.caps["platform"]
        group = {"macos": toga.Group.APP, "android": toga.Group.COMMANDS}.get(platform, toga.Group.HELP)
        check = toga.Command(lambda command, **kwargs: self._check_for_update(quiet=False),
                             text="Check for OpenDisco updates…", group=group, section=-1 if platform == "macos" else 0,
                             order=1)
        self.commands.add(check)
        if not self.phone_ui:
            settings = toga.Command.standard(self, toga.Command.PREFERENCES, text="Settings…")
            self.commands.add(settings or toga.Command(lambda command, **kwargs: self.preferences(), text="Settings…"))

    def _show_panel(self, title, content, size, on_close=None, resizable=False):
        """A small window over the main one; on phones, which have one window, a page shown in
        place of the main window's content (iOS: pushed over it, with a back button). Returns what
        closes it. on_close runs when it's closed from its title bar."""
        if self.phone_ui:  # with the phone's looks
            return phone.push_panel(self, title, content, on_close, fit=True)
        if self.caps["mobile"]:
            page = toga.Box(style=Pack(direction=COLUMN, margin=12, gap=10), children=[
                toga.Label(title, style=Pack(font_weight="bold", font_size=18)), content])
            return self._push_page(page, title, on_back=on_close)
        closed = []

        def closing(widget, **kwargs):
            closed.append(True)
            if on_close:
                on_close()
            return True

        def close():
            if not closed:
                closed.append(True)
                window.close()

        window = toga.Window(title=title, size=size, resizable=resizable, on_close=closing,
                             position=self._over_main(size))
        window.content = content
        self._show_over_main(window)
        self._fit_window(window)
        return close

    def _push_page(self, page, title, subtitle="", on_back=None):
        """Android: show a page in place of the main window's content, over what was there (a
        page shown already comes to the top). Returns what takes it away; Back and Up do that,
        then on_back, as a window's close button would."""
        self._pop_page(page, show_next=False)

        def back():
            self._pop_page(page)
            if on_back:
                on_back()

        self._panels.append((page, back, title, subtitle))
        self.main_window.content = page
        self._top_changed()
        return lambda: self._pop_page(page)

    def _pop_page(self, page, show_next=True):
        shown = [entry for entry in self._panels if entry[0] is page]
        if not shown:
            return
        on_top = self._panels[-1] is shown[0]
        self._panels.remove(shown[0])
        if on_top and show_next:
            self.main_window.content = self._panels[-1][0] if self._panels else self.main_content
            self._top_changed()

    def _top_changed(self):
        """Android: Back closes a page while one is open, and otherwise leaves the app; the title
        bar shows what's on top."""
        if self.back_callback is not None:
            self.back_callback.setEnabled(bool(self._panels))
        if self.phone_ui and self.caps["platform"] == "android":
            phone.native(self).show_bar(self)

    def _fit_window(self, window):
        """macOS: Toga grows a window to fit its content by comparing the content with the whole
        window, title bar included, which can leave the bottom of the content under the edge.
        Make the area inside at least as big as the content needs."""
        if self.caps["platform"] != "macos":
            return
        try:
            from rubicon.objc import NSSize
            layout, native = window.content.layout, window._impl.native
            inside = native.contentView.frame.size
            width, height = max(inside.width, layout.min_width), max(inside.height, layout.min_height)
            if (width, height) != (inside.width, inside.height):
                native.setContentSize(NSSize(width, height))
        except Exception:
            pass  # cosmetic

    def _wrap(self, text: str) -> str:
        """Labels don't wrap by themselves: a long line would run past the window's edge."""
        width = 40 if self.caps["mobile"] else 68
        return "\n".join(textwrap.fill(part, width) for part in text.split("\n"))

    def preferences(self, *args, **kwargs):
        """The Settings window: the switches, the subnets every scan also sweeps, and where
        temporary addresses work, the networks probed through them. Toga's standard Settings…
        command calls this."""
        if self.close_settings:  # open already: bring it back to the front
            self.close_settings()
        mono = Pack(flex=1, font_family="monospace", font_size=12 if self.caps["mobile"] else 11)
        sweep = toga.MultilineTextInput(value="\n".join(map(str, self.settings.get(records.SWEEP_KEY) or [])),
                                        placeholder="10.20.0.0/24   # a subnet or an address a line", style=mono)
        sweep_said, networks_said = toga.Label("", style=Pack(flex=1)), toga.Label("", style=Pack(flex=1))
        saved = {"sweep": sweep.value, "networks": None}
        swept = records.sweep_targets(self.settings.get(records.SWEEP_KEY))
        if swept:
            sweep_said.text = self._wrap(f"Every scan also sweeps {records.describe_targets(swept)}.")

        def save_sweep(*args, **kwargs) -> bool:
            targets, problems = records.parse_sweep_list(sweep.value)
            if problems:
                sweep_said.text = self._wrap(problems[0])
                return False
            self.settings[records.SWEEP_KEY] = [line.rstrip() for line in sweep.value.strip().splitlines()]
            self._save_settings()
            saved["sweep"] = sweep.value
            sweep_said.text = self._wrap(f"Saved: every scan also sweeps {records.describe_targets(targets)}."
                                         if targets else "Saved: no extra subnets.")
            return True

        def save_networks(*args, **kwargs) -> bool:
            ok = self.on_save_networks()
            networks_said.text = self._wrap(self.status.text)
            if ok:
                saved["networks"] = self.networks.value
            return ok

        def save_changed() -> bool:
            ok = sweep.value == saved["sweep"] or save_sweep()
            if self.networks is not None and self.networks.value != saved["networks"]:
                ok = save_networks() and ok
            return ok

        def done(*args, **kwargs):
            if not save_changed():  # stays open, saying what's wrong
                return
            close, self.close_settings, self.networks = self.close_settings, None, None
            if close:
                close()

        def closed():  # from the title bar (phones: Back): what can be saved is
            self.close_settings = None
            if not save_changed():
                self.status.text = "Settings: a list with a mistake wasn't saved."
            self.networks = None

        def changed(widget, key, **kwargs):
            self.settings[key] = widget.value
            self._save_settings()

        switches = [toga.Switch(text, value=self.settings.get(key, True),
                                on_change=lambda widget, key=key, **kwargs: changed(widget, key))
                    for key, text in SETTINGS.items() if key != "check_app_updates" or self.caps["updates"]]
        if self.phone_ui:  # the scan buttons there have no options beside them
            def deep(widget, **kwargs):
                self.deep.value = widget.value
                changed(widget, "deep_checks")

            switches.insert(0, toga.Switch(self.deep.text, value=self.deep.value, on_change=deep))
        heading = Pack(font_weight="bold", margin_top=6)
        lists = [toga.Label("Also sweep these subnets", style=heading),
                 toga.Label(self._wrap("Routed or VPN subnets that every scan also probes with UBNT discovery, so "
                                       "gear there turns up from here: a subnet or an address a line, # starts a "
                                       f"comment. Up to {records.SWEEP_LIMIT:,} addresses in all, about "
                                       f"{records.sweep_seconds(records.SWEEP_LIMIT):.0f}{records.SECONDS} more per "
                                       "scan.")),
                 sweep,
                 toga.Box(style=Pack(direction=ROW, align_items="center", gap=8), children=[
                     sweep_said, toga.Button("Save", on_press=save_sweep)])]
        if self.caps["aliases"]:  # desktops: Probe listed networks
            self.networks = toga.MultilineTextInput(value=self.networks_path.read_text(encoding="utf-8"),
                                                    style=Pack(flex=2, font_family="monospace", font_size=11))
            saved["networks"] = self.networks.value
            lists += [toga.Label("Networks probed through temporary addresses", style=heading),
                      toga.Label(self._wrap("With Probe listed networks on, a scan gives this computer an address "
                                            f"in each for a moment. Kept in {self.networks_path}")),
                      self.networks,
                      toga.Box(style=Pack(direction=ROW, align_items="center", gap=8), children=[
                          networks_said, toga.Button("Restore defaults", on_press=self.on_reset_networks),
                          toga.Button("Save", on_press=save_networks)])]
        content = toga.Box(style=Pack(direction=COLUMN, flex=1, margin=14, gap=8), children=[
            *switches,
            toga.Label(textwrap.fill(vulns.NVD_NOTICE, 60), style=Pack(font_size=10)),
            *lists,
            toga.Box(style=Pack(direction=ROW), children=[toga.Box(style=Pack(flex=1)),
                                                          toga.Button("Done", on_press=done)])])
        size = (760, 740) if self.caps["aliases"] else (560, 480)
        self.close_settings = self._show_panel("Settings", content, size, on_close=closed, resizable=True)

    def _launch_checks(self):
        if self.caps["updates"]:
            failed = self._after_update()
            if self.settings.get("check_app_updates", True) and not failed:  # not the same offer straight away
                self._check_for_update(quiet=True)
        if self.settings.get("check_cve_updates", True) and vulns.refresh_due(self.paths.data):  # about daily
            self._refresh_cves()

    def _refresh_cves(self):
        """Fetch fresh CVE data from the NVD in the background (Settings: "Check for new CVEs when
        opening"), so newly published CVEs are flagged without a new release. Offline, it's a Log
        line; a newer list re-checks the devices on screen."""
        def work():
            updated = vulns.refresh(self.paths.data, lambda m: self._from_worker(self._append_log, m, False))
            if updated:
                self._from_worker(self._recheck_cves)

        threading.Thread(target=work, daemon=True).start()

    def _recheck_cves(self):
        res = self.result
        if res is None or self.running or not res.diag_args:
            return
        core.diagnose(res.inv, *res.diag_args)
        res.devices = core.sorted_devices(res.inv)
        self._show_devices(res.devices)
        d = self._selected_device()
        if d is not None:
            self.details.value = core.render_details(d)

    def _check_for_update(self, quiet: bool):
        """Ask GitHub for the latest release, in the background. quiet (the launch check): only a
        Log line unless there's a newer version; asked from the menu, say what was found."""
        if self.updating:
            if not quiet:
                self.status.text = "An update is already under way."
            return
        self.updating = True
        if not quiet:
            self.status.text = "Checking for OpenDisco updates…"

        def work():
            release, error = None, None
            try:
                release = update.latest(timeout=5 if quiet else 15)
            except update.UpdateError as e:
                error = str(e)
            except Exception as e:
                error = f"{type(e).__name__}: {e}"
            self._from_worker(self._checked, release, error, quiet)

        threading.Thread(target=work, daemon=True).start()

    def _checked(self, release, error, quiet):
        if error or not release.newer:
            self.updating = False
            text = (f"Update check: {error}." if error
                    else f"Update check: OpenDisco {__version__} is the latest version.")
            self._append_log(text, status=False)  # the launch check stays in the Log
            if not quiet:
                self.status.text = ("Couldn't check for updates." if error
                                    else f"OpenDisco {__version__} is the latest version.")
                asyncio.create_task(self.main_window.dialog(
                    toga.ErrorDialog("Couldn't check for updates", f"{error[0].upper()}{error[1:]}.") if error
                    else toga.InfoDialog("No update", f"OpenDisco {__version__} is the latest version.")))
            return
        self._append_log(f"Update check: OpenDisco {release.version} is out (this is {__version__}).", status=False)
        self.status.text = f"OpenDisco {release.version} is out."
        self._offer_update(release)

    def _offer_update(self, release):
        """Say what's new, with buttons to update or not now. A copy that can't replace itself
        (run from source, say) links the release instead."""
        kind, target = update.installed_as()
        asset = update.pick_asset(release, kind)
        if kind == "source":
            why = "This copy runs from source, so it doesn't update itself: the release page has the new version."
        elif asset is None:
            why = (f"The release has no {update.asset_names(release.version, kind)[0]}, so this copy can't "
                   "update itself: the release page has the other installers.")
        else:
            why = update.cannot_update(kind, target)
            why = f"This copy can't update itself: {why}." if why else ""
        heading = f"OpenDisco {release.version} is out; this is {__version__}."
        if release.title not in (release.version, f"v{release.version}", f"OpenDisco {release.version}"):
            heading += f"\n{release.title}"
        notes = toga.MultilineTextInput(readonly=True, value=update.excerpt(release.notes) or "No release notes.",
                                        style=Pack(flex=1, font_size=12 if self.caps["mobile"] else 11))

        def finish(choice):
            close()
            if choice == "update":
                asyncio.create_task(self._start_update(release, kind, target, asset))
                return
            self.updating = False
            if choice == "page":
                webbrowser.open(release.page)

        not_now = toga.Button("Not now", on_press=lambda w, **kwargs: finish(None))
        if why:
            buttons = [not_now, toga.Button("Open release page", on_press=lambda w, **kwargs: finish("page"))]
        else:
            buttons = [toga.Button("Release notes", on_press=lambda w, **kwargs: webbrowser.open(release.page)),
                       not_now, toga.Button("Update", on_press=lambda w, **kwargs: finish("update"))]
        if not self.caps["mobile"]:  # the answers on the right
            buttons.insert(len(buttons) - 2, toga.Box(style=Pack(flex=1)))
        content = toga.Box(style=Pack(direction=COLUMN, flex=1, gap=10, margin=0 if self.caps["mobile"] and not self.phone_ui else 14),
                           children=[toga.Label(self._wrap(heading)), notes,
                                     *([toga.Label(self._wrap(why))] if why else []),
                                     toga.Box(style=Pack(direction=ROW, gap=8), children=buttons)])
        close = self._show_panel("OpenDisco update", content, (620, 440), on_close=lambda: finish(None),
                                 resizable=True)

    def _busy(self) -> str:
        """What restarting for an update would end, or "" for nothing."""
        ending = []
        if self.running or self.rescanning or self.finding:
            ending.append("the scan in progress stops")
        if self.term and self.term.sessions:
            ending.append("the SSH and ping sessions close")
        if self.holding:
            ending.append("the kept addresses are removed")
        return ", ".join(ending)

    async def _start_update(self, release, kind, target, asset):
        busy = self._busy()
        if busy and not await self.main_window.dialog(toga.QuestionDialog(
                "Update now?", f"Updating restarts OpenDisco: {busy}. Update now?")):
            self.updating = False
            return
        android = kind == "android"
        try:
            folder = self._android_download_folder(asset.name) if android else update.download_folder()
        except Exception as e:
            self._update_failed(release, f"no folder to download it to ({e})")
            return
        cancel = self.update_cancel = threading.Event()
        label = toga.Label(self._wrap(f"Downloading {asset.name}"))
        amount = toga.Label("")
        bar = toga.ProgressBar(max=1.0, style=Pack(flex=1))
        stop = toga.Button("Cancel", on_press=lambda w, **kwargs: cancel.set())
        content = toga.Box(style=Pack(direction=COLUMN, gap=10, margin=0 if self.caps["mobile"] and not self.phone_ui else 14), children=[
            label, bar, amount, toga.Box(style=Pack(direction=ROW), children=[toga.Box(style=Pack(flex=1)), stop])])
        close = self._show_panel("Updating OpenDisco", content, (520, 200), on_close=cancel.set)

        def shown(done, total):
            bar.value = min(1.0, done / total) if total else 0.0
            amount.text = f"{done / 1e6:.1f} of {total / 1e6:.1f} MB" if total else f"{done / 1e6:.1f} MB"

        def installing(text):
            stop.enabled = False  # past the point where stopping leaves nothing changed
            bar.value = 1.0
            label.text, amount.text = text, ""

        def log(msg):  # the details go to the Log; the status line would cut them off
            self._from_worker(self._append_log, msg, False)

        def work():
            path, error = None, None
            try:
                path = update.download(asset, folder, lambda done, total: self._from_worker(shown, done, total), cancel)
                log(f"Downloaded {asset.name}: its SHA-256 matches the one GitHub lists.")
                if kind in ("macos", "deb", "rpm", "tarball"):
                    self._from_worker(installing, f"Installing OpenDisco {release.version}…")
                if kind == "macos":
                    update.install_macos(path, target, release.version, log)
                elif kind in ("deb", "rpm"):
                    update.install_package(path, kind, log)
                elif kind == "tarball":
                    update.install_tarball(path, target, release.version, log)
            except update.UpdateError as e:
                error = str(e)
            except Exception as e:
                error = f"{type(e).__name__}: {e}"
                log(traceback.format_exc())
            if error:
                shutil.rmtree(folder, ignore_errors=True)
            self._from_worker(self._update_ready, release, kind, target, path, folder, error, close)

        threading.Thread(target=work, daemon=True).start()

    def _update_failed(self, release, error):
        self.updating = False
        self._append_log(f"Update to OpenDisco {release.version} failed: {error}.", status=False)
        self.status.text = f"The update to {release.version} failed: this is still {__version__}."
        asyncio.create_task(self.main_window.dialog(toga.ErrorDialog(
            "Update failed", f"{error[0].upper()}{error[1:]}.\n\nNothing was changed: this is still OpenDisco "
                             f"{__version__}.")))

    def _update_ready(self, release, kind, target, path, folder, error, close):
        """Downloaded and checked (and on macOS and Linux, installed): restart into it."""
        close()
        self.update_cancel = None
        if error == "cancelled":
            self.updating = False
            self.status.text = "Update cancelled."
            return
        if error:
            self._update_failed(release, error)
            return
        if kind == "android":
            if self._may_install_apps():
                self._hand_apk_over(release, path, folder)
            else:
                self._install_when_allowed(release, path, folder)
            return
        self.settings["update"] = {"version": release.version, "folder": str(folder)}
        self._save_settings()
        try:
            if kind == "windows":
                update.start_windows_update(path, target, folder / "update.log")
            else:
                update.relaunch_after_exit(update.relaunch_command(kind, target))
        except Exception as e:
            if kind == "windows":  # nothing was installed
                self.settings.pop("update", None)
                self._save_settings()
                shutil.rmtree(folder, ignore_errors=True)
                self._update_failed(release, f"the installer didn't start ({e})")
            else:
                self.updating = False
                self.status.text = f"Installed OpenDisco {release.version}: it runs from the next start."
            return
        self._append_log(f"Restarting into OpenDisco {release.version}…")
        self.request_exit()

    def _after_update(self) -> bool:
        """The first time the app opens after an update: say whether it took, and delete the
        download (and Windows' copy of the previous version). True when it didn't take."""
        done = self.settings.pop("update", None)
        if not isinstance(done, dict):
            return False
        self._save_settings()
        folder = Path(str(done.get("folder") or ""))
        report = ""
        if folder.name.startswith("opendisco-update"):  # ours: never delete anything else
            try:
                report = (folder / "update.log").read_text(encoding="utf-8-sig", errors="replace")
            except OSError:
                pass
            shutil.rmtree(folder, ignore_errors=True)
        wanted = str(done.get("version") or "")
        if update.version_key(__version__) >= update.version_key(wanted):
            self._append_log(f"Updated to OpenDisco {__version__}.")
            return False
        lines = [line.split("  ", 1)[-1] for line in report.strip().splitlines()]  # without the times
        detail = lines[-1] if lines else ""
        self._append_log(f"The update to OpenDisco {wanted} didn't install: this is still {__version__}."
                         + (f"\n{report.strip()}" if report.strip() else ""), status=False)
        self.status.text = f"OpenDisco {wanted} didn't install."
        asyncio.create_task(self.main_window.dialog(toga.ErrorDialog(
            "Update not installed", f"OpenDisco {wanted} didn't install: this is still {__version__}."
                                    + (f"\n\n{detail}" if detail else ""))))
        return True

    def _android_download_folder(self, keep: str) -> Path:
        """Android: downloads go in the part of the app's cache that Briefcase's FileProvider
        shares (shared/), so Android's installer can read them. The file named keep stays: if
        the installer was left without installing it, another try needn't download it again."""
        context = self._impl.native.getApplicationContext()
        folder = Path(str(context.getCacheDir().getAbsolutePath())) / "shared" / "opendisco-update"
        folder.mkdir(parents=True, exist_ok=True)
        for item in folder.iterdir():
            if item.name != keep:
                shutil.rmtree(item) if item.is_dir() else item.unlink()
        return folder

    def _may_install_apps(self) -> bool:
        """Android 8 and later install apps from OpenDisco only once Settings allows it."""
        from java import jclass
        if jclass("android.os.Build$VERSION").SDK_INT < 26:
            return True
        return bool(self._impl.native.getPackageManager().canRequestPackageInstalls())

    def _install_when_allowed(self, release, path, folder):
        """Android: open the setting that allows installing apps from OpenDisco, and hand the
        .apk over as soon as the app is back in front with it allowed. (Android's installer can
        ask for the setting itself, but then leaves the install behind.)"""
        def hand_over(*args, **kwargs):
            self.main_window.on_gain_focus = None
            close()
            self._hand_apk_over(release, path, folder)

        def not_now(*args, **kwargs):
            self.main_window.on_gain_focus = None
            close()
            self.updating = False

        def back(*args, **kwargs):
            if self._may_install_apps():
                hand_over()

        text = (f"OpenDisco {release.version} is downloaded and checked. Android installs it once installing "
                "apps from OpenDisco is allowed: turn on Allow from this source in the settings that open, then "
                "come back to OpenDisco.")
        content = toga.Box(style=Pack(direction=COLUMN, gap=10, margin=14 if self.phone_ui else 0), children=[
            toga.Label(self._wrap(text)),
            toga.Box(style=Pack(direction=ROW, gap=8), children=[
                toga.Button("Not now", on_press=not_now),
                toga.Button("Settings", on_press=lambda w, **kwargs: self._open_install_setting()),
                toga.Button("Install", on_press=hand_over)])])
        close = self._show_panel(f"Install OpenDisco {release.version}", content, (480, 200), on_close=not_now)
        self.main_window.on_gain_focus = back
        self._open_install_setting()

    def _open_install_setting(self):
        from java import jclass
        intent = jclass("android.content.Intent")(jclass("android.provider.Settings").ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                                                  jclass("android.net.Uri").parse(f"package:{self.app_id}"))
        self._impl.native.startActivity(intent)

    def _hand_apk_over(self, release, path, folder):
        self.updating = False  # the install is Android's now; backing out of it allows another try
        self.settings["update"] = {"version": release.version, "folder": str(folder)}
        self._save_settings()
        try:
            self._install_apk(path)
        except Exception as e:
            self.settings.pop("update", None)
            self._save_settings()
            self._update_failed(release, f"Android's installer didn't start ({e})")
            return
        self._append_log(f"Android's installer takes over to install OpenDisco {release.version}.", status=False)
        self.status.text = "Android's installer takes over."

    def _install_apk(self, path: Path):
        """Android: hand the .apk to the system's installer, which asks before installing."""
        from java import jclass
        activity = self._impl.native
        uri = jclass("androidx.core.content.FileProvider").getUriForFile(
            activity, f"{self.app_id}.fileprovider", jclass("java.io.File")(str(path)))
        intent_class = jclass("android.content.Intent")
        intent = intent_class(intent_class.ACTION_VIEW)
        intent.setDataAndType(uri, "application/vnd.android.package-archive")
        intent.addFlags(intent_class.FLAG_GRANT_READ_URI_PERMISSION | intent_class.FLAG_ACTIVITY_NEW_TASK)
        activity.startActivity(intent)

    def handle_exit(self, app, **kwargs):
        core.STOP.set()
        if self.update_cancel:
            self.update_cancel.set()
        if self.cancel_password:
            self.cancel_password()
        if self.cancel_ssh_login:
            self.cancel_ssh_login()
        if self.cancel_port_warning:
            self.cancel_port_warning()
        if self.term:
            self.term.close_all()  # ends ssh and ping
        if self.result and self.result.mgr:
            self.result.mgr.remove_all()  # never leave a temporary address behind
        if self.multicast_lock is not None:
            self.multicast_lock.release()
        return True


def main():
    # Author and version are given here because the Windows build has no package metadata: without
    # them its About box showed no version.
    return OpenDiscoApp("OpenDisco", "com.michaelfroehlke.opendisco", icon="resources/icon",
                        author="Michael Froehlke", version=__version__)
