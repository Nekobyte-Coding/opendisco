"""OpenDisco's GUI (Toga): native on macOS, Windows, Linux, iOS and Android.

The scanning is opendisco.core; this module only builds the window, runs scans in a
worker thread and shows what they find. Each platform offers the modes it allows: phones and
Windows can't capture traffic, add addresses or tag VLANs.
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

from opendisco import FULL_NAME, __version__, core

# (name, description, command-line flags, needs) where needs is a capability from core.capabilities()
MODES = [
    ("Quick", "Broadcast and multicast discovery only, like Ubiquiti's old Java tool.", ["--quick"], None),
    ("Full scan", "Discovery plus a sweep of your subnets, mDNS, SSDP and the ARP table.", [], None),
    ("Sniff the wire", "Listen on every port for gear on any subnet (ARP, LLDP, CDP, broadcasts).",
     ["--sniff"], "listen"),
    ("Trunk VLANs", "Find the VLANs on a trunk port, then probe each one through a temporary tagged interface.",
     ["--vlans"], "vlans"),
    ("Direct to a device", "Wired straight into one radio: find its IP and VLAN from what it says, then probe it.",
     ["--direct"], "vlans"),
]
COLUMNS = list(core.EXPORT_COLUMNS)
ACCESSORS = [c.lower() for c in COLUMNS]
ANY_PORT = "Any port"
# What a device's right-click menu (and the Device menu) offers; None separates groups.
DEVICE_ACTIONS = [("web", "Open Web UI"), ("ssh", "Open SSH…"), ("ping", "Ping"), ("rescan", "Rescan device"), None,
                  ("copy_ip", "Copy IP address"), ("copy_mac", "Copy MAC address"), None,
                  ("forget", "Forget SSH key"), ("hide", "Hide device")]
NO_SESSION = "Right-click a device to get started: Open SSH or Ping."
# The data folder's name before 1.4.0, which renamed the app: folder name now -> earlier names.
LEGACY_FOLDERS = {"com.michaelfroehlke.opendisco": ("com.michaelfroehlke.ubnt-discover",),
                  "OpenDisco": ("UBNT Discovery Reloaded", "UBNT Discover"),
                  "opendisco": ("ubnt-discover", "ubnt_discover")}

_MENU_TARGET = None


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
    def startup(self):
        self.caps = core.capabilities()
        self.caps["vlans"] = self.caps["aliases"] and self.caps["listen"]
        offered = dict(self.caps)
        if self.caps["platform"] == "windows":  # listed before Npcap is installed: starting one offers it
            offered.update(listen=True, vlans=self.caps["aliases"])
        self.modes = [m for m in MODES if m[3] is None or offered.get(m[3])]
        self.offers_listening = offered["listen"]
        self.result = None  # the last finished scan
        self.live_inv = None  # the inventory of the scan that's running
        self.running = False
        self.rescanning = False
        self.holding = False
        self.cancel_password = None
        self.cancel_ssh_login = None
        self._move_old_data()
        self.networks_path = self._networks_file()
        self.settings_path = Path(self.paths.data) / "settings.json"
        self.known_hosts = Path(self.paths.data) / "known_hosts"  # SSH host keys, filed by MAC
        self.settings = self._load_settings()
        self.hidden = self.settings.setdefault("hidden", {})  # device key (its MAC) -> what it was
        if not self.caps["mobile"]:
            core.SUDO_ASKPASS = self._ask_password  # no terminal here, so the GUI asks
        self.multicast_lock = self._android_multicast_lock()

        mobile = self.caps["mobile"]
        self.mode = toga.Selection(items=[m[0] for m in self.modes], on_change=self.on_mode,
                                   style=Pack(flex=1) if mobile else Pack(width=190))
        self.port = toga.Selection(items=self._ports(), style=Pack(width=230))
        self.start_button = toga.Button("Start", on_press=self.on_start, style=Pack(width=90))
        self.stop_button = toga.Button("Stop", on_press=self.on_stop, enabled=False, style=Pack(width=90))
        self.aliases = toga.Switch("Probe my networks (temporary addresses)", enabled=self.caps["aliases"])
        self.deep = toga.Switch("Deep checks (ports, console API)")
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

        self.table = toga.Table(columns=COLUMNS, on_select=self.on_select, style=Pack(flex=1))
        mono = Pack(flex=1, font_family="monospace", font_size=11)
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
        if not mobile:  # SSH and ping sessions to devices
            from opendisco import terminal
            self.term = terminal.TerminalPane(toga, Pack)
            tabs.append(("Terminal", self.term.box))
        tabs += [("On the wire", self.wire), ("Notes", self.notes), ("Log", self.log)]
        if self.caps["aliases"]:
            self.networks = toga.MultilineTextInput(value=self.networks_path.read_text(encoding="utf-8"), style=mono)
            networks_box = toga.Box(style=Pack(direction=COLUMN, flex=1, gap=6), children=[
                toga.Label(f"Networks probed through temporary addresses ({self.networks_path})"),
                self.networks,
                toga.Box(style=Pack(direction=ROW, gap=6), children=[
                    toga.Button("Save", on_press=self.on_save_networks),
                    toga.Button("Restore defaults", on_press=self.on_reset_networks)])])
            tabs.append(("Networks", networks_box))
        self.tabs = toga.OptionContainer(content=tabs, style=Pack(flex=1))

        self.spinner = toga.ActivityIndicator()
        self.status = toga.Label("Ready.", style=Pack(flex=1, margin_left=6))
        self.export_button = toga.Button("Export…", on_press=self.on_export, enabled=False)
        self.hold_button = toga.Button("Keep addresses", on_press=self.on_hold, enabled=False)

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
        if mobile:  # phones: one column, no splitter
            body = toga.Box(style=Pack(direction=COLUMN, flex=1, gap=6), children=[self.table, self.tabs])
        else:
            body = toga.SplitContainer(content=[self.table, self.tabs], direction=toga.SplitContainer.HORIZONTAL,
                                       style=Pack(flex=1))
        # Phones' title bars have room for the short name only.
        title = f"{self.formal_name if mobile else FULL_NAME} {__version__}"
        self.main_window = toga.MainWindow(title=title, size=(1250, 780))
        self.main_window.content = toga.Box(style=Pack(direction=COLUMN, margin=10, gap=8), children=[
            toga.Box(style=row, children=controls),
            *([self.mode_help] if mobile else []),
            toga.Box(style=row, children=options),
            body,
            toga.Box(style=row, children=footer),
        ])
        self.on_exit = self.handle_exit
        self.on_mode(self.mode)
        if not mobile:
            self._add_device_menu()
        self.main_window.show()
        if not mobile:
            self._install_context_menu()
        # macOS re-centres the tab labels whenever it re-tiles the tab view (window resizes,
        # dragging the divider, tab changes, moving to another display), so snap a moment later.
        self.main_window.on_resize = lambda *args, **kwargs: (self.loop.call_later(0.05, self._align_tab_labels),
                                                              self.loop.call_later(0.05, self._size_columns))
        self.tabs.on_select = lambda *args, **kwargs: self.loop.call_later(0.05, self._align_tab_labels)
        self._watch_tab_labels()
        self.loop.call_later(0.3, self._align_tab_labels)
        self.loop.call_later(0.5, self._size_columns)

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
                                                      if k in ("hidden", "ssh_user")}, indent=1), encoding="utf-8")
        except OSError:
            pass

    def _move_old_data(self):
        """Versions before 1.4.0 kept the networks file, hidden devices and SSH keys in a folder
        named after the app's earlier names (the app ID on macOS, its name on Windows and Linux):
        bring them over once."""
        new = Path(self.paths.data)
        try:
            if new.is_dir() and any(new.iterdir()):
                return
            for n, part in enumerate(new.parts):
                for old_part in LEGACY_FOLDERS.get(part, ()):
                    old = Path(*new.parts[:n], old_part, *new.parts[n + 1:])
                    if old.is_dir():
                        shutil.copytree(old, new, dirs_exist_ok=True)
                        return
        except OSError:
            pass

    def _networks_file(self) -> Path:
        """The editable networks file lives in the app's data folder (the bundle is read-only)."""
        path = Path(self.paths.data) / "networks.txt"
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(core.DEFAULT_NETWORKS_FILE, path)
        return path

    def _ports(self) -> list:
        try:
            links = core.hardware_links(core.local_interfaces())
        except Exception:
            links = []
        links = [l for l in links if l.active or not l.label.startswith("Ethernet Adapter (")]  # Apple's virtual ports
        return [ANY_PORT] + [f"{l.name} ({l.label})" + ("" if l.active else ", no link") for l in links]

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

    COLUMN_WEIGHTS = (1.1, 0.5, 0.9, 1.3, 1.0, 1.4, 0.9, 0.7, 0.6, 0.7, 1.1, 1.3)  # IP ... Status

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

    def _append_log(self, msg):
        self.log.value += msg.rstrip("\n") + "\n"
        self.log.scroll_to_bottom()
        if msg.strip():
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
            self.aliases.enabled = not forced and name != "Quick"
            if forced:
                self.aliases.value = True
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
        port = self.port.value
        if port and port != ANY_PORT:
            args += ["-i", port.split(" ")[0]]
        if self.caps["mobile"]:  # phones can't do these, so don't waste the time
            args += ["--no-mdns", "--no-ssdp", "--no-arp"]
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
                    "signed by the Nmap Project, and starts it for you to click through (Windows will ask "
                    "for permission). Npcap's free license covers 5 computers.")):
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
                    "Temporary addresses change your network adapter, which Windows only lets administrators "
                    "do. Restart OpenDisco as administrator? Windows will ask first; then start "
                    "the scan again.")):
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
        """Fill the table, minus hidden devices. Rows change in place when the same devices are
        listed, so the selection stays put while a scan or a rescan updates them."""
        rows = [(d.key, dict(zip(ACCESSORS, core.device_row(d)))) for d in devices if d.key not in self.hidden]
        data = self.table.data
        if [key for key, _ in rows] == [getattr(row, "key", None) for row in data]:
            for row, (_, values) in zip(data, rows):
                for attr, value in values.items():
                    if getattr(row, attr) != value:
                        setattr(row, attr, value)
        else:
            self.table.data = [dict(values, key=key) for key, values in rows]

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
        self.hold_button.enabled = bool(result.mgr) and any(d.alias for d in result.devices)
        if self.shown_packets:  # now with the interface counters and the final checks
            self.details.value = core.render_details(self.shown_packets[0])
            self._show_packets(self.shown_packets[0], force=True)
        if result.trunks:
            self.tabs.current_tab = "On the wire"

    def _device(self, key):
        return next((d for d in self._all_devices() if d.key == key), None)

    def _selected_device(self):
        row = self.table.selection
        return self._device(getattr(row, "key", None)) if row is not None else None

    def on_select(self, widget, **kwargs):
        d = self._selected_device()
        if d is not None:
            self.details.value = core.render_details(d)
            self._show_packets(d, force=True)
            if self.term:  # its session, if it has one; the others keep running
                self.term.show_device(d.key, d.ip or d.mac or "this device")
            if self.tabs.current_tab.text not in ("Details", "Packets", "Terminal"):
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
        return {
            "web": (f"Open Web UI  ({core.web_url(d, fallback=True)})" if ip else titles["web"], ip),
            "ssh": ("Show SSH session" if ssh else f"Open SSH…  (port {d.port('ssh')})", ip),
            "ping": ("Show ping" if ping and ping.alive else titles["ping"], ip),
            "rescan": (titles["rescan"], ip and bool(self.result) and not self.running and not self.rescanning),
            "copy_ip": (f"Copy IP address  ({d.ip})" if ip else titles["copy_ip"], ip),
            "copy_mac": (f"Copy MAC address  ({d.mac})" if d.mac else titles["copy_mac"], bool(d.mac)),
            "forget": (titles["forget"], ip),
            "hide": (titles["hide"], True),
        }

    def _device_action(self, name):
        d = self._selected_device()
        if d is None:
            self.status.text = "Select a device first."
            return
        title, enabled = self._menu_state(d)[name]
        if not enabled:
            self.status.text = ("Rescan works once a scan has finished." if name == "rescan"
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
        elif name == "rescan":
            self._rescan(d)
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
        password = toga.PasswordInput(placeholder="empty: type it in the terminal, or use your SSH key",
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
        self.spinner.start()
        self.status.text = f"Rescanning {d.ip}…"
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
        if result is not self.result:  # a new scan started meanwhile
            return
        self._show_devices(result.devices)
        if self._selected_device() is d:
            self.details.value = core.render_details(d)
            self._show_packets(d, force=True)
        if error:
            self.status.text = f"Rescan of {d.ip} failed: {error}"
            return
        ports = ", ".join(f"{p} {k}" for p, k in sorted(d.services.items())) or "no management ports open"
        self.status.text = (f"Rescanned {d.ip}: " + ("answered discovery" if answered else "no discovery reply")
                            + f"; {ports}.")

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
            toga.Label("These are left out of the table, by MAC address, in every scan until you unhide them. "
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
        if not self.result:
            return
        name = f"opendisco-scan-{time.strftime('%Y%m%d-%H%M')}.html"
        try:
            path = await self.main_window.dialog(toga.SaveFileDialog(
                "Export results (.html opens on any phone; .csv, .json)", name, file_types=["html", "csv", "json"]))
        except (NotImplementedError, AttributeError):  # no file dialogs on this platform
            path = Path(self.paths.data) / name
        if not path:
            return
        core.write_export(self.result, str(path))
        self.status.text = f"Saved {path}"

    async def on_hold(self, widget, **kwargs):
        if self.holding:
            await self._release_hold()
            return
        res = self.result
        self.hold_button.enabled = False

        def work():
            try:
                core.authorize_sudo("Keeping the addresses needs administrator rights.", lambda m: None)
                lines = core.hold_start(res.mgr, res.inv, lambda m: self._from_worker(self._append_log, m))
            except SystemExit as e:
                lines = [f"[error] {e.code}"]
            self._from_worker(self._held, lines)

        threading.Thread(target=work, daemon=True).start()

    def _held(self, lines):
        self.hold_button.enabled = True
        if not self.result.mgr.active:
            self.notes.value += "\n\n" + ("\n".join(lines) or "Nothing was reached through an address to keep.")
            return
        self.holding = True
        self.hold_button.text = "Release addresses"
        self.notes.value = "Keeping these addresses so you can manage the gear:\n" + "\n".join(lines) + \
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

    # -- networks file -------------------------------------------------------------
    def on_save_networks(self, widget, **kwargs):
        try:
            for n, line in enumerate(self.networks.value.splitlines(), 1):
                line = line.split("#", 1)[0].strip()
                if line:
                    core.parse_alias_spec(line)
        except ValueError as e:
            self.status.text = f"Networks line {n}: {e}"
            return
        self.networks_path.write_text(self.networks.value, encoding="utf-8")
        self.status.text = f"Saved {self.networks_path}"

    def on_reset_networks(self, widget, **kwargs):
        self.networks.value = Path(core.DEFAULT_NETWORKS_FILE).read_text(encoding="utf-8")

    def handle_exit(self, app, **kwargs):
        core.STOP.set()
        if self.cancel_password:
            self.cancel_password()
        if self.cancel_ssh_login:
            self.cancel_ssh_login()
        if self.term:
            self.term.close_all()  # ends ssh and ping
        if self.result and self.result.mgr:
            self.result.mgr.remove_all()  # never leave a temporary address behind
        if self.multicast_lock is not None:
            self.multicast_lock.release()
        return True


def main():
    return OpenDiscoApp("OpenDisco", "com.michaelfroehlke.opendisco", icon="resources/icon")
