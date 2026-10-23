"""OpenDisco's GUI (Toga): native on macOS, Windows, Linux, iOS and Android.

The scanning is opendisco.core; this module only builds the window, runs scans in a
worker thread and shows what they find. Each platform offers the modes it allows: phones and
Windows can't capture traffic, add addresses or tag VLANs.
"""
import asyncio
import json
import shutil
import threading
import time
import traceback
from pathlib import Path

import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW

from opendisco import __version__, core

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


class OpenDiscoApp(toga.App):
    def startup(self):
        self.caps = core.capabilities()
        self.caps["vlans"] = self.caps["aliases"] and self.caps["listen"]
        self.modes = [m for m in MODES if m[3] is None or self.caps.get(m[3])]
        self.result = None  # the last finished scan
        self.live_inv = None  # the inventory of the scan that's running
        self.running = False
        self.holding = False
        self.shown_rows = None
        self.cancel_password = None
        self.networks_path = self._networks_file()
        self.settings_path = Path(self.paths.data) / "settings.json"
        settings = self._load_settings()
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
        self.listen = toga.NumberInput(min=5, max=300, step=5, value=20, style=Pack(width=70))
        self.mode_help = toga.Label("", style=Pack(flex=1, margin_left=8))
        # Your standard ports: gear reporting another gets flagged, and deep checks verify them.
        self.https_ports = toga.TextInput(value=settings.get("https_ports", ""), placeholder="e.g. 443",
                                          on_change=self._save_settings, style=Pack(width=110))
        self.ssh_ports = toga.TextInput(value=settings.get("ssh_ports", ""), placeholder="e.g. 22",
                                        on_change=self._save_settings, style=Pack(width=110))

        self.table = toga.Table(columns=COLUMNS, on_select=self.on_select, style=Pack(flex=1))
        mono = Pack(flex=1, font_family="monospace", font_size=11)
        self.details = toga.MultilineTextInput(readonly=True, placeholder="Select a device to see everything "
                                               "it reported and what to check.", style=mono)
        self.wire = toga.MultilineTextInput(readonly=True, placeholder="Sniff, Trunk VLANs and Direct show what "
                                            "they heard on the wire here.", style=mono)
        self.notes = toga.MultilineTextInput(readonly=True, style=mono)
        self.log = toga.MultilineTextInput(readonly=True, style=mono)
        tabs = [("Details", self.details), ("On the wire", self.wire), ("Notes", self.notes), ("Log", self.log)]
        if self.caps["aliases"]:
            self.networks = toga.MultilineTextInput(value=self.networks_path.read_text(), style=mono)
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
        controls += [self.start_button, self.stop_button, self.mode_help]
        options = [self.aliases, self.deep] if not mobile else [self.deep]
        if self.caps["listen"]:
            options += [toga.Label("Listen (s)"), self.listen]
        options += [toga.Label("Your HTTPS port"), self.https_ports, toga.Label("SSH port"), self.ssh_ports]
        footer = [self.spinner, self.status, self.export_button]
        if self.caps["aliases"]:
            footer.append(self.hold_button)

        row = Pack(direction=ROW, align_items="center", gap=8)
        if mobile:  # phones: one column, no splitter
            body = toga.Box(style=Pack(direction=COLUMN, flex=1, gap=6), children=[self.table, self.tabs])
        else:
            body = toga.SplitContainer(content=[self.table, self.tabs], direction=toga.SplitContainer.HORIZONTAL,
                                       style=Pack(flex=1))
        self.main_window = toga.MainWindow(title=f"{self.formal_name} {__version__}", size=(1250, 780))
        self.main_window.content = toga.Box(style=Pack(direction=COLUMN, margin=10, gap=8), children=[
            toga.Box(style=row, children=controls),
            toga.Box(style=row, children=options),
            body,
            toga.Box(style=row, children=footer),
        ])
        self.on_exit = self.handle_exit
        self.on_mode(self.mode)
        self.main_window.show()
        # macOS re-centres the tab labels after resize and tab-change events, so snap a moment later.
        self.main_window.on_resize = lambda *args, **kwargs: self.loop.call_later(0.05, self._align_tab_labels)
        self.tabs.on_select = lambda *args, **kwargs: self.loop.call_later(0.05, self._align_tab_labels)
        self.loop.call_later(0.3, self._align_tab_labels)

    # -- set-up helpers -----------------------------------------------------
    def _load_settings(self) -> dict:
        try:
            return json.loads(self.settings_path.read_text())
        except (OSError, ValueError):
            return {}

    def _save_settings(self, widget=None, **kwargs):
        try:
            self.settings_path.write_text(json.dumps({"https_ports": self.https_ports.value.strip(),
                                                      "ssh_ports": self.ssh_ports.value.strip()}))
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
            window = toga.Window(title="Administrator password", size=(460, 170), resizable=False, closable=False)
            window.content = toga.Box(style=Pack(direction=COLUMN, margin=14, gap=10), children=[
                toga.Label(reason),
                toga.Label("It's passed straight to sudo and not stored."),
                box,
                toga.Box(style=Pack(direction=ROW, gap=8), children=[
                    toga.Box(style=Pack(flex=1)),
                    toga.Button("Cancel", on_press=lambda w: finish(None)),
                    toga.Button("OK", on_press=lambda w: finish(box.value))])])
            window.show()
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
        self.mode_help.text = description
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
        if self.https_ports.value.strip():
            args += ["--https-port", self.https_ports.value.replace(" ", "")]
        if self.ssh_ports.value.strip():
            args += ["--ssh-port", self.ssh_ports.value.replace(" ", "")]
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

    async def on_start(self, widget, **kwargs):
        if self.running:
            return
        try:
            opts = core.parse_args(self._args())
        except SystemExit as e:
            await self.main_window.dialog(toga.ErrorDialog("Can't start", str(e.code)))
            return
        await self._release_hold()
        self.running, self.result, self.live_inv, self.shown_rows = True, None, None, None
        self.table.data = []
        self.details.value = self.wire.value = self.notes.value = ""
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
            await asyncio.sleep(1.0)

    def _show_devices(self, devices):
        rows = [dict(zip(ACCESSORS, core.device_row(d)), key=d.key) for d in devices]
        signature = [tuple(r.values()) for r in rows]
        if signature != self.shown_rows:  # don't reset the selection for nothing
            self.shown_rows = signature
            self.table.data = rows

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
        self.status.text = (f"{len(result.devices)} device(s), {heard} answered UBNT discovery, "
                            f"{result.elapsed:.0f}s" + (" (stopped early)" if result.interrupted else ""))
        self.export_button.enabled = bool(result.devices or result.trunks)
        self.hold_button.enabled = bool(result.mgr) and any(d.alias for d in result.devices)
        if result.trunks:
            self.tabs.current_tab = "On the wire"

    def _device(self, key):
        devices = self.result.devices if self.result else list((self.live_inv or core.Inventory()).devices.values())
        return next((d for d in devices if d.key == key), None)

    def on_select(self, widget, **kwargs):
        row = self.table.selection
        d = self._device(getattr(row, "key", None)) if row is not None else None
        if d is not None:
            self.details.value = core.render_details(d)
            self.tabs.current_tab = "Details"

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
        self.networks_path.write_text(self.networks.value)
        self.status.text = f"Saved {self.networks_path}"

    def on_reset_networks(self, widget, **kwargs):
        self.networks.value = Path(core.DEFAULT_NETWORKS_FILE).read_text()

    def handle_exit(self, app, **kwargs):
        core.STOP.set()
        if self.cancel_password:
            self.cancel_password()
        if self.result and self.result.mgr:
            self.result.mgr.remove_all()  # never leave a temporary address behind
        if self.multicast_lock is not None:
            self.multicast_lock.release()
        return True


def main():
    return OpenDiscoApp("OpenDisco", "com.michaelfroehlke.opendisco", icon="resources/icon")
