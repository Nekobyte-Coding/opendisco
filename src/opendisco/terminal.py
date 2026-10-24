"""The app's Terminal tab: SSH and ping sessions to devices, shown with xterm.js.

Each session runs its program (ssh, ping) in its own pseudo-terminal, so it behaves exactly as
in a terminal window: ping streams, Ctrl+C stops it, full-screen programs and resizing work.
Sessions keep running while another one is shown. Windows needs pywinpty for that; without
it, SSH and ping open in a console window of their own instead.

The terminal itself is xterm.js in a web view. The web view has no way to call Python, so the
pane polls it for keystrokes and sends output back in batches.
"""
import asyncio
import base64
import json
import os
import re
import shutil
import signal
import struct
import subprocess
import sys
import threading
from collections import deque
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"
RESOURCES = Path(__file__).with_name("resources")
PASSWORD_PROMPT = re.compile(rb"(?i)pass(word|code)[^\r\n]{0,60}:\s*$")
KEY_CHANGED = b"REMOTE HOST IDENTIFICATION HAS CHANGED"

if IS_WINDOWS:
    try:  # a real console (ConPTY) for each session
        from winpty import PtyProcess as WinPty
    except ImportError:
        WinPty = None
else:
    import fcntl
    import pty
    import termios


def in_app_terminals() -> bool:
    """Whether sessions can run inside the app (otherwise they open in a console window)."""
    return not IS_WINDOWS or WinPty is not None


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

_LEGACY = None


def legacy_ssh_options() -> list:
    """Let ssh talk to old firmware (airOS 5/6, old EdgeOS) that only offers SHA-1 key exchange,
    ssh-rsa or ssh-dss host keys, or CBC ciphers. Modern OpenSSH turns these off by default and
    some builds drop them entirely, which makes naming them an error, so only the ones this
    ssh still has are added. They're appended, so ssh still prefers the strong ones."""
    global _LEGACY
    if _LEGACY is None:
        wanted = {"KexAlgorithms": ("kex", ["diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1",
                                            "diffie-hellman-group1-sha1"]),
                  "HostKeyAlgorithms": ("key", ["ssh-rsa", "ssh-dss"]),
                  "Ciphers": ("cipher", ["aes128-cbc", "aes256-cbc", "3des-cbc"])}
        _LEGACY = []
        for option, (query, names) in wanted.items():
            try:
                known = subprocess.run([ssh_program(), "-Q", query], capture_output=True, text=True, timeout=5,
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout.split()
            except (OSError, subprocess.SubprocessError):
                continue
            have = [n for n in names if n in known]
            if have:
                _LEGACY += ["-o", f"{option}=+{','.join(have)}"]
    return _LEGACY


def ssh_program() -> str:
    return shutil.which("ssh") or ("ssh.exe" if IS_WINDOWS else "/usr/bin/ssh")


def host_key_alias(mac: str | None, ip: str) -> str:
    """The name ssh files a device's host key under: its MAC, so a different radio at the same
    factory address isn't mistaken for the last one, while a changed key on the same device is
    still caught."""
    return "ubnt-" + mac.replace(":", "") if mac else ip


def ssh_argv(ip: str, port: int, user: str, alias: str, known_hosts: Path) -> list:
    argv = [ssh_program(), "-p", str(port),  # quoted: ssh splits this option on spaces ("Application Support")
            "-o", f'UserKnownHostsFile="{known_hosts}"', "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"HostKeyAlias={alias}", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15",
            *legacy_ssh_options()]
    if user:
        argv += ["-l", user]
    return argv + [ip]


def ping_argv(ip: str) -> list:
    return ["ping", "-t", ip] if IS_WINDOWS else [shutil.which("ping") or "/sbin/ping", ip]


def forget_host_key(alias: str, known_hosts: Path) -> bool:
    """Remove a device's saved SSH host key, so the next connection trusts its new one."""
    keygen = shutil.which("ssh-keygen") or "ssh-keygen"
    try:
        r = subprocess.run([keygen, "-R", alias, "-f", str(known_hosts)], capture_output=True, text=True,
                           timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0 and "not found" not in (r.stdout + r.stderr)


def open_console_window(argv: list) -> None:
    """Windows without pywinpty: run the session in a console window of its own."""
    subprocess.Popen(argv, creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0))


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

def _take_terminal():  # runs in the child between fork and exec, so nothing that imports or allocates
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)  # so ssh can read the password from its terminal


class Session:
    """One program running in a pseudo-terminal. A thread collects its output for the pane
    to collect; once it ends, Enter starts it again with the same settings."""

    def __init__(self, sid: str, device_key: str, kind: str, title: str, argv: list, password: str | None = None):
        self.sid, self.device_key, self.kind, self.title, self.argv = sid, device_key, kind, title, argv
        self.password = password or None  # in memory only, to log in again after a reconnect
        self.size = (24, 80)  # rows, cols
        self.out, self.lock = deque(), threading.Lock()
        self.alive = False
        self.key_changed = False
        self.proc = self.fd = None
        self.start()

    # -- running ---------------------------------------------------------
    def start(self) -> None:
        self.typed_password, self.tail = False, b""
        env = dict(os.environ, TERM="xterm-256color")
        rows, cols = self.size
        if IS_WINDOWS:
            self.proc = WinPty.spawn(self.argv, dimensions=(rows, cols), env=env)
        else:
            master, slave = pty.openpty()
            self._set_size(slave)
            try:
                self.proc = subprocess.Popen(self.argv, stdin=slave, stdout=slave, stderr=slave, env=env,
                                             start_new_session=True, preexec_fn=_take_terminal)
            finally:
                os.close(slave)
            self.fd = master
        self.alive = True
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        while True:
            try:
                if IS_WINDOWS:
                    data = self.proc.read(65536).encode("utf-8", "replace")
                else:
                    data = os.read(self.fd, 65536)
            except (OSError, EOFError):  # Linux reports EIO once the program exits
                break
            if not data:
                break
            self._watch(data)
            self._emit(data)
        code = self.proc.wait()
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        self.alive = False
        self._emit(self._ended(code))

    def _watch(self, data: bytes) -> None:
        """Type the password when ssh asks for it, once per connection: if it asks again, the
        password was wrong, and the prompt is left for you."""
        seen = self.tail + data  # all of it: ssh's warning can arrive in one long read
        if KEY_CHANGED in seen:
            self.key_changed = True
        self.tail = seen[-300:]
        if self.password and not self.typed_password and PASSWORD_PROMPT.search(self.tail):
            self.typed_password = True
            self.write((self.password + "\r").encode())

    def _ended(self, code) -> bytes:
        if self.kind == "ping":
            msg = "Ping stopped. Press Enter to ping again."
        else:
            msg = f"Connection closed{f' (ssh exit code {code})' if code else ''}. Press Enter to connect again."
            if self.key_changed:
                msg = ("This device's SSH key changed since you last connected: it was reset or replaced, or "
                       "something is in between. If you expect that, right-click it and choose Forget SSH key, "
                       "then press Enter here.")
        return f"\r\n\x1b[33m[{msg}]\x1b[0m\r\n".encode()

    def _emit(self, data: bytes) -> None:
        with self.lock:
            self.out.append(data)

    def drain(self) -> bytes:
        with self.lock:
            data = b"".join(self.out)
            self.out.clear()
        return data

    # -- input -----------------------------------------------------------
    def write(self, data: bytes) -> None:
        try:
            if IS_WINDOWS:
                self.proc.write(data.decode("utf-8", "replace"))
            elif self.fd is not None:
                os.write(self.fd, data)
        except (OSError, EOFError):
            pass

    def type(self, data: bytes) -> None:
        """Keystrokes from the terminal: to the program, or Enter to start it again."""
        if self.alive:
            self.write(data)
        elif b"\r" in data:
            self._emit(b"\r\n")
            self.start()

    def resize(self, cols: int, rows: int) -> None:
        if cols < 2 or rows < 2 or (rows, cols) == self.size:
            return
        self.size = (rows, cols)
        if not self.alive:
            return
        if IS_WINDOWS:
            self.proc.setwinsize(rows, cols)
        elif self.fd is not None:
            self._set_size(self.fd)  # the program gets SIGWINCH

    def _set_size(self, fd) -> None:
        rows, cols = self.size
        try:
            fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        except OSError:
            pass

    def close(self) -> None:
        self.password = None
        if not self.alive:
            return
        if IS_WINDOWS:
            self.proc.terminate(force=True)
            return
        try:
            os.killpg(self.proc.pid, signal.SIGHUP)  # its own session, so the whole group
        except OSError:
            pass


# ---------------------------------------------------------------------------
# The pane
# ---------------------------------------------------------------------------

def page_html() -> str:
    xterm = RESOURCES / "xterm"
    return """<!doctype html><html><head><meta charset="utf-8"><style>%s
html, body { margin: 0; height: 100%%; background: #1e1e1e; overflow: hidden; }
.xterm .xterm-viewport { background-color: #1e1e1e !important; }
::-webkit-scrollbar { width: 10px; }
::-webkit-scrollbar-track { background: #1e1e1e; }
::-webkit-scrollbar-thumb { background: #4a4a4a; border-radius: 5px; }
.term { position: absolute; inset: 4px 2px 2px 6px; display: none; }
.term.on { display: block; }
#empty { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center;
         padding: 0 24px; text-align: center; color: #a0a0a0;
         font: 13px -apple-system, "Segoe UI", system-ui, sans-serif; }
</style><script>%s</script><script>%s</script></head><body>
<div id="empty">Right-click a device to get started: Open SSH or Ping.</div>
<script>
const S = {}, outbox = [];
let current = null;
function make(id) {
  const el = document.createElement('div');
  el.className = 'term';
  document.body.appendChild(el);
  const t = new Terminal({fontFamily: 'Menlo, Consolas, "DejaVu Sans Mono", monospace', fontSize: 12,
                          cursorBlink: true, scrollback: 10000, theme: {background: '#1e1e1e'}});
  const fit = new FitAddon.FitAddon();
  t.loadAddon(fit);
  t.open(el);
  t.onData(d => outbox.push([id, 'd', d]));
  t.onBinary(d => outbox.push([id, 'd', d]));
  t.onResize(s => outbox.push([id, 'r', s.cols, s.rows]));
  S[id] = {el, t, fit};
}
function show(id, message) {
  if (id && !S[id]) make(id);
  for (const k in S) S[k].el.classList.toggle('on', k === id);
  const empty = document.getElementById('empty');
  if (message) empty.textContent = message;
  empty.style.display = id ? 'none' : 'flex';
  current = id;
  if (id) {
    S[id].fit.fit();
    S[id].t.focus();
    outbox.push([id, 'r', S[id].t.cols, S[id].t.rows]);
  }
}
function write(batch) {
  for (const id in batch) {
    if (!S[id]) make(id);
    const b = atob(batch[id]), u = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
    S[id].t.write(u);
  }
}
function drop(id) {
  if (S[id]) { S[id].t.dispose(); S[id].el.remove(); delete S[id]; }
}
function take() { const s = JSON.stringify(outbox); outbox.length = 0; return s; }
new ResizeObserver(() => { if (current && S[current]) S[current].fit.fit(); }).observe(document.body);
</script></body></html>""" % ((xterm / "xterm.css").read_text(encoding="utf-8"), (xterm / "xterm.js").read_text(encoding="utf-8"),
                               (xterm / "addon-fit.js").read_text(encoding="utf-8"))


class TerminalPane:
    """The Terminal tab: a session picker over an xterm.js web view with one terminal per
    session. Showing a device shows its latest session; the others keep running."""

    def __init__(self, toga, Pack, on_close=None):
        from toga.style.pack import COLUMN, ROW
        self.toga = toga
        self.sessions: dict = {}  # sid -> Session
        self.order: list = []  # sids, most recently shown last
        self.count = 0
        self.ready = False
        self.pending: list = []  # JavaScript to run once the page is ready
        self.pumping = False
        self.on_close = on_close
        self.view = toga.WebView(style=Pack(flex=1))
        self.view.set_content("https://terminal.invalid/", page_html())
        self.choice = toga.Selection(items=[], on_change=self._chosen, style=Pack(width=360))
        self.close_button = toga.Button("Close session", on_press=self._close_current, enabled=False)
        self.box = toga.Box(style=Pack(direction=COLUMN, flex=1, gap=6), children=[
            toga.Box(style=Pack(direction=ROW, align_items="center", gap=8), children=[
                toga.Label("Session"), self.choice, self.close_button]),
            self.view])

    # -- sessions --------------------------------------------------------
    def find(self, device_key: str, kind: str):
        return next((self.sessions[sid] for sid in reversed(self.order)
                     if self.sessions[sid].device_key == device_key and self.sessions[sid].kind == kind), None)

    def open(self, device_key: str, kind: str, title: str, argv: list, password: str | None = None) -> Session:
        self.count += 1
        sid = f"s{self.count}"
        titles = {s.title for s in self.sessions.values()}
        while title in titles:
            title += " ·"
        session = Session(sid, device_key, kind, title, argv, password)
        self.sessions[sid] = session
        self._refresh_choice(session)
        self._start_pump()
        return session

    def show(self, session: Session) -> None:
        if self.choice.value != session.title:
            self.choice.value = session.title  # _chosen does the rest
        else:
            self._show(session)

    def show_device(self, device_key: str, label: str) -> None:
        """Show the device's latest session, or say it has none (the others keep running)."""
        session = next((self.sessions[sid] for sid in reversed(self.order)
                        if self.sessions[sid].device_key == device_key), None)
        if session:
            self.show(session)
        else:
            self._js(f"show(null, {json.dumps(f'No session with {label} yet. Right-click it for SSH or Ping.')})")

    def _show(self, session: Session) -> None:
        if session.sid in self.order:
            self.order.remove(session.sid)
        self.order.append(session.sid)
        self.close_button.enabled = True
        self._js(f"show({json.dumps(session.sid)})")

    def _chosen(self, widget, **kwargs):
        session = next((s for s in self.sessions.values() if s.title == self.choice.value), None)
        if session:
            self._show(session)

    def _refresh_choice(self, show: Session | None = None) -> None:
        self.choice.items = [s.title for s in self.sessions.values()]
        if show:
            self.show(show)
        elif not self.sessions:
            self.close_button.enabled = False
            self._js("show(null, 'Right-click a device to get started: Open SSH or Ping.')")

    def _close_current(self, widget=None, **kwargs):
        session = next((s for s in self.sessions.values() if s.title == self.choice.value), None)
        if session:
            self.close(session)

    def close(self, session: Session) -> None:
        session.close()
        self.sessions.pop(session.sid, None)
        if session.sid in self.order:
            self.order.remove(session.sid)
        self._js(f"drop({json.dumps(session.sid)})")
        nxt = self.sessions.get(self.order[-1]) if self.order else None
        self._refresh_choice(nxt)

    def close_all(self) -> None:
        for session in list(self.sessions.values()):
            session.close()
        self.sessions.clear()

    # -- talking to the page ---------------------------------------------
    def _js(self, code: str) -> None:
        if self.ready:
            self.view.evaluate_javascript(code)
        else:
            self.pending.append(code)
            self._start_pump()

    def _start_pump(self) -> None:
        if not self.pumping:
            self.pumping = True
            asyncio.get_event_loop().create_task(self._pump())

    async def _pump(self) -> None:
        """Every 30 ms: keystrokes and terminal sizes from the page, output to it."""
        try:
            while self.sessions or self.pending:
                if not self.ready:
                    self.ready = str(await self.view.evaluate_javascript("typeof take")) == "function"
                    if self.ready:
                        for code in self.pending:
                            self.view.evaluate_javascript(code)
                        self.pending.clear()
                    else:
                        await asyncio.sleep(0.1)
                        continue
                raw = await self.view.evaluate_javascript("take()")
                for item in json.loads(str(raw) if raw else "[]"):
                    session = self.sessions.get(item[0])
                    if session is None:
                        continue
                    if item[1] == "d":
                        session.type(item[2].encode("utf-8"))
                    elif item[1] == "r":
                        session.resize(int(item[2]), int(item[3]))
                batch = {}
                for sid, session in self.sessions.items():
                    data = session.drain()
                    if data:
                        batch[sid] = base64.b64encode(data).decode()
                if batch:
                    self.view.evaluate_javascript(f"write({json.dumps(batch)})")
                await asyncio.sleep(0.03)
        finally:
            self.pumping = False
