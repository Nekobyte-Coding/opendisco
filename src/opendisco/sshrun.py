"""Commands and file copies on one device for the device tools, through the system's ssh and scp.

They run in a pseudo-terminal (pywinpty on Windows) so the password can be typed when they ask
for it, the way the Terminal tab's sessions do, with the app's known_hosts and each device's host
key filed under its MAC. On macOS and Linux a command's output comes back through a pipe of its
own, so it arrives exactly as the device sent it; Windows' console mixes it with ssh's messages,
so files always travel by scp.

Every failure is an SSHError whose text says what went wrong in terms of the device: a changed
host key, a wrong password, no answer, an SSH server that only speaks retired algorithms.
"""
import atexit
import hashlib
import os
import re
import select
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path

from opendisco import terminal
from opendisco.i18n import _, tr
from opendisco.sshcommon import (ANSI, Login, Result, SSHError, _as_dict, last_hop,
                                 nested_command, route_text)  # (shared with phonessh)

IS_WINDOWS = terminal.IS_WINDOWS
PASSPHRASE_PROMPT = re.compile(rb"(?i)passphrase for key[^\r\n]{0,200}:\s*$")
PROGRESS = re.compile(rb"(\d{1,3})%")
# Windows' console (ConPTY) paints what it shows: a line can start with a cursor move to its row
# instead of a line break, and spaces can be cursor moves to the right.
ROW_MOVE = re.compile(r"\x1b\[\d*(?:;\d*)?[Hf]")
RIGHT_MOVE = re.compile(r"\x1b\[(\d*)C")

if not IS_WINDOWS:
    import pty


def available() -> bool:
    """ssh and scp are installed, and passwords can be typed into them here."""
    return terminal.in_app_terminals() and bool(shutil.which("ssh")) and bool(shutil.which("scp"))


def scp_program() -> str:
    return shutil.which("scp") or ("scp.exe" if IS_WINDOWS else "/usr/bin/scp")


_SCP_LEGACY = None


def scp_legacy_flag() -> list:
    """["-O"] where scp has it. From OpenSSH 9.0 on, scp copies over SFTP, which the Dropbear
    servers on airOS and UniFi gear don't offer; -O is the original protocol they all speak.
    Older scp (Windows 10's 8.1) speaks only that one and doesn't know -O."""
    global _SCP_LEGACY
    if _SCP_LEGACY is None:
        try:
            usage = subprocess.run([scp_program()], capture_output=True, text=True, timeout=5,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stderr
        except (OSError, subprocess.SubprocessError):
            usage = ""
        flags = re.search(r"\[-([0-9A-Za-z]+)\]", usage)
        _SCP_LEGACY = ["-O"] if flags and "O" in flags.group(1) else []
    return _SCP_LEGACY


def _options(login: Login) -> list:
    # One password prompt per attempt, so a wrong one fails at once instead of asking again.
    return ["-o", f'UserKnownHostsFile="{login.known_hosts}"', "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"HostKeyAlias={login.alias}", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3", "-o", "NumberOfPasswordPrompts=1", *terminal.legacy_ssh_options()]


def ssh_command(login: Login, command: str | None, *extra) -> list:
    """ssh to the device (through the devices on the way), running command (None: a session)."""
    tail = [command] if command is not None else []
    if login.via:
        return [terminal.ssh_program(), "-F", str(route_config(login)), *extra, TARGET, *tail]
    return [terminal.ssh_program(), *extra, "-p", str(login.port), *_options(login), "-l", login.user, login.ip,
            *tail]


def scp_command(login: Login, source: str, target: str) -> list:
    if login.via:
        return [scp_program(), *scp_legacy_flag(), "-F", str(route_config(login)), source, target]
    return [scp_program(), *scp_legacy_flag(), "-P", str(login.port), *_options(login), source, target]


def remote(login: Login, path: str) -> str:
    return f"{TARGET}:{path}" if login.via else f"{login.user}@{login.ip}:{path}"


# ---------------------------------------------------------------------------
# Routes through other devices
# ---------------------------------------------------------------------------

TARGET = "opendisco-target"
_ROUTES = None  # a folder for route configs, removed when the app quits


def _hop_entry(name: str, login: Login, jump: str | None) -> str:
    lines = [f"Host {name}", f"  HostName {login.ip}", f"  Port {login.port}", f"  User {login.user}",
             f"  HostKeyAlias {login.alias}", f'  UserKnownHostsFile "{login.known_hosts}"',
             "  StrictHostKeyChecking accept-new", "  ConnectTimeout 10", "  ServerAliveInterval 15",
             "  ServerAliveCountMax 3", "  NumberOfPasswordPrompts 1"]
    options = terminal.legacy_ssh_options()
    lines += [f"  {o.replace('=', ' ', 1)}" for o in options[1::2]]
    if jump:
        lines.append(f"  ProxyJump {jump}")
    return "\n".join(lines) + "\n"


def route_config(login: Login, upto: int | None = None) -> Path:
    """An ssh_config with an entry for each device on the way (opendisco-hop-1, -2...) and the
    device itself (opendisco-target), each reached with ProxyJump through the one before. ssh
    passes the file on to the ssh it starts for each jump, so every hop keeps its own port,
    user and host key. No passwords in it. upto: the target is that hop instead."""
    global _ROUTES
    if _ROUTES is None:
        import tempfile
        _ROUTES = Path(tempfile.mkdtemp(prefix="opendisco-routes-"))
        atexit.register(shutil.rmtree, _ROUTES, True)
    hops = list(login.via) + [login]
    if upto is not None:
        hops = hops[:upto + 1]
    text, jump = "", None
    for n, hop in enumerate(hops):
        name = TARGET if n == len(hops) - 1 else f"opendisco-hop-{n + 1}"
        text += _hop_entry(name, hop, jump)
        jump = name
    path = _ROUTES / f"route-{hashlib.sha256(text.encode()).hexdigest()[:16]}.conf"
    if not path.exists():
        path.write_text(text, encoding="utf-8")
        path.chmod(0o600)
    return path


def run(login: Login, command: str, timeout: float = 60, stop: threading.Event | None = None) -> Result:
    """Run a command on the device. Raises SSHError when ssh couldn't connect or log in;
    otherwise the result holds the command's exit code (255: the connection dropped). Through a
    device that refuses to forward, the command runs on the last hop's own SSH client."""
    if login.nested:
        return _run_nested(login, command, timeout, stop)
    extra = []
    if IS_WINDOWS:
        # Windows' console draws what arrives a moment later, and can report the end before it has
        # drawn the last line: the device stays on half a second, keeping the command's exit code.
        command += (" " if command.rstrip().endswith("&") else "; ") + "rc=$?; sleep 0.5; exit $rc"
        # -n: with its input a console, Windows' ssh can hang after the command has ended (about one
        # run in five); the password is read from the console either way.
        extra = ["-n"]
    code, out, err = _spawn(ssh_command(login, command, "-T", *extra), login.passwords, timeout, timeout, stop=stop,
                            capture=True)
    failure = _failure(err, code, login)
    if failure and failure.kind == "forwarding" and login.via:
        login.nested = True
        return _run_nested(login, command, timeout, stop)
    if failure and (code == 255 or failure.kind in ("key", "auth")):
        raise failure
    return Result(code, out, err)


def _run_nested(login: Login, command: str, timeout: float, stop) -> Result:
    hop = last_hop(login)
    # A terminal on the hop, so its client can ask for the password; everything comes back on it.
    code, _out, text = _spawn(ssh_command(hop, nested_command(login, command), "-tt"),
                              {**_as_dict(hop), login.ip: login.password}, timeout, timeout, stop=stop)
    lines = [l for l in text.split("\n") if not terminal.PASSWORD_PROMPT.search(l.encode() + b" ")
             and not l.startswith(("Warning: Permanently added", "Connection to ", "Host '"))]
    failure = _failure(text, code, login)
    if failure and (code == 255 or failure.kind in ("key", "auth")):
        raise failure
    out = "\n".join(lines).strip("\n") + "\n"
    return Result(code, out, text)


def check_login(login: Login, stop: threading.Event | None = None) -> None:
    """Log in and out again: raises SSHError if that doesn't work."""
    result = run(login, "true", timeout=40, stop=stop)
    if result.code:
        raise _failure(result.err, 255, login) or SSHError(
            tr("Logging in to {device} worked, but the device didn't run a command (exit code {code}).",
               device=login.where, code=result.code))


def upload(login: Login, local: Path, path: str, progress=None, stop: threading.Event | None = None,
           idle: float = 120) -> None:
    """Copy a file to the device. progress(percent) as scp reports it."""
    _copy(login, scp_command(login, str(local), remote(login, path)), progress, stop, idle)


def download(login: Login, path: str, local: Path, stop: threading.Event | None = None) -> None:
    _copy(login, scp_command(login, remote(login, path), str(local)), None, stop, 120)


def _copy(login: Login, argv: list, progress, stop, idle: float) -> None:
    def seen(data: bytes) -> None:
        if progress:
            found = PROGRESS.findall(data)
            if found:
                progress(min(100, int(found[-1])))

    if login.nested:
        raise SSHError(tr("A device on the way to {ip} ({route}) doesn't forward connections, so files can't be "
                          "copied to or from it.", ip=login.ip, route=route_text(login)), "forwarding")
    code, _out, err = _spawn(argv, login.passwords, 24 * 3600, idle, on_tty=seen, stop=stop)
    if code:
        raise _failure(err, 255, login) or SSHError(
            tr("Copying failed: {reason}", reason=_last_line(err) or tr("scp exit code {code}", code=code)))


def _spawn(argv: list, password: str, timeout: float, idle: float, on_tty=None, stop=None,
           capture: bool = False) -> tuple:
    """Run ssh or scp in a pseudo-terminal, typing the password when asked. Returns
    (exit code, what it printed to stdout when captured, what it printed to the terminal)."""
    env = dict(os.environ, TERM="dumb")
    env.pop("SSH_ASKPASS", None)  # never a password window of its own
    if IS_WINDOWS:
        return _spawn_windows(argv, password, timeout, idle, on_tty, stop, env)
    master, slave = pty.openpty()
    try:
        proc = subprocess.Popen(argv, stdin=slave, stdout=subprocess.PIPE if capture else slave, stderr=slave,
                                env=env, start_new_session=True, preexec_fn=terminal._take_terminal)
    finally:
        os.close(slave)
    out = bytearray()
    reader = None
    if capture:
        reader = threading.Thread(target=lambda: out.extend(proc.stdout.read()), daemon=True)
        reader.start()
    watcher = _Watcher(password, lambda data: os.write(master, data), on_tty)
    try:
        start = last = time.monotonic()
        while True:
            ready = select.select([master], [], [], 0.2)[0]
            if ready:
                try:
                    data = os.read(master, 65536)
                except OSError:  # Linux: EIO once the program has exited
                    data = b""
                if not data:
                    break
                last = time.monotonic()
                watcher.feed(data)
            elif proc.poll() is not None:
                break
            _check_limits(proc, stop, start, last, timeout, idle, watcher)
        code = proc.wait()
    except BaseException:
        _kill(proc)
        raise
    finally:
        os.close(master)
    if reader:
        reader.join(10)
    return code, out.decode("utf-8", "replace"), watcher.text()


def _spawn_windows(argv, password, timeout, idle, on_tty, stop, env) -> tuple:
    import queue
    proc = terminal.WinPty.spawn(argv, dimensions=(50, 250), env=env)
    chunks: queue.Queue = queue.Queue()

    def read():
        while True:
            try:
                data = proc.read(65536)
            except (EOFError, OSError):
                break
            if not data:
                if not proc.isalive():
                    break
                time.sleep(0.05)
                continue
            chunks.put(data.encode("utf-8", "replace"))
        chunks.put(None)

    threading.Thread(target=read, daemon=True).start()
    watcher = _Watcher(password, lambda data: proc.write(data.decode("utf-8", "replace")), on_tty)
    try:
        start = last = time.monotonic()
        ended = None
        while True:
            try:
                data = chunks.get(timeout=0.2)
            except queue.Empty:
                data = b""
            if data is None:
                break
            if data:
                last = time.monotonic()
                watcher.feed(data)
            elif not proc.isalive():  # ConPTY can keep the reader waiting after the program has ended
                ended = ended or time.monotonic()
                if time.monotonic() - ended > 0.6:  # what it printed last has been read by now
                    break
            _check_limits(proc, stop, start, last, timeout, idle, watcher)
        proc.wait()
    except BaseException:
        proc.terminate(force=True)
        raise
    text = watcher.text()
    return proc.exitstatus or 0, text, text


class _Watcher:
    """Collects what ssh and scp print to the terminal and answers their questions: the password,
    at most twice (a device can ask once by keyboard-interactive and once by password), and
    Enter for a key's passphrase, so ssh moves on to the password."""

    def __init__(self, password, write, on_tty):
        self.password, self.write, self.on_tty = password, write, on_tty
        self.seen, self.tail, self.typed = bytearray(), b"", {}
        self.unanswered = False

    def feed(self, data: bytes) -> None:
        self.seen += data
        if self.on_tty:
            self.on_tty(data)
        self.tail = (self.tail + data)[-400:]
        shown = terminal.plain(self.tail)  # Windows' console ends a prompt with escapes
        if terminal.PASSWORD_PROMPT.search(shown):
            who, password = terminal.prompt_password(self.password, shown)
            self.tail = b""
            if password and self.typed.get(who, 0) < 2:
                self.typed[who] = self.typed.get(who, 0) + 1
                self.write((password + "\r").encode("utf-8"))
            else:
                self.unanswered = True
        elif PASSPHRASE_PROMPT.search(shown):
            self.tail = b""
            self.write(b"\r")

    def text(self) -> str:
        shown = self.seen.decode("utf-8", "replace")
        if IS_WINDOWS:
            shown = ROW_MOVE.sub("\n", RIGHT_MOVE.sub(lambda m: " " * int(m.group(1) or 1), shown))
        return ANSI.sub("", shown).replace("\r\n", "\n").replace("\r", "\n")


def _check_limits(proc, stop, start, last, timeout, idle, watcher) -> None:
    now = time.monotonic()
    if stop is not None and stop.is_set():
        _kill(proc)
        raise SSHError(_("Cancelled."), "cancelled")
    if watcher.unanswered:
        _kill(proc)
        if any(watcher.typed.values()):
            raise SSHError(_("The device didn't accept the username and password."), "auth")
        raise SSHError(_("The device asks for a password, and none was given."), "auth")
    if now - start > timeout or now - last > idle:
        _kill(proc)
        raise SSHError(_("The device stopped answering (timed out)."), "timeout")


def _kill(proc) -> None:
    if IS_WINDOWS:
        try:
            proc.terminate(force=True)
        except Exception:
            pass
        return
    if proc.poll() is not None:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except OSError:
            pass
        try:
            proc.wait(3)
            return
        except subprocess.TimeoutExpired:
            continue


# ---------------------------------------------------------------------------
# What went wrong
# ---------------------------------------------------------------------------

def _last_line(text: str) -> str:
    lines = [l.strip() for l in text.splitlines() if l.strip() and not terminal.PASSWORD_PROMPT.search(l.encode())]
    return lines[-1] if lines else ""


def _failure(text: str, code: int, login: Login) -> SSHError | None:
    """The SSHError that what ssh or scp printed describes, if any."""
    t = text.lower()
    where = login.where
    if terminal.KEY_CHANGED.decode().lower() in t or "host key verification failed" in t:
        return SSHError(tr("The SSH key of {ip} changed since the last connection: it was reset or replaced, or "
                           "something is in between. If that's expected, right-click it and choose Forget SSH key, "
                           "then try again.", ip=login.ip), "key")
    # Not scp's "scp: /path: Permission denied", which is about a file.
    if re.search(r"permission denied(?: \(|, please)|too many authentication failures|authentication failed", t):
        asked = terminal.ASKER.findall(text.encode())  # whose prompt was answered last
        hop = next((h for h in login.via if asked and asked[-1][1].decode() in (h.alias, h.ip)), None)
        if hop:
            return SSHError(tr("{hop}, on the way to {ip}, didn't accept its username and password.", hop=hop.ip,
                               ip=login.ip), "auth")
        return SSHError(tr("{device} didn't accept the username and password.", device=where), "auth")
    if "administratively prohibited" in t or "stdio forwarding failed" in t or re.search(r"channel \d+: open failed", t):
        return SSHError(tr("A device on the way to {ip} ({route}) doesn't forward connections (TCP forwarding is off "
                           "in its SSH server).", ip=login.ip, route=route_text(login) or _("its route")), "forwarding")
    if "connection refused" in t:
        return SSHError(tr("Nothing accepts SSH connections on {device}.", device=where), "refused")
    if "timed out" in t:
        return SSHError(tr("No SSH answer from {device} (timed out).", device=where), "timeout")
    if any(s in t for s in ("no route to host", "host is down", "network is unreachable", "host unreachable")):
        return SSHError(tr("{ip} can't be reached from this computer.", ip=login.ip), "unreachable")
    if "no matching" in t or "unable to negotiate" in t:
        return SSHError(tr("{device} only offers SSH algorithms this computer's ssh no longer has: {said}",
                           device=where, said=_last_line(text)), "algorithms")
    if "no space left" in t:
        return SSHError(_("The device ran out of space for the file (its memory is full). Rebooting it frees "
                          "memory; then try again."), "space")
    if code == 255:
        line = _last_line(text)
        if not line or "closed" in t or "reset" in t or "broken pipe" in t:
            return SSHError(tr("The connection to {device} dropped: {said}", device=where, said=line) if line else
                            tr("The connection to {device} dropped.", device=where), "other")
        return SSHError(tr("SSH to {device} failed: {said}", device=where, said=line), "other")
    return None
