"""Commands and file copies on one device for the device tools, through the system's ssh and scp.

They run in a pseudo-terminal (pywinpty on Windows) so the password can be typed when they ask
for it, the way the Terminal tab's sessions do, with the app's known_hosts and each device's host
key filed under its MAC. On macOS and Linux a command's output comes back through a pipe of its
own, so it arrives exactly as the device sent it; Windows' console mixes it with ssh's messages,
so files always travel by scp.

Every failure is an SSHError whose text says what went wrong in terms of the device: a changed
host key, a wrong password, no answer, an SSH server that only speaks retired algorithms.
"""
import os
import re
import select
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from opendisco import terminal

IS_WINDOWS = terminal.IS_WINDOWS
PASSPHRASE_PROMPT = re.compile(rb"(?i)passphrase for key[^\r\n]{0,200}:\s*$")
PROGRESS = re.compile(rb"(\d{1,3})%")
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|\x1b[=>]")

if not IS_WINDOWS:
    import pty


class SSHError(Exception):
    """kind: "key" (host key changed), "auth", "refused", "timeout", "unreachable",
    "algorithms", "space", "cancelled" or "other"."""

    def __init__(self, message: str, kind: str = "other"):
        super().__init__(message)
        self.kind = kind


@dataclass
class Login:
    ip: str
    port: int
    user: str
    password: str
    alias: str  # the name its host key is filed under (terminal.host_key_alias)
    known_hosts: Path

    @property
    def where(self) -> str:
        return f"{self.ip} port {self.port}"


@dataclass
class Result:
    code: int
    out: str  # what the command printed (on Windows, mixed with what ssh printed)
    err: str  # what it and ssh printed to the terminal


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


def ssh_command(login: Login, command: str) -> list:
    return [terminal.ssh_program(), "-T", "-p", str(login.port), *_options(login), "-l", login.user, login.ip,
            command]


def scp_command(login: Login, source: str, target: str) -> list:
    return [scp_program(), *scp_legacy_flag(), "-P", str(login.port), *_options(login), source, target]


def remote(login: Login, path: str) -> str:
    return f"{login.user}@{login.ip}:{path}"


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------

def run(login: Login, command: str, timeout: float = 60, stop: threading.Event | None = None) -> Result:
    """Run a command on the device. Raises SSHError when ssh couldn't connect or log in;
    otherwise the result holds the command's exit code (255: the connection dropped)."""
    code, out, err = _spawn(ssh_command(login, command), login.password, timeout, timeout, stop=stop,
                            capture=True)
    failure = _failure(err, code, login)
    if failure and (code == 255 or failure.kind in ("key", "auth")):
        raise failure
    return Result(code, out, err)


def check_login(login: Login, stop: threading.Event | None = None) -> None:
    """Log in and out again: raises SSHError if that doesn't work."""
    result = run(login, "true", timeout=40, stop=stop)
    if result.code:
        raise _failure(result.err, 255, login) or SSHError(
            f"Logging in to {login.where} worked, but the device didn't run a command (exit code {result.code}).")


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

    code, _out, err = _spawn(argv, login.password, 24 * 3600, idle, on_tty=seen, stop=stop)
    if code:
        raise _failure(err, 255, login) or SSHError(f"Copying failed: {_last_line(err) or f'scp exit code {code}'}")


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
        self.seen, self.tail, self.typed = bytearray(), b"", 0
        self.unanswered = False

    def feed(self, data: bytes) -> None:
        self.seen += data
        if self.on_tty:
            self.on_tty(data)
        self.tail = (self.tail + data)[-400:]
        if terminal.PASSWORD_PROMPT.search(self.tail):
            self.tail = b""
            if self.password and self.typed < 2:
                self.typed += 1
                self.write((self.password + "\r").encode("utf-8"))
            else:
                self.unanswered = True
        elif PASSPHRASE_PROMPT.search(self.tail):
            self.tail = b""
            self.write(b"\r")

    def text(self) -> str:
        return ANSI.sub("", self.seen.decode("utf-8", "replace")).replace("\r\n", "\n").replace("\r", "\n")


def _check_limits(proc, stop, start, last, timeout, idle, watcher) -> None:
    now = time.monotonic()
    if stop is not None and stop.is_set():
        _kill(proc)
        raise SSHError("Cancelled.", "cancelled")
    if watcher.unanswered:
        _kill(proc)
        if watcher.typed:
            raise SSHError("The device didn't accept the username and password.", "auth")
        raise SSHError("The device asks for a password, and none was given.", "auth")
    if now - start > timeout or now - last > idle:
        _kill(proc)
        raise SSHError("The device stopped answering (timed out).", "timeout")


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
        return SSHError(f"The SSH key of {login.ip} changed since the last connection: it was reset or replaced, or "
                        "something is in between. If that's expected, right-click it and choose Forget SSH key, "
                        "then try again.", "key")
    # Not scp's "scp: /path: Permission denied", which is about a file.
    if re.search(r"permission denied(?: \(|, please)|too many authentication failures|authentication failed", t):
        return SSHError(f"{where} didn't accept the username and password.", "auth")
    if "connection refused" in t:
        return SSHError(f"Nothing accepts SSH connections on {where}.", "refused")
    if "timed out" in t:
        return SSHError(f"No SSH answer from {where} (timed out).", "timeout")
    if any(s in t for s in ("no route to host", "host is down", "network is unreachable", "host unreachable")):
        return SSHError(f"{login.ip} can't be reached from this computer.", "unreachable")
    if "no matching" in t or "unable to negotiate" in t:
        return SSHError(f"{where} only offers SSH algorithms this computer's ssh no longer has: "
                        f"{_last_line(text)}", "algorithms")
    if "no space left" in t:
        return SSHError("The device ran out of space for the file (its memory is full). Rebooting it frees "
                        "memory; then try again.", "space")
    if code == 255:
        line = _last_line(text)
        if not line or "closed" in t or "reset" in t or "broken pipe" in t:
            return SSHError(f"The connection to {where} dropped" + (f": {line}" if line else "."), "other")
        return SSHError(f"SSH to {where} failed: {line}", "other")
    return None
