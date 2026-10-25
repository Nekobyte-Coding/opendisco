"""SSH on the phones, in the app itself (asyncssh): iOS and Android run no ssh program.

The calls devicetools makes of sshrun (the desktop's, through the system's ssh) are here under the
same names: Login, Result, SSHError, run, upload, download and check_login, so firmware checks and
Scan from device work the same. Shell is the interactive session in the phone's Tools.

Connections run on one asyncio loop in a thread of their own; the calls block until they're done,
for worker threads, the way sshrun's do. A device found through others (Login.via) is reached
through SSH tunnels from one to the next; when one on the way refuses to forward, commands and
shells run through its own SSH client (Dropbear's dbclient) instead, as sshrun's do.

Host keys: the first key a device shows is kept in the app's known_hosts under its MAC
(host_key_alias), as the desktop's ssh does with accept-new; a different one later is refused
(SSHError kind "key") until Forget SSH key. The key is checked before the password is sent. Old
gear (airOS, EdgeOS) may offer only SHA-1 key exchange and ssh-rsa host keys: those are allowed
after the modern ones.
"""
import asyncio
import concurrent.futures
import errno
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path

try:
    import asyncssh
except ImportError:  # the desktop: sshrun instead
    asyncssh = None

# asyncssh asks getpass for this device's own user name, which a phone app doesn't have.
os.environ.setdefault("LOGNAME", "opendisco")

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|\x1b[=>]")
PASSWORD_PROMPT = re.compile(r"(?i)pass(word|code)[^\r\n]{0,60}:\s*$")
# What a hop's own SSH client says about the connection, not the command's output: "Host '…' key
# accepted unconditionally." and the fingerprint under it (Dropbear), "Warning: Permanently added…"
CLIENT_NOISE = re.compile(r"dbclient:\s*$|(dbclient: )?Host '|\(\S+ fingerprint |Warning: Permanently added"
                          r"|Connection to ")
CONNECT_TIMEOUT = 15


class SSHError(Exception):
    """kind: "key" (host key changed), "auth", "refused", "timeout", "unreachable",
    "algorithms", "forwarding", "space", "cancelled" or "other" (sshrun's kinds)."""

    def __init__(self, message: str, kind: str = "other"):
        super().__init__(message)
        self.kind = kind


@dataclass
class Login:
    ip: str
    port: int
    user: str
    password: str
    alias: str  # the name its host key is filed under (host_key_alias)
    known_hosts: Path
    via: tuple = ()  # the logins of the devices on the way to it, the nearest first
    nested: bool = False  # a device on the way refused to forward: run commands on the last hop instead

    @property
    def where(self) -> str:
        return f"{self.ip} port {self.port}" + (f" (via {route_text(self)})" if self.via else "")

    @property
    def passwords(self):
        """The password to type, or one per device on the way, by the name its prompt shows."""
        if not self.via:
            return self.password
        return {**{hop.alias: hop.password for hop in self.via}, self.alias: self.password, self.ip: self.password}


@dataclass
class Result:
    code: int
    out: str
    err: str


def route_text(login: Login) -> str:
    return " → ".join(hop.ip for hop in login.via)


def last_hop(login: Login) -> Login:
    """The device just before this one on its route, reached through the ones before it."""
    *before, hop = login.via
    return Login(hop.ip, hop.port, hop.user, hop.password, hop.alias, hop.known_hosts, tuple(before))


def _quote(text: str) -> str:
    return "'" + text.replace("'", "'\\''") + "'"


def nested_command(login: Login, command: str | None) -> str:
    """Run command (None: a shell) on the device through the last hop's own SSH client (Dropbear's
    dbclient, or ssh), for a hop that refuses to forward connections. That hop checks the
    device's host key."""
    target = f"-p {login.port} -l {_quote(login.user)} {login.ip}" + (f" {_quote(command)}" if command else "")
    return (f"if command -v dbclient >/dev/null 2>&1; then dbclient -y {target}; "
            f"else ssh -o StrictHostKeyChecking=accept-new {target}; fi")


def host_key_alias(mac: str | None, ip: str) -> str:
    """The name a device's host key is kept under: its MAC, as on the desktop (terminal.py)."""
    return "ubnt-" + mac.replace(":", "") if mac else ip


def available() -> bool:
    return asyncssh is not None


# -- the loop the connections run on ------------------------------------------------
_loop = None
_lock = threading.Lock()


def _ssh_loop() -> asyncio.AbstractEventLoop:
    global _loop
    with _lock:
        if _loop is None:
            _loop = asyncio.new_event_loop()
            threading.Thread(target=_loop.run_forever, name="opendisco-ssh", daemon=True).start()
        return _loop


def _call(coro, stop: threading.Event | None = None):
    """Run a coroutine on the SSH loop and wait for it; stop cancels it."""
    future = asyncio.run_coroutine_threadsafe(coro, _ssh_loop())
    while True:
        try:
            return future.result(0.2)
        except concurrent.futures.TimeoutError:
            if stop is not None and stop.is_set():
                future.cancel()
                raise SSHError("Stopped.", "cancelled") from None
        except concurrent.futures.CancelledError:
            raise SSHError("Stopped.", "cancelled") from None


# -- connecting ------------------------------------------------------------------------
def _algorithms(default, every) -> list:
    """The modern ones first, then the rest asyncssh has (SHA-1, ssh-rsa...) for old gear."""
    default = [a.decode() for a in default()]
    return default + [a.decode() for a in every() if a.decode() not in default]


def _options() -> dict:
    from asyncssh import encryption, kex, mac, public_key
    return {"kex_algs": _algorithms(kex.get_default_kex_algs, kex.get_kex_algs),
            "server_host_key_algs": _algorithms(public_key.get_default_public_key_algs,
                                                public_key.get_public_key_algs),
            "encryption_algs": _algorithms(encryption.get_default_encryption_algs, encryption.get_encryption_algs),
            "mac_algs": _algorithms(mac.get_default_mac_algs, mac.get_mac_algs)}


def _failure(e: BaseException, login: Login, hop: Login | None = None, through: Login | None = None) -> SSHError:
    """The SSHError that an exception from asyncssh or the network means, worded as sshrun's. hop:
    the device on the way to login where it failed; through: the device before the one that failed."""
    who = hop or login
    where = who.where if hop is None else f"{hop.ip}, on the way to {login.ip},"
    if isinstance(e, SSHError):
        return e
    if isinstance(e, asyncssh.PermissionDenied):
        return SSHError(f"{where} didn't accept the username and password.", "auth")
    if isinstance(e, asyncssh.ChannelOpenError):  # the device before it couldn't pass the connection on
        if e.code == 1:  # SSH_OPEN_ADMINISTRATIVELY_PROHIBITED: its SSH server forwards nothing
            return SSHError(f"A device on the way to {login.ip} ({route_text(login) or 'its route'}) doesn't "
                            "forward connections (TCP forwarding is off in its SSH server).", "forwarding")
        return SSHError(f"{who.ip} port {who.port} can't be reached from {through.ip if through else 'its route'}"
                        + (f", on the way to {login.ip}" if hop else "") + f" ({e.reason or 'connecting failed'}).",
                        "unreachable")
    if isinstance(e, asyncssh.KeyExchangeFailed):
        return SSHError(f"{who.where} and OpenDisco have no SSH algorithms in common: {e}", "algorithms")
    if isinstance(e, ConnectionRefusedError):
        return SSHError(f"Nothing accepts SSH connections on {who.where}.", "refused")
    if isinstance(e, (asyncio.TimeoutError, TimeoutError)):
        return SSHError(f"No SSH answer from {who.where} (timed out).", "timeout")
    if isinstance(e, OSError) and e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN):
        return SSHError(f"{who.ip} can't be reached from this phone.", "unreachable")
    if isinstance(e, (asyncssh.ConnectionLost, ConnectionResetError, BrokenPipeError)):
        return SSHError(f"The connection to {who.where} dropped.", "other")
    if isinstance(e, asyncssh.Error):
        return SSHError(f"SSH to {who.where} failed: {e.reason or e}", "other")
    return SSHError(f"SSH to {who.where} failed: {e}", "other")


def _kept_keys(login: Login) -> list:
    """[(type, base64)] filed under the device's alias."""
    path = Path(login.known_hosts)
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines() if path.exists() else []
    return [tuple(l.split()[1:3]) for l in lines if len(l.split()) >= 3 and l.split()[0] == login.alias]


def _host_key_checker(login: Login):
    """An asyncssh client that checks the device's key during the key exchange, before the
    password is sent: the one kept is trusted, a first one (of a type not kept) is kept, a
    different one of a kept type is refused."""
    class Checker(asyncssh.SSHClient):
        changed = False

        def validate_host_public_key(self, host, addr, port, key) -> bool:
            kind, data = key.export_public_key("openssh").decode().split()[:2]
            kept = _kept_keys(login)
            if (kind, data) in kept:
                return True
            if any(k == kind for k, _ in kept):
                self.changed = True
                return False
            path = Path(login.known_hosts)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as f:
                f.write(f"{login.alias} {kind} {data}\n")
            return True

    return Checker()


def forget_host_key(alias: str, known_hosts: Path) -> bool:
    """Remove a device's saved host keys, so the next connection trusts its new one."""
    path = Path(known_hosts)
    if not path.exists():
        return False
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    kept = [l for l in lines if not (l.split() and l.split()[0] == alias)]
    if len(kept) == len(lines):
        return False
    path.write_text("".join(l + "\n" for l in kept), encoding="utf-8")
    return True


async def _open(login: Login, tunnel=None, hop_of: Login | None = None, through: Login | None = None):
    checker = _host_key_checker(login)
    try:
        # known_hosts=([], [], []): no key is trusted outright, so every one goes to the checker.
        return await asyncio.wait_for(asyncssh.connect(
            login.ip, login.port, tunnel=tunnel, username=login.user, password=login.password,
            client_factory=lambda: checker, config=[], known_hosts=([], [], []), client_keys=None,
            agent_path=None, preferred_auth=("password", "keyboard-interactive"), keepalive_interval=15,
            **_options()), CONNECT_TIMEOUT)
    except Exception as e:
        if checker.changed:
            raise SSHError(f"The SSH key of {login.ip} changed since the last connection: it was reset or replaced, "
                           "or something is in between. If that's expected, use Forget SSH key, then try again.",
                           "key") from None
        raise _failure(e, hop_of or login, login if hop_of else None, through) from None


async def _connect(login: Login) -> list:
    """The connections to each device on the way, then to the device itself (last)."""
    conns, route = [], [*login.via, login]
    try:
        for n, hop in enumerate(route):
            conns.append(await _open(hop, conns[-1] if conns else None, None if hop is login else login,
                                     route[n - 1] if n else None))
    except BaseException:
        _close(conns)
        raise
    return conns


def _close(conns) -> None:
    for conn in reversed(conns):
        conn.close()


# -- what devicetools calls ------------------------------------------------------------
def run(login: Login, command: str, timeout: float = 60, stop: threading.Event | None = None) -> Result:
    """Run a command on the device. Raises SSHError when it couldn't connect or log in, or the
    connection dropped or went quiet, as sshrun does; otherwise the result has the command's exit
    code. Through a device that refuses to forward, it runs on that device's own SSH client."""
    if login.nested:
        return _run_nested(login, command, timeout, stop)

    async def go():
        conns = await _connect(login)
        try:
            done = await asyncio.wait_for(conns[-1].run(command, check=False), timeout)
        except (asyncio.TimeoutError, TimeoutError):
            raise SSHError(f"{login.where} stopped answering (no answer within {timeout:.0f}s).", "timeout") from None
        except Exception as e:
            raise _failure(e, login) from None
        finally:
            _close(conns)
        code = done.exit_status if done.exit_status is not None and done.exit_status >= 0 else 255
        return Result(code, _text(done.stdout), _text(done.stderr))

    try:
        return _call(go(), stop)
    except SSHError as e:
        if e.kind != "forwarding" or not login.via:
            raise
    login.nested = True
    return _run_nested(login, command, timeout, stop)


def _run_nested(login: Login, command: str | None, timeout: float, stop) -> Result:
    hop = last_hop(login)

    async def go():
        conns = await _connect(hop)
        try:
            process = await conns[-1].create_process(nested_command(login, command), term_type="dumb",
                                                     term_size=(200, 50), encoding="utf-8", errors="replace")
            typer = _PasswordTyper({**_as_dict(hop), login.ip: login.password}, process.stdin.write)
            text = []
            while True:
                data = await asyncio.wait_for(process.stdout.read(65536), timeout)
                if not data:
                    break
                text.append(data)
                typer.feed(data)
                if typer.unanswered:
                    raise SSHError(f"{login.where} didn't accept the username and password.", "auth")
            await process.wait_closed()
            return process.exit_status, ANSI.sub("", "".join(text)).replace("\r\n", "\n").replace("\r", "\n")
        except (asyncio.TimeoutError, TimeoutError):
            raise SSHError(f"{login.where} stopped answering (timed out).", "timeout") from None
        except Exception as e:
            raise _failure(e, login) from None
        finally:
            _close(conns)

    code, text = _call(go(), stop)
    code = code if code is not None and code >= 0 else 255
    failure = _nested_failure(text, login)
    if failure and (code == 255 or failure.kind in ("key", "auth")):
        raise failure
    lines = [line for line in text.split("\n")
             if not PASSWORD_PROMPT.search(line + " ") and not CLIENT_NOISE.match(line)]
    return Result(code, "\n".join(lines).strip("\n") + "\n", text)


def _as_dict(login: Login) -> dict:
    passwords = login.passwords
    return passwords if isinstance(passwords, dict) else {login.alias: passwords, login.ip: passwords}


class _PasswordTyper:
    """Types the password when a hop's own SSH client asks for it ("ubnt@10.0.0.5's password:"),
    at most twice for each device."""
    ASKER = re.compile(r"([^\s@']+)@([^\s@']+)'s password")

    def __init__(self, passwords: dict, write):
        self.passwords, self.write = passwords, write
        self.tail, self.typed, self.unanswered = "", {}, False

    def feed(self, data: str) -> None:
        self.tail = (self.tail + data)[-400:]
        if not PASSWORD_PROMPT.search(self.tail):
            return
        asker = self.ASKER.findall(self.tail)
        who = asker[-1][1] if asker else None
        password = self.passwords.get(who) if who else next(iter(self.passwords.values()), None)
        self.tail = ""
        if password and self.typed.get(who, 0) < 2:
            self.typed[who] = self.typed.get(who, 0) + 1
            self.write(password + "\r")
        else:
            self.unanswered = True


def _nested_failure(text: str, login: Login) -> SSHError | None:
    """What a hop's own SSH client printed, as an SSHError, if it failed."""
    t = text.lower()
    if "host key mismatch" in t or "remote host identification has changed" in t:
        return SSHError(f"The SSH key of {login.ip} changed since {route_text(login)} last connected to it. If "
                        "that's expected, remove it from that device's known hosts, then try again.", "key")
    if "permission denied" in t or "authentication failed" in t or "exited: no auth methods" in t:
        return SSHError(f"{login.where} didn't accept the username and password.", "auth")
    if "connection refused" in t:
        return SSHError(f"Nothing accepts SSH connections on {login.where}.", "refused")
    if "timed out" in t:
        return SSHError(f"No SSH answer from {login.where} (timed out).", "timeout")
    if "no route to host" in t or "network is unreachable" in t or "host is unreachable" in t:
        return SSHError(f"{login.ip} can't be reached from {login.via[-1].ip}.", "unreachable")
    return None


def check_login(login: Login, stop: threading.Event | None = None) -> None:
    """Log in and out again: raises SSHError if that doesn't work."""
    result = run(login, "true", timeout=40, stop=stop)
    if result.code:
        raise _nested_failure(result.err, login) or SSHError(
            f"Logging in to {login.where} worked, but the device didn't run a command (exit code {result.code}).")


def upload(login: Login, local: Path, path: str, progress=None, stop: threading.Event | None = None,
           idle: float = 120) -> None:
    """Copy a file to the device (scp: Dropbear on airOS has no SFTP). progress(percent)."""
    moved = [time.monotonic()]

    def shown(_src, _dst, copied, total):
        moved[0] = time.monotonic()
        if progress and total:
            progress(int(copied * 100 / total))

    async def go():
        conns = await _connect(login)
        try:
            copying = asyncio.ensure_future(asyncssh.scp(str(local), (conns[-1], path), progress_handler=shown))
            while not copying.done():  # stopped when nothing moves for idle seconds
                await asyncio.wait([copying], timeout=1)
                if not copying.done() and time.monotonic() - moved[0] > idle:
                    copying.cancel()
                    raise SSHError(f"{login.where} stopped answering (timed out).", "timeout")
            copying.result()
        except (asyncssh.Error, OSError) as e:
            raise _copy_failure(e, login) from None
        finally:
            _close(conns)
    _not_nested(login)
    _call(go(), stop)


def download(login: Login, path: str, local: Path, stop: threading.Event | None = None) -> None:
    async def go():
        conns = await _connect(login)
        try:
            await asyncssh.scp((conns[-1], path), str(local))
        except (asyncssh.Error, OSError) as e:
            raise _copy_failure(e, login) from None
        finally:
            _close(conns)
    _not_nested(login)
    _call(go(), stop)


def _not_nested(login: Login) -> None:
    if login.nested:
        raise SSHError(f"A device on the way to {login.ip} ({route_text(login)}) doesn't forward connections, so "
                       "files can't be copied to or from it.", "forwarding")


def _copy_failure(e, login: Login) -> SSHError:
    if not isinstance(e, asyncssh.SFTPError) and isinstance(e, (asyncssh.DisconnectError, asyncssh.ChannelOpenError,
                                                                  OSError)):
        return _failure(e, login)  # the connection, not the copy
    text = str(getattr(e, "reason", "") or e)
    if "no space left" in text.lower():
        return SSHError("The device ran out of space for the file (its memory is full). Rebooting it frees "
                        "memory; then try again.", "space")
    return SSHError(f"Copying a file over SSH with {login.where} failed: {text}", "other")


def _text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value or ""


# -- the interactive session -------------------------------------------------------------
class Shell:
    """A shell on the device for the phone's console, a line at a time: on_output(text) as the
    device sends it (escape sequences and carriage returns removed), on_end(reason) once it's
    over. Both are called from the SSH thread. Creating one logs in and blocks until the shell
    is up (call it from a worker thread); raises SSHError. Through a device that refuses to
    forward, the shell runs through that device's own SSH client, which is given the password."""

    def __init__(self, login: Login, on_output, on_end, columns: int = 60):
        self.login, self.on_output, self.on_end = login, on_output, on_end
        self._typer, self._started = None, time.monotonic()
        try:
            if login.nested:
                raise SSHError("", "forwarding")
            self._conns, self._process = _call(self._start(login, None, columns))
        except SSHError as e:
            if e.kind != "forwarding" or not login.via:
                raise
            login.nested = True
            hop = last_hop(login)
            self._conns, self._process = _call(self._start(hop, nested_command(login, None), columns))
            self._typer = _PasswordTyper({**_as_dict(hop), login.ip: login.password}, self._process.stdin.write)
        self._reader = asyncio.run_coroutine_threadsafe(self._read(), _ssh_loop())

    async def _start(self, login: Login, command: str | None, columns: int):
        conns = await _connect(login)
        try:
            process = await conns[-1].create_process(command, term_type="dumb", term_size=(columns, 40),
                                                     encoding="utf-8", errors="replace")
        except Exception as e:
            _close(conns)
            raise _failure(e, login) from None
        return conns, process

    async def _read(self):
        reason = ""
        try:
            while True:
                data = await self._process.stdout.read(4096)
                if not data:
                    break
                if self._typer and time.monotonic() - self._started < 30:  # only while logging in
                    self._typer.feed(data)
                text = ANSI.sub("", data).replace("\r\n", "\n").replace("\r", "")
                if text:
                    self.on_output(text)
        except Exception as e:
            reason = str(_failure(e, self.login))
        finally:
            _close(self._conns)
        self.on_end(reason)

    def send(self, text: str) -> None:
        """Type text into the shell (a command ends with "\\n")."""
        _ssh_loop().call_soon_threadsafe(self._process.stdin.write, text)

    def interrupt(self) -> None:
        """Ctrl-C."""
        self.send("\x03")

    def resize(self, columns: int, rows: int = 40) -> None:
        _ssh_loop().call_soon_threadsafe(self._process.change_terminal_size, columns, rows)

    def close(self) -> None:
        _ssh_loop().call_soon_threadsafe(_close, self._conns)
