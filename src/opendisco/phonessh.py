"""Commands, file copies and shells on one device for the phones' device tools, through asyncssh.

A phone has no ssh program to run, so this gives devicetools and the phone screens what sshrun
gives them on a computer, from Python: the same Login, Result and SSHError and the same calls.
asyncssh (and the cryptography package it stands on) is part of the iOS and Android apps, and
imported only when a call needs it.

Host keys are trusted on first use and filed under each device's alias (terminal.host_key_alias:
its MAC) in the app's known_hosts, as the desktop's ssh does; a changed one is refused. A device
behind others is reached through their forwarding, each with its own login and host key, or,
when one refuses to forward, through the last one's own SSH client (Dropbear's dbclient). Old
firmware's key exchanges, host keys and ciphers are allowed after the strong ones.

Every call blocks, like sshrun's: call them from a worker thread. They run on an asyncio loop of
their own, on a thread of their own, never on the UI's. Every failure is an SSHError whose text
says what went wrong in terms of the device.
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

PASSWORD_PROMPT = re.compile(r"(?i)pass(word|code)[^\r\n]{0,60}:\s*$")
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|\x1b[=>]")
# Allowed after asyncssh's own choices, for airOS 5/6, old EdgeOS and other old firmware.
LEGACY = {"kex_algs": ["diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1",
                       "diffie-hellman-group1-sha1"],
          "server_host_key_algs": ["ssh-rsa", "ssh-dss"],
          "encryption_algs": ["aes128-cbc", "aes256-cbc", "3des-cbc"],
          "mac_algs": ["hmac-sha1", "hmac-md5"]}
CONNECT_TIMEOUT = 10
# asyncssh asks getpass for this device's own user name before every connection, and an iOS
# app has none (getpass raises): every login failed with "Unknown local username" there.
os.environ.setdefault("LOGNAME", "opendisco")
# What a hop's own SSH client says about the connection, not the command's output: "Host '…' key
# accepted unconditionally." and the fingerprint under it (Dropbear), "Warning: Permanently added…"
CLIENT_NOISE = re.compile(r"dbclient:\s*$|(dbclient: )?Host '|\(\S+ fingerprint |Warning: Permanently added"
                          r"|Connection to ")


class SSHError(Exception):
    """kind: "key" (host key changed), "auth", "refused", "timeout", "unreachable",
    "algorithms", "space", "cancelled", "forwarding" or "other"."""

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
    via: tuple = ()  # the logins of the devices on the way to it, the nearest to this phone first
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
    out: str  # what the command printed
    err: str  # what it printed to stderr


def available() -> bool:
    """asyncssh is here to use (the phone apps bring it)."""
    import importlib.util
    return importlib.util.find_spec("asyncssh") is not None


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


def plain(text: str) -> str:
    """Terminal output without its escape sequences, for a plain console."""
    return ANSI.sub("", text).replace("\r\n", "\n").replace("\r", "\n")


# ---------------------------------------------------------------------------
# Host keys: known_hosts lines "alias type base64", trusted on first use
# ---------------------------------------------------------------------------

def host_key_alias(mac: str | None, ip: str) -> str:
    """The name a device's host key is filed under: its MAC, so a different radio at the same
    factory address isn't mistaken for the last one, while a changed key on the same device is
    still caught. (The same as terminal.host_key_alias, which phones don't have.)"""
    return "ubnt-" + mac.replace(":", "") if mac else ip


def _names(line: str) -> list:
    return line.split()[0].split(",") if line.strip() and not line.startswith(("#", "@")) else []


def _stored_keys(login: Login) -> list:
    import asyncssh
    try:
        lines = login.known_hosts.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    keys = []
    for line in lines:
        names = _names(line)
        if login.alias in names or any(n.startswith(f"[{login.alias}]:") for n in names):
            try:
                keys.append(asyncssh.import_public_key(" ".join(line.split()[1:3])))
            except (asyncssh.KeyImportError, ValueError):
                pass
    return keys


def forget_host_key(alias: str, known_hosts: Path) -> bool:
    """Remove a device's saved SSH host key, so the next connection trusts its new one."""
    try:
        lines = known_hosts.read_text(encoding="utf-8").splitlines(keepends=True)
    except OSError:
        return False
    kept = [line for line in lines
            if not any(n == alias or n.startswith(f"[{alias}]:") for n in _names(line))]
    if len(kept) == len(lines):
        return False
    known_hosts.write_text("".join(kept), encoding="utf-8")
    return True


def _client_class():
    import asyncssh

    class Client(asyncssh.SSHClient):
        """Trusts a device's first host key and files it; refuses one that differs from what's on file."""

        def __init__(self, login: Login, stored: list):
            self.login, self.stored, self.changed = login, stored, False

        def validate_host_public_key(self, host, addr, port, key) -> bool:
            if self.stored:  # on file, and this isn't it
                self.changed = True
                return False
            line = " ".join(key.export_public_key("openssh").decode("ascii").split()[:2])
            try:
                path = self.login.known_hosts
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a", encoding="utf-8") as f:
                    f.write(f"{self.login.alias} {line}\n")
            except OSError:
                pass  # trusted for this connection; asked about again next time
            return True

    return Client


# ---------------------------------------------------------------------------
# The loop the connections run on
# ---------------------------------------------------------------------------

_LOOP = None
_LOOP_LOCK = threading.Lock()


def _loop() -> asyncio.AbstractEventLoop:
    global _LOOP
    with _LOOP_LOCK:
        if _LOOP is None:
            _LOOP = asyncio.new_event_loop()
            threading.Thread(target=_LOOP.run_forever, name="phonessh", daemon=True).start()
        return _LOOP


def _call(make, limit: float, stop: threading.Event | None = None):
    """Run the coroutine make() on phonessh's loop and wait for it, up to limit seconds; stop
    cancels it."""
    future = asyncio.run_coroutine_threadsafe(make(), _loop())
    deadline = time.monotonic() + limit
    while True:
        try:
            return future.result(0.2)
        except concurrent.futures.TimeoutError:
            if stop is not None and stop.is_set():
                future.cancel()
                raise SSHError("Cancelled.", "cancelled") from None
            if time.monotonic() > deadline:
                future.cancel()
                raise SSHError("The device stopped answering (timed out).", "timeout") from None
        except concurrent.futures.CancelledError:
            raise SSHError("Cancelled.", "cancelled") from None


def _algorithms() -> dict:
    """asyncssh's own algorithms, then the old ones it has but doesn't offer by default."""
    from asyncssh.encryption import get_encryption_algs
    from asyncssh.kex import get_kex_algs
    from asyncssh.mac import get_mac_algs
    from asyncssh.public_key import get_public_key_algs
    have = {"kex_algs": get_kex_algs(), "server_host_key_algs": get_public_key_algs(),
            "encryption_algs": get_encryption_algs(), "mac_algs": get_mac_algs()}
    extra = {option: ",".join(n for n in names if n.encode() in have[option]) for option, names in LEGACY.items()}
    return {option: "+" + names for option, names in extra.items() if names}


# ---------------------------------------------------------------------------
# Connecting, through the devices on the way
# ---------------------------------------------------------------------------

async def _connect(login: Login, target: Login, tunnel=None, through: Login | None = None):
    """One SSH connection: to login, which is target itself or a device on the way to it,
    through the connection tunnel to the device before it (through)."""
    import asyncssh
    stored = _stored_keys(login)
    client = _client_class()(login, stored)
    try:
        conn, _ = await asyncio.wait_for(asyncssh.create_connection(
            lambda: client, login.ip, login.port, tunnel=tunnel, username=login.user or None,
            password=login.password or None, known_hosts=(stored, [], []), client_keys=None, agent_path=None,
            connect_timeout=CONNECT_TIMEOUT, keepalive_interval=15, keepalive_count_max=3,
            **_algorithms()), CONNECT_TIMEOUT * 4)
        return conn
    except Exception as e:
        raise _failure(e, target, None if login is target else login, client.changed, through) from e


async def _open(login: Login) -> list:
    """The connections to each device on the way and then to the device, nearest first."""
    conns, route = [], [*login.via, login]
    try:
        for n, hop in enumerate(route):
            conns.append(await _connect(hop, login, conns[-1] if conns else None, route[n - 1] if n else None))
    except BaseException:
        _close(conns)
        raise
    return conns


def _close(conns) -> None:
    for conn in reversed(conns):
        conn.close()


def _failure(e: Exception, login: Login, hop: Login | None = None, changed: bool = False,
             through: Login | None = None) -> SSHError:
    """The SSHError that an asyncssh or network error means for login (failing at hop, a device
    on the way to it, when given; reached through the device through)."""
    import asyncssh
    if isinstance(e, SSHError):
        return e
    who = hop or login
    where = f"{hop.ip}, on the way to {login.ip}," if hop else login.where
    if changed or isinstance(e, asyncssh.HostKeyNotVerifiable):
        return SSHError(f"The SSH key of {who.ip} changed since the last connection: it was reset or replaced, or "
                        "something is in between. If that's expected, forget its saved SSH key, then try again.",
                        "key")
    if isinstance(e, asyncssh.PermissionDenied):
        return SSHError(f"{where} didn't accept the username and password." if hop else
                        f"{login.where} didn't accept the username and password.", "auth")
    if isinstance(e, asyncssh.ChannelOpenError):  # the device before it couldn't pass the connection on
        if e.code == 1:  # SSH_OPEN_ADMINISTRATIVELY_PROHIBITED: its SSH server forwards nothing
            return SSHError(f"A device on the way to {login.ip} ({route_text(login) or 'its route'}) doesn't forward "
                            "connections (TCP forwarding is off in its SSH server).", "forwarding")
        return SSHError(f"{who.ip} port {who.port} can't be reached from {through.ip if through else 'its route'}"
                        + (f", on the way to {login.ip}" if hop else "") + f" ({e.reason or 'connecting failed'}).",
                        "unreachable")
    if isinstance(e, ConnectionRefusedError):
        return SSHError(f"Nothing accepts SSH connections on {who.ip} port {who.port}"
                        + (f", on the way to {login.ip}." if hop else "."), "refused")
    if isinstance(e, (asyncio.TimeoutError, TimeoutError, asyncssh.TimeoutError)):
        return SSHError(f"No SSH answer from {who.ip} port {who.port}"
                        + (f", on the way to {login.ip}" if hop else "") + " (timed out).", "timeout")
    if isinstance(e, OSError) and e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN):
        return SSHError(f"{who.ip} can't be reached from this phone.", "unreachable")
    if isinstance(e, asyncssh.KeyExchangeFailed):
        return SSHError(f"{who.ip} port {who.port} only offers SSH algorithms this app doesn't have: {e.reason}",
                        "algorithms")
    if isinstance(e, (asyncssh.ConnectionLost, asyncssh.DisconnectError, ConnectionResetError, BrokenPipeError)):
        reason = getattr(e, "reason", "") or str(e)
        return SSHError(f"The connection to {login.where} dropped" + (f": {reason}" if reason else "."), "other")
    return SSHError(f"SSH to {login.where} failed: {getattr(e, 'reason', '') or e or type(e).__name__}", "other")


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------

def run(login: Login, command: str, timeout: float = 60, stop: threading.Event | None = None) -> Result:
    """Run a command on the device. Raises SSHError when it couldn't connect or log in, or the
    connection dropped; otherwise the result holds the command's exit code. Through a device that
    refuses to forward, the command runs on the last hop's own SSH client."""
    if login.nested:
        return _run_nested(login, command, timeout, stop)

    async def work():
        import asyncssh
        conns = await _open(login)
        try:
            done = await conns[-1].run(command, check=False, timeout=timeout, encoding="utf-8", errors="replace")
        except asyncssh.TimeoutError:
            raise SSHError("The device stopped answering (timed out).", "timeout") from None
        except Exception as e:
            raise _failure(e, login) from e
        finally:
            _close(conns)
        code = done.exit_status if done.exit_status is not None and done.exit_status >= 0 else 255
        return Result(code, done.stdout or "", done.stderr or "")

    try:
        return _call(work, timeout + CONNECT_TIMEOUT * 4 * (len(login.via) + 1), stop)
    except SSHError as e:
        if e.kind == "forwarding" and login.via:
            login.nested = True
            return _run_nested(login, command, timeout, stop)
        raise


def _run_nested(login: Login, command: str | None, timeout: float, stop) -> Result:
    hop = last_hop(login)

    async def work():
        conns = await _open(hop)
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
            return process.exit_status, plain("".join(text))
        except asyncio.TimeoutError:
            raise SSHError("The device stopped answering (timed out).", "timeout") from None
        except SSHError:
            raise
        except Exception as e:
            raise _failure(e, login) from e
        finally:
            _close(conns)

    code, text = _call(work, timeout + CONNECT_TIMEOUT * 4 * len(login.via), stop)
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


# ---------------------------------------------------------------------------
# Copying files (SCP: Dropbear on airOS and UniFi gear has no SFTP)
# ---------------------------------------------------------------------------

def upload(login: Login, local: Path, path: str, progress=None, stop: threading.Event | None = None,
           idle: float = 120) -> None:
    """Copy a file to the device. progress(percent) as it goes."""
    _copy(login, lambda conn: (str(local), (conn, path)), progress, stop, idle)


def download(login: Login, path: str, local: Path, stop: threading.Event | None = None) -> None:
    _copy(login, lambda conn: ((conn, path), str(local)), None, stop, 120)


def _copy(login: Login, paths, progress, stop, idle: float) -> None:
    if login.nested:
        raise SSHError(f"A device on the way to {login.ip} ({route_text(login)}) doesn't forward connections, so "
                       "files can't be copied to or from it.", "forwarding")
    moved = [time.monotonic()]

    def seen(_source, _target, done: int, total: int) -> None:
        moved[0] = time.monotonic()
        if progress and total:
            progress(min(100, int(done * 100 / total)))

    async def work():
        import asyncssh
        conns = await _open(login)
        try:
            source, target = paths(conns[-1])
            copying = asyncio.ensure_future(asyncssh.scp(source, target, progress_handler=seen))
            while not copying.done():
                await asyncio.wait([copying], timeout=1)
                if not copying.done() and time.monotonic() - moved[0] > idle:
                    copying.cancel()
                    raise SSHError("The device stopped answering (timed out).", "timeout")
            copying.result()
        except asyncssh.SFTPError as e:  # what the device's scp said
            reason = str(e.reason or e)
            if "no space" in reason.lower():
                raise SSHError("The device ran out of space for the file (its memory is full). Rebooting it frees "
                               "memory; then try again.", "space") from None
            raise SSHError(f"Copying failed: {reason}") from None
        except (SSHError, asyncio.CancelledError):
            raise
        except Exception as e:
            raise _failure(e, login) from e
        finally:
            _close(conns)

    _call(work, 24 * 3600, stop)


# ---------------------------------------------------------------------------
# An interactive shell, for the Tools console
# ---------------------------------------------------------------------------

class Shell:
    """A login shell on the device in a pseudo-terminal. on_output(text) gets what it prints, with
    its terminal escapes (plain() strips them); on_closed(reason) once when it ends, reason ""
    when it was closed or exited. Both are called on phonessh's thread. Through a device that
    refuses to forward, the shell runs through the last hop's own SSH client."""

    def __init__(self, login: Login, on_output, on_closed, cols: int = 80, rows: int = 24):
        self.login, self.on_output, self.on_closed = login, on_output, on_closed
        self.size, self.process, self.conns, self.ended = (cols, rows), None, [], False
        self.task = asyncio.run_coroutine_threadsafe(self._run(), _loop())

    async def _start(self, login: Login, command: str | None):
        self.conns = await _open(login)
        return await self.conns[-1].create_process(command, term_type="xterm-256color", term_size=self.size,
                                                   encoding="utf-8", errors="replace")

    async def _run(self) -> None:
        reason, typer, started = "", None, time.monotonic()
        try:
            if self.login.nested:
                raise SSHError("forwarding", "forwarding")
            self.process = await self._start(self.login, None)
        except SSHError as e:
            if e.kind != "forwarding" or not self.login.via:
                return self._end(str(e))
            self.login.nested = True
        except Exception as e:
            return self._end(str(_failure(e, self.login)))
        try:
            if self.process is None:  # through the last hop's own client, which asks for the password
                hop = last_hop(self.login)
                self.process = await self._start(hop, nested_command(self.login, None))
                typer = _PasswordTyper({**_as_dict(hop), self.login.ip: self.login.password}, self.process.stdin.write)
            while True:
                data = await self.process.stdout.read(65536)
                if not data:
                    break
                if typer and time.monotonic() - started < 30:  # only while logging in
                    typer.feed(data)
                self.on_output(data)
        except Exception as e:
            reason = str(_failure(e, self.login))
        finally:
            _close(self.conns)
        self._end(reason)

    def _end(self, reason: str) -> None:
        if not self.ended:
            self.ended = True
            self.on_closed(reason)

    def send(self, text: str) -> None:
        """Type into the shell ("\\r" for Enter)."""
        if self.process is not None and not self.ended:
            _loop().call_soon_threadsafe(self.process.stdin.write, text)

    def resize(self, cols: int, rows: int) -> None:
        self.size = (cols, rows)
        if self.process is not None and not self.ended:
            _loop().call_soon_threadsafe(self.process.change_terminal_size, cols, rows)

    def close(self) -> None:
        def closing():
            if self.process is not None:
                self.process.close()
            _close(self.conns)

        _loop().call_soon_threadsafe(closing)

    @property
    def alive(self) -> bool:
        return not self.ended
