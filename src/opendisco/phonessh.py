"""Commands, file copies and shells on one device for the phones' device tools, through asyncssh.

A phone has no ssh program to run, so this gives devicetools and the phone screens what sshrun
gives them on a computer, from Python: the same Login, Result and SSHError and the same calls.
asyncssh (and the cryptography package it stands on) is part of the iOS and Android apps, and
imported only when a call needs it. The Linux AppImage and the portable version bring it too, for
a computer without ssh and scp: there devicetools uses this in place of sshrun, and the Terminal
tab's SSH sessions run on Shell (terminal.OwnSession).

Host keys are trusted on first use and filed under each device's alias (terminal.host_key_alias:
its MAC) in the app's known_hosts, as the desktop's ssh does, whose hashed lines are read too; a
changed one is refused. A device
behind others is reached through their forwarding, each with its own login and host key, or,
when one refuses to forward, through the last one's own SSH client (Dropbear's dbclient). Old
firmware's key exchanges, host keys and ciphers are allowed after the strong ones.

Every call blocks, like sshrun's: call them from a worker thread. They run on an asyncio loop of
their own, on a thread of their own, never on the UI's. Every failure is an SSHError whose text
says what went wrong in terms of the device.
"""
from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import errno
import hashlib
import hmac
import os
import re
import threading
import time
from pathlib import Path

from opendisco import core
from opendisco.i18n import _, tr
from opendisco.sshcommon import (ANSI, CLIENT_NOISE, Login, Result, SSHError, last_hop, nested_command,
                                 nested_failure, route_text)  # (shared with sshrun)

PASSWORD_PROMPT = re.compile(r"(?i)pass(word|code)[^\r\n]{0,60}:\s*$")
# Allowed after asyncssh's own choices, for airOS 5/6, old EdgeOS and other old firmware.
LEGACY = {"kex_algs": ["diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1",
                       "diffie-hellman-group1-sha1"],
          "server_host_key_algs": ["ssh-rsa", "ssh-dss"],
          "encryption_algs": ["aes128-cbc", "aes256-cbc", "3des-cbc"],
          "mac_algs": ["hmac-sha1", "hmac-md5"]}
CONNECT_TIMEOUT = 10
HERE = "this phone" if core.platform_name() in ("ios", "android") else "this computer"
# asyncssh asks getpass for this device's own user name before every connection, and an iOS
# app has none (getpass raises): every login failed with "Unknown local username" there.
os.environ.setdefault("LOGNAME", "opendisco")


def available() -> bool:
    """asyncssh is here to use (the phone apps bring it)."""
    import importlib.util
    return importlib.util.find_spec("asyncssh") is not None


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
    mac = (mac or "").lower()
    valid = re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac)  # (anything else could be a known_hosts pattern)
    return "ubnt-" + mac.replace(":", "") if valid else ip


def _names(line: str) -> list:
    return line.split()[0].split(",") if line.strip() and not line.startswith(("#", "@")) else []


def _hashed(name: str, alias: str) -> bool:
    """Whether a hashed known_hosts name (|1|salt|HMAC-SHA1 of the name) is alias's: OpenSSH
    writes them where HashKnownHosts is on, as Debian's and Ubuntu's ssh_config have it."""
    try:
        salt, digest = (base64.b64decode(part) for part in name[3:].split("|", 1))
    except ValueError:
        return False
    return hmac.compare_digest(hmac.new(salt, alias.encode("utf-8"), hashlib.sha1).digest(), digest)


def _is_for(line: str, alias: str) -> bool:
    return any(n == alias or n.startswith(f"[{alias}]:") or (n.startswith("|1|") and _hashed(n, alias))
               for n in _names(line))


def _stored_keys(login: Login) -> list:
    import asyncssh
    try:
        lines = login.known_hosts.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    keys = []
    for line in lines:
        if _is_for(line, login.alias):
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
    kept = [line for line in lines if not _is_for(line, alias)]
    if len(kept) == len(lines):
        return False
    known_hosts.write_text("".join(kept), encoding="utf-8")
    return True


def _client_class():
    import asyncssh

    class Client(asyncssh.SSHClient):
        """Trusts a device's first host key and files it; refuses one that differs from what's on file.
        With ask, a password the login has none for, or one it didn't take, is asked for (up to 3)."""

        def __init__(self, login: Login, stored: list, ask=None):
            self.login, self.stored, self.changed = login, stored, False
            self.ask, self.asked = ask, 0

        def password_auth_requested(self):
            if self.ask is None or self.asked >= 3:
                return None
            self.asked += 1
            who = f"{self.login.user}@{self.login.ip}" if self.login.user else self.login.ip
            return self.ask(f"{who}'s password: ")

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
                raise SSHError(_("Cancelled."), "cancelled") from None
            if time.monotonic() > deadline:
                future.cancel()
                raise SSHError(_("The device stopped answering (timed out)."), "timeout") from None
        except concurrent.futures.CancelledError:
            raise SSHError(_("Cancelled."), "cancelled") from None


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

async def _connect(login: Login, target: Login, tunnel=None, through: Login | None = None, ask=None,
                   keys: bool = False):
    """One SSH connection: to login, which is target itself or a device on the way to it,
    through the connection tunnel to the device before it (through). ask(prompt): a coroutine
    giving a password typed by hand. keys: also this account's SSH keys and agent, as ssh would."""
    import asyncssh
    stored = _stored_keys(login)
    client = _client_class()(login, stored, ask)
    try:
        conn, _ = await asyncio.wait_for(asyncssh.create_connection(
            lambda: client, login.ip, login.port, tunnel=tunnel, username=login.user or None,
            password=login.password or None, known_hosts=(stored, [], []),
            client_keys=() if keys else None, agent_path=() if keys else None,
            connect_timeout=CONNECT_TIMEOUT, keepalive_interval=15, keepalive_count_max=3,
            **_algorithms()), CONNECT_TIMEOUT * 4 + (120 if ask else 0))  # (time to type it)
        return conn
    except Exception as e:
        raise _failure(e, target, None if login is target else login, client.changed, through) from e


async def _open(login: Login, ask=None, keys: bool = False) -> list:
    """The connections to each device on the way and then to the device, nearest first; ask is
    for the device's own password (_connect)."""
    conns, route = [], [*login.via, login]
    try:
        for n, hop in enumerate(route):
            conns.append(await _connect(hop, login, conns[-1] if conns else None, route[n - 1] if n else None,
                                        ask if hop is login else None, keys))
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
    if changed or isinstance(e, asyncssh.HostKeyNotVerifiable):
        return SSHError(tr("The SSH key of {ip} changed since the last connection: it was reset or replaced, or "
                           "something is in between. If that's expected, forget its saved SSH key, then try again.",
                           ip=who.ip), "key")
    if isinstance(e, asyncssh.PermissionDenied):
        return SSHError(tr("{hop}, on the way to {ip}, didn't accept the username and password.", hop=hop.ip,
                           ip=login.ip) if hop else
                        tr("{device} didn't accept the username and password.", device=login.where), "auth")
    if isinstance(e, asyncssh.ChannelOpenError):  # the device before it couldn't pass the connection on
        if e.code == 1:  # SSH_OPEN_ADMINISTRATIVELY_PROHIBITED: its SSH server forwards nothing
            return SSHError(tr("A device on the way to {ip} ({route}) doesn't forward connections (TCP forwarding is "
                               "off in its SSH server).", ip=login.ip, route=route_text(login) or _("its route")),
                            "forwarding")
        source, reason = through.ip if through else _("its route"), e.reason or _("connecting failed")
        return SSHError(tr("{ip} port {port} can't be reached from {source}, on the way to {target} ({reason}).",
                           ip=who.ip, port=who.port, source=source, target=login.ip, reason=reason) if hop else
                        tr("{ip} port {port} can't be reached from {source} ({reason}).", ip=who.ip, port=who.port,
                           source=source, reason=reason), "unreachable")
    if isinstance(e, ConnectionRefusedError):
        return SSHError(tr("Nothing accepts SSH connections on {ip} port {port}, on the way to {target}.", ip=who.ip,
                           port=who.port, target=login.ip) if hop else
                        tr("Nothing accepts SSH connections on {ip} port {port}.", ip=who.ip, port=who.port), "refused")
    if isinstance(e, (asyncio.TimeoutError, TimeoutError, asyncssh.TimeoutError)):
        return SSHError(tr("No SSH answer from {ip} port {port}, on the way to {target} (timed out).", ip=who.ip,
                           port=who.port, target=login.ip) if hop else
                        tr("No SSH answer from {ip} port {port} (timed out).", ip=who.ip, port=who.port), "timeout")
    if isinstance(e, OSError) and e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN):
        return SSHError(tr("{ip} can't be reached from this phone.", ip=who.ip) if HERE == "this phone" else
                        tr("{ip} can't be reached from this computer.", ip=who.ip), "unreachable")
    if isinstance(e, asyncssh.KeyExchangeFailed):
        return SSHError(tr("{ip} port {port} only offers SSH algorithms this app doesn't have: {reason}", ip=who.ip,
                           port=who.port, reason=e.reason), "algorithms")
    if isinstance(e, (asyncssh.ConnectionLost, asyncssh.DisconnectError, ConnectionResetError, BrokenPipeError)):
        reason = getattr(e, "reason", "") or str(e)
        return SSHError(tr("The connection to {device} dropped: {said}", device=login.where, said=reason) if reason
                        else tr("The connection to {device} dropped.", device=login.where), "other")
    return SSHError(tr("SSH to {device} failed: {said}", device=login.where,
                       said=getattr(e, 'reason', '') or e or type(e).__name__), "other")


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
            raise SSHError(_("The device stopped answering (timed out)."), "timeout") from None
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
            typer = _PasswordTyper(login, process.stdin.write)
            text = []
            while True:
                data = await asyncio.wait_for(process.stdout.read(65536), timeout)
                if not data:
                    break
                text.append(data)
                typer.feed(data)
                if typer.unanswered:
                    raise SSHError(tr("{device} didn't accept the username and password.", device=login.where),
                                   "auth")
            await process.wait_closed()
            return process.exit_status, plain("".join(text))
        except asyncio.TimeoutError:
            raise SSHError(_("The device stopped answering (timed out)."), "timeout") from None
        except SSHError:
            raise
        except Exception as e:
            raise _failure(e, login) from e
        finally:
            _close(conns)

    code, text = _call(work, timeout + CONNECT_TIMEOUT * 4 * len(login.via), stop)
    code = code if code is not None and code >= 0 else 255
    failure = nested_failure(text, login)
    if failure:  # (it's about reaching the device, not what the command printed)
        raise failure
    lines = [line for line in text.split("\n")
             if not PASSWORD_PROMPT.search(line + " ") and not CLIENT_NOISE.match(line)]
    return Result(code, "\n".join(lines).strip("\n") + "\n", text)


class _PasswordTyper:
    """Types the device's password when the last hop's own SSH client asks for it ("ubnt@10.0.0.5's
    password:"), at most twice. Only that prompt: the hops log in through asyncssh, so a prompt
    naming anything else (or nothing) comes from the device itself and gets no password."""
    ASKER = re.compile(r"([^\s@']+)@([^\s@']+)'s password")

    def __init__(self, login: Login, write):
        self.ip, self.password, self.write = login.ip, login.password, write
        self.tail, self.typed, self.unanswered = "", 0, False

    def feed(self, data: str) -> None:
        self.tail = (self.tail + data)[-400:]
        if not PASSWORD_PROMPT.search(self.tail):
            return
        asker = self.ASKER.findall(self.tail)
        who = asker[-1][1] if asker else None
        self.tail = ""
        if who == self.ip and self.password and self.typed < 2:
            self.typed += 1
            self.write(self.password + "\r")
        else:
            self.unanswered = True


def check_login(login: Login, stop: threading.Event | None = None) -> None:
    """Log in and out again: raises SSHError if that doesn't work."""
    result = run(login, "true", timeout=40, stop=stop)
    if result.code:
        raise nested_failure(result.err, login) or SSHError(
            tr("Logging in to {device} worked, but the device didn't run a command (exit code {code}).",
               device=login.where, code=result.code))


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
        raise SSHError(tr("A device on the way to {ip} ({route}) doesn't forward connections, so files can't be "
                          "copied to or from it.", ip=login.ip, route=route_text(login)), "forwarding")
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
                    raise SSHError(_("The device stopped answering (timed out)."), "timeout")
            copying.result()
        except asyncssh.SFTPError as e:  # what the device's scp said
            reason = str(e.reason or e)
            if "no space" in reason.lower():
                raise SSHError(_("The device ran out of space for the file (its memory is full). Rebooting it frees "
                                 "memory; then try again."), "space") from None
            raise SSHError(tr("Copying failed: {reason}", reason=reason)) from None
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
    """A login shell on the device in a pseudo-terminal, or command in one (ping). on_output(text)
    gets what it prints, with its terminal escapes (plain() strips them); on_closed(reason) once
    when it ends, reason "" when it was closed or exited, and error the SSHError it ended with.
    Both are called on phonessh's thread. Through a device that refuses to forward, it runs
    through the last hop's own SSH client. ask and keys, for the desktop's Terminal tab: as
    _connect's."""

    def __init__(self, login: Login, on_output, on_closed, cols: int = 80, rows: int = 24,
                 command: str | None = None, ask=None, keys: bool = False):
        self.login, self.on_output, self.on_closed = login, on_output, on_closed
        self.command, self.ask, self.keys, self.error = command, ask, keys, None
        self.size, self.process, self.conns, self.ended = (cols, rows), None, [], False
        self.task = asyncio.run_coroutine_threadsafe(self._run(), _loop())

    async def _start(self, login: Login, command: str | None, ask=None):
        self.conns = await _open(login, ask, self.keys)
        return await self.conns[-1].create_process(command, term_type="xterm-256color", term_size=self.size,
                                                   encoding="utf-8", errors="replace")

    async def _run(self) -> None:
        reason, typer, started = "", None, time.monotonic()
        try:
            if self.login.nested:
                raise SSHError("forwarding", "forwarding")
            self.process = await self._start(self.login, self.command, self.ask)
        except SSHError as e:
            if e.kind != "forwarding" or not self.login.via:
                return self._end(str(e), e)
            self.login.nested = True
        except Exception as e:
            failure = _failure(e, self.login)
            return self._end(str(failure), failure)
        try:
            if self.process is None:  # through the last hop's own client, which asks for the password
                hop = last_hop(self.login)
                self.process = await self._start(hop, nested_command(self.login, self.command))
                typer = _PasswordTyper(self.login, self.process.stdin.write)
            while True:
                data = await self.process.stdout.read(65536)
                if not data:
                    break
                if typer and time.monotonic() - started < 30:  # only while logging in
                    typer.feed(data)
                self.on_output(data)
        except Exception as e:
            self.error = _failure(e, self.login)
            reason = str(self.error)
        finally:
            _close(self.conns)
        self._end(reason)

    def _end(self, reason: str, error: SSHError | None = None) -> None:
        if not self.ended:
            self.ended, self.error = True, error or self.error
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


class Forward(Shell):
    """127.0.0.1:local on this computer forwarded through the device to host:port, until it's
    closed: the desktop's web UI of a device behind others (ssh -L). on_output and on_closed as
    Shell's; nothing is typed into it."""

    def __init__(self, login: Login, local: int, host: str, port: int, on_output, on_closed, keys: bool = False):
        self.target = (local, host, port)
        super().__init__(login, on_output, on_closed, keys=keys)

    async def _run(self) -> None:
        local, host, port = self.target
        try:
            self.conns = await _open(self.login, None, self.keys)
            await self.conns[-1].forward_local_port("127.0.0.1", local, host, port)
        except Exception as e:
            _close(self.conns)
            failure = _failure(e, self.login)
            return self._end(str(failure), failure)
        self.on_output(tr("Forwarding 127.0.0.1:{local} to {host}:{port} through {device}: close this session to "
                          "stop.", local=local, host=host, port=port, device=self.login.ip) + "\r\n")
        await self.conns[-1].wait_closed()
        self._end("")
