"""SSH on the phones, in the app itself (asyncssh): iOS and Android run no ssh program.

The calls devicetools makes of sshrun (the desktop's, through the system's ssh) are here under the
same names: Login, Result, SSHError, run, upload, download and check_login, so firmware checks and
Scan from device work the same. Shell is the interactive session in the phone's Tools.

Connections run on one asyncio loop in a thread of their own; the calls block until they're done,
for worker threads, the way sshrun's do. A device found through others (Login.via) is reached
through SSH tunnels from one to the next.

Host keys: the first key a device shows is kept in the app's known_hosts under its MAC
(host_key_alias), as the desktop's ssh does with accept-new; a different one later is refused
(SSHError kind "key") until Forget SSH key. Old gear (airOS, EdgeOS) may offer only SHA-1 key
exchange and ssh-rsa host keys: those are allowed after the modern ones.
"""
import asyncio
import concurrent.futures
import errno
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path

try:
    import asyncssh
except ImportError:  # the desktop: sshrun instead
    asyncssh = None

# asyncssh asks getpass for this device's own user name, which a phone app doesn't have.
os.environ.setdefault("LOGNAME", "opendisco")

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|\x1b[=>]")
CONNECT_TIMEOUT = 15


class SSHError(Exception):
    """kind: "key" (host key changed), "auth", "refused", "timeout", "unreachable",
    "algorithms", "forwarding", "cancelled" or "other" (sshrun's kinds)."""

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
    nested: bool = False  # sshrun's; never set here

    @property
    def where(self) -> str:
        return f"{self.ip} port {self.port}" + (f" (via {route_text(self)})" if self.via else "")


@dataclass
class Result:
    code: int
    out: str
    err: str


def route_text(login: Login) -> str:
    return " → ".join(hop.ip for hop in login.via)


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


def _failure(e: BaseException, login: Login, hop: Login | None = None) -> SSHError:
    """The SSHError that an exception from asyncssh or the network means, worded as sshrun's."""
    who = hop or login
    where = who.where if hop is None else f"{hop.ip}, on the way to {login.ip},"
    if isinstance(e, SSHError):
        return e
    if isinstance(e, asyncssh.PermissionDenied):
        return SSHError(f"{where} didn't accept the username and password.", "auth")
    if isinstance(e, asyncssh.ChannelOpenError):
        return SSHError(f"A device on the way to {login.ip} ({route_text(login) or 'its route'}) doesn't forward "
                        "connections (TCP forwarding is off in its SSH server).", "forwarding")
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


def _check_host_key(login: Login, key) -> None:
    """Trust a device's first key; refuse a different one later."""
    shown = key.export_public_key("openssh").decode().split()
    kind, data = shown[0], shown[1]
    path = Path(login.known_hosts)
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines() if path.exists() else []
    kept = [l.split() for l in lines if l.split() and l.split()[0] == login.alias]
    if any(k[1:3] == [kind, data] for k in kept if len(k) >= 3):
        return
    if any(len(k) >= 3 and k[1] == kind for k in kept):
        raise SSHError(f"The SSH key of {login.ip} changed since the last connection: it was reset or replaced, "
                       "or something is in between. If that's expected, use Forget SSH key, then try again.", "key")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(f"{login.alias} {kind} {data}\n")


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


async def _open(login: Login, tunnel=None, hop_of: Login | None = None):
    try:
        conn = await asyncio.wait_for(asyncssh.connect(
            login.ip, login.port, tunnel=tunnel, username=login.user, password=login.password,
            config=[], known_hosts=None, client_keys=None, agent_path=None,
            preferred_auth=("password", "keyboard-interactive"), keepalive_interval=15, **_options()),
            CONNECT_TIMEOUT)
    except Exception as e:
        raise _failure(e, hop_of or login, login if hop_of else None) from None
    try:
        _check_host_key(login, conn.get_server_host_key())
    except SSHError:
        conn.close()
        raise
    return conn


async def _connect(login: Login) -> list:
    """The connections to each device on the way, then to the device itself (last)."""
    conns = []
    try:
        for hop in login.via:
            conns.append(await _open(hop, conns[-1] if conns else None, hop_of=login))
        conns.append(await _open(login, conns[-1] if conns else None))
    except BaseException:
        _close(conns)
        raise
    return conns


def _close(conns) -> None:
    for conn in reversed(conns):
        conn.close()


# -- what devicetools calls ------------------------------------------------------------
def run(login: Login, command: str, timeout: float = 60, stop: threading.Event | None = None) -> Result:
    """Run a command on the device. Raises SSHError when it couldn't connect or log in;
    otherwise the result has the command's exit code (255: the connection dropped)."""
    async def go():
        conns = await _connect(login)
        try:
            done = await asyncio.wait_for(conns[-1].run(command, check=False), timeout)
        except (asyncio.TimeoutError, TimeoutError):
            return Result(255, "", f"{command}: no answer within {timeout:.0f}s")
        except asyncssh.Error as e:
            return Result(255, "", str(e))
        finally:
            _close(conns)
        code = done.exit_status if done.exit_status is not None else 255
        return Result(code, _text(done.stdout), _text(done.stderr))
    return _call(go(), stop)


def check_login(login: Login, stop: threading.Event | None = None) -> None:
    """Log in and out again: raises SSHError if that doesn't work."""
    result = run(login, "true", timeout=40, stop=stop)
    if result.code:
        raise SSHError(f"Logging in to {login.where} worked, but the device didn't run a command (exit code "
                       f"{result.code}).")


def upload(login: Login, local: Path, path: str, progress=None, stop: threading.Event | None = None,
           idle: float = 120) -> None:
    """Copy a file to the device (scp: Dropbear on airOS has no SFTP). progress(percent)."""
    def shown(_src, _dst, copied, total):
        if progress and total:
            progress(int(copied * 100 / total))

    async def go():
        conns = await _connect(login)
        try:
            await asyncssh.scp(str(local), (conns[-1], path), progress_handler=shown)
        except (asyncssh.Error, OSError) as e:
            raise _copy_failure(e, login) from None
        finally:
            _close(conns)
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
    _call(go(), stop)


def _copy_failure(e, login: Login) -> SSHError:
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
    is up (call it from a worker thread); raises SSHError."""

    def __init__(self, login: Login, on_output, on_end, columns: int = 60):
        self.login, self.on_output, self.on_end = login, on_output, on_end
        self._conns, self._process = _call(self._start(columns))
        self._reader = asyncio.run_coroutine_threadsafe(self._read(), _ssh_loop())

    async def _start(self, columns: int):
        conns = await _connect(self.login)
        try:
            process = await conns[-1].create_process(term_type="dumb", term_size=(columns, 40), encoding="utf-8",
                                                     errors="replace")
        except Exception as e:
            _close(conns)
            raise _failure(e, self.login) from None
        return conns, process

    async def _read(self):
        reason = ""
        try:
            while True:
                data = await self._process.stdout.read(4096)
                if not data:
                    break
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

    def close(self) -> None:
        _ssh_loop().call_soon_threadsafe(_close, self._conns)
