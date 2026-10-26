"""Device logins kept in the operating system's own credential store, never in a file of the app's:
the macOS Keychain (through the security tool), Windows Credential Manager (CredWrite/CredRead),
or a Secret Service keyring on Linux (through secret-tool, when it's installed). Where there's
none, available() is False and nothing is remembered.

Each device's login is filed under its MAC address. The password never goes on a command line,
where other programs could read it from the process list: the security tool gets it hex-encoded
on its standard input, secret-tool on its standard input.
"""
import re
import shutil
import subprocess
import sys

from opendisco.i18n import _

SERVICE = "com.michaelfroehlke.opendisco.device-login"
LABEL = "OpenDisco device login"
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_available = None


def store_name() -> str:
    """What the store is called, for the Remember checkbox (in the app's language)."""
    if sys.platform == "darwin":
        return _("the macOS Keychain")
    if sys.platform == "win32":
        return _("Windows Credential Manager")
    return _("the desktop keyring")  # GNOME Keyring or KWallet, through the Secret Service


def available() -> bool:
    global _available
    if _available is None:
        try:
            if sys.platform == "darwin":
                _available = bool(shutil.which("security"))
            elif sys.platform == "win32":
                import ctypes
                _available = hasattr(ctypes, "windll") and hasattr(ctypes.windll.advapi32, "CredWriteW")
            elif sys.platform.startswith("linux"):
                _available = _secret_service_answers()
            else:
                _available = False
        except Exception:
            _available = False
    return _available


def save(mac: str, user: str, password: str) -> bool:
    try:
        if sys.platform == "darwin":
            command = (f'add-generic-password -U -a "{_account(mac)}" -s "{SERVICE}" -l "{LABEL}" '
                       f'-X {password.encode("utf-8").hex()}\n')
            return _run(["security", "-i"], command).returncode == 0
        if sys.platform == "win32":
            return _win_write(mac, user, password)
        return _run(["secret-tool", "store", f"--label={LABEL} {_account(mac)}", "service", SERVICE,
                     "account", _account(mac)], password).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def load(mac: str) -> str | None:
    try:
        if sys.platform == "darwin":
            r = _run(["security", "find-generic-password", "-a", _account(mac), "-s", SERVICE, "-g"])
            if r.returncode:
                return None
            # "password: "text"" or, when it has quotes, backslashes or non-ASCII letters,
            # "password: 0x<hex>  "<escaped>"".
            line = next((l for l in r.stderr.splitlines() if l.startswith("password: ")), "")
            m = re.match(r'password: 0x([0-9A-Fa-f]*)', line)
            if m:
                return bytes.fromhex(m.group(1)).decode("utf-8", "replace")
            m = re.match(r'password: "(.*)"$', line)
            return m.group(1) if m else None
        if sys.platform == "win32":
            return _win_read(mac)
        r = _run(["secret-tool", "lookup", "service", SERVICE, "account", _account(mac)])
        return r.stdout if r.returncode == 0 and r.stdout else None
    except (OSError, subprocess.SubprocessError):
        return None


def forget(mac: str) -> bool:
    try:
        if sys.platform == "darwin":
            return _run(["security", "delete-generic-password", "-a", _account(mac), "-s", SERVICE]).returncode == 0
        if sys.platform == "win32":
            return _win_delete(mac)
        return _run(["secret-tool", "clear", "service", SERVICE, "account", _account(mac)]).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _account(mac: str) -> str:
    return mac.lower()


def _run(argv, stdin: str | None = None, timeout: float = 60):
    """Up to a minute: the store may ask to be unlocked first."""
    return subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout,
                          creationflags=_NO_WINDOW)


def _secret_service_answers() -> bool:
    """secret-tool is installed and a Secret Service runs in this session: looking up an item that
    doesn't exist fails quietly, while no D-Bus session or no keyring daemon fails with an error."""
    if not shutil.which("secret-tool"):
        return False
    try:
        r = _run(["secret-tool", "lookup", "service", SERVICE, "account", "-"], timeout=20)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode in (0, 1) and not r.stderr.strip()


# ---------------------------------------------------------------------------
# Windows Credential Manager
# ---------------------------------------------------------------------------

CRED_TYPE_GENERIC = 1
CRED_PERSIST_LOCAL_MACHINE = 2


def _win_target(mac: str) -> str:
    return f"OpenDisco/device/{_account(mac)}"


def _win_api():
    import ctypes
    from ctypes import wintypes

    class FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

    class CREDENTIALW(ctypes.Structure):
        _fields_ = [("Flags", wintypes.DWORD), ("Type", wintypes.DWORD), ("TargetName", wintypes.LPWSTR),
                    ("Comment", wintypes.LPWSTR), ("LastWritten", FILETIME),
                    ("CredentialBlobSize", wintypes.DWORD), ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
                    ("Persist", wintypes.DWORD), ("AttributeCount", wintypes.DWORD),
                    ("Attributes", ctypes.c_void_p), ("TargetAlias", wintypes.LPWSTR),
                    ("UserName", wintypes.LPWSTR)]

    api = ctypes.WinDLL("advapi32", use_last_error=True)
    api.CredWriteW.argtypes = [ctypes.POINTER(CREDENTIALW), wintypes.DWORD]
    api.CredWriteW.restype = wintypes.BOOL
    api.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                              ctypes.POINTER(ctypes.POINTER(CREDENTIALW))]
    api.CredReadW.restype = wintypes.BOOL
    api.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    api.CredDeleteW.restype = wintypes.BOOL
    api.CredFree.argtypes = [ctypes.c_void_p]
    api.CredFree.restype = None
    return ctypes, api, CREDENTIALW


def _win_write(mac: str, user: str, password: str) -> bool:
    ctypes, api, CREDENTIALW = _win_api()
    blob = password.encode("utf-16-le")
    buffer = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob) if blob else None
    cred = CREDENTIALW()
    cred.Type, cred.Persist = CRED_TYPE_GENERIC, CRED_PERSIST_LOCAL_MACHINE
    cred.TargetName, cred.UserName, cred.Comment = _win_target(mac), user, LABEL
    cred.CredentialBlobSize = len(blob)
    cred.CredentialBlob = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)) if buffer else None
    return bool(api.CredWriteW(ctypes.byref(cred), 0))


def _win_read(mac: str) -> str | None:
    ctypes, api, CREDENTIALW = _win_api()
    found = ctypes.POINTER(CREDENTIALW)()
    if not api.CredReadW(_win_target(mac), CRED_TYPE_GENERIC, 0, ctypes.byref(found)):
        return None
    try:
        cred = found.contents
        if not cred.CredentialBlobSize:
            return ""
        return ctypes.string_at(cred.CredentialBlob, cred.CredentialBlobSize).decode("utf-16-le")
    finally:
        api.CredFree(found)


def _win_delete(mac: str) -> bool:
    ctypes, api, _ = _win_api()
    return bool(api.CredDeleteW(_win_target(mac), CRED_TYPE_GENERIC, 0))
