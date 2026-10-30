"""OpenDisco's terms of use: the text (resources/TERMS.md; TERMS.md at the top of the repository is
the same file) and the record of each acceptance, which the app and the command line share:
terms.json in the app's data folder, the last few acceptances, each with the version, the time
(UTC), the SHA-256 of the exact text and how it was accepted. Terms whose text changes, in a new
version or not, are asked again. The app shows them in its language where there's a translation
(TERMS.es.md, TERMS.pt-BR.md, TERMS.ja.md beside TERMS.md, which binds and controls), with the
English text a switch away; what's accepted and hashed is always the English text."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import sys
import time
from pathlib import Path

from opendisco import __version__, i18n
from opendisco.i18n import N_, _

FILE = Path(__file__).parent / "resources" / "TERMS.md"
RECORD = "terms.json"
KEPT = 10  # acceptances kept, newest last
# The app's window (translated where it's shown)
TITLE = N_("OpenDisco Terms of Use")
PROMPT = N_('Selecting "I agree" accepts these terms, including the sections on risk, liability, indemnity and '
            "release, and confirms that OpenDisco will be used only on networks and devices the User owns or is "
            "authorized to manage.")
IOS_NOTE = N_("Anyone who does not agree must close OpenDisco and delete it from this device.")
AGREE, QUIT = N_("I agree"), N_("Quit")
ORIGINAL = N_("Show the English original")
ONLINE = "https://github.com/Nekobyte-Coding/opendisco/blob/v{version}/TERMS.md"
# The command line, which never shows the app's window
CLI_INTRO = "OpenDisco's terms of use must be accepted before it's used."
CLI_WHERE = "The full terms: {path}\nOnline: {online}\n{command} --terms prints them."
CLI_ASK = ("Accepting them confirms that OpenDisco will be used only on networks and devices the User owns or is "
           "authorized to manage.\nType I agree to accept them, or anything else to quit: ")
CLI_REFUSED = "Terms not accepted. OpenDisco can't be used without accepting them."
CLI_UNATTENDED = ("OpenDisco's terms of use haven't been accepted. Run {command} in a terminal to read and accept "
                  "them, or read them with {command} --terms and then pass --accept-terms.")
# The Mac app's command line writes to the system log, never a terminal: the app asks instead.
CLI_UNATTENDED_MACOS = ("OpenDisco's terms of use haven't been accepted. Open the OpenDisco app to read and accept "
                        "them, or read them at {online} and then pass --accept-terms.")
# Said in each device tool's confirmation (A2 of the terms' review). TESTED stays while it's true,
# saying the same as TERMS.md section 5 and the README's Limitations: change all three together.
RISKS = {
    "firmware": N_("If the update fails or is interrupted, the device can stop working, and getting it back may "
                   "need someone on site."),
    "save": N_("A wrong config takes effect at the next reboot and can cut the device off; getting it back may need "
               "someone on site."),
    "apply": N_("A wrong config takes effect now and can cut the device off; getting it back may need someone on "
                "site."),
    "upload": N_("Check every line before saving or applying: the file replaces the device's whole config, its radio "
                 "settings, address and logins included."),
    "login": N_("If the new login is lost, the device can only be reached again after a reset, which may need "
                "someone on site."),
    "reboot": N_("The device can fail to come back after restarting, and getting it back may need someone on site."),
}
TESTED = N_("OpenDisco's device tools have been tested only on simulated devices, not yet on real equipment.")


def risk(kind: str) -> str:
    """The lines a device tool's confirmation ends with, in the app's language."""
    return i18n.sentences(_(RISKS[kind]), _(TESTED))


def text() -> str:
    """TERMS.md as published, for this version: what's accepted, and hashed."""
    return FILE.read_text(encoding="utf-8").replace("{version}", __version__)


def translation(language: str | None = None) -> str | None:
    """The terms in a language other than English (the app's by default), as published for this
    version: None for English, or where there's no translation."""
    language = i18n.language if language is None else language
    path = FILE.with_name(f"TERMS.{language}.md")
    if language == i18n.ENGLISH or not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8").replace("{version}", __version__)
    except OSError:
        return None


def shown(raw: str | None = None) -> str:
    """As the app's window shows it: without its title (the window has it) and its headings' #."""
    raw = text() if raw is None else raw
    raw = re.sub(r"\A#[^\n]*\n+", "", raw)
    return re.sub(r"^#+\s*", "", raw, flags=re.MULTILINE)


def digest(raw: str | None = None) -> str:
    """The SHA-256 of the text accepted, as published in each release's notes."""
    return hashlib.sha256((text() if raw is None else raw).encode("utf-8")).hexdigest()


def accepted(folder) -> list:
    """The acceptances kept in this data folder, oldest first."""
    try:
        records = json.loads((Path(folder) / RECORD).read_text(encoding="utf-8")).get("accepted", [])
        return [r for r in records if isinstance(r, dict)]
    except (OSError, ValueError, AttributeError):
        return []


def agreed(folder) -> bool:
    """Whether these exact terms (this version, this text) were accepted."""
    wanted = (__version__, digest())
    return any((r.get("version"), r.get("sha256")) == wanted for r in accepted(folder))


def record(folder, via: str, platform: str, channel: str = "github", language: str = i18n.ENGLISH) -> dict:
    """Keep an acceptance. via: "app" or "cli"; channel: where this copy came from; language: the
    text on screen when it was accepted (a translation's own SHA-256 is kept beside the English one's)."""
    entry = {"version": __version__, "sha256": digest(),
             "agreed": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             "via": via, "platform": platform, "channel": channel}
    translated = translation(language)
    if translated is not None:
        entry.update(language=language, translation_sha256=digest(translated))
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    tmp = folder / (RECORD + ".tmp")  # written beside it, then swapped in: a crash can't leave it half there
    tmp.write_text(json.dumps({"accepted": (accepted(folder) + [entry])[-KEPT:]}, indent=1), encoding="utf-8")
    os.replace(tmp, folder / RECORD)
    return entry


def private(folder) -> None:
    """The data folder (config backups with password hashes and secrets, remembered device lists,
    notes) readable by this account only, whether the app or the command line made it. Windows'
    is per-user already."""
    if sys.platform == "win32":
        return
    try:
        folder = Path(folder)
        folder.mkdir(parents=True, exist_ok=True)
        folder.chmod(0o700)
    except OSError:
        pass


def licenses() -> str:
    """OpenDisco's own notice and the bundled components' licenses (THIRD-PARTY-NOTICES.md)."""
    try:
        return shown((FILE.parent / "THIRD-PARTY-NOTICES.md").read_text(encoding="utf-8"))
    except OSError as e:
        return f"The notices file is missing from this copy: {e}"


def summary(raw: str | None = None) -> str:
    """The Summary section of TERMS.md, read from the file so it can't drift."""
    found = re.search(r"^#+\s*Summary\s*\n(.*?)(?=^#)", text() if raw is None else raw, re.MULTILINE | re.DOTALL)
    return found.group(1).strip() if found else ""


def command() -> str:
    """What runs this copy's command line, for the messages that name it: the AppImage file itself,
    the portable version's launcher, the app's own program on macOS and Windows, opendisco from the
    .deb and .rpm, or the way a checkout was started (opendisco.py or python3 -m opendisco)."""
    from opendisco import update  # (update imports core, which imports this)
    kind, target = update.installed_as()
    path = {"appimage": target, "tarball": target and target / "opendisco",
            "macos": target and target / "Contents" / "MacOS" / "OpenDisco",
            "windows": target and target / "opendisco.cmd"}.get(kind)
    if path and sys.platform == "win32":
        return f'"{path}"' if " " in str(path) else str(path)
    if path:
        return shlex.quote(str(path))
    if kind in ("deb", "rpm"):
        return "opendisco"
    python = "python" if sys.platform == "win32" else "python3"
    if os.path.basename(sys.argv[0]) == "opendisco.py":
        return sys.argv[0] if os.sep in sys.argv[0] or "/" in sys.argv[0] else f"{python} {sys.argv[0]}"
    return f"{python} -m opendisco"


def _typed() -> bool:
    """Whether stdin is a terminal someone can type the answer in. Windows counts NUL as one (a
    script's `< NUL`), so there it must also be a console."""
    try:
        if not sys.stdin.isatty():
            return False
        if sys.platform == "win32":
            import ctypes
            import msvcrt
            mode = ctypes.c_ulong()
            handle = msvcrt.get_osfhandle(sys.stdin.fileno())
            return bool(ctypes.windll.kernel32.GetConsoleMode(ctypes.c_void_p(handle), ctypes.byref(mode)))
    except (AttributeError, OSError, ValueError):
        return False
    return True


def cli_gate(folder, accept: bool) -> bool:
    """The command line: go ahead once these terms are accepted, here or in the app. Asked in a
    terminal ("I agree" typed); otherwise --accept-terms accepts them. Says why it stops."""
    if agreed(folder):
        return True
    if not accept:
        online = ONLINE.format(version=__version__)
        if not (_typed() and sys.stderr.isatty()):  # (the Mac app's output goes to the system log)
            from opendisco import update
            said = CLI_UNATTENDED_MACOS if update.installed_as()[0] == "macos" else CLI_UNATTENDED
            print(said.format(command=command(), online=online), file=sys.stderr)
            return False
        print(f"{CLI_INTRO}\n\n{summary()}\n\n"
              + CLI_WHERE.format(path=FILE, online=online, command=command()) + "\n", file=sys.stderr)
        try:
            print(CLI_ASK, end="", file=sys.stderr, flush=True)
            answer = input()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer.strip().lower() != AGREE.lower():
            print(CLI_REFUSED, file=sys.stderr)
            return False
    try:
        record(folder, "cli", sys.platform)
    except OSError as e:  # accepted all the same; asked again next time
        print(f"The acceptance couldn't be saved in {folder}: {e}", file=sys.stderr)
    return True
