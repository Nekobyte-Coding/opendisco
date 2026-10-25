"""OpenDisco's terms of use: the text (resources/TERMS.md; TERMS.md at the top of the repository is
the same file) and the record of each acceptance, which the app and the command line share:
terms.json in the app's data folder, the last few acceptances, each with the version, the time
(UTC), the SHA-256 of the exact text and how it was accepted. Terms whose text changes, in a new
version or not, are asked again."""
from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from pathlib import Path

from opendisco import __version__

FILE = Path(__file__).parent / "resources" / "TERMS.md"
RECORD = "terms.json"
KEPT = 10  # acceptances kept, newest last
TITLE = "OpenDisco Terms of Use"
PROMPT = ('Selecting "I agree" accepts these terms, including the sections on risk, liability, indemnity and '
          "release, and confirms that OpenDisco will be used only on networks and devices the User owns or is "
          "authorized to manage.")
IOS_NOTE = "Anyone who does not agree must close OpenDisco and delete it from this device."
AGREE, QUIT = "I agree", "Quit"
ONLINE = "https://github.com/Nekobyte-Coding/opendisco/blob/v{version}/TERMS.md"
# The command line, which never shows the app's window
CLI_INTRO = "OpenDisco's terms of use must be accepted before it's used."
CLI_WHERE = "The full terms: {path}\nOnline: {online}\nopendisco --terms prints them."
CLI_ASK = ("Accepting them confirms that OpenDisco will be used only on networks and devices the User owns or is "
           "authorized to manage.\nType I agree to accept them, or anything else to quit: ")
CLI_REFUSED = "Terms not accepted. OpenDisco can't be used without accepting them."
CLI_UNATTENDED = ("OpenDisco's terms of use haven't been accepted. Run opendisco in a terminal to read and accept "
                  "them, or read them with opendisco --terms and then pass --accept-terms.")
# Said in each device tool's confirmation (A2 of the terms' review). TESTED stays while it's true,
# saying the same as TERMS.md section 5 and the README's Limitations: change all three together.
RISKS = {
    "firmware": "If the update fails or is interrupted, the device can stop working, and getting it back may need "
                "someone on site.",
    "save": "A wrong config takes effect at the next reboot and can cut the device off; getting it back may need "
            "someone on site.",
    "apply": "A wrong config takes effect now and can cut the device off; getting it back may need someone on site.",
    "upload": "Check every line before saving or applying: the file replaces the device's whole config, its radio "
              "settings, address and logins included.",
    "login": "If the new login is lost, the device can only be reached again after a reset, which may need someone "
             "on site.",
    "reboot": "The device can fail to come back after restarting, and getting it back may need someone on site.",
}
TESTED = "OpenDisco's device tools have been tested only on simulated devices, not yet on real equipment."


def risk(kind: str) -> str:
    """The lines a device tool's confirmation ends with."""
    return f"{RISKS[kind]} {TESTED}"


def text() -> str:
    """TERMS.md as published, for this version: what's accepted, and hashed."""
    return FILE.read_text(encoding="utf-8").replace("{version}", __version__)


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


def record(folder, via: str, platform: str, channel: str = "github") -> dict:
    """Keep an acceptance. via: "app" or "cli"; channel: where this copy came from."""
    entry = {"version": __version__, "sha256": digest(),
             "agreed": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             "via": via, "platform": platform, "channel": channel}
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / RECORD).write_text(json.dumps({"accepted": (accepted(folder) + [entry])[-KEPT:]}, indent=1),
                                 encoding="utf-8")
    return entry


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


def cli_gate(folder, accept: bool) -> bool:
    """The command line: go ahead once these terms are accepted, here or in the app. Asked in a
    terminal ("I agree" typed); otherwise --accept-terms accepts them. Says why it stops."""
    if agreed(folder):
        return True
    if not accept:
        if not sys.stdin.isatty():
            print(CLI_UNATTENDED, file=sys.stderr)
            return False
        print(f"{CLI_INTRO}\n\n{summary()}\n\n"
              + CLI_WHERE.format(path=FILE, online=ONLINE.format(version=__version__)) + "\n", file=sys.stderr)
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
