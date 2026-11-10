"""OpenDisco's built-in update key: what the update server (https://git.nekohosting.moe/updates/
opendisco) asks for in each request's X-Update-Key header. docs/UPDATES.md has the whole story.

- The release builds put the key in resources/update-key (never committed: .gitignore), and the
  release workflow adds it to each release as the file update-key, listed in the signed SHA256SUMS.
- The app keeps its own copy, update-key in its data folder (owner-only: 0600, in a 0700 folder
  on macOS and Linux; Windows' and Android's data folders are this user's or this app's alone).
  The copy holds the key and, on a second line, the version it came with.
- load() prefers that copy, and takes the bundled key over it when this is a different version
  from the one the copy came with (a release installed by hand brings its own key).
- After an update, the new release's update-key (checked against the signed SHA256SUMS) waits
  as update-key.pending until the new version opens, then becomes the copy (promote()). That is
  how a new key reaches every install.

The key is never logged or shown: UpdateKey's str() and repr() give only its last 4 characters,
and so does hint(). Anyone with the app can dig the key out of it; it keeps scanners and other
products' users off the update server, not a secret per customer.
"""
from __future__ import annotations

import base64
import binascii
import os
import re
import sys
from pathlib import Path

from opendisco import __version__

NAME = "update-key"
PENDING = NAME + ".pending"
RESOURCE = Path(__file__).resolve().parent / "resources" / NAME
_CHARS = re.compile(r"[A-Za-z0-9_-]+={0,2}")


def valid(text) -> bool:
    """Base64url (padded or not) for at least 32 bytes."""
    if not isinstance(text, str) or not _CHARS.fullmatch(text):
        return False
    try:
        raw = base64.urlsafe_b64decode(text.rstrip("=") + "=" * (-len(text.rstrip("=")) % 4))
    except (binascii.Error, ValueError):
        return False
    return len(raw) >= 32


class UpdateKey:
    """The key, kept out of logs: str() and repr() give only its hint."""
    __slots__ = ("_value", "origin", "version")

    def __init__(self, value: str, origin: str, version: str = ""):
        self._value, self.origin, self.version = value, origin, version

    @property
    def value(self) -> str:
        return self._value

    def hint(self) -> str:
        return "…" + self._value[-4:]

    def __repr__(self) -> str:
        return f"<update key {self.hint()} ({self.origin})>"

    __str__ = __repr__

    def __eq__(self, other) -> bool:
        return isinstance(other, UpdateKey) and other._value == self._value

    __hash__ = None


def _read(path: Path):
    """(key, version) from a key file, or None when there's none or it's not a key."""
    try:
        lines = Path(path).read_text(encoding="ascii").split("\n")
    except (OSError, UnicodeDecodeError):
        return None
    key = lines[0].strip()
    version = lines[1].strip() if len(lines) > 1 else ""
    return (key, version) if valid(key) else None


def _write(path: Path, key: str, version: str) -> None:
    """Write a key file readable by this user only, all at once: beside it, then swapped in."""
    if not valid(key):
        raise ValueError("not an update key")
    path = Path(path)
    folder = path.parent
    folder.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        try:
            folder.chmod(0o700)
        except OSError:
            pass
    tmp = path.with_name(path.name + ".tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        os.write(fd, f"{key}\n{version}\n".encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    if sys.platform != "win32":
        os.chmod(path, 0o600)


def bundled():
    """The key this build carries, or None (a copy run from source, or built without one)."""
    found = _read(RESOURCE)
    return UpdateKey(found[0], "built-in", __version__) if found else None


def load(folder):
    """The key to send: the data folder's copy, brought up to date from the bundled key first
    (see the module's docstring). None when there's neither."""
    path = Path(folder) / NAME
    stored = _read(path)
    built = bundled()
    if built and (stored is None or (stored[0] != built.value and stored[1] != __version__)):
        try:
            _write(path, built.value, __version__)
            stored = (built.value, __version__)
        except (OSError, ValueError):
            return built
    if stored:
        return UpdateKey(stored[0], "built-in", stored[1])
    return built


def stage(folder, key: str, version: str) -> None:
    """Keep a downloaded release's key until that version opens (promote())."""
    _write(Path(folder) / PENDING, key, version)


def promote(folder, version: str = __version__) -> bool:
    """This version opened after an update: the key that came with it becomes the copy.
    True when it replaced the copy."""
    pending = Path(folder) / PENDING
    found = _read(pending)
    try:
        if found and found[1] == version:
            _write(Path(folder) / NAME, found[0], version)
            return True
        return False
    finally:
        pending.unlink(missing_ok=True)


def discard(folder) -> None:
    """The update didn't take: forget the key that came with it."""
    (Path(folder) / PENDING).unlink(missing_ok=True)
