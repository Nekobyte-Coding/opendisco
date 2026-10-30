"""What the app's two SSH clients share: sshrun (the system's ssh and scp) and phonessh (asyncssh,
on phones and on a computer without ssh). devicetools uses either one with the same calls, so the
login, the result, the error and a route's commands are one set of objects for both."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from opendisco.i18n import tr

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|\x1b[=>]")
# What a hop's own SSH client says about the connection, not the command's output: "Host '…' key
# accepted unconditionally." and the fingerprint under it (Dropbear), "Warning: Permanently added…"
CLIENT_NOISE = re.compile(r"dbclient:\s*$|(dbclient: )?Host '|\(\S+ fingerprint |Warning: Permanently added"
                          r"|Connection to ")
# The lines in which a hop's own client (Dropbear's dbclient, or ssh) speaks of reaching the device
CLIENT_SAYS = re.compile(r"(?i)^(?:dbclient|ssh)\b|exited:|permission denied \(|host key|remote host identification")


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
    alias: str  # the name its host key is filed under (terminal.host_key_alias)
    known_hosts: Path
    via: tuple = ()  # the logins of the devices on the way to it, the nearest to this computer first
    nested: bool = False  # a device on the way refused to forward: run commands on the last hop instead

    @property
    def where(self) -> str:
        if self.via:
            return tr("{ip} port {port} (via {route})", ip=self.ip, port=self.port, route=route_text(self))
        return tr("{ip} port {port}", ip=self.ip, port=self.port)

    @property
    def passwords(self):
        """The password to type, or one per device on the way, by the name its prompt shows: its
        host key alias for ssh, its address for a hop's own client."""
        if not self.via:
            return self.password
        return {**{hop.alias: hop.password for hop in self.via}, self.alias: self.password, self.ip: self.password}


def route_text(login: Login) -> str:
    return " → ".join(hop.ip for hop in login.via)


@dataclass
class Result:
    code: int
    out: str  # what the command printed (on Windows' ssh, mixed with what ssh printed)
    err: str  # what it (and the system's ssh) printed to stderr or the terminal


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


def _as_dict(login: Login) -> dict:
    passwords = login.passwords
    return passwords if isinstance(passwords, dict) else {login.alias: passwords, login.ip: passwords}


def nested_failure(text: str, login: Login) -> SSHError | None:
    """What the last hop's own SSH client printed about reaching the device, as an SSHError; None
    when it got there. Only the client's own lines count, not what the command printed."""
    t = "\n".join(line for line in text.split("\n") if CLIENT_SAYS.search(line)).lower()
    if "host key mismatch" in t or "remote host identification has changed" in t:
        return SSHError(tr("The SSH key of {ip} changed since {route} last connected to it. If that's expected, "
                           "remove it from that device's known hosts, then try again.", ip=login.ip,
                           route=route_text(login)), "key")
    if "permission denied" in t or "authentication failed" in t or "exited: no auth methods" in t:
        return SSHError(tr("{device} didn't accept the username and password.", device=login.where), "auth")
    if "connection refused" in t:
        return SSHError(tr("Nothing accepts SSH connections on {device}.", device=login.where), "refused")
    if "timed out" in t:
        return SSHError(tr("No SSH answer from {device} (timed out).", device=login.where), "timeout")
    if "no route to host" in t or "network is unreachable" in t or "host is unreachable" in t:
        return SSHError(tr("{ip} can't be reached from {hop}.", ip=login.ip, hop=login.via[-1].ip), "unreachable")
    return None
