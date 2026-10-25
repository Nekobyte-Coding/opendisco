"""Finding devices and keeping records of them: the search over the device list, a note per device
(kept by MAC in the app's data folder), a device's own report, and the extras Export offers after
the scan report: a security report, every config backup, every note and the Log. Also the
Settings list of routed or VPN subnets that every scan sweeps.

Shared by the desktop and the phones: app.py calls in here and makes the widgets; nothing here
does. Standard library only.

    filter_tree(devices, query)     the table's rows for a search: matches and their parents
    Notes(folder)                   .text(d) .set(d, text) .apply(devices) .entries()
    write_device_export(path, d, res, backups)   a device's report (.html), or a .zip with backups
    write_site_export(kind, path, ...)            SITE_EXPORTS' extras
    parse_sweep_list(text)          Settings' "Also sweep these subnets": (targets, problems)
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import re
import tempfile
import time
import zipfile
from html import escape
from pathlib import Path

from opendisco import __version__, core, vulns

NOTES_FILE = "notes.json"
NOTE_MARK = "✎"  # after the name of a device with a note, in the list
SWEEP_KEY = "sweep_subnets"  # settings.json: the list's lines, comments and all
# What the extra subnets may add up to: at the sweep's 500 addresses a second, sent twice, a /19's
# worth adds about half a minute to every scan.
SWEEP_LIMIT = 8192
SWEEP_RATE = 500  # core.parse_args' --rate default

# Export's choices after the scan report: (kind, button, what it saves, file types, the first the default)
SITE_EXPORTS = [
    ("security", "Security report…", "Known CVEs and outdated firmware, device by device: HTML or CSV",
     ["html", "csv"]),
    ("backups", "Config backups…", "Every saved config backup, in a .zip with an index", ["zip"]),
    ("notes", "Notes…", "Every device's note, seen in this scan or not: HTML, CSV or JSON", ["html", "csv", "json"]),
    ("log", "Log…", "The Log, as a text file", ["txt"]),
]


# -- search ----------------------------------------------------------------------------
_MAC_LIKE = re.compile(r"[0-9a-f]{1,4}(?:[:.-][0-9a-f]{1,4})+")


def search_text(d) -> str:
    """Everything the search looks through for a device, in lower case: its addresses, MACs,
    model, name, vendor, firmware, Status text (and the name of each finding), Via and note."""
    macs = [m for m in (d.mac, *sorted(d.other_macs)) if m]
    fields = [*d.ips, *macs, *(m.replace(":", "") for m in macs), d.model, d.name, d.vendor, d.firmware,
              d.info.get("firmware") or "", core.status_cell(d)[0],
              *(core.status_label(tag) for _, tag, _ in d.issues),
              ",".join(v for v in core.VIA_ORDER if v in d.via), d.note]
    return "\n".join(str(f) for f in fields if f).lower()


def _found(word: str, text: str) -> bool:
    if word in text:
        return True
    # A MAC written another way (aa-bb-cc, aabb.ccdd.eeff), but not an address or a version
    if _MAC_LIKE.fullmatch(word) and not re.fullmatch(r"[\d.]+", word):
        return re.sub(r"[:.-]", "", word) in text
    return False


def matches(d, query: str) -> bool:
    """Whether a device has every word of the search, in any of search_text's fields, ignoring case."""
    words = query.lower().split()
    if not words:
        return True
    text = search_text(d)
    return all(_found(word, text) for word in words)


def filter_tree(devices, query: str) -> list:
    """[(device, depth)] in core.tree_order's order, keeping the devices that match the search and
    the ones each was found through, so an indented row still sits under its parent. An empty
    search keeps every device."""
    rows = core.tree_order(devices)
    if not query.split():
        return rows
    by_key = {d.key: d for d, _ in rows}
    keep = set()
    for d, _ in rows:
        if matches(d, query):
            current = d
            while current is not None and current.key not in keep:
                keep.add(current.key)
                current = by_key.get(current.found_by.get("key"))
    return [(d, depth) for d, depth in rows if d.key in keep]


# -- notes -----------------------------------------------------------------------------
class Notes:
    """A note per device, kept by MAC in notes.json in the app's data folder, so it outlives
    rescans, restarts and updates: {mac: {"text", "updated", and the device as it was then:
    "ip", "model", "name"}}."""

    def __init__(self, folder):
        self.path = Path(folder) / NOTES_FILE
        self.unreadable = False  # the file was there but not JSON: kept aside before it's replaced
        self.items = self._load()

    def _load(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError):
            self.unreadable = True
            return {}
        if not isinstance(data, dict):
            self.unreadable = True
            return {}
        return {core.norm_mac(mac): entry for mac, entry in data.items()
                if isinstance(entry, dict) and str(entry.get("text") or "").strip()}

    def key(self, d) -> str | None:
        """The MAC a device's note is kept under: its own, or another of its MACs that has one.
        None for a device without a MAC, which can't have a note."""
        if not d.mac:
            return None
        for mac in (d.mac, *sorted(d.other_macs)):
            if core.norm_mac(mac) in self.items:
                return core.norm_mac(mac)
        return core.norm_mac(d.mac)

    def entry(self, d) -> dict:
        key = self.key(d)
        return self.items.get(key, {}) if key else {}

    def text(self, d) -> str:
        return str(self.entry(d).get("text") or "")

    def set(self, d, text: str) -> bool:
        """Keep text as the device's note (empty deletes it), save, and put it on the device.
        False for a device without a MAC. Raises OSError when it can't be saved."""
        key = self.key(d)
        if key is None:
            return False
        text = text.strip()
        if text:
            self.items[key] = {"text": text, "updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
                               "ip": d.ip, "model": d.model, "name": d.name}
        else:
            self.items.pop(key, None)
        self.save()
        d.note = text
        return True

    def apply(self, devices) -> None:
        """Put each device's note on it (Device.note), for Details, the table, search and exports."""
        for d in devices:
            d.note = self.text(d)

    def entries(self) -> list:
        """[(mac, entry)], by the device's address as it was when the note was written."""
        def order(item):
            try:
                return 0, int(ipaddress.IPv4Address(item[1].get("ip") or ""))
            except ValueError:
                return 1, item[0]
        return sorted(self.items.items(), key=order)

    def save(self) -> None:
        """Write notes.json whole or not at all (a new file, then renamed over the old one)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.unreadable and self.path.exists():  # never overwrite notes that couldn't be read
            os.replace(self.path, self.path.with_name(f"notes-unreadable-{time.strftime('%Y%m%d-%H%M%S')}.json"))
            self.unreadable = False
        fd, tmp = tempfile.mkstemp(prefix=".notes-", suffix=".json", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.items, f, indent=1, ensure_ascii=False)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


# -- what the other device tools add (Desktop A's backups, Desktop B's health checks) -------
def _devicetools():
    try:
        from opendisco import devicetools
        return devicetools
    except Exception:  # left out of the iOS app, or its SSH library missing
        return None


def _paths(found) -> list:
    out = []
    for item in found or ():
        path = Path(getattr(item, "path", item))
        if path.is_file():
            out.append(path)
    return out


def backups_for(d) -> list:
    """d's saved config backups (devicetools.list_backups), newest first; [] where it has none
    or this platform has no device tools."""
    tools = _devicetools()
    if not d.mac or tools is None or not hasattr(tools, "list_backups"):
        return []
    try:
        return _paths(tools.list_backups(d.mac))
    except Exception:
        return []


def all_backups() -> list:
    """[(mac, [backup paths, newest first])] for every device with saved config backups."""
    tools = _devicetools()
    if tools is None or not hasattr(tools, "list_backups"):
        return []
    try:
        found = tools.list_backups()
    except Exception:
        return []
    if isinstance(found, dict):  # {mac: [paths]}
        items = [(core.norm_mac(mac), _paths(paths)) for mac, paths in found.items()]
    else:  # [(mac, path)] or objects with .mac and .path
        grouped = {}
        for item in found or ():
            mac, path = (item if isinstance(item, tuple) else (getattr(item, "mac", ""), item))
            grouped.setdefault(core.norm_mac(mac) if mac else "", []).extend(_paths([path]))
        items = list(grouped.items())
    return sorted((mac, paths) for mac, paths in items if paths)


def latency_text(d) -> str:
    """What the latency check measured for d, in a line; "" when it wasn't measured."""
    try:
        from opendisco import health
    except Exception:
        health = None
    if health is not None and hasattr(health, "latency_text"):
        try:
            return health.latency_text(d) or ""
        except Exception:
            return ""
    value = getattr(d, "latency", None)
    if not value:
        return ""
    if isinstance(value, dict):
        return ", ".join(f"{k} {v}" for k, v in value.items() if v is not None)
    return str(value)


def latest_firmware(d) -> tuple:
    """(the latest firmware for d as text, whether d runs older firmware than that), from what
    the firmware check during the scan put on the device; ("", None) when it isn't known."""
    try:
        from opendisco import health
    except Exception:
        health = None
    if health is not None and hasattr(health, "latest_firmware"):
        try:
            found = health.latest_firmware(d)
            if found:
                return found
        except Exception:
            pass
    value = getattr(d, "latest_firmware", None)
    if isinstance(value, dict):
        value = value.get("version") or ""
    latest = str(value or "")
    if not latest or not d.firmware:
        return latest, None
    return latest, vulns.version_key(d.firmware) < vulns.version_key(latest)


def cve_fix(d) -> str:
    """The firmware version that fixes every known CVE of d that names a fix, or ""."""
    fixes = [m.fixed for m in d.cves or () if m.fixed]
    return max(fixes, key=vulns.version_key) if fixes else ""


# -- HTML --------------------------------------------------------------------------------
_CSS = ("body{font:14px -apple-system,Segoe UI,Roboto,sans-serif;margin:16px;color:#222;background:#fff}"
        "table{border-collapse:collapse;width:100%;font-size:13px}"
        "th,td{border-bottom:1px solid #ddd;padding:6px;text-align:left;vertical-align:top}th{background:#f4f4f4}"
        "pre{background:#f6f6f6;padding:10px;overflow-x:auto;font-size:12px}.wrap{overflow-x:auto}ul{margin:0;padding-left:18px}"
        ".note{white-space:pre-wrap;background:#fff8dc;padding:8px 10px;border-left:3px solid #e0b000}"
        ".error{color:#c62828}.warn{color:#b26a00}.info{color:#1565c0}.ok{color:#2e7d32}.muted{color:#777}"
        "summary{cursor:pointer;margin:8px 0}"
        "@media (prefers-color-scheme: dark){body{background:#121212;color:#ddd}th{background:#222}"
        "th,td{border-color:#333}pre{background:#1e1e1e}.note{background:#2a2614}a{color:#64b5f6}"
        ".error{color:#ef5350}.warn{color:#ffb74d}.info{color:#64b5f6}.ok{color:#81c784}}")
_LEVEL_CLASS = {"error": "error", "warn": "warn", "note": "info", "ok": "ok"}


def _page(title: str, body: str) -> str:
    return (f'<!doctype html><html><head><meta charset="utf-8">\n'
            f'<meta name="viewport" content="width=device-width, initial-scale=1"><title>{escape(title)}</title>\n'
            f"<style>{_CSS}</style>\n</head><body>{body}\n"
            f'<p class="muted">Exported {time.strftime("%Y-%m-%d %H:%M")} by OpenDisco {__version__}.</p>'
            "</body></html>\n")


def _linked(msg: str, links: dict) -> str:
    """The message, escaped, with each CVE id linked to its NVD page."""
    return re.sub(r"\bCVE-\d{4}-\d{4,}\b", lambda m: f'<a href="{links.get(m.group(0), vulns.nvd_url(m.group(0)))}">'
                                                    f"{m.group(0)}</a>", escape(msg))


def _issue_list(d) -> str:
    links = dict(core.issue_links(d))
    return "".join(f'<li><b class="{_LEVEL_CLASS.get(level, "warn")}">{escape(core.status_label(tag))}</b> '
                   f"{_linked(msg, links)}</li>" for level, tag, msg in d.issues)


def _table(head, rows) -> str:
    """A table of cells already escaped; head None for one without a heading row."""
    cells = "".join(f"<tr>{''.join(f'<td>{c}</td>' for c in row)}</tr>" for row in rows)
    heading = f"<tr>{''.join(f'<th>{h}</th>' for h in head)}</tr>" if head else ""
    return f'<div class="wrap"><table>{heading}{cells}</table></div>'


def _cve_rows(d) -> list:
    rows = []
    for m in d.cves or ():
        severity = m.cve.get("severity") or "unrated"
        score = m.cve.get("score")
        level = _LEVEL_CLASS[vulns.LEVELS.get(severity, "warn")]
        rows.append([f'<a href="{vulns.nvd_url(m.cve["id"])}">{escape(m.cve["id"])}</a>',
                     f'<span class="{level}">{escape(severity)}{f" {score:g}" if score is not None else ""}</span>',
                     escape(f"{vulns.FAMILY_SOFTWARE.get(m.family, 'Firmware')} {m.version}"),
                     escape(m.fixed or "none named"), escape(m.cve.get("summary") or "")])
    return rows


def _who(d) -> str:
    return d.name or d.model or d.ip or d.mac or "device"


def _plain(fn, *args) -> str:
    """Text from one of core's renderers without terminal colours."""
    was, core.Style.on = core.Style.on, False
    try:
        return fn(*args)
    finally:
        core.Style.on = was


def _packets_summary(text: str) -> str:
    """render_packets' heading lines: what came in and what the checks found, before the listing."""
    head = []
    for line in text.splitlines():
        if not line.strip():
            break
        head.append(line)
    return "\n".join(head)


def device_report(d, res=None, backups=(), noted: str = "") -> str:
    """A device's own report, HTML that opens on any phone or computer: who it is, its note, what's
    wrong with it, its known CVEs, firmware, latency and ports, then all Details shows and its
    packets (the summary, with the full listing folded away). backups: the names of the config
    backups packed with it; noted: when the note was written (Notes.entry's "updated")."""
    title = _who(d)
    ident = " · ".join(escape(x) for x in (d.ip, d.mac or "", d.model, d.vendor) if x)
    seen = time.strftime("%Y-%m-%d %H:%M", time.localtime(d.last_seen))
    out = [f"<h1>{escape(title)}</h1><p>{ident}</p><p class=\"muted\">Last heard {seen}"
           + (f"; found through {escape(d.found_by.get('ip', '?'))}" if d.found_by else "") + "</p>"]
    if d.note:
        when = f'<p class="muted">Written {escape(noted.replace("T", " ")[:16])}</p>' if noted else ""
        out.append(f'<h2>Note</h2><div class="note">{escape(d.note)}</div>{when}')
    status, _ = core.status_cell(d)
    issues = _issue_list(d)
    out.append(f"<h2>Status: {escape(status)}</h2>" + (f"<ul>{issues}</ul>" if issues else "<p>Nothing found wrong.</p>"))

    firmware = [["Running", escape(d.info.get("firmware") or d.firmware or "not reported")]]
    latest, outdated = latest_firmware(d)
    if latest:
        firmware.append(["Latest", escape(latest) + (' <b class="warn">(newer than this one)</b>' if outdated else
                                                     " (this one)" if outdated is False else "")])
    fix = cve_fix(d)
    if fix:
        firmware.append(["Fixes its known CVEs", escape(fix) + " or later"])
    out.append("<h2>Firmware</h2>" + _table(None, firmware))
    latency = latency_text(d)
    if latency:
        out.append(f"<h2>Latency</h2><p>{escape(latency)}</p>")

    if d.cves:
        out.append(f"<h2>Known CVEs ({len(d.cves)})</h2><p class=\"muted\">From the {escape(vulns.list_label())}. "
                   f"{escape(vulns.NVD_NOTICE)}</p>" + _table(["CVE", "Severity", "Affects", "Fixed in", "Summary"],
                                                              _cve_rows(d)))
    elif d.cves is not None:
        out.append(f"<h2>Known CVEs</h2><p>None in the {escape(vulns.list_label())}; no match isn't proof it's safe.</p>")
    else:
        out.append("<h2>Known CVEs</h2><p>Not checked: the CVE list doesn't cover this model or firmware.</p>")

    out.append("<h2>Ports</h2>" + _ports_html(d))
    out.append(f"<h2>Details</h2><pre>{escape(_plain(core.render_details, d))}</pre>")
    packets = _plain(core.render_packets, d, res.inv if res else None, res.counters if res else None)
    out.append(f"<h2>Packets</h2><pre>{escape(_packets_summary(packets))}</pre>"
               f"<details><summary>Every packet kept, decoded</summary><pre>{escape(packets)}</pre></details>")
    if backups:
        out.append("<h2>Config backups</h2><p>In this .zip's backups folder, newest first:</p><ul>"
                   + "".join(f'<li><a href="backups/{escape(name)}">{escape(name)}</a></li>' for name in backups)
                   + "</ul>")
    return _page(f"OpenDisco: {title}", "\n".join(out))


def _ports_html(d) -> str:
    parts = []
    said = [[escape(label), escape("; ".join(f"{port} ({core.PORT_SOURCES[source]})" for source, port in ports.items()))]
            for label, ports in (("HTTP", d.said_ports("http")), ("HTTPS", d.said_ports("https")),
                                 ("SSH", d.said_ports("ssh"))) if ports]
    if said:
        parts.append("<p>What it says:</p>" + _table(["Service", "Port"], said))
    if d.ports is None:
        parts.append("<p>No deep check ran on it (Deep checks, or a port search, check its TCP ports).</p>")
    elif not d.ports:
        parts.append("<p>No TCP port answered the deep check.</p>")
    else:
        parts.append("<p>Open TCP ports:</p>" + _table(["Port", "Service", "What answered"],
                                                       [[str(p), escape(d.services.get(p, "")),
                                                         escape(str(d.service_info.get(p, "")))] for p in d.ports]))
    if d.port_search:
        ps = d.port_search
        what = "every TCP port" if ps["checked"] >= 65535 else f"{ps['checked']:,} of 65,535 TCP ports"
        parts.append(f"<p>Port search for {escape(core.SERVICE_NAMES.get(ps['for'], ps['for']))}: {what}"
                     + (" (stopped early)" if ps.get("stopped") else "")
                     + f", {time.strftime('%Y-%m-%d %H:%M', time.localtime(ps['at']))}.</p>")
    url = core.web_url(d)
    if url:
        parts.append(f'<p>Web UI: <a href="{escape(url)}">{escape(url)}</a></p>')
    return "".join(parts)


def _safe(text: str, limit: int = 40) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-.")[:limit] or "device"


def device_file_name(d, ext: str) -> str:
    """opendisco-<name>-<when><ext>, with only characters every file system takes."""
    return f"opendisco-{_safe(_who(d))}-{time.strftime('%Y%m%d-%H%M')}{ext}"


def write_device_export(path, d, res=None, backups=(), noted: str = "") -> None:
    """A device's report: a .zip holds it and the config backups given (backups/<file>);
    anything else is the report alone, as HTML."""
    path = Path(path)
    backups = [Path(b) for b in backups]
    if path.suffix.lower() == ".zip":
        names = _unique_names(backups)
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr(path.stem + ".html", device_report(d, res, names, noted))
            for backup, name in zip(backups, names):
                z.write(backup, f"backups/{name}")
        return
    path.write_text(device_report(d, res, (), noted), encoding="utf-8")


def _unique_names(paths) -> list:
    names, taken = [], set()
    for p in paths:
        name, n = p.name, 1
        while name in taken:
            n += 1
            name = f"{p.stem}-{n}{p.suffix}"
        taken.add(name)
        names.append(name)
    return names


# -- the site-wide extras ------------------------------------------------------------------
def security_rows(devices) -> list:
    """[{"device", "cves", "worst", "latest", "outdated", "fix"}] for the devices whose firmware
    is known or was checked: the ones with the worst known CVEs first, then outdated firmware,
    then the rest, then those the CVE list doesn't cover."""
    rows = []
    for d in devices:
        latest, outdated = latest_firmware(d)
        if d.cves is None and not d.firmware and not latest:
            continue
        worst = max((m.cve.get("score") or 0 for m in d.cves or ()), default=0)
        rows.append({"device": d, "cves": list(d.cves or ()), "worst": worst, "latest": latest,
                     "outdated": outdated, "fix": cve_fix(d)})
    def order(r):
        group = 0 if r["cves"] else 1 if r["outdated"] else 3 if r["device"].cves is None else 2
        return group, -r["worst"], -len(r["cves"]), core._ip_sort_key(r["device"])
    return sorted(rows, key=order)


def _severities(cves) -> dict:
    counts = {}
    for m in cves:
        severity = m.cve.get("severity") or "unrated"
        counts[severity] = counts.get(severity, 0) + 1
    return counts


_SEVERITY_ORDER = ("critical", "high", "medium", "low", "unrated")


def security_report(devices) -> str:
    """Known CVEs and outdated firmware, device by device, as HTML."""
    devices = list(devices)
    rows = security_rows(devices)
    with_cves = [r for r in rows if r["cves"]]
    outdated = [r for r in rows if r["outdated"]]
    unchecked = [r for r in rows if r["device"].cves is None]
    tally = _severities([m for r in with_cves for m in r["cves"]])
    counts = ", ".join(f"{tally[s]} {s}" for s in _SEVERITY_ORDER if tally.get(s))
    latest_known = any(r["latest"] for r in rows)  # the firmware check during the scan found the latest
    summary = (f"{len(rows)} device(s) with firmware to check: {len(with_cves)} with known CVEs"
               + (f" ({counts})" if counts else "")
               + (f", {len(outdated)} running older firmware than the latest" if latest_known
                  else "; the latest firmware wasn't looked up for any of them")
               + (f", {len(unchecked)} the CVE list doesn't cover" if unchecked else "") + ".")
    left_out = len(devices) - len(rows)
    table = []
    for r in rows:
        d = r["device"]
        sev = _severities(r["cves"])
        cves = (", ".join(f'<span class="{_LEVEL_CLASS[vulns.LEVELS.get(s, "warn")]}">{sev[s]} {s}</span>'
                          for s in _SEVERITY_ORDER if sev.get(s)) if r["cves"]
                else "not checked" if d.cves is None else '<span class="ok">none known</span>')
        latest = escape(r["latest"]) + (' <b class="warn">newer</b>' if r["outdated"] else "") if r["latest"] else "?"
        table.append([escape(d.ip or "-"), escape(d.name or ""), escape(d.model or ""), escape(d.firmware or "?"),
                      *([latest] if latest_known else []), cves, escape(r["fix"] + " or later") if r["fix"] else ""])
    head = ["IP", "Name", "Model", "Firmware", *(["Latest"] if latest_known else []), "Known CVEs", "Fixed by"]
    out = [f"<h1>Security report</h1><p>{escape(summary)}</p>", _table(head, table)]
    if left_out:
        out.append(f'<p class="muted">{left_out} other device(s) reported no firmware, so nothing could be '
                   "checked for them.</p>")
    for r in with_cves:
        d = r["device"]
        out.append(f"<h2>{escape(d.ip or d.mac or '-')} {escape(_who(d) if _who(d) != d.ip else '')}</h2>"
                   + _table(["CVE", "Severity", "Affects", "Fixed in", "Summary"], _cve_rows(d)))
    out.append(f'<p class="muted">CVEs from the {escape(vulns.list_label())}. No match isn\'t proof a device is safe: '
               f"only models and firmware versions discovery identifies for certain are checked. "
               f"{escape(vulns.NVD_NOTICE)}</p>")
    return _page("OpenDisco security report", "\n".join(out))


def security_csv(devices) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["IP", "MAC", "Model", "Name", "Firmware", "Latest firmware", "Outdated", "Known CVEs",
                     *(s.capitalize() for s in _SEVERITY_ORDER[:4]), "Fixed by", "CVE IDs"])
    for r in security_rows(devices):
        d = r["device"]
        sev = _severities(r["cves"])
        writer.writerow([d.ip, d.mac or "", d.model, d.name, d.firmware, r["latest"],
                         {True: "yes", False: "no"}.get(r["outdated"], ""),
                         len(r["cves"]) if d.cves is not None else "not checked",
                         *(sev.get(s, 0) for s in _SEVERITY_ORDER[:4]), r["fix"],
                         " ".join(m.cve["id"] for m in r["cves"])])
    return out.getvalue()


def _note_rows(notes: Notes | None, devices) -> list:
    """[(mac, entry, the device in this scan or None)] for every note."""
    if notes is None:
        return []
    by_key = {}
    for d in devices:
        key = notes.key(d)
        if key:
            by_key.setdefault(key, d)
    return [(mac, entry, by_key.get(mac)) for mac, entry in notes.entries()]


def notes_html(notes: Notes, devices=()) -> str:
    rows = []
    for mac, entry, d in _note_rows(notes, devices):
        ip = d.ip if d else entry.get("ip") or ""
        who = (d.name or d.model) if d else entry.get("name") or entry.get("model") or ""
        rows.append([escape(mac), escape(ip), escape(who), "yes" if d else '<span class="muted">no</span>',
                     escape(str(entry.get("updated", "")).replace("T", " ")), f'<div class="note">{escape(entry["text"])}</div>'])
    body = (f"<h1>Device notes</h1><p>{len(rows)} note(s), kept by MAC address.</p>"
            + _table(["MAC", "IP", "Device", "In this scan", "Updated", "Note"], rows))
    return _page("OpenDisco notes", body)


def notes_csv(notes: Notes, devices=()) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["MAC", "IP", "Model", "Name", "In this scan", "Updated", "Note"])
    for mac, entry, d in _note_rows(notes, devices):
        writer.writerow([mac, d.ip if d else entry.get("ip", ""), d.model if d else entry.get("model", ""),
                         d.name if d else entry.get("name", ""), "yes" if d else "no", entry.get("updated", ""),
                         entry["text"]])
    return out.getvalue()


def notes_json(notes: Notes, devices=()) -> str:
    return json.dumps({"tool": "opendisco", "version": __version__, "exported_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                       "notes": [{"mac": mac, **entry, "in_scan": d is not None, **({"ip": d.ip} if d else {})}
                                 for mac, entry, d in _note_rows(notes, devices)]}, indent=2, ensure_ascii=False)


def write_backups_zip(path, backups, notes: Notes | None = None, devices=()) -> int:
    """Every config backup given ([(mac, [paths])], as all_backups() lists them) in a .zip, a
    folder a device, with an index.txt naming the devices. Returns how many files went in."""
    known = {d.mac: d for d in devices if d.mac}
    lines, count = ["OpenDisco config backups, " + time.strftime("%Y-%m-%d %H:%M"), ""], 0
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for mac, paths in backups:
            d = known.get(mac)
            entry = notes.items.get(mac, {}) if notes else {}
            who = (d.name or d.model) if d else entry.get("name") or entry.get("model") or ""
            ip = d.ip if d else entry.get("ip") or ""
            folder = (mac or "unknown").replace(":", "-")
            lines.append(f"{folder}/  {ip}  {who}".rstrip())
            for p, name in zip(paths, _unique_names(paths)):
                z.write(p, f"{folder}/{name}")
                lines.append(f"    {name}  {time.strftime('%Y-%m-%d %H:%M', time.localtime(p.stat().st_mtime))}")
                count += 1
        z.writestr("index.txt", "\n".join(lines) + "\n")
    return count


def _write(path, text: str) -> None:
    # A byte order mark on CSV, or Excel reads it in the PC's legacy code page (as core.write_export)
    with open(path, "w", encoding="utf-8-sig" if str(path).lower().endswith(".csv") else "utf-8", newline="") as f:
        f.write(text)


def write_site_export(kind: str, path, devices=(), notes: Notes | None = None, log_text: str = "") -> None:
    """One of SITE_EXPORTS; its format follows the file's extension."""
    ext = Path(path).suffix.lower()
    devices = list(devices)
    if kind == "security":
        _write(path, security_csv(devices) if ext == ".csv" else security_report(devices))
    elif kind == "backups":
        write_backups_zip(path, all_backups(), notes, devices)
    elif kind == "notes":
        maker = {".csv": notes_csv, ".json": notes_json}.get(ext, notes_html)
        _write(path, maker(notes, devices))
    elif kind == "log":
        _write(path, log_text)
    else:
        raise ValueError(f"no export called {kind!r}")


# -- Settings: "Also sweep these subnets" ---------------------------------------------------
def _addresses(net: ipaddress.IPv4Network) -> int:
    """How many addresses the sweep sends to (core.expand_targets: every host of the subnet)."""
    return net.num_addresses if net.prefixlen >= 31 else net.num_addresses - 2


def _check(spec: str):
    """(the network, "") or (None, what's wrong with it)."""
    if ":" in spec:
        return None, f"{spec} is IPv6: UBNT discovery runs over IPv4"
    if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?", spec):
        return None, (f"{spec!r} isn't an IPv4 subnet or address: write one like 10.20.0.0/24 or 10.20.0.7"
                      + (" (names aren't looked up here)" if re.search(r"[A-Za-z]", spec) else ""))
    try:
        net = ipaddress.IPv4Network(spec, strict=False)
    except ValueError:
        return None, f"{spec} isn't a valid address: each part is 0 to 255, and the mask /0 to /32"
    first = net.network_address
    for test, why in ((first.is_loopback, "is this computer's own loopback"),
                      (first.is_multicast, "is multicast, not devices"),
                      (first.is_link_local, "is link-local, which no router or VPN forwards"),
                      (int(first) >> 24 == 0, "isn't an address devices use"),
                      (first.is_reserved, "is reserved (240.0.0.0 and up), not devices")):
        if test:
            return None, f"{net} {why}"
    if net.prefixlen < 16:
        return None, f"{net} is larger than a /16 ({net.num_addresses:,} addresses): give the subnets the gear is on"
    return net, ""


def parse_sweep_list(text: str) -> tuple:
    """(targets, problems) from Settings' "Also sweep these subnets": one subnet or address a line
    (commas or spaces separate more), "#" starts a comment. targets are what the scan sweeps
    ("10.20.0.0/24", "10.20.0.7"); each problem names its line. Together the subnets may add up
    to SWEEP_LIMIT addresses."""
    targets, problems, seen, total = [], [], set(), 0
    for n, line in enumerate((text or "").splitlines(), 1):
        for spec in re.split(r"[,\s]+", line.split("#", 1)[0].strip()):
            if not spec:
                continue
            net, why = _check(spec)
            if net is None:
                problems.append(f"Line {n}: {why}.")
                continue
            if net in seen:
                continue
            seen.add(net)
            total += _addresses(net)
            targets.append(str(net.network_address) if net.prefixlen == 32 else str(net))
    if total > SWEEP_LIMIT:
        problems.append(f"These add up to {total:,} addresses, about {sweep_seconds(total):.0f} s more on every "
                        f"scan; the limit is {SWEEP_LIMIT:,} (a /19's worth). List the subnets the gear is on.")
    return targets, problems


def sweep_seconds(addresses: int) -> float:
    """What sweeping this many more addresses adds to a scan (two passes, core.Scanner)."""
    return 2 * addresses / SWEEP_RATE


def sweep_targets(saved) -> list:
    """What a scan sweeps from the saved list (settings.json's lines). Settings saves only a list
    without problems; one edited by hand loses its bad lines, and all of it when it's over
    SWEEP_LIMIT."""
    text = "\n".join(map(str, saved)) if isinstance(saved, list) else str(saved or "")
    targets, _problems = parse_sweep_list(text)
    total = sum(_addresses(ipaddress.IPv4Network(t)) for t in targets)
    return targets if total <= SWEEP_LIMIT else []


def describe_targets(targets) -> str:
    total = sum(_addresses(ipaddress.IPv4Network(t)) for t in targets)
    return (f"{', '.join(targets[:4])}{f' and {len(targets) - 4} more' if len(targets) > 4 else ''} "
            f"({total:,} address{'es' if total != 1 else ''}, about {max(1, round(sweep_seconds(total)))} s)")
