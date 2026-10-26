"""Finding devices and keeping records of them: the search over the device list, a note per device
(kept by MAC in the app's data folder), a device's own report, and what Export offers: the Site
Report (a scan as a page to print), the scan's data, a security report, every config backup, every
note and the Log. Also the Settings list of routed or VPN subnets that every scan sweeps.

Shared by the desktop and the phones: app.py calls in here and makes the widgets; nothing here
does. Standard library only.

    filter_tree(devices, query)     the table's rows for a search: matches and their parents
    Notes(folder)                   .text(d) .set(d, text) .apply(devices) .entries()
    write_device_export(path, d, res, backups)   a device's report (.html), or a .zip with backups
    write_site_export(kind, path, ...)            SITE_EXPORTS' extras
    site_report(res, site, demo)    the Site Report (core.write_export writes it to a .html)
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
from collections import Counter
from html import escape
from pathlib import Path

from opendisco import __version__, core, i18n, vulns
from opendisco.i18n import _, N_, tr

NOTES_FILE = "notes.json"
NOTE_MARK = "✎"  # after the name of a device with a note, in the list
SWEEP_KEY = "sweep_subnets"  # settings.json: the list's lines, comments and all
SITE_KEY = "site_name"  # settings.json: the site the last Site Report was for, offered for the next
# What the extra subnets may add up to: at the sweep's 500 addresses a second, sent twice, a /19's
# worth adds about half a minute to every scan.
SWEEP_LIMIT = 8192
SWEEP_RATE = 500  # core.parse_args' --rate default
SECONDS = "\u00a0s"  # after a number: a no-break space, so a wrapped label never ends a line on it

# Export's choices: (kind, button, what it saves, file types, the first the default and on phones
# the only one). The Site Report comes first, then the scan's data, then the site-wide extras.
SCAN_EXPORT = ("scan", N_("Site Report…"), N_("The site's devices, firmware, CVEs, factory logins and every issue, "
                                              "a page to print or save as PDF"), ["html"])
DATA_EXPORT = ("data", N_("Scan data…"), N_("Every device as the table lists it, with diagnostics, for a spreadsheet "
                                            "or a script"), ["csv", "json"])
SITE_EXPORTS = [
    ("security", N_("Security report…"), N_("Known CVEs and outdated firmware, device by device"), ["html", "csv"]),
    ("backups", N_("Config backups…"), N_("Every saved config backup, with an index"), ["zip"]),
    ("notes", N_("Notes…"), N_("Every device's note, seen in this scan or not"), ["html", "csv", "json"]),
    ("log", N_("Log…"), N_("The Log"), ["txt"]),
]
FORMAT_NAMES = {"html": "HTML", "csv": "CSV", "json": "JSON", "zip": N_("a .zip"), "txt": N_("a text file")}


def choice_text(text: str, types, extra: str = "") -> str:
    """An export choice's line: what it saves (text, translated), how many (extra), and the formats
    it's saved in ("Known CVEs ...: HTML or CSV.")."""
    names = [_(FORMAT_NAMES.get(t, t.upper())) for t in types]
    formats = names[0] if len(names) == 1 else tr("{formats} or {last}", formats=", ".join(names[:-1]), last=names[-1])
    return (tr("{text} ({extra}): {formats}.", text=text, extra=extra, formats=formats) if extra
            else tr("{text}: {formats}.", text=text, formats=formats))



# -- search ----------------------------------------------------------------------------
_MAC_LIKE = re.compile(r"[0-9a-f]{1,4}(?:[:.-][0-9a-f]{1,4})+")


def search_text(d) -> str:
    """Everything the search looks through for a device, in lower case: its addresses, MACs,
    model, name, vendor, firmware, Status text (and the name of each finding, in English too), Via and note."""
    macs = [m for m in (d.mac, *sorted(d.other_macs)) if m]
    fields = [*d.ips, *macs, *(m.replace(":", "") for m in macs), d.model, d.name, d.vendor, d.firmware,
              d.info.get("firmware") or "", core.status_cell(d)[0],
              *(core.status_label(tag) for _, tag, _ in d.issues),
              *(core.STATUS_LABELS.get(tag, "") for _, tag, _ in d.issues),
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


def _backups(tools, mac: str) -> list:
    """One device's saved configs (devicetools.list_backups: Backups, newest first) as their paths."""
    try:
        return _paths(tools.list_backups(mac))
    except Exception:
        return []


def backups_for(d) -> list:
    """d's saved config backups, newest first, as the config files' paths (each has its
    devicetools .json beside it); [] where it has none or this platform has no device tools."""
    tools = _devicetools()
    if not d.mac or tools is None or not hasattr(tools, "list_backups"):
        return []
    return _backups(tools, d.mac)


def all_backups() -> list:
    """[(mac, [backup paths, newest first])] for every device with saved config backups
    (devicetools.backup_macs)."""
    tools = _devicetools()
    if tools is None or not hasattr(tools, "backup_macs") or not hasattr(tools, "list_backups"):
        return []
    try:
        macs = tools.backup_macs()
    except Exception:
        return []
    found = [(core.norm_mac(mac), _backups(tools, mac)) for mac in macs]
    return [(mac, paths) for mac, paths in found if paths]


def _sidecar(path: Path) -> Path | None:
    """The .json devicetools keeps beside a backup (where it came from: model, firmware,
    reason...), if it's there; a restore checks the model with it."""
    meta = path.with_name(path.name + ".json")
    return meta if meta.is_file() else None


def _reason(path: Path) -> str:
    """Why the backup was taken ("backup", "before upload"...), from its .json."""
    meta = _sidecar(path)
    try:
        return str(json.loads(meta.read_text(encoding="utf-8")).get("reason") or "") if meta else ""
    except (OSError, ValueError, AttributeError):
        return ""


def _pack_backups(z: zipfile.ZipFile, folder: str, paths) -> list:
    """Put backups and their .json files in the zip under folder/; returns the names given."""
    names = _unique_names(paths)
    for path, name in zip(paths, names):
        z.write(path, f"{folder}/{name}")
        meta = _sidecar(path)
        if meta:
            z.write(meta, f"{folder}/{name}.json")
    return names


def _linkhealth():
    try:
        from opendisco import linkhealth
        return linkhealth
    except Exception:  # not in this build
        return None


def _health():
    try:
        from opendisco import health
        return health
    except Exception:  # not in this build
        return None


def latency_text(d) -> str:
    """What the latency check during the scan measured for d (health.py): its Details row
    (min/avg/max and loss), else its table cell; "" when it wasn't measured."""
    health = _health()
    if health is None or not (getattr(d, "health", None) or {}).get("latency"):
        return ""
    try:
        rows = dict(health.detail_rows(d)) if hasattr(health, "detail_rows") else {}
        return rows.get(_("Latency")) or rows.get("Latency") or health.latency_cell(d) or ""
    except Exception:
        return ""


def latest_firmware(d) -> tuple:
    """(the latest firmware for d, whether a newer one than d runs is out), from the firmware
    check during the scan (health.py, d.health["firmware"]); ("", None) when it wasn't looked up
    or Ubiquiti's list has none for it."""
    found = (getattr(d, "health", None) or {}).get("firmware") or {}
    health = _health()
    try:
        latest = health.latest_version(d) if health is not None else found.get("latest") or ""
    except Exception:
        latest = found.get("latest") or ""
    if not latest:
        return "", None
    return str(latest), bool(found.get("newer"))


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
    made = tr("Exported {date} by OpenDisco {version}.", date=time.strftime("%Y-%m-%d %H:%M"), version=__version__)
    return (f'<!doctype html><html><head><meta charset="utf-8">\n'
            f'<meta name="viewport" content="width=device-width, initial-scale=1"><title>{escape(title)}</title>\n'
            f"<style>{_CSS}</style>\n</head><body>{body}\n"
            f'<p class="muted">{made}</p>'
            "</body></html>\n")


def _linked(msg: str, links: dict) -> str:
    """The message, escaped, with each CVE id linked to its NVD page."""
    return re.sub(r"\bCVE-\d{4}-\d{4,}\b", lambda m: f'<a href="{links.get(m.group(0), vulns.nvd_url(m.group(0)))}">'
                                                    f"{m.group(0)}</a>", escape(msg))


def _issue_list(d, issues=None) -> str:
    """d's findings (or these of them) as list items, each CVE linked to its NVD page."""
    links = dict(core.issue_links(d))
    return "".join(f'<li><b class="{_LEVEL_CLASS.get(level, "warn")}">{escape(core.status_label(tag))}</b> '
                   f"{_linked(msg, links)}</li>" for level, tag, msg in (d.issues if issues is None else issues))


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
                     f'<span class="{level}">{escape(_(severity))}{f" {score:g}" if score is not None else ""}</span>',
                     escape(f"{vulns.FAMILY_SOFTWARE.get(m.family, _('Firmware'))} {m.version}"),
                     escape(m.fixed or _("none named")), escape(m.cve.get("summary") or "")])
    return rows


def _who(d) -> str:
    return d.name or d.model or d.ip or d.mac or _("device")


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
    packets (the summary, with the full listing folded away). backups: the config backups packed
    with it, names or (name, why it was taken); noted: when the note was written (Notes.entry's
    "updated")."""
    title = _who(d)
    ident = " · ".join(escape(x) for x in (d.ip, d.mac or "", d.model, d.vendor) if x)
    seen = time.strftime("%Y-%m-%d %H:%M", time.localtime(d.last_seen))
    heard = (tr("Last heard {when}; found through {address}", when=seen, address=escape(d.found_by.get("ip", "?")))
             if d.found_by else tr("Last heard {when}", when=seen))
    out = [f"<h1>{escape(title)}</h1><p>{ident}</p><p class=\"muted\">{heard}</p>"]
    if d.note:
        when = (f'<p class="muted">{tr("Written {when}", when=escape(noted.replace("T", " ")[:16]))}</p>' if noted
                else "")
        out.append(f'<h2>{_("Note")}</h2><div class="note">{escape(d.note)}</div>{when}')
    status = core.status_cell(d)[0]
    issues = _issue_list(d)
    out.append(f"<h2>{tr('Status: {status}', status=escape(status))}</h2>"
               + (f"<ul>{issues}</ul>" if issues else f"<p>{_('Nothing found wrong.')}</p>"))

    firmware = [[_("Running"), escape(d.info.get("firmware") or d.firmware or _("not reported"))]]
    latest, outdated = latest_firmware(d)
    if latest:
        firmware.append([_("Latest"), escape(latest) + (f' <b class="warn">{_("(newer than this one)")}</b>' if outdated
                                                        else f" {_('(up to date)')}")])
    fix = cve_fix(d)
    if fix:
        firmware.append([_("Fixes its known CVEs"), tr("{version} or later", version=escape(fix))])
    out.append(f"<h2>{_('Firmware')}</h2>" + _table(None, firmware))
    latency = latency_text(d)
    if latency:
        out.append(f"<h2>{_('Latency')}</h2><p>{escape(latency)}</p>")

    listed = escape(vulns.list_label())
    if d.cves:
        out.append(f"<h2>{tr('Known CVEs ({count})', count=len(d.cves))}</h2><p class=\"muted\">"
                   f"{i18n.sentences(tr('From the {list}.', list=listed), escape(_(vulns.NVD_NOTICE)))}</p>"
                   + _table(["CVE", _("Severity"), _("Affects"), _("Fixed in"), _("Summary")], _cve_rows(d)))
    elif d.cves is not None:
        out.append(f"<h2>{_('Known CVEs')}</h2><p>"
                   + tr("None in the {list}; no match isn't proof it's safe.", list=listed) + "</p>")
    else:
        out.append(f"<h2>{_('Known CVEs')}</h2><p>"
                   + _("Not checked: the CVE list doesn't cover this model or firmware.") + "</p>")

    out.append(f"<h2>{_('Ports')}</h2>" + _ports_html(d))
    out.append(f"<h2>{_('Details')}</h2><pre>{escape(_plain(core.render_details, d))}</pre>")
    packets = _plain(core.render_packets, d, res.inv if res else None, res.counters if res else None)
    out.append(f"<h2>{_('Packets')}</h2><pre>{escape(_packets_summary(packets))}</pre>"
               f"<details><summary>{_('Every packet kept, decoded')}</summary><pre>{escape(packets)}</pre></details>")
    if backups:
        out.append(f"<h2>{_('Config backups')}</h2><p>"
                   + _("In this .zip's backups folder, newest first, each with a .json of where it came from:")
                   + "</p><ul>"
                   + "".join(f'<li><a href="backups/{escape(name)}">{escape(name)}</a>'
                             + (f" ({escape(_(reason))})" if reason else "") + "</li>"
                             for name, reason in (b if isinstance(b, tuple) else (b, "") for b in backups))
                   + "</ul>")
    return _page(f"OpenDisco: {title}", "\n".join(out))


def _ports_html(d) -> str:
    parts = []
    said = [[escape(label), escape("; ".join(f"{port} ({_(core.PORT_SOURCES[source])})"
                                             for source, port in ports.items()))]
            for label, ports in (("HTTP", d.said_ports("http")), ("HTTPS", d.said_ports("https")),
                                 ("SSH", d.said_ports("ssh"))) if ports]
    if said:
        parts.append(f"<p>{_('What it says:')}</p>" + _table([_("Service"), _("Port")], said))
    if d.ports is None:
        parts.append(f"<p>{_('No deep check ran on it (Deep checks, or a port search, check its TCP ports).')}</p>")
    elif not d.ports:
        parts.append(f"<p>{_('No TCP port answered the deep check.')}</p>")
    else:
        parts.append(f"<p>{_('Open TCP ports:')}</p>" + _table([_("Port"), _("Service"), _("What answered")],
                                                               [[str(p), escape(d.services.get(p, "")),
                                                                 escape(str(d.service_info.get(p, "")))]
                                                                for p in d.ports]))
    if d.port_search:
        ps = d.port_search
        what = (_("every TCP port") if ps["checked"] >= 65535
                else tr("{count:,} of 65,535 TCP ports", count=ps["checked"]))
        service = escape(_(core.SERVICE_NAMES.get(ps["for"], ps["for"])))
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(ps["at"]))
        parts.append("<p>" + (tr("Port search for {service}: {what} (stopped early), {when}.", service=service,
                                 what=what, when=when) if ps.get("stopped")
                              else tr("Port search for {service}: {what}, {when}.", service=service, what=what,
                                      when=when)) + "</p>")
    url = core.web_url(d)
    if url:
        link = f'<a href="{escape(url)}">{escape(url)}</a>'
        parts.append(f"<p>{tr('Web UI: {link}', link=link)}</p>")
    return "".join(parts)


def _safe(text: str, limit: int = 40) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-.")[:limit] or "device"


def device_file_name(d, ext: str) -> str:
    """opendisco-<name>-<when><ext>, with only characters every file system takes."""
    return f"opendisco-{_safe(_who(d))}-{time.strftime('%Y%m%d-%H%M')}{ext}"


def write_device_export(path, d, res=None, backups=(), noted: str = "") -> None:
    """A device's report: a .zip holds it and the config backups given, each with its .json
    (backups/<file>); anything else is the report alone, as HTML."""
    path = Path(path)
    backups = [Path(b) for b in backups]
    if path.suffix.lower() == ".zip":
        listed = [(name, _reason(b)) for b, name in zip(backups, _unique_names(backups))]
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr(path.stem + ".html", device_report(d, res, listed, noted))  # first: what to open
            _pack_backups(z, "backups", backups)
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


_SEVERITY_ORDER = (N_("critical"), N_("high"), N_("medium"), N_("low"), N_("unrated"))  # (the CVE list's words)


def security_report(devices) -> str:
    """Known CVEs and outdated firmware, device by device, as HTML."""
    devices = list(devices)
    rows = security_rows(devices)
    with_cves = [r for r in rows if r["cves"]]
    outdated = [r for r in rows if r["outdated"]]
    unchecked = [r for r in rows if r["device"].cves is None]
    tally = _severities([m for r in with_cves for m in r["cves"]])
    counts = ", ".join(f"{tally[s]} {_(s)}" for s in _SEVERITY_ORDER if tally.get(s))
    latest_known = any(r["latest"] for r in rows)  # the firmware check during the scan found the latest
    found = [tr("{count} with known CVEs", count=len(with_cves)) + (f" ({counts})" if counts else "")]
    if latest_known:
        found.append(tr("{count} running older firmware than the latest", count=len(outdated)))
    else:
        found[0] = tr("{found}; the latest firmware wasn't looked up for any of them", found=found[0])
    if unchecked:
        found.append(tr("{count} the CVE list doesn't cover", count=len(unchecked)))
    summary = tr("{count} device(s) with firmware to check: {found}.", count=len(rows), found=", ".join(found))
    left_out = len(devices) - len(rows)
    table = []
    for r in rows:
        d = r["device"]
        sev = _severities(r["cves"])
        cves = (", ".join(f'<span class="{_LEVEL_CLASS[vulns.LEVELS.get(s, "warn")]}">{sev[s]} {_(s)}</span>'
                          for s in _SEVERITY_ORDER if sev.get(s)) if r["cves"]
                else _("not checked") if d.cves is None else f'<span class="ok">{_("none known")}</span>')
        latest = (escape(r["latest"]) + (f' <b class="warn">{_("newer")}</b>' if r["outdated"] else "")
                  if r["latest"] else "?")
        table.append([escape(d.ip or "-"), escape(d.name or ""), escape(d.model or ""), escape(d.firmware or "?"),
                      *([latest] if latest_known else []), cves,
                      escape(tr("{version} or later", version=r["fix"])) if r["fix"] else ""])
    head = ["IP", _("Name"), _("Model"), _("Firmware"), *([_("Latest")] if latest_known else []), _("Known CVEs"),
            _("Fixed by")]
    out = [f"<h1>{_('Security report')}</h1><p>{escape(summary)}</p>", _table(head, table)]
    if left_out:
        out.append('<p class="muted">'
                   + tr("{count} other device(s) reported no firmware, so nothing could be checked for them.",
                        count=left_out) + "</p>")
    for r in with_cves:
        d = r["device"]
        out.append(f"<h2>{escape(d.ip or d.mac or '-')} {escape(_who(d) if _who(d) != d.ip else '')}</h2>"
                   + _table(["CVE", _("Severity"), _("Affects"), _("Fixed in"), _("Summary")], _cve_rows(d)))
    out.append('<p class="muted">'
               + i18n.sentences(tr("CVEs from the {list}.", list=escape(vulns.list_label())),
                                _("No match isn't proof a device is safe: only models and firmware versions discovery "
                                  "identifies for certain are checked."), escape(_(vulns.NVD_NOTICE))) + "</p>")
    return _page(_("OpenDisco security report"), "\n".join(out))


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
        rows.append([escape(mac), escape(ip), escape(who), _("yes") if d else f'<span class="muted">{_("no")}</span>',
                     escape(str(entry.get("updated", "")).replace("T", " ")), f'<div class="note">{escape(entry["text"])}</div>'])
    body = (f"<h1>{_('Device notes')}</h1><p>{tr('{count} note(s), kept by MAC address.', count=len(rows))}</p>"
            + _table(["MAC", "IP", _("Device"), _("In this scan"), _("Updated"), _("Note")], rows))
    return _page(_("OpenDisco notes"), body)


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
    folder a device named like devicetools' (aa-bb-cc-dd-ee-ff), each backup with its .json, and an
    index.txt naming the devices. Returns how many backups went in."""
    known = {d.mac: d for d in devices if d.mac}
    lines, count = [tr("OpenDisco config backups, {date}", date=time.strftime("%Y-%m-%d %H:%M")), ""], 0
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for mac, paths in backups:
            d = known.get(mac)
            entry = notes.items.get(mac, {}) if notes else {}
            who = (d.name or d.model) if d else entry.get("name") or entry.get("model") or ""
            ip = d.ip if d else entry.get("ip") or ""
            folder = (mac or "unknown").replace(":", "-")
            lines.append(f"{folder}/  {ip}  {who}".rstrip())
            for p, name in zip(paths, _pack_backups(z, folder, paths)):
                why = _reason(p)
                lines.append(f"    {name}  {time.strftime('%Y-%m-%d %H:%M', time.localtime(p.stat().st_mtime))}"
                             + (f"  ({why})" if why else ""))
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


# -- the Site Report -----------------------------------------------------------------------
DEMO_STAMP = N_("Demo network: made-up devices")
# Its sections of issues after Known CVEs, with Firmware updates between the two: (title, the tags of
# core.STATUS_LABELS each gathers). Every other issue, one added later included, goes under Other
# issues, device by device.
REPORT_SECTIONS = [(N_("Factory logins and factory defaults"), ("FACTORY-LOGIN", "DEFAULT")),
                   (N_("Latency"), ("HIGH-LATENCY", "PING-LOSS")),
                   (N_("airMAX link health"), ("WEAK-SIGNAL", "HOT-SIGNAL", "CHAIN-IMBALANCE", "LOW-SNR",
                                               "LOW-CAPACITY", "LOW-QUALITY"))]
LEVEL_NAMES = {"error": N_("Errors"), "warn": N_("Warnings"), "note": N_("Notices")}
ATTENTION_SHOWN = 10  # the summary's list of devices needing attention first
LATENCY_SHOWN = 10  # the Latency table's slowest devices, besides the ones flagged
# The families the summary counts devices by: vulns' families, as Ubiquiti names them (translated
# where they're shown)
FAMILY_NAMES = {"airmax-ac": "airMAX AC", "airmax-m": "airMAX M", "af60": "airFiber 60", "af60-xg": "airFiber 60",
                "airfiber": "airFiber", "gbe": "GigaBeam", "aircube": "airCube", "edgeos": "EdgeRouter",
                "edgeswitch": "EdgeSwitch", "edgeswitch-x": "EdgeSwitch X", "edgeswitch-xp": "EdgeSwitch XP",
                "airgateway": "airGateway", "edgepower": "EdgePower", "usg": "UniFi Security Gateway",
                "unifi-os": N_("UniFi OS console"), "unifi-ap": N_("UniFi access point"),
                "unifi-switch": N_("UniFi switch"), "uxg": N_("UniFi gateway"), "unifi-lte": "UniFi LTE",
                "ubb": "UniFi Building Bridge"}
_RANK = {level: n for n, level in enumerate(core.LEVEL_ORDER)}

_REPORT_CSS = """
:root{color-scheme:light dark;--fg:#1d1d1f;--bg:#fff;--muted:#6e6e73;--line:#d2d2d7;--head:#f5f5f7;
--error:#c62828;--warn:#a15c00;--info:#1565c0;--ok:#2e7d32;--link:#0b57d0;--stamp:#fff4ce;--stamp-line:#d9a900;
--note:#fff8dc}
body{font:14px/1.45 -apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;margin:0 auto;max-width:1100px;
padding:16px;color:var(--fg);background:var(--bg)}
a{color:var(--link)}h1{font-size:26px;margin:2px 0 8px}h2{font-size:19px;margin:28px 0 8px;padding-top:10px;
border-top:2px solid var(--line)}h3{font-size:15px;margin:14px 0 4px}p{margin:6px 0}
.kicker{text-transform:uppercase;letter-spacing:.08em;font-size:12px;color:var(--muted);margin:0}
.stamp{border:2px solid var(--stamp-line);background:var(--stamp);padding:6px 10px;font-weight:600;margin-bottom:10px}
.facts{display:grid;grid-template-columns:max-content 1fr;gap:2px 14px;margin:8px 0}.facts dt{color:var(--muted)}
.facts dd{margin:0}
.tiles{display:flex;flex-wrap:wrap;gap:10px;margin:10px 0}.tile{border:1px solid var(--line);border-radius:8px;
padding:8px 14px;min-width:120px}.tile b{display:block;font-size:24px;line-height:1.2}
.tile span{color:var(--muted);font-size:12px}
.tile.error b{color:var(--error)}.tile.warn b{color:var(--warn)}.tile.info b{color:var(--info)}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid var(--line);padding:5px 6px;
text-align:left;vertical-align:top}th{background:var(--head);font-weight:600}.wrap{overflow-x:auto}
td.nw{white-space:nowrap}@media screen and (max-width:700px){table.wide{min-width:860px}}
ul,ol{margin:4px 0;padding-left:22px}li{margin:2px 0}
.device{margin:10px 0 14px}.device h3 small{font-weight:normal;color:var(--muted)}
table.link{width:auto;margin-top:4px}table.link th,table.link td{border:0;padding:1px 10px 1px 0;background:none;
font-weight:normal}table.link th{color:var(--muted);white-space:nowrap}
.note{white-space:pre-wrap;background:var(--note);padding:6px 10px;border-left:3px solid var(--stamp-line)}
pre{background:var(--head);padding:10px;overflow-x:auto;font-size:12px;white-space:pre-wrap}
.error{color:var(--error)}.warn{color:var(--warn)}.info{color:var(--info)}.ok{color:var(--ok)}.muted{color:var(--muted)}
footer{margin-top:28px;font-size:12px;color:var(--muted)}
@media screen and (prefers-color-scheme:dark){:root{--fg:#e8e8ea;--bg:#161618;--muted:#9a9aa0;--line:#3a3a3c;
--head:#222224;--error:#ef5350;--warn:#ffb74d;--info:#64b5f6;--ok:#81c784;--link:#8ab4f8;--stamp:#3a3000;
--stamp-line:#b38f00;--note:#2a2614}}
@page{margin:14mm 12mm}
@media print{:root{color-scheme:light}body{max-width:none;padding:0;font-size:10pt}h1{font-size:20pt}
h2,h3{break-after:avoid;page-break-after:avoid;break-inside:avoid;page-break-inside:avoid}h2{font-size:14pt}
table{font-size:8.5pt}th,td{padding:3px 4px}thead{display:table-header-group}tr,.device,.tile,li{break-inside:avoid;
page-break-inside:avoid}.wrap{overflow:visible}pre{white-space:pre-wrap;font-size:8pt}a{text-decoration:none}
.stamp,.note,th{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
"""


def scan_mode(opts) -> str:
    """The scan's mode as the app's list names it, with what was added to it ("Full scan, with deep
    checks and temporary addresses")."""
    vlans = opts.vlans or bool(getattr(opts, "vlan_ids", None))
    name = (_("Direct to a device") if opts.direct else _("Trunk VLANs") if vlans else _("Sniff the wire")
            if opts.sniff else _("Listen only") if opts.listen else _("Quick") if opts.quick else _("Full scan"))
    extras = [_("deep checks") if opts.deep else _("port checks") if opts.ports else "",
              _("every TCP port of the addresses given") if opts.all_ports else "",
              _("temporary addresses") if (opts.aliases or opts.alias) and not (vlans or opts.direct) else ""]
    extras = [e for e in extras if e]
    if not extras:
        return name
    joined = extras[0]
    for extra in extras[1:]:
        joined = tr("{first} and {second}", first=joined, second=extra)
    return tr("{mode}, with {extras}", mode=name, extras=joined)


def scanned_networks(res) -> list:
    """What the scan covered, a phrase each: each interface's subnet ("10.60.12.0/24 on en0
    (Ethernet)"), the subnets and addresses it was given (Settings' list, the command line's), the
    networks reached through temporary addresses and the VLANs probed."""
    out = [tr("{network} on {interface}", network=i.network, interface=i.name) + (f" ({i.label})" if i.label else "")
           for i in res.ifaces if i.prefix < 32 and not i.ip.startswith("169.254.")]
    out += list(res.opts.targets or ())
    out += [tr("{network} (temporary address)", network=t.network) for t in res.base_targets]
    vlans = set(getattr(res.opts, "vlan_ids", None) or ())
    if not res.opts.direct:
        vlans |= {v for trunk in res.trunks for v in trunk.tagged_ids()}
    if vlans:
        ids = ", ".join(map(str, sorted(vlans)))
        out.append(tr("VLANs {ids}", ids=ids) if len(vlans) > 1 else tr("VLAN {ids}", ids=ids))
    return list(dict.fromkeys(out))


def family_name(d) -> str:
    """The product family the summary counts d in ("airMAX AC", "EdgeRouter"), or "" when it
    isn't known."""
    found = vulns.device_family(d)
    if found:
        return FAMILY_NAMES.get(found[0], "")
    if d.console:
        return FAMILY_NAMES["unifi-os"]
    if re.match(r"(?i)ltu", d.fw_platform or d.info.get("platform") or ""):
        return "LTU"
    return ""


def _worst(d) -> int:
    return max((_RANK.get(level, _RANK["warn"]) for level, _, _ in d.issues), default=0)


def needs_attention(devices) -> list:
    """The devices with a warning or an error, the worst first: by their worst finding, then their
    worst known CVE's score, then how many findings they have."""
    found = [d for d in devices if _worst(d) >= _RANK["warn"]]
    return sorted(found, key=lambda d: (-_worst(d), -max((m.cve.get("score") or 0 for m in d.cves or ()), default=0),
                                        -len(d.issues), core._ip_sort_key(d)))


def _report_table(head, rows, nowrap=(), wide=False) -> str:
    """A table of cells already escaped, its heading repeated on every printed page; nowrap: the
    columns kept on one line (addresses); wide: on a phone, wider than the screen and scrolled
    sideways, not squeezed a word to a line."""
    body = "".join("<tr>" + "".join(f'<td{" class=nw" if n in nowrap else ""}>{c}</td>' for n, c in enumerate(row))
                   + "</tr>" for row in rows)
    heading = "".join(f"<th>{h}</th>" for h in head)
    return (f'<div class="wrap"><table{" class=wide" if wide else ""}><thead><tr>{heading}</tr></thead>'
            f"<tbody>{body}</tbody></table></div>")


def _status_html(d) -> str:
    """The Status column, each finding named in its level's colour."""
    found = dict.fromkeys((level, tag) for level, tag, _ in d.issues)
    if not found:
        return f'<span class="info">{_("Console")}</span>' if d.console else f'<span class="ok">{_("OK")}</span>'
    return ", ".join(f'<span class="{_LEVEL_CLASS.get(level, "warn")}">{escape(core.status_label(tag))}</span>'
                     for level, tag in found)


def _anchor(d, ids: dict) -> str:
    return f"d{ids.get(d.key, 0)}"


def _ip_link(d, ids: dict) -> str:
    """Its address, linked to its row in the device table."""
    return f'<a href="#{_anchor(d, ids)}">{escape(d.ip or d.mac or "-")}</a>'


def _device_heading(d, ids: dict) -> str:
    """A device's heading in a section, linked to its row in the device table."""
    who = d.name if d.name and d.name != d.ip else ""
    return f"<h3>{_ip_link(d, ids)} {escape(who)} <small>{escape(d.model)}</small></h3>"


def _issue_section(devices, tags, ids: dict) -> list:
    """Each device's findings with these tags (None: every tag not in REPORT_SECTIONS or CVE), in
    table order."""
    known = {t for _, section in REPORT_SECTIONS for t in section} | {"CVE"}
    out = []
    for d in devices:
        found = [i for i in d.issues if (i[1] in tags if tags is not None else i[1] not in known)]
        if found:
            out.append(f'<div class="device">{_device_heading(d, ids)}<ul>{_issue_list(d, found)}</ul></div>')
    return out


def _summary(devices, ids: dict) -> str:
    """The tiles (devices, then issues by level), the devices by vendor and family, and the ones
    needing attention first."""
    tiles = [("", len(devices), _("devices") if len(devices) != 1 else _("device"),
              tr("{count} need attention", count=len(needs_attention(devices))))]
    for level in ("error", "warn", "note"):
        issues = sum(1 for d in devices for lv, _, _ in d.issues if lv == level)
        hit = sum(1 for d in devices if any(lv == level for lv, _, _ in d.issues))
        tiles.append((_LEVEL_CLASS[level] if issues else "", issues, _(LEVEL_NAMES[level]).lower(),
                      (tr("on {count} devices", count=hit) if hit != 1 else tr("on {count} device", count=hit))
                      if issues else _("none")))
    out = ['<div class="tiles">' + "".join(f'<div class="tile {cls}"><b>{n}</b>{escape(what)}<br><span>{escape(sub)}'
                                          f"</span></div>" for cls, n, what, sub in tiles) + "</div>"]
    groups, families = {}, {d.model: family_name(d) for d in devices if family_name(d)}
    for d in devices:  # (one whose family isn't known takes another of its model's)
        groups.setdefault((d.vendor or _("Unknown vendor"), family_name(d) or families.get(d.model, "")), []).append(
            d.model or "?")
    rows = [[escape(vendor), escape(_(family)) if family else f'<span class="muted">{_("not known")}</span>',
             escape(", ".join(f"{m} ×{n}" if n > 1 else m for m, n in sorted(Counter(models).items()))),
             str(len(models))]
            for (vendor, family), models in sorted(groups.items(), key=lambda g: (-len(g[1]), g[0]))]
    out.append(f"<h3>{_('By vendor and family')}</h3>"
               + _report_table([_("Vendor"), _("Family"), _("Models"), _("Devices")], rows))
    worst = needs_attention(devices)
    if worst:
        items = "".join(f'<li>{_ip_link(d, ids)} {escape(d.name if d.name != d.ip else "")} '
                        f'<span class="muted">{escape(d.model)}</span>: {_status_html(d)}</li>'
                        for d in worst[:ATTENTION_SHOWN])
        more = len(worst) - ATTENTION_SHOWN
        out.append(f"<h3>{_('Needing attention first')}</h3><ol>{items}</ol>"
                   + ('<p class="muted">' + tr("And {count} more with warnings: see the device table.", count=more)
                      + "</p>" if more > 0 else ""))
    else:
        out.append(f'<p class="ok">{_("No device has a warning or an error.")}</p>')
    return "\n".join(out)


def _device_table(rows, ids: dict) -> str:
    """Every device in the app's table order, each found through another one under it."""
    cells = []
    for d, depth in rows:
        latest, outdated = latest_firmware(d)
        latest = (f'<b class="warn">{escape(latest)}</b>' if outdated
                  else f'<span class="muted">{escape(latest)}</span>' if latest else "")
        ip = escape(core.nested_ip(d, depth) or d.mac or "-").replace(" ", "&nbsp;")
        runs = ((d.health or {}).get("firmware") or {}).get("current") or d.firmware  # without its build number
        cells.append([f'<a id="{_anchor(d, ids)}"></a>{ip}', escape(d.vlan_label), escape(d.vendor), escape(d.model),
                      escape(d.name), escape(d.mac or ""), escape(runs), latest, _status_html(d)])
    return _report_table(["IP", "VLAN", _("Vendor"), _("Model"), _("Name"), "MAC", _("Firmware"), _("Latest"),
                          _("Status")], cells, nowrap=(0, 3, 5), wide=True)


def _cve_section(devices, ids: dict) -> str:
    """The known CVEs found, the worst first, each with the devices it was found on; then each
    device's finding (what it runs, and the firmware that fixes it)."""
    found = {}
    for d in devices:
        for m in d.cves or ():
            found.setdefault(m.cve["id"], (m, []))[1].append(d)
    with_cves = [d for d in devices if d.cves or any(tag == "CVE" for _, tag, _ in d.issues)]
    unchecked = sum(1 for d in devices if d.cves is None and d.firmware)
    listed = escape(vulns.list_label())
    if with_cves:
        cves = tr("{count} known CVEs", count=len(found)) if len(found) != 1 else tr("{count} known CVE", count=1)
        on = (tr("{count} devices", count=len(with_cves)) if len(with_cves) != 1
              else tr("{count} device", count=len(with_cves)))
        intro = tr("{cves} on {devices}, from the {list}.", cves=cves, devices=on, list=listed)
    else:
        intro = tr("No device matches a known CVE, from the {list}.", list=listed)
    if not unchecked:
        proof = _("No match isn't proof a device is safe: only models and firmware versions discovery identifies "
                  "for certain are checked.")
    elif unchecked == 1:
        proof = tr("No match isn't proof a device is safe: only models and firmware versions discovery identifies "
                   "for certain are checked; {count} device reported firmware the list doesn't cover.", count=1)
    else:
        proof = tr("No match isn't proof a device is safe: only models and firmware versions discovery identifies "
                   "for certain are checked; {count} devices reported firmware the list doesn't cover.",
                   count=unchecked)
    out = [f"<h2>{tr('Known CVEs ({count})', count=len(found)) if found else _('Known CVEs')}</h2>"
           f"<p>{i18n.sentences(intro, proof)}</p>"]
    rows = []
    for cve_id, (m, hit) in sorted(found.items(), key=lambda f: (-(f[1][0].cve.get("score") or 0), f[0])):
        severity = m.cve.get("severity") or "unrated"
        score = m.cve.get("score")
        rows.append([f'<a href="{vulns.nvd_url(cve_id)}">{escape(cve_id)}</a>',
                     f'<span class="{_LEVEL_CLASS[vulns.LEVELS.get(severity, "warn")]}">{escape(_(severity))}'
                     f'{f" {score:g}" if score is not None else ""}</span>', escape(m.fixed or _("none named")),
                     escape(m.cve.get("summary") or ""),
                     ", ".join(_ip_link(d, ids) for d in hit)])
    if rows:
        out.append(_report_table(["CVE", _("Severity"), _("Fixed in"), _("Summary"), _("Found on")], rows,
                                 nowrap=(0,), wide=True))
    out += _issue_section(devices, ("CVE",), ids)
    if found:
        out.append('<p class="muted">'
                   + i18n.sentences(tr("Each CVE's page: {url}.", url=escape(vulns.nvd_url(_("<CVE ID>")))),
                                    escape(_(vulns.NVD_NOTICE))) + "</p>")
    return "\n".join(out)


def _firmware_section(devices, ids: dict) -> str:
    """The devices running older firmware than the latest Ubiquiti's firmware server lists."""
    checked = [(d, *latest_firmware(d)) for d in devices]
    checked = [(d, latest, outdated) for d, latest, outdated in checked if latest]
    newer = [(d, latest) for d, latest, outdated in checked if outdated]
    if not checked:
        return (f"<h2>{_('Firmware updates')}</h2><p>"
                + _("The latest firmware wasn't looked up in this scan (Check firmware versions during scans is off "
                    "in Settings, or Ubiquiti's firmware server didn't answer).") + "</p>")
    if not newer:
        return (f"<h2>{_('Firmware updates')}</h2><p class=\"ok\">"
                + (tr("All {count} devices whose latest firmware Ubiquiti's firmware server lists run it.",
                      count=len(checked)) if len(checked) != 1
                   else tr("All {count} device whose latest firmware Ubiquiti's firmware server lists run it.",
                           count=len(checked))) + "</p>")
    rows = []
    for d, latest in newer:
        found = (d.health or {}).get("firmware") or {}
        fix = cve_fix(d)
        rows.append([_ip_link(d, ids), escape(d.name),
                     escape(d.model), escape(found.get("current") or d.firmware), f"<b>{escape(latest)}</b>",
                     escape(found.get("date") or ""),
                     f'<span class="error">{tr("{version} or later", version=escape(fix))}</span>' if fix else ""])
    older = (tr("{count} of {total} devices whose latest firmware Ubiquiti's firmware server lists run an older "
                "version.", count=len(newer), total=len(checked)) if len(checked) != 1
             else tr("{count} of {total} device whose latest firmware Ubiquiti's firmware server lists run an older "
                     "version.", count=len(newer), total=len(checked)))
    return (f"<h2>{tr('Firmware updates ({count})', count=len(newer))}</h2><p>{older}</p>"
            + _report_table(["IP", _("Name"), _("Model"), _("Runs"), _("Latest"), _("Released"),
                             _("Fixes its known CVEs")], rows, nowrap=(0,), wide=True))


def _ms(value: float) -> str:
    return f"{value:.1f}" if value < 10 else f"{value:.0f}"


def _latency_cells(d) -> list:
    """[average, range, replies] of the pings after the scan, or None when it wasn't pinged."""
    lat = (d.health or {}).get("latency") or {}
    sent, replies = lat.get("sent") or 0, lat.get("replies_ms") or []
    if not sent:
        return None
    if not replies:
        return [_("no reply"), "", tr("{count} of {total}", count=0, total=sent)]
    lost = sent - len(replies)
    return [f"{_ms(sum(replies) / len(replies))} ms", f"{_ms(min(replies))}–{_ms(max(replies))} ms",
            tr("{count} of {total} ({percent}% lost)", count=len(replies), total=sent, percent=round(lost * 100 / sent))
            if lost else tr("{count} of {total}", count=len(replies), total=sent)]


def _latency_table(devices, tags, ids: dict) -> str:
    """What the pings after the scan measured: the devices flagged, then the slowest others."""
    measured = [(d, _latency_cells(d)) for d in devices]
    measured = [(d, cells) for d, cells in measured if cells]
    if not measured:
        return "<p>" + _("Latency wasn't measured in this scan.") + "</p>"

    def average(d):
        replies = d.health["latency"].get("replies_ms") or []
        return sum(replies) / len(replies) if replies else -1

    flagged = [m for m in measured if any(tag in tags for _, tag, _ in m[0].issues)]
    rest = sorted((m for m in measured if m not in flagged), key=lambda m: -average(m[0]))
    rows = [[_ip_link(d, ids), escape(d.name), escape(d.model), *cells] for d, cells in flagged + rest[:LATENCY_SHOWN]]
    answered = sum(1 for d, _ in measured if average(d) >= 0)
    count, total = answered, len(measured)
    if flagged:
        said = (tr("{count} of {total} devices pinged after the scan answered; those flagged come first, then the rest "
                   "slowest first.", count=count, total=total) if total != 1
                else tr("{count} of {total} device pinged after the scan answered; those flagged come first, then the "
                        "rest slowest first.", count=count, total=total))
    else:
        said = (tr("{count} of {total} devices pinged after the scan answered; they're listed slowest first.",
                   count=count, total=total) if total != 1
                else tr("{count} of {total} device pinged after the scan answered; they're listed slowest first.",
                        count=count, total=total))
    out = [f"<p>{said}</p>",
           _report_table(["IP", _("Name"), _("Model"), _("Average"), _("Range"), _("Replies")], rows, nowrap=(0, 3, 4),
                         wide=True)]
    left = rest[LATENCY_SHOWN:]
    if left:
        slowest = _ms(max(average(d) for d, _ in left))
        out.append('<p class="muted">'
                   + (tr("{count} other devices answered in {milliseconds} ms or less on average.", count=len(left),
                         milliseconds=slowest) if len(left) != 1
                      else tr("{count} other device answered in {milliseconds} ms or less on average.", count=1,
                              milliseconds=slowest)) + "</p>")
    return "\n".join(out)


def _link_section(devices, title, tags, ids: dict) -> str:
    """airMAX radios whose link was read (Link health…) or flagged: each one's findings, then its
    reading (linkhealth.html). Left out when no radio's link was read."""
    links = _linkhealth()
    blocks = []
    for d in devices:
        found = [i for i in d.issues if i[1] in tags]
        reading = links.html(d) if links is not None and (d.health or {}).get("link") else ""
        if found or reading:
            blocks.append(f'<div class="device">{_device_heading(d, ids)}'
                          + (f"<ul>{_issue_list(d, found)}</ul>" if found
                             else f'<p class="ok">{_("Nothing flagged.")}</p>')
                          + f"{reading}</div>")
    if not blocks:
        return ""
    flagged = sum(1 for d in devices if any(tag in tags for _, tag, _ in d.issues))
    return f"<h2>{escape(_(title))}{f' ({flagged})' if flagged else ''}</h2>" + "\n".join(blocks)


def _notes_section(rows, ids: dict) -> str:
    noted = [d for d, _ in rows if d.note]
    if not noted:
        return ""
    return (f"<h2>{tr('Device notes ({count})', count=len(noted))}</h2>"
            + _report_table(["IP", _("Device"), _("Note")], [[_ip_link(d, ids), escape(_who(d)),
                                                              f'<div class="note">{escape(d.note)}</div>']
                                                             for d in noted], nowrap=(0,)))


def report_file_name(site: str) -> str:
    """opendisco-site-report-<site>-<when>.html, with only characters every file system takes."""
    return f"opendisco-site-report-{f'{_safe(site)}-' if site.strip() else ''}{time.strftime('%Y%m%d-%H%M')}.html"


def site_report(res, site: str = "", demo: bool = False) -> str:
    """The Site Report: a scan as one self-contained HTML page that opens on any phone or computer
    and prints cleanly (or saves as PDF): the site, when and how it was scanned, a summary, every
    device, then known CVEs, factory logins, firmware updates, latency, every other issue device by
    device, and the devices' notes. site: the name in its heading; demo: stamped as the demo
    network's (DEMO_STAMP)."""
    rows = core.tree_order(res.devices)
    devices = [d for d, _ in rows]
    ids = {d.key: n for n, d in enumerate(devices, 1)}
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(getattr(res, "finished", None) or time.time()))
    networks = scanned_networks(res)
    heard = sum(1 for d in devices if d.ubnt_packets)
    took = (tr("{count}, {answered} answered UBNT discovery; the scan took {seconds:.0f}{unit} (stopped early)",
               count=len(devices), answered=heard, seconds=res.elapsed, unit=SECONDS) if res.interrupted
            else tr("{count}, {answered} answered UBNT discovery; the scan took {seconds:.0f}{unit}",
                    count=len(devices), answered=heard, seconds=res.elapsed, unit=SECONDS))
    facts = [(_("Scanned"), when), (_("Mode"), scan_mode(res.opts)),
             *([(_("Networks"), ", ".join(networks))] if networks else []), (_("Devices"), took)]
    head = ((f'<div class="stamp">{escape(_(DEMO_STAMP))}</div>' if demo else "")
            + (f'<p class="kicker">{_("Site Report")}</p><h1>{escape(site)}</h1>' if site
               else f"<h1>{_('Site Report')}</h1>")
            + '<dl class="facts">' + "".join(f"<dt>{escape(k)}</dt><dd>{escape(v)}</dd>" for k, v in facts) + "</dl>")
    out = [f"<header>{head}</header>", f"<h2>{_('Summary')}</h2>", _summary(devices, ids),
           f"<h2>{tr('Devices ({count})', count=len(devices))}</h2>",
           _device_table(rows, ids) if rows else f"<p>{_('No devices were found.')}</p>", _cve_section(devices, ids)]
    title, tags = REPORT_SECTIONS[0]
    found = _issue_section(devices, tags, ids)
    out.append(f"<h2>{escape(_(title))}{f' ({len(found)})' if found else ''}</h2>" + ("\n".join(found) if found else
               f'<p class="ok">{_("No device takes its factory login or reports factory defaults.")}</p>'))
    out.append(_firmware_section(devices, ids))
    title, tags = REPORT_SECTIONS[1]
    found = _issue_section(devices, tags, ids)
    out.append(f"<h2>{escape(_(title))}{f' ({len(found)})' if found else ''}</h2>"
               + _latency_table(devices, tags, ids) + "\n".join(found))
    out.append(_link_section(devices, *REPORT_SECTIONS[2], ids))
    others = _issue_section(devices, None, ids)
    out.append(f"<h2>{tr('Other issues ({count})', count=len(others))}</h2>" + "\n".join(others) if others else
               f'<h2>{_("Other issues")}</h2><p class="ok">{_("None.")}</p>')
    out.append(_notes_section(rows, ids))
    wire = res.wire_text(verbose=True)
    if wire:
        out.append(f"<h2>{escape(_(res.wire_title()))}</h2><pre>{escape(wire)}</pre>")
    if res.notes:
        out.append(f"<h2>{_('Scan notes')}</h2><ul>" + "".join(f"<li>{escape(msg)}</li>" for _, msg in res.notes)
                   + "</ul>")
    made = tr("Made {date} by OpenDisco {version}.", date=time.strftime("%Y-%m-%d %H:%M"), version=__version__)
    out.append(f"<footer>{made}</footer>")
    title = " · ".join(x for x in (_("Site Report"), site, when, _("Demo") if demo else "") if x)
    return (f'<!doctype html><html lang="{i18n.language}"><head><meta charset="utf-8">\n'
            f'<meta name="viewport" content="width=device-width, initial-scale=1"><title>{escape(title)}</title>\n'
            f"<style>{_REPORT_CSS}</style>\n</head><body>\n" + "\n".join(o for o in out if o) + "\n</body></html>\n")


# -- Settings: "Also sweep these subnets" ---------------------------------------------------
def _addresses(net: ipaddress.IPv4Network) -> int:
    """How many addresses the sweep sends to (core.expand_targets: every host of the subnet)."""
    return net.num_addresses if net.prefixlen >= 31 else net.num_addresses - 2


def _check(spec: str):
    """(the network, "") or (None, what's wrong with it)."""
    if ":" in spec:
        return None, tr("{spec} is IPv6: UBNT discovery runs over IPv4", spec=spec)
    if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?", spec):
        if re.search(r"[A-Za-z]", spec):
            return None, tr("{spec!r} isn't an IPv4 subnet or address: write one like 10.20.0.0/24 or 10.20.0.7 "
                            "(names aren't looked up here)", spec=spec)
        return None, tr("{spec!r} isn't an IPv4 subnet or address: write one like 10.20.0.0/24 or 10.20.0.7", spec=spec)
    try:
        net = ipaddress.IPv4Network(spec, strict=False)
    except ValueError:
        return None, tr("{spec} isn't a valid address: each part is 0 to 255, and the mask /0 to /32", spec=spec)
    first = net.network_address
    for test, why in ((first.is_loopback, tr("{network} is this computer's own loopback", network=net)),
                      (first.is_multicast, tr("{network} is multicast, not devices", network=net)),
                      (first.is_link_local, tr("{network} is link-local, which no router or VPN forwards",
                                               network=net)),
                      (int(first) >> 24 == 0, tr("{network} isn't an address devices use", network=net)),
                      (first.is_reserved, tr("{network} is reserved (240.0.0.0 and up), not devices", network=net))):
        if test:
            return None, why
    if net.prefixlen < 16:
        return None, tr("{network} is larger than a /16 ({count:,} addresses): give the subnets the gear is on",
                        network=net, count=net.num_addresses)
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
                problems.append(tr("Line {line}: {problem}.", line=n, problem=why))
                continue
            if net in seen:
                continue
            seen.add(net)
            total += _addresses(net)
            targets.append(str(net.network_address) if net.prefixlen == 32 else str(net))
    if total > SWEEP_LIMIT:
        problems.append(tr("These add up to {count:,} addresses, about {seconds:.0f}{unit} more on every scan; the "
                           "limit is {limit:,} (a /19's worth). List the subnets the gear is on.", count=total,
                           seconds=sweep_seconds(total), unit=SECONDS, limit=SWEEP_LIMIT))
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
    listed = (tr("{targets} and {count} more", targets=", ".join(targets[:4]), count=len(targets) - 4)
              if len(targets) > 4 else ", ".join(targets))
    seconds = max(1, round(sweep_seconds(total)))
    if total != 1:
        return tr("{targets} ({count:,} addresses, about {seconds}{unit})", targets=listed, count=total,
                  seconds=seconds, unit=SECONDS)
    return tr("{targets} ({count:,} address, about {seconds}{unit})", targets=listed, count=total, seconds=seconds,
              unit=SECONDS)
