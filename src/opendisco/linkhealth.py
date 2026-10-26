"""Link health for airMAX radios (airOS 8 on AC, airOS 5 and 6 on M): what a radio says of its own
wireless link and, on an access point, of each station's, read over SSH (Device > Link health on
desktops, Tools on phones), and flagged when it's weak, the way health.py flags latency.

- devicetools.read_link runs two of airOS's own commands: mca-status (the radio itself, key=value
  lines: mode, channel, noise floor, and on a station its signal, chains and rates) and wstalist
  (the stations associated with it, JSON: on an AP each station, on a station its AP).
- parse() makes them one plain dict (the reading), which keep() puts on the device,
  d.health["link"], and in READINGS by MAC for the rest of the app's run: a new scan finds the
  device afresh, and core.diagnose gives it its reading back (apply), then flags it (issues).
- Signal, noise floor, SNR (signal over the noise floor) and CINR in dB(m); capacities and rates
  in Mbps; airtime in percent; distance in metres.

Standard library only, like core; devicetools (which imports core) does the SSH part.
"""
from __future__ import annotations

import json
import re
import time

from opendisco import core, i18n
from opendisco.i18n import _, N_, tr

# The reading of each radio read this run, by MAC: {mac: reading}. diagnose puts it back on the
# device after a new scan (apply). Not kept past the run: a link's numbers are of the moment.
READINGS = {}

# Ubiquiti's guidance, from the UISP Help Center:
# - "airMAX - Frequently Asked Questions (FAQs)", What is the best signal strength and noise floor?:
#   the signal should be between -45 and -65 dBm, and -40 dBm or stronger "can increase EVM and
#   reduce performance"; an SNR of at least 25, preferably 30 or more. What is airMAX Capacity (AMC)
#   & airMAX Quality (AMQ)? (airMAX M): AMQ above 80% needs no changes; AMC is the share of the
#   rate the link could reach (a 1x1 radio's is 50% at most, half a 2x2's).
# - "ISP Wireless - Link with Poor Wireless Performance": CINR is "basically SNR in dB"; the MIMO
#   chains' signals should be less than 4 dB apart, and the signal within 1-2 dB of the one the
#   link's design expects.
# Ubiquiti says which signal is needed is a matter of the SNR, so a weak signal alone is a note
# and a low SNR a warning. It gives no figure for capacity: half of what airOS expects of the link
# (airOS 8), or an AMC under a perfect 1x1 link's 50% (airMAX M), is flagged.
WEAK_SIGNAL_DBM = -65  # weaker than this: WEAK-SIGNAL
HOT_SIGNAL_DBM = -40  # this or stronger: HOT-SIGNAL
LOW_SNR_DB = 25  # an SNR (or CINR) under this: LOW-SNR
CHAINS_APART_DB = 4  # chains this far apart: CHAIN-IMBALANCE
LOW_CAPACITY_SHARE = 0.5  # airOS 8: capacity under this share of the expected one: LOW-CAPACITY
LOW_AMC_PCT = 50  # airMAX M: airMAX Capacity under this: LOW-CAPACITY
LOW_AMQ_PCT = 80  # airMAX M: airMAX Quality under this: LOW-QUALITY

# airMAX AC firmware platforms (devicetools.AIROS_PLATFORMS has M's too): CINR means something
# only between two of them.
AC_PLATFORMS = {"XC", "WA", "2XC", "2WA"}
NAMED = 4  # radios named in an issue's message; "and N more" for the rest
_MAC = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")


# ---------------------------------------------------------------------------
# Reading airOS's output
# ---------------------------------------------------------------------------

def mca_status(lines) -> dict:
    """mca-status: a first line of comma-separated key=value pairs (deviceName, deviceId,
    firmwareVersion, platform, deviceIp), then a key=value pair a line. The first line is split
    only where a new key follows, as a name may have a comma in it."""
    found = {}
    for line in lines:
        parts = re.split(r",(?=[A-Za-z][A-Za-z0-9_]*=)", line) if line.startswith("deviceName=") else [line]
        for part in parts:
            key, sep, value = part.partition("=")
            if sep and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", key.strip()):
                found[key.strip()] = value.strip()
    return found


def station_list(text: str) -> list:
    """wstalist's JSON: a list of stations (some versions wrap it in an object). [] when it
    isn't JSON (no wstalist on the device, or a message in its place)."""
    try:
        stations = json.loads(text) if text.strip() else []
    except ValueError:
        return []
    if isinstance(stations, dict):
        stations = stations.get("stations") or stations.get("sta") or []
    return [s for s in stations if isinstance(s, dict)] if isinstance(stations, list) else []


def _number(value) -> float | None:
    """A number from airOS's output: 300.0, "300.0", "130 Mbps"; None for anything else."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    m = re.match(r"\s*(-?\d+(?:\.\d+)?)", str(value or ""))
    return float(m.group(1)) if m else None


def _level(value) -> float | None:
    """A signal or noise level in dBm: airOS gives 0 where it has none."""
    n = _number(value)
    return n if n is not None and n < 0 else None


def _positive(value) -> float | None:
    n = _number(value)
    return n if n is not None and n > 0 else None


def _round(value, digits: int = 0):
    if value is None:
        return None
    return int(round(value)) if digits == 0 else round(value, digits)


def _chains(rssi, offset: float | None) -> list:
    """Each receive chain's signal in dBm. wstalist gives them as RSSI (chainrssi), on the scale
    of its own rssi, which is the signal plus 96 (rssi 44 with signal -52 dBm, in airOS 8.7
    captures): offset is signal minus rssi. A chain the radio hasn't (RSSI 0) is left out."""
    if not isinstance(rssi, list) or offset is None:
        return []
    return [_round(r + offset) for r in (_positive(v) for v in rssi) if r is not None]


def _is_ac(firmware: str) -> bool | None:
    """Whether firmware ("WA.ar934x.v8.7.18...") is airMAX AC's; None when unknown."""
    m = re.match(r"([A-Za-z0-9]+)\.", firmware or "")
    return m.group(1).upper() in AC_PLATFORMS if m else None


def _peer(s: dict, here_ac: bool | None) -> dict:
    """One wstalist entry: the radio at the other end of a link (a station on an AP, the AP on
    a station). "signal" and the rest are as this radio hears it, "remote_..." as it hears this one.

    Where each comes from (airOS 8 field names from captures of airOS 8.7 radios; airOS 5 and 6
    from the airOS SDK's own readers of wstalist, tinysnmp's airos-stats.c and the web UI's
    stalist.js):
      mac, lastip, name                  the station's MAC, its last IP, the name it's given
      signal, rssi, noisefloor           what this radio hears of it (dBm; rssi = signal + 96);
                                         noisefloor is this radio's own
      chainrssi                          each chain's RSSI (_chains)
      remote.signal, .noisefloor,        the same as the other radio hears this one (airOS 8);
        .chainrssi, .rssi                remote.hostname, .platform and .version name it
      airmax.rx.cinr, airmax.tx.cinr     CINR here and at the other end (airOS 7 and 8, AC)
      airmax.dl_capacity, .ul_capacity   the capacity down (AP to station) and up, in kbit/s (airOS 8)
      dl_capacity_expect, ul_...         what the link's design expects of it, kbit/s; 0 when none
      airmax.tx.usage, airmax.rx.usage   the airtime it takes sending and receiving, in tenths of
                                         a percent (the AP's wireless.polling.use, their sum, reads
                                         266 on a busy sector)
      tx, rx                             the data rate to and from it, Mbit/s (airOS 5 and 6)
      airmax.quality, airmax.capacity    airMAX Quality and Capacity, percent (airMAX M)
      ccq                                its CCQ, percent (tenths in some versions)
      distance, tx_latency, uptime       metres (0: unknown), ms, seconds associated
    """
    airmax = s.get("airmax") if isinstance(s.get("airmax"), dict) else {}
    remote = s.get("remote") if isinstance(s.get("remote"), dict) else {}
    rx = airmax.get("rx") if isinstance(airmax.get("rx"), dict) else {}
    tx = airmax.get("tx") if isinstance(airmax.get("tx"), dict) else {}
    signal, rssi = _level(s.get("signal")), _positive(s.get("rssi"))
    remote_signal, remote_rssi = _level(remote.get("signal")), _positive(remote.get("rssi"))
    noise, remote_noise = _level(s.get("noisefloor")), _level(remote.get("noisefloor"))
    firmware = str(remote.get("version") or "")
    # Between an AC radio and an M one (in compatibility mode) airOS still lists a CINR, 3 dB in a
    # capture of one with a strong signal: it says nothing, so it's left out.
    there_ac = _is_ac(firmware)
    cinr_ok = here_ac is not False and there_ac is not False
    ccq = _positive(s.get("ccq"))

    def capacity(key):
        kbps = _positive(airmax.get(key) if key in airmax else s.get(key))
        return _round(kbps / 1000, 1) if kbps else None

    def usage(side):
        tenths = _number(side.get("usage"))
        return _round(tenths / 10, 1) if tenths is not None and tenths >= 0 else None

    return {
        "mac": core.norm_mac(str(s["mac"])) if _MAC.fullmatch(str(s.get("mac", ""))) else "",
        "ip": "" if str(s.get("lastip") or "0.0.0.0") == "0.0.0.0" else str(s["lastip"]),
        "name": str(remote.get("hostname") or s.get("name") or ""),
        "model": str(remote.get("platform") or ""),
        "firmware": firmware,
        "signal_dbm": _round(signal),
        "chains_dbm": _chains(s.get("chainrssi"), signal - rssi if signal is not None and rssi else -96.0),
        "noise_dbm": _round(noise),
        "snr_db": _round(signal - noise) if signal is not None and noise is not None else None,
        "cinr_db": _round(_positive(rx.get("cinr"))) if cinr_ok else None,
        "remote_signal_dbm": _round(remote_signal),
        "remote_chains_dbm": _chains(remote.get("chainrssi"), remote_signal - remote_rssi
                                     if remote_signal is not None and remote_rssi else -96.0),
        "remote_noise_dbm": _round(remote_noise),
        "remote_snr_db": (_round(remote_signal - remote_noise)
                          if remote_signal is not None and remote_noise is not None else None),
        "remote_cinr_db": _round(_positive(tx.get("cinr"))) if cinr_ok else None,
        "dl_capacity_mbps": capacity("dl_capacity"),
        "ul_capacity_mbps": capacity("ul_capacity"),
        "dl_expected_mbps": capacity("dl_capacity_expect"),
        "ul_expected_mbps": capacity("ul_capacity_expect"),
        "tx_rate_mbps": _round(_positive(s.get("tx")), 1),
        "rx_rate_mbps": _round(_positive(s.get("rx")), 1),
        "airtime_tx_pct": usage(tx),
        "airtime_rx_pct": usage(rx),
        "quality_pct": _round(_positive(airmax.get("quality"))),  # 0 with airMAX off
        "capacity_pct": _round(_positive(airmax.get("capacity"))),
        "ccq_pct": _round(ccq / 10 if ccq and ccq > 100 else ccq),
        "distance_m": _round(_positive(s.get("distance"))),
        "latency_ms": _round(_number(s.get("tx_latency"))),
        "uptime_s": _round(_number(s.get("uptime"))),
    }


def parse(status_lines, stations_text: str, at: float | None = None) -> dict:
    """The reading: mca-status's lines and wstalist's JSON made one dict.

    From mca-status (the radio itself; the same keys on airOS 6 and 8):
      wlanOpmode                  its mode: "ap", "sta" (airOS 5 and 6), "ap-ptmp", "sta-ptp"... (8)
      essid, freq, chanbw         the SSID, frequency (MHz) and channel width (MHz)
      txPower, wlanConnections    its output power (dBm) and how many stations are associated
      noise                       its noise floor (dBm)
      signal, chain0Signal...     on a station, the AP's signal and each chain's (dBm); a chain
                                  at -96 dBm (RSSI 0) it hasn't
      wlanTxRate, wlanRxRate      on a station, the data rate to and from the AP (Mbit/s)
      wlanPollingQuality,         airMAX Quality and Capacity (airMAX M; on an AP, the average
        wlanPollingCapacity       of its stations')
      ccq                         CCQ, in tenths of a percent
      distance, wlanTxLatency     the link's distance (metres) and latency (ms)
      apMac                       on a station, its AP's MAC
    A station's own link is its one wstalist entry, its AP, with what mca-status adds."""
    mca = mca_status(status_lines)
    mode = mca.get("wlanOpmode", "")
    ap = mode.startswith("ap")
    here_ac = _is_ac(mca.get("firmwareVersion", ""))
    peers = [_peer(s, here_ac) for s in station_list(stations_text)]
    chains = [_round(c) for c in (_level(mca.get(f"chain{n}Signal")) for n in range(4)) if c is not None and c > -96]
    rate = {k: _number(mca.get(k)) for k in ("wlanTxRate", "wlanRxRate")}
    rate = {k: (v / 1e6 if v >= 100000 else v) if v else None for k, v in rate.items()}  # some report bit/s
    ccq = _positive(mca.get("ccq"))
    # airMAX Quality and Capacity are airMAX M's (AC gives its capacity in Mbps), and 0 with airMAX off
    polling = here_ac is not True and mca.get("wlanPolling") != "0"
    reading = {
        "at": time.time() if at is None else at,
        "mode": mode,
        "ap": ap,
        "essid": mca.get("essid", ""),
        "frequency_mhz": _round(_positive(mca.get("freq"))),
        "width_mhz": _round(_positive(mca.get("chanbw"))),
        "tx_power_dbm": _round(_number(mca.get("txPower"))),
        "noise_dbm": _round(_level(mca.get("noise"))),
        "stations_associated": _round(_number(mca.get("wlanConnections"))),
        "ap_mac": (core.norm_mac(mca["apMac"]) if _MAC.fullmatch(mca.get("apMac", ""))
                   and mca["apMac"] != "00:00:00:00:00:00" else ""),  # all zeros: not associated
        "signal_dbm": None if ap else _round(_level(mca.get("signal"))),
        "chains_dbm": [] if ap else chains,
        "tx_rate_mbps": None if ap else _round(rate["wlanTxRate"], 1),
        "rx_rate_mbps": None if ap else _round(rate["wlanRxRate"], 1),
        "quality_pct": _round(_positive(mca.get("wlanPollingQuality"))) if polling else None,
        "capacity_pct": _round(_positive(mca.get("wlanPollingCapacity"))) if polling else None,
        "ccq_pct": _round(ccq / 10 if ccq and ccq > 100 else ccq),
        "distance_m": _round(_positive(mca.get("distance"))),
        "latency_ms": _round(_number(mca.get("wlanTxLatency"))),
        "stations": peers,
    }
    if not ap and not peers and reading["signal_dbm"] is not None:  # a station whose wstalist said nothing
        peers.append(_peer({"mac": reading["ap_mac"]}, here_ac))
    if not ap and peers:  # its link to its AP: what mca-status says fills in what wstalist doesn't
        link = peers[0]
        for key, value in (("signal_dbm", reading["signal_dbm"]), ("chains_dbm", chains),
                           ("noise_dbm", reading["noise_dbm"]), ("tx_rate_mbps", reading["tx_rate_mbps"]),
                           ("rx_rate_mbps", reading["rx_rate_mbps"]), ("quality_pct", reading["quality_pct"]),
                           ("capacity_pct", reading["capacity_pct"]), ("ccq_pct", reading["ccq_pct"]),
                           ("distance_m", reading["distance_m"]), ("latency_ms", reading["latency_ms"])):
            if link.get(key) in (None, []) and value not in (None, []):
                link[key] = value
        if link.get("snr_db") is None and link.get("signal_dbm") is not None and link.get("noise_dbm") is not None:
            link["snr_db"] = link["signal_dbm"] - link["noise_dbm"]
    return reading


# ---------------------------------------------------------------------------
# Keeping it
# ---------------------------------------------------------------------------

def keep(d, reading: dict) -> None:
    """The reading on the device, and in READINGS by its MAC for the rest of the run."""
    d.health["link"] = reading
    if d.mac:
        READINGS[core.norm_mac(d.mac)] = reading


def apply(d) -> None:
    """Give a device found again (a new scan) its reading of this run (core.diagnose)."""
    reading = READINGS.get(core.norm_mac(d.mac)) if d.mac else None
    if reading is not None:
        d.health["link"] = reading


def reading_of(d) -> dict | None:
    return d.health.get("link") or None


# ---------------------------------------------------------------------------
# Issues
# ---------------------------------------------------------------------------

def _who(p: dict) -> str:
    return p.get("name") or p.get("ip") or p.get("mac") or _("a station")


def _ends(reading: dict) -> tuple:
    """What this radio and the other end are called: ("the AP", "the station") or the other way."""
    return (_("the AP"), _("the station")) if reading["ap"] else (_("this station"), _("the AP"))


def _dbm(value) -> str:
    return f"{value} dBm"


def _at(value, end: str) -> str:
    """A reading at one end of the link: "-52 dBm at the AP"."""
    return tr("{value} at {end}", value=value, end=end)


def _and(phrases) -> str:
    """Phrases joined with "and": "a and b and c"."""
    text = phrases[0]
    for phrase in phrases[1:]:
        text = tr("{first} and {second}", first=text, second=phrase)
    return text


def _chain_text(chains) -> str:
    return "/".join(str(c) for c in chains)


def _apart(chains) -> int:
    return max(chains) - min(chains) if len(chains) > 1 else 0


def _ratio(p: dict, remote: bool = False) -> tuple:
    """(dB, "SNR" or "CINR"): the lower of the SNR and the CINR (where airOS gives one) at one end."""
    pre = "remote_" if remote else ""
    found = [(p.get(f"{pre}{k}_db"), k.upper()) for k in ("snr", "cinr") if p.get(f"{pre}{k}_db") is not None]
    return min(found) if found else (None, "")


def _findings(reading: dict) -> list:
    """[(tag, level, peer, text)]: what's wrong with each link, in a phrase about that link."""
    here, there = _ends(reading)
    found = []
    for p in reading.get("stations") or []:
        ends = [(p.get("signal_dbm"), here, p.get("chains_dbm") or []),
                (p.get("remote_signal_dbm"), there, p.get("remote_chains_dbm") or [])]
        weak = [_at(_dbm(s), end) for s, end, _ in ends if s is not None and s < WEAK_SIGNAL_DBM]
        if weak:
            found.append(("WEAK-SIGNAL", "note", p, _and(weak)))
        hot = [_at(_dbm(s), end) for s, end, _ in ends if s is not None and s >= HOT_SIGNAL_DBM]
        if hot:
            found.append(("HOT-SIGNAL", "note", p, _and(hot)))
        apart = [tr("{difference} dB apart at {end} ({chains} dBm)", difference=_apart(c), end=end,
                    chains=_chain_text(c)) for _, end, c in ends if _apart(c) >= CHAINS_APART_DB]
        if apart:
            found.append(("CHAIN-IMBALANCE", "note", p, _and(apart)))
        low = [_at(f"{kind} {db} dB", end) for (db, kind), end in ((_ratio(p), here), (_ratio(p, True), there))
               if db is not None and db < LOW_SNR_DB]
        if low:
            found.append(("LOW-SNR", "warn", p, _and(low)))
        short = []
        for way in ("dl", "ul"):
            got, expected = p.get(f"{way}_capacity_mbps"), p.get(f"{way}_expected_mbps")
            if got and expected and got < LOW_CAPACITY_SHARE * expected:
                short.append(tr("{got:.0f} of the {expected:.0f} Mbps expected down", got=got, expected=expected)
                             if way == "dl" else
                             tr("{got:.0f} of the {expected:.0f} Mbps expected up", got=got, expected=expected))
        if p.get("capacity_pct") is not None and p["capacity_pct"] < LOW_AMC_PCT:
            short.append(tr("airMAX Capacity {percent}%", percent=p["capacity_pct"]))
        if short:
            found.append(("LOW-CAPACITY", "warn", p, _and(short)))
        if p.get("quality_pct") is not None and p["quality_pct"] < LOW_AMQ_PCT:
            found.append(("LOW-QUALITY", "warn", p, tr("airMAX Quality {percent}%", percent=p["quality_pct"])))
    return found


# What each finding means and what to check, after the links it was found on: templates filled with
# ADVICE_LIMITS.
ADVICE = {
    "WEAK-SIGNAL": N_("Ubiquiti recommends {best} to {weak} dBm. A weak signal needs a quiet channel to keep its SNR: "
                      "check the alignment and the line of sight (60% of the first Fresnel zone clear), or use "
                      "higher-gain antennas."),
    "HOT-SIGNAL": N_("At {hot} dBm or stronger, Ubiquiti says, the signal raises EVM and lowers throughput: turn the "
                     "output power down."),
    "CHAIN-IMBALANCE": N_("Ubiquiti says the chains should be less than {apart} dB apart: more points to the "
                          "alignment, or an obstruction or reflection (multipath) on one chain."),
    "LOW-SNR": N_("Ubiquiti recommends an SNR (or CINR) of at least {snr} dB, better 30: the signal is too close to "
                  "the noise and interference, so the link drops to slower modulation. Find a clear channel with "
                  "airView from both ends, narrow the channel width, or raise the signal."),
    "LOW-CAPACITY": N_("A link this far under what it could carry takes more of the AP's airtime for the same data, "
                       "which slows every station on it: check its signal, SNR and alignment."),
    "LOW-QUALITY": N_("Ubiquiti says airMAX Quality above {quality}% needs no changes; lower means retries, likely "
                      "interference: try another channel."),
}
ADVICE_LIMITS = {"best": -45, "weak": WEAK_SIGNAL_DBM, "hot": HOT_SIGNAL_DBM, "apart": CHAINS_APART_DB,
                 "snr": LOW_SNR_DB, "quality": LOW_AMQ_PCT}
WHAT = {"WEAK-SIGNAL": N_("Weak signal"), "HOT-SIGNAL": N_("Signal too strong"), "CHAIN-IMBALANCE": N_("Uneven chains"),
        "LOW-SNR": N_("Low SNR"), "LOW-CAPACITY": N_("Low capacity"), "LOW-QUALITY": N_("Low airMAX Quality")}


def issues(d, advice: bool = True) -> list:
    """Diagnostics from its link reading (core.diagnose adds them), one per kind of finding: on an
    AP naming the stations it's found on, on a station its link to its AP. Each message ends with
    ADVICE, unless advice is False."""
    reading = reading_of(d)
    if not reading:
        return []
    by_tag = {}
    for tag, level, p, text in _findings(reading):
        by_tag.setdefault(tag, (level, []))[1].append((p, text))
    out = []
    for tag, (level, found) in by_tag.items():
        if reading["ap"]:
            of = len(reading.get("stations") or [])
            named = "; ".join(f"{_who(p)}, {text}" for p, text in found[:NAMED])
            more = "; " + tr("and {count} more", count=len(found) - NAMED) if len(found) > NAMED else ""
            which = _("its station") if of == 1 else tr("{count} of its {total} stations", count=len(found), total=of)
            head = tr("{what} on {which}: {stations}.", what=_(WHAT[tag]), which=which, stations=named + more)
        else:
            p, text = found[0]
            named = f" ({p['name']})" if p.get("name") else ""
            head = tr("{what} on its link to its AP{name}: {finding}.", what=_(WHAT[tag]), name=named, finding=text)
        out.append((level, tag, i18n.sentences(head, core.shown(ADVICE[tag], **ADVICE_LIMITS)) if advice else head))
    return out


# ---------------------------------------------------------------------------
# Details, exports and the Log
# ---------------------------------------------------------------------------

def _distance(m) -> str:
    return f"{m / 1000:.1f} km" if m >= 1000 else f"{m} m"


def _mbps(value) -> str:
    return f"{value:.0f}" if value >= 10 else f"{value:.1f}"


def _signal_text(signal, chains, end: str) -> str:
    if len(chains) > 1:
        return tr("{value} at {end} (chains {chains})", value=_dbm(signal), end=end, chains=_chain_text(chains))
    return _at(_dbm(signal), end)


def peer_lines(reading: dict, p: dict) -> list:
    """A link's numbers, a line for each kind, as Details shows them."""
    here, there = _ends(reading)
    lines = []
    signals = [_signal_text(s, c, end) for s, c, end in ((p.get("signal_dbm"), p.get("chains_dbm") or [], here),
               (p.get("remote_signal_dbm"), p.get("remote_chains_dbm") or [], there)) if s is not None]
    if signals:
        lines.append(tr("Signal {readings}", readings=", ".join(signals)))
    noise = [_at(_dbm(n), end) for n, end in ((p.get("noise_dbm"), here), (p.get("remote_noise_dbm"), there))
             if n is not None]
    if noise:
        lines.append(tr("Noise floor {readings}", readings=", ".join(noise)))
    ratios = [f"{kind} {', '.join(_at(f'{v} dB', end) for v, end in pair)}" for kind, pair in (
        ("SNR", [(v, end) for v, end in ((p.get("snr_db"), here), (p.get("remote_snr_db"), there)) if v is not None]),
        ("CINR", [(v, end) for v, end in ((p.get("cinr_db"), here), (p.get("remote_cinr_db"), there))
                  if v is not None])) if pair]
    if ratios:
        lines.append("; ".join(ratios))
    carry = []
    if p.get("dl_capacity_mbps") or p.get("ul_capacity_mbps"):
        expect = (" " + tr("(expected {down} and {up})", down=_mbps(p["dl_expected_mbps"]),
                           up=_mbps(p["ul_expected_mbps"]))
                  if p.get("dl_expected_mbps") and p.get("ul_expected_mbps") else "")
        down, up = p.get("dl_capacity_mbps"), p.get("ul_capacity_mbps")
        carry.append(tr("Capacity {capacities}", capacities=_and(
            ([tr("{rate} Mbps down", rate=_mbps(down))] if down else [])
            + ([tr("{rate} Mbps up", rate=_mbps(up))] if up else []))) + expect)
    if p.get("tx_rate_mbps") or p.get("rx_rate_mbps"):
        tx, rx = p.get("tx_rate_mbps"), p.get("rx_rate_mbps")
        carry.append(tr("Rate {rates}", rates=_and(
            ([tr("{rate} Mbps from {end}", rate=_mbps(tx), end=here)] if tx else [])
            + ([tr("{rate} Mbps to {end}", rate=_mbps(rx), end=here)] if rx else []))))
    amq = []
    if p.get("quality_pct") is not None:
        amq.append(tr("airMAX Quality {percent}%", percent=p["quality_pct"]))
    if p.get("capacity_pct") is not None:
        amq.append(tr("airMAX Capacity {percent}%", percent=p["capacity_pct"]))
    if p.get("ccq_pct") is not None:
        amq.append(f"CCQ {p['ccq_pct']}%")
    if carry or amq:
        lines.append("; ".join(carry + amq))
    rest = []
    if p.get("airtime_tx_pct") is not None or p.get("airtime_rx_pct") is not None:
        rest.append(tr("Airtime at {end} {sending:.1f}% sending, {receiving:.1f}% receiving", end=here,
                       sending=p.get("airtime_tx_pct") or 0, receiving=p.get("airtime_rx_pct") or 0))
    if p.get("distance_m"):
        rest.append(tr("distance {distance}", distance=_distance(p["distance_m"])))
    if p.get("latency_ms") is not None:
        rest.append(tr("latency {latency} ms", latency=p["latency_ms"]))
    if rest:
        text = "; ".join(rest)
        lines.append(text[0].upper() + text[1:])
    return lines


def _summary(reading: dict) -> list:
    """The radio's own, in two lines: its mode, SSID and when it was read; its channel, noise
    floor, output power and stations."""
    mode = reading.get("mode") or "?"
    first = tr("access point ({mode})", mode=mode) if reading["ap"] else tr("station ({mode})", mode=mode)
    if reading.get("essid"):
        first += f", SSID {reading['essid']}"
    first += ", " + tr("read {time}", time=time.strftime("%H:%M:%S", time.localtime(reading["at"])))
    bits = []
    if reading.get("frequency_mhz"):
        bits.append(f"{reading['frequency_mhz']} MHz" + (", " + tr("{width} MHz wide", width=reading["width_mhz"])
                                                         if reading.get("width_mhz") else ""))
    if reading.get("noise_dbm") is not None:
        bits.append(tr("noise floor {value}", value=_dbm(reading["noise_dbm"])))
    if reading.get("tx_power_dbm") is not None:
        bits.append(tr("output {power} dBm", power=reading["tx_power_dbm"]))
    if reading["ap"]:
        n = len(reading.get("stations") or [])
        bits.append(tr("{count} station", count=n) if n == 1 else tr("{count} stations", count=n))
    if not bits:
        return [first]
    text = ", ".join(bits)
    return [first, text[0].upper() + text[1:]]


def _peer_title(p: dict) -> str:
    model = p.get("model") if p.get("model") != p.get("name") else ""
    return ", ".join(x for x in (p.get("name"), p.get("ip"), p.get("mac"), model) if x) or _("unnamed")


def detail_rows(d) -> list:
    """[(label, text)] for Details' Link section, in the app's language: the radio's own, then each link."""
    reading = reading_of(d)
    if not reading:
        return []
    own = _summary(reading)
    rows = [(_("Link"), own[0])] + [("", line) for line in own[1:]]
    peers = reading.get("stations") or []
    if not peers:
        rows.append(("", _("no stations associated") if reading["ap"] else _("not associated with an AP")))
    for n, p in enumerate(peers, 1):
        label = tr("Station {number}", number=n) if reading["ap"] else _("Its AP")
        rows.append((label, _peer_title(p)))
        rows += [("", line) for line in peer_lines(reading, p)]
    return rows


def to_dict(d) -> dict:
    """The JSON export's part: the reading as it was taken (None when the link wasn't read)."""
    reading = reading_of(d)
    if not reading:
        return {"link": None}
    return {"link": {**{k: v for k, v in reading.items() if k != "at"},
                     "read_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(reading["at"]))}}


def html(d) -> str:
    """The HTML export's part: Details' Link rows as a small table ("" when the link wasn't read)."""
    from html import escape
    rows = detail_rows(d)
    if not rows:
        return ""
    cells = "".join(f"<tr><th>{escape(label)}</th><td>{escape(text)}</td></tr>" for label, text in rows)
    return f'<table class="link">{cells}</table>'


def summary(d) -> str:
    """A reading in a line, for the Log and status bar."""
    reading = reading_of(d)
    if not reading:
        return tr("Link health of {ip}: not read.", ip=d.ip)
    flagged = [core.status_label(tag) for _, tag, _ in issues(d)]
    peers = reading.get("stations") or []
    if reading["ap"]:
        what = tr("{count} station", count=len(peers)) if len(peers) == 1 else tr("{count} stations", count=len(peers))
    else:
        p = peers[0] if peers else {}
        what = (tr("its AP at {signal}", signal=_dbm(p["signal_dbm"])) if p.get("signal_dbm") is not None
                else _("not associated") if not peers else _("its AP"))
    if flagged:
        return tr("Link health of {ip}: {state}; {findings}.", ip=d.ip, state=what, findings=", ".join(flagged))
    return tr("Link health of {ip}: {state}, nothing flagged.", ip=d.ip, state=what)
