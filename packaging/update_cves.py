#!/usr/bin/env python3
"""Regenerate the built-in CVE list, src/opendisco/resources/cves.json, from current NVD data,
Ubiquiti's bulletins newer than vulns.BULLETINS_REVIEWED, and the ranges checked by hand in
src/opendisco/vulns.py (CURATED). The app's "check for new CVEs" runs the same build.
Run: .venv/bin/python packaging/update_cves.py

Bulletins it leaves out (a product or a condition it doesn't understand) are listed: read those
by hand into CURATED, then move BULLETINS_REVIEWED to the day of the newest one.
"""
import collections
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from opendisco import vulns  # noqa: E402


def main() -> int:
    print("Fetching from the NVD...")
    try:
        cves = vulns.fetch_nvd(log=print, timeout=120.0)
        print(f"Reading Ubiquiti's bulletins published after {vulns.BULLETINS_REVIEWED}...")
        advisories, skipped = vulns.fetch_bulletins(timeout=120.0)
    except (OSError, ValueError, KeyError, TimeoutError) as e:
        print(f"Couldn't fetch: {e}", file=sys.stderr)
        return 1
    for ids, why, title in skipped:
        print(f"  left out {', '.join(ids)} ({title}): {why}")
    data = vulns.build_rules(cves, advisories)
    vulns.BUNDLED.write_text(vulns.dumps(data), encoding="utf-8")
    families = collections.Counter(family for c in data["cves"] for family in {a["family"] for a in c["affects"]})
    sources = collections.Counter(c["source"] for c in data["cves"])
    print(f"Wrote {vulns.BUNDLED}: {len(data['cves'])} CVEs as of {data['generated']} "
          f"({', '.join(f'{n} {s}' for s, n in sorted(sources.items()))}), from {len(cves)} NVD records")
    print("  " + ", ".join(f"{family} {n}" for family, n in sorted(families.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
