#!/usr/bin/env python3
"""Regenerate the built-in CVE list, src/opendisco/resources/cves.json, from current NVD data and
the ranges checked by hand in src/opendisco/vulns.py (CURATED). The app's "check for new CVEs"
runs the same build. Run: .venv/bin/python packaging/update_cves.py
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
    except (OSError, ValueError, TimeoutError) as e:
        print(f"Couldn't fetch from the NVD: {e}", file=sys.stderr)
        return 1
    data = vulns.build_rules(cves)
    vulns.BUNDLED.write_text(vulns.dumps(data), encoding="utf-8")
    families = collections.Counter(a["family"] for c in data["cves"] for a in {a["family"]: a for a in c["affects"]}.values())
    print(f"Wrote {vulns.BUNDLED}: {len(data['cves'])} CVEs as of {data['generated']} "
          f"({sum(c['curated'] for c in data['cves'])} checked by hand), from {len(cves)} NVD records")
    print("  " + ", ".join(f"{family} {n}" for family, n in sorted(families.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
