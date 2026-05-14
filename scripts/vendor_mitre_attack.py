#!/usr/bin/env python3
"""Fetch the MITRE ATT&CK Enterprise STIX bundle and extract the set of valid
tactic + technique IDs into a slim JSON file vendored alongside the source.

The full STIX bundle is ~46 MB; we only need the IDs themselves, which fit in a
few KB. Run this script whenever the upstream bundle is refreshed:

    python scripts/vendor_mitre_attack.py

Output: src/dshield_enrich/data/mitre_attack_ids.json
"""
from __future__ import annotations

import datetime as _dt
import json
import sys
import urllib.request
from pathlib import Path

SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
OUTPUT = Path(__file__).resolve().parents[1] / "src" / "dshield_enrich" / "data" / "mitre_attack_ids.json"


def main() -> int:
    print(f"Fetching {SOURCE_URL} ...", file=sys.stderr)
    with urllib.request.urlopen(SOURCE_URL, timeout=60) as resp:
        bundle = json.load(resp)

    tactics: set[str] = set()
    techniques: set[str] = set()
    for obj in bundle.get("objects", []):
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        t = obj.get("type")
        if t not in ("x-mitre-tactic", "attack-pattern"):
            continue
        for ref in obj.get("external_references") or []:
            if ref.get("source_name") != "mitre-attack":
                continue
            eid = ref.get("external_id") or ""
            if t == "x-mitre-tactic" and eid.startswith("TA"):
                tactics.add(eid)
            elif t == "attack-pattern" and eid.startswith("T") and not eid.startswith("TA"):
                techniques.add(eid)

    payload = {
        "source_url": SOURCE_URL,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "tactics": sorted(tactics),
        "techniques": sorted(techniques),
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(payload, indent=2) + "\n")
    print(
        f"Wrote {OUTPUT} — {len(tactics)} tactics, {len(techniques)} techniques",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
