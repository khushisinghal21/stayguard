"""Fail if coverage drops below the gates: 85% overall, 95% on the decision path.
Usage: python scripts/check_coverage.py coverage.json"""

from __future__ import annotations

import json
import sys

OVERALL = 85.0
STRICT = {"stayguard/engine.py": 95.0, "stayguard/signals.py": 95.0, "stayguard/links.py": 95.0}


def main(path: str) -> int:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    failures = []
    total = data["totals"]["percent_covered"]
    if total < OVERALL:
        failures.append(f"overall {total:.1f}% < {OVERALL}%")
    for f, gate in STRICT.items():
        pct = data["files"].get(f, {}).get("summary", {}).get("percent_covered", 0.0)
        if pct < gate:
            failures.append(f"{f} {pct:.1f}% < {gate}%")
        print(f"{f}: {pct:.1f}% (gate {gate}%)")
    print(f"overall: {total:.1f}% (gate {OVERALL}%)")
    for msg in failures:
        print("FAIL", msg)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "coverage.json"))
