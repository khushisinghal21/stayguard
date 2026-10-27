"""Maintenance commands.

python -m stayguard.maintenance purge          # drop raw message text older than the retention period
python -m stayguard.maintenance anchor         # append the current audit head to the anchor file
python -m stayguard.maintenance verify-audit   # check the hash chain and every anchor
"""

from __future__ import annotations

import argparse
import json
import sys

from . import db


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="stayguard.maintenance")
    ap.add_argument("command", choices=["purge", "anchor", "verify-audit"])
    args = ap.parse_args(argv)
    if args.command == "purge":
        print(json.dumps({"purged": db.purge_raw_text()}))
        return 0
    if args.command == "anchor":
        print(json.dumps(db.anchor_audit()))
        return 0
    result = db.audit_verify()
    print(json.dumps(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
