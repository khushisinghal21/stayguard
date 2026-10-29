"""Shadow mode report and the labelled feedback queue (DECISIONS #41).

Every number so far comes from written test messages. The way to learn how StayGuard does on real traffic is to run it
in shadow mode (STAYGUARD_ENFORCE=0: decisions are computed and stored, the platform does not act on them), collect
what hotels, guests and analysts say each message really was (POST /v1/messages/{id}/label), and then:

- `python -m stayguard.feedback report` compares the stored decisions with the labels (what shadow mode would have
  caught and wrongly held), and
- `python -m stayguard.feedback export` writes data/feedback/labelled_queue.jsonl, which the context models train on
  (stayguard/ctx_classifier.py).

Label resolution: an analyst's latest label wins. Without one, hotel and guest labels must agree; a disagreement is left
out of the queue and counted as needing review. A guest's word alone is enough, because a guest who reports a scam is
the case that matters most, and a hotel alone is enough because it knows what it sent.

Only the masked text is exported (PII was masked before storage). Any message whose text matches a row of a held-out or
calibration set is dropped, so real traffic can never leak an evaluation message into training.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from . import config, db
from .signals import normalise

QUEUE = config.ROOT / "data" / "feedback" / "labelled_queue.jsonl"
PROTECTED_SETS = ("golden_eval.jsonl", "heldout_v2.jsonl", "heldout_v3.jsonl")


def _key(text: str) -> str:
    return " ".join(normalise(text).lower().split())


def protected_texts() -> set[str]:
    out: set[str] = set()
    for name in PROTECTED_SETS:
        path = config.DATA_CURATED / name
        if path.exists():
            out |= {_key(json.loads(x)["text"]) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()}
    return out


def resolve(labels: list[dict[str, Any]]) -> int | None:
    """One label per message, or None when hotel and guest disagree and no analyst has decided."""
    analyst = [x for x in labels if x["source"] == "analyst"]
    if analyst:
        return int(max(analyst, key=lambda x: (x["created"], x["id"]))["label"])
    values = {int(x["label"]) for x in labels}
    return values.pop() if len(values) == 1 else None


def labelled_messages() -> tuple[list[dict[str, Any]], int]:
    c = db.con()
    rows = c.execute(
        "SELECT m.id, m.text, m.direction, m.decision, m.result, l.id AS lid, l.created, l.label, l.source "
        "FROM messages m JOIN labels l ON l.message_id = m.id ORDER BY m.id, l.id"
    ).fetchall()
    by_msg: dict[str, dict[str, Any]] = {}
    for r in rows:
        entry = by_msg.setdefault(r["id"], {"row": r, "labels": []})
        entry["labels"].append({"id": r["lid"], "created": r["created"], "label": r["label"], "source": r["source"]})
    out, conflicts = [], 0
    for mid, entry in by_msg.items():
        label = resolve(entry["labels"])
        if label is None:
            conflicts += 1
            continue
        r = entry["row"]
        result = json.loads(r["result"]) if r["result"] else {}
        out.append(
            {
                "id": mid,
                "text": r["text"],
                "label": label,
                "terms": result.get("payment_terms"),
                "direction": r["direction"],
                "first_in_thread": result.get("first_in_thread"),
                "decision": r["decision"],
                "enforced": result.get("enforced", True),
                "label_sources": sorted({x["source"] for x in entry["labels"]}),
            }
        )
    return out, conflicts


def export(path: Path = QUEUE) -> dict[str, Any]:
    rows, conflicts = labelled_messages()
    protected = protected_texts()
    kept = [r for r in rows if _key(r["text"]) not in protected]
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in kept:
            f.write(json.dumps({k: r[k] for k in ("id", "text", "label", "terms", "direction", "first_in_thread")}) + "\n")
    return {
        "written": len(kept),
        "dropped_matching_evaluation_sets": len(rows) - len(kept),
        "needs_review_conflicting_labels": conflicts,
        "path": str(path),
    }


def report() -> dict[str, Any]:
    """How the stored (shadow or enforced) decisions compare with what the messages really were."""
    rows, conflicts = labelled_messages()
    flagged = {"hold", "block"}
    scams = [r for r in rows if r["label"] == 1]
    legit = [r for r in rows if r["label"] == 0]

    def rate(k: int, n: int) -> float | None:
        return round(k / n, 6) if n else None

    caught = sum(r["decision"] in flagged for r in scams)
    false_holds = sum(r["decision"] in flagged for r in legit)
    return {
        "labelled": len(rows),
        "needs_review_conflicting_labels": conflicts,
        "scams": len(scams),
        "scams_held_or_blocked": caught,
        "scams_warned": sum(r["decision"] == "warn" for r in scams),
        "scams_delivered_clean": sum(r["decision"] == "deliver" for r in scams),
        "catch_rate": rate(caught, len(scams)),
        "legit": len(legit),
        "legit_held_or_blocked": false_holds,
        "legit_warned": sum(r["decision"] == "warn" for r in legit),
        "false_hold_rate": rate(false_holds, len(legit)),
        "shadow_rows": sum(not r["enforced"] for r in rows),
        "note": "Labels arrive mostly for messages someone noticed, so these rates are not a random sample of traffic.",
    }


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    cmd = args[0] if args else "report"
    if cmd == "export":
        print(json.dumps(export(), indent=2))
    elif cmd == "report":
        print(json.dumps(report(), indent=2))
    else:
        print("usage: python -m stayguard.feedback [report|export]", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
