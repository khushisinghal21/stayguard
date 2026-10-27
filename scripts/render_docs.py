"""Render the numbers README.md and DECISIONS.md quote from eval/report.json, between markers:

    <!-- results:start --> ... <!-- results:end -->      (README results table)
    <!-- num:KEY -->value<!-- /num -->                    (single inline numbers anywhere in README/DECISIONS)

Run after `python -m eval.evaluate`. tests/test_docs_drift.py fails if the docs differ from what this renders,
so no number in the docs can drift from the latest report.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = [ROOT / "README.md", ROOT / "DECISIONS.md"]


def fmt(key: str, v: object) -> str:
    if v is None:
        return "n/a"
    if isinstance(v, float):
        if key.startswith("est_cost"):
            return f"${v:.4f}"
        if key.endswith("_ms"):
            return f"{v:.1f} ms"
        if key in ("c3_heldout_fp",):
            return f"{v:.3%}"
        if 0 <= v <= 1:
            return f"{v:.1%}" if key in ("judge_share", "c2_heldout") else f"{v:.0%}" if v in (0.0, 1.0) else f"{v:.1%}"
        return f"{v}"
    if isinstance(v, int):
        return f"{v:,}"
    return str(v)


def results_table(h: dict) -> str:
    f = lambda k: fmt(k, h[k])  # noqa: E731
    rows = [
        ("Held-out scams caught (written from cited public reports, never tuned on)", f"**{f('heldout_caught')}** of {f('heldout_n_scam')}"),
        ("Held-out legitimate messages wrongly held / delivered with a warning", f"**{f('heldout_false_holds')}** / {f('heldout_legit_warned')}"),
        ("Same held-out set: generic spam filter caught / wrongly held", f"{f('heldout_spam_filter_caught')} / {f('heldout_spam_filter_false_holds')}"),
        ("Same held-out set: phishing blocklist alone caught", f('heldout_blocklist_caught')),
        ("Held-out scams caught with the AI judges down", f('heldout_degraded_caught')),
        ("Held-out scams caught after rewriting (no deadline + fresh domain + leetspeak)", f('robust_combined_heldout')),
        ("Dev set (written alongside the rules): caught / wrongly held", f"{f('dev_caught')} / {f('dev_false_holds')}"),
        (f"Real everyday SMS wrongly held ({f('sms_ham_n')} messages, domain-shifted)", f('sms_ham_held')),
        (f"Unseen legit domains flagged ({f('c3_heldout_n')} domains, ranks 110k-210k)", f('c3_heldout_fp')),
        (f"Unseen Booking look-alike phishing hosts flagged, blocklist off ({f('c1_heldout_n')} hosts)", f('c1_heldout')),
        ("Random phishing hosts from the whole feed flagged, blocklist off", f('c2_heldout')),
        ("Messages sent to the AI judges / estimated LLM cost per 1,000 messages", f"{f('judge_share')} / {f('est_cost_per_1000')} (vs {f('est_cost_per_1000_all_llm')} if every message went to the judges)"),
        ("Latency p50 / p95 (in-process, offline judge)", f"{f('p50_ms')} / {f('p95_ms')}"),
    ]
    return "\n".join(["| | |", "|---|---|"] + [f"| {a} | {b} |" for a, b in rows])


def render(text: str, h: dict) -> str:
    text = re.sub(r"(<!-- results:start -->).*?(<!-- results:end -->)",
                  lambda m: m.group(1) + "\n" + results_table(h) + "\n" + m.group(2), text, flags=re.DOTALL)
    return re.sub(r"<!-- num:(\w+) -->.*?<!-- /num -->", lambda m: f"<!-- num:{m.group(1)} -->{fmt(m.group(1), h[m.group(1)])}<!-- /num -->", text)


def main(check: bool = False) -> int:
    h = json.loads((ROOT / "eval" / "report.json").read_text())["headline"]
    stale = []
    for p in DOCS:
        old = p.read_text(encoding="utf-8")
        new = render(old, h)
        if new != old:
            stale.append(p.name)
            if not check:
                p.write_text(new, encoding="utf-8")
    if check and stale:
        print("out of date:", ", ".join(stale))
        return 1
    print("docs up to date" if check else f"rendered {', '.join(stale) or 'nothing (already current)'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(check="--check" in sys.argv))
