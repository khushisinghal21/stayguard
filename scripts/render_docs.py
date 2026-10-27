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
    if isinstance(v, list) and len(v) == 2:  # a 95% interval
        d = 2 if v[1] < 0.05 else 1
        return f"{v[0]:.{d}%}-{v[1]:.{d}%}"
    if isinstance(v, float):
        if "est_cost" in key:
            return f"${v:.4f}"
        if key.endswith("_ms"):
            return f"{v:.1f} ms"
        if key in ("model_low", "model_high"):
            return f"{v:.2f}"
        if key in ("c3_heldout_fp",) or (key.endswith("_held") and v < 0.01 and v > 0):
            return f"{v:.3%}"
        if 0 <= v <= 1:
            return f"{v:.0%}" if v in (0.0, 1.0) else f"{v:.1%}"
        return f"{v}"
    if isinstance(v, int):
        return f"{v:,}"
    return str(v)


def results_table(h: dict) -> str:
    f = lambda k: fmt(k, h[k])  # noqa: E731
    rows = []
    if h.get("v2_caught") is not None:
        rows += [
            (
                f"**Held-out v2** (blind; written by an agent with no code access, first run frozen): scams caught "
                f"({f('v2_n_scam')} scams, 95% CI)",
                f"**{f('v2_caught')}** ({f('v2_caught_ci')})",
            ),
            (
                f"Held-out v2: legitimate messages wrongly held (95% CI) / delivered with a warning "
                f"({h['v2_n'] - h['v2_n_scam']} legit)",
                f"**{f('v2_false_holds')}** ({f('v2_false_holds_ci')}) / {f('v2_legit_warned')}",
            ),
            (
                f"Held-out v2: legitimate payment messages handled correctly ({f('v2_legit_payment_n')} messages)",
                f("v2_legit_payment_accuracy"),
            ),
            (
                "Held-out v2, same messages: StayGuard's classifier alone / generic spam filter / StayGuard with judges down",
                f"{f('v2_classifier_only_caught')} / {f('v2_spam_filter_caught')} / {f('v2_degraded_caught')} caught",
            ),
        ]
    rows += [
        (
            "Held-out v1 scams caught, first blind run (frozen before any v1 result was seen; 95% CI)",
            f"**{f('heldout_first_look_caught')}** of {f('heldout_n_scam')} ({f('heldout_first_look_caught_ci')}), "
            f"wrongly held {f('heldout_first_look_false_holds')}",
        ),
        (
            "Held-out v1 scams caught now (NOT blind: later fixes targeted its first-run misses)",
            f"{f('heldout_caught')} of {f('heldout_n_scam')}",
        ),
        (
            "Held-out v1 legitimate messages wrongly held / delivered with a warning (now)",
            f"{f('heldout_false_holds')} / {f('heldout_legit_warned')}",
        ),
        (
            "Held-out v1, same messages: StayGuard's classifier alone caught / wrongly held",
            f"{f('heldout_classifier_only_caught')} / {f('heldout_classifier_only_false_holds')}",
        ),
        (
            "Held-out v1, same messages: generic spam filter caught / wrongly held",
            f"{f('heldout_spam_filter_caught')} / {f('heldout_spam_filter_false_holds')}",
        ),
        (
            "Held-out v1: phishing blocklist alone caught (uninformative: "
            f"{f('heldout_blocklist_urls_listed')} of its {f('heldout_blocklist_urls')} URLs are in the feeds)",
            f("heldout_blocklist_caught"),
        ),
        ("Held-out v1 scams caught with the AI judges down", f("heldout_degraded_caught")),
        ("Held-out v1 scams caught after rewriting (no deadline + fresh domain + leetspeak)", f("robust_combined_heldout")),
        ("Dev set (written alongside the rules): caught / wrongly held", f"{f('dev_caught')} / {f('dev_false_holds')}"),
        (
            f"Real everyday SMS wrongly held ({f('sms_ham_n')} messages, domain-shifted; 95% CI)",
            f"{f('sms_ham_held')} ({f('sms_ham_held_ci')})",
        ),
        (f"Unseen legit domains flagged ({f('c3_heldout_n')} domains, ranks 110k-210k)", f("c3_heldout_fp")),
        (
            f"Unseen legit domains containing a travel-brand word flagged ({f('c3_heldout_brand_n')} domains)",
            f("c3_heldout_brand_fp"),
        ),
        (f"Unseen Booking look-alike phishing hosts flagged, blocklist off ({f('c1_heldout_n')} hosts)", f("c1_heldout")),
        ("Random phishing hosts from the whole feed flagged, blocklist off", f("c2_heldout")),
        (
            "Messages sent to the AI judges / estimated LLM cost per 1,000: hotel messages (held-out v1)",
            f"{f('hotel_judge_share')} / {f('hotel_est_cost_per_1000')}",
        ),
        (
            "Same on the SMS-heavy 1,000-message mix",
            f"{f('judge_share')} / {f('est_cost_per_1000')} "
            f"(vs {f('est_cost_per_1000_all_llm')} if every message went to the judges)",
        ),
        ("Evaluation messages that crashed and failed closed (counted as caught if non-zero)", f("fail_closed_crashes")),
        ("Latency p50 / p95 (in-process, offline judge)", f"{f('p50_ms')} / {f('p95_ms')}"),
    ]
    return "\n".join(["| | |", "|---|---|"] + [f"| {a} | {b} |" for a, b in rows])


def render(text: str, h: dict) -> str:
    text = re.sub(
        r"(<!-- results:start -->).*?(<!-- results:end -->)",
        lambda m: m.group(1) + "\n" + results_table(h) + "\n" + m.group(2),
        text,
        flags=re.DOTALL,
    )
    return re.sub(
        r"<!-- num:(\w+) -->.*?<!-- /num -->",
        lambda m: f"<!-- num:{m.group(1)} -->{fmt(m.group(1), h[m.group(1)])}<!-- /num -->",
        text,
    )


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
