"""StayGuard evaluation. Run:  python -m eval.evaluate   (writes eval/report.json and eval/report.md)

Every section reports DEV and HELD-OUT separately. Dev data was looked at while building the rules; held-out data
was not. Headline numbers are held-out.

A. Messages. Dev = data/curated/golden_eval.jsonl (115, hand-written alongside the rules). Held-out =
   data/curated/heldout_eval.jsonl (124, built from cited public scam reports and hotel templates, committed
   before its first run). StayGuard vs baselines. The very first held-out run is frozen in
   eval/heldout_first_look.json and never overwritten.
B. Real false alarms: the SMS test split (never trained on, never used for calibration), pushed through the full
   pipeline as hotel->guest on a pay-at-property booking. Domain-shifted: these are personal SMS, not hotel chat.
C. Links nobody has reported yet (blocklist off). Dev = what the heuristics were tuned on; held-out = never seen:
   C1 the other half of the Booking-themed phishing hosts; C2 a disjoint random feed sample; C3 legit domains
   ranked 110,001-210,000 (dev: 10,001-110,000).
D. Session model (synthetic logins - see stayguard/session_risk.py).
E. Cost and latency on a 1,000-message mix. Cost is an ESTIMATE (price from config, tokens estimated).
F. Robustness: scams rewritten to dodge filters, on dev and held-out scams.

Options: --fast (CI: small samples, fixture-sized data)   --compare OLD_REPORT.json [--allow-drift]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from sklearn.metrics import f1_score  # noqa: E402

from stayguard import config  # noqa: E402
from stayguard.classifier import build_pipeline, prep, sms_splits, train  # noqa: E402
from stayguard.engine import VERSIONS, Engine, judge_cost_estimate_usd  # noqa: E402
from stayguard.links import LinkChecker, _raw_blocklist  # noqa: E402
from stayguard.session_risk import train as train_sessions  # noqa: E402
from stayguard.signals import extract  # noqa: E402

PROPERTY_DOMAINS = ["lisboncityhotel.pt", "algarveresorthotel.pt"]
FIRST_LOOK = config.EVAL_DIR / "heldout_first_look.json"
SYSTEM_NAMES = [
    "baseline_blocklist_only",
    "baseline_generic_spam_filter",
    "stayguard_full",
    "stayguard_rules_only",
    "stayguard_zero_day_links_blocklist_off",
    "stayguard_degraded_llm_down",
]


def load_rows(name: str) -> list[dict[str, Any]]:
    with open(config.DATA_CURATED / name, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def ctx_for(x: dict[str, Any]) -> dict[str, Any]:
    return {
        "payment_terms": x.get("terms", "unknown"),
        "direction": x.get("direction", "hotel_to_guest"),
        "property_domains": PROPERTY_DOMAINS,
    }


def score(y: list[int], flagged: list[bool], warned: list[bool] | None = None) -> dict[str, Any]:
    tp = sum(1 for a, b in zip(y, flagged, strict=True) if a and b)
    fn = sum(1 for a, b in zip(y, flagged, strict=True) if a and not b)
    fp = sum(1 for a, b in zip(y, flagged, strict=True) if not a and b)
    tn = sum(1 for a, b in zip(y, flagged, strict=True) if not a and not b)
    out: dict[str, Any] = {
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "catch_rate": round(tp / (tp + fn), 4) if tp + fn else None,
        "false_alarm_rate": round(fp / (fp + tn), 4) if fp + tn else None,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "f1": round(float(f1_score(y, flagged, zero_division=0)), 4) if any(y) else None,
    }
    if warned is not None:
        legit_warned = sum(1 for a, f, w in zip(y, flagged, warned, strict=True) if not a and w and not f)
        out["legit_warned_rate"] = round(legit_warned / (fp + tn), 4) if fp + tn else None
        scam_warned = sum(1 for a, f, w in zip(y, flagged, warned, strict=True) if a and w and not f)
        out["scam_warned_not_held_rate"] = round(scam_warned / (tp + fn), 4) if tp + fn else None
    return out


def wilson(k: int, n: int, z: float = 1.96) -> list[float] | None:
    """95% Wilson interval for a proportion - small samples get wide intervals, and the report shows them."""
    if not n:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def section_a(rows: list[dict[str, Any]], engine: Engine, engine_nobl: Engine, sms_only: Any) -> dict[str, Any]:
    y = [x["label"] for x in rows]
    systems: dict[str, dict[str, Any]] = {}
    lc = engine.links
    bl = [any("KNOWN_PHISHING_DOMAIN" in lc.check(u).reasons for u in extract(x["text"]).urls) for x in rows]
    systems["baseline_blocklist_only"] = score(y, bl)
    sp = [sms_only.predict_proba([prep(x["text"])])[0, 1] >= 0.5 for x in rows]
    systems["baseline_generic_spam_filter"] = score(y, sp)

    def run(eng: Engine, name: str, outage: bool = False) -> list[Any]:
        eng.breaker.forced_outage = outage
        ds = [eng.check(x["text"], ctx_for(x), record=False) for x in rows]
        eng.breaker.forced_outage = False
        systems[name] = score(y, [d.decision in ("hold", "block") for d in ds], [d.decision == "warn" for d in ds])
        return ds

    full = run(engine, "stayguard_full")
    rules_only = [
        any(t.get("decided") for t in d.trace if t["stage"] == "rules") and d.decision in ("hold", "block") for d in full
    ]
    systems["stayguard_rules_only"] = score(y, rules_only)
    run(engine_nobl, "stayguard_zero_day_links_blocklist_off")
    run(engine, "stayguard_degraded_llm_down", outage=True)
    f = systems["stayguard_full"]
    f["catch_rate_ci95"] = wilson(f["tp"], f["tp"] + f["fn"])
    f["false_alarm_rate_ci95"] = wilson(f["fp"], f["fp"] + f["tn"])

    per_cat: dict[str, dict[str, Any]] = defaultdict(lambda: {"n": 0, "correct": 0})
    per_lang: dict[str, dict[str, Any]] = defaultdict(lambda: {"n": 0, "correct": 0})
    paths: dict[str, int] = defaultdict(int)
    errors = []
    for x, d in zip(rows, full, strict=True):
        flagged = d.decision in ("hold", "block")
        ok = flagged == bool(x["label"])
        for bucket, key in ((per_cat, x["category"]), (per_lang, x["lang"])):
            bucket[key]["n"] += 1
            bucket[key]["correct"] += int(ok)
        paths[d.path] += 1
        if not ok or (x["label"] == 0 and d.decision == "warn"):
            errors.append(
                {
                    "id": x["id"],
                    "label": x["label"],
                    "decision": d.decision,
                    "path": d.path,
                    "reasons": d.reasons,
                    "category": x["category"],
                    "lang": x["lang"],
                    "text": x["text"],
                }
            )
    for b in (per_cat, per_lang):
        for v in b.values():
            v["accuracy"] = round(v["correct"] / v["n"], 4)
    return {
        "n": len(rows),
        "n_scam": sum(y),
        "n_legit": len(y) - sum(y),
        "systems": systems,
        "per_category": dict(per_cat),
        "per_language": dict(per_lang),
        "paths": dict(paths),
        "errors_and_warnings": errors,
    }


def section_b(engine: Engine, fast: bool) -> dict[str, Any]:
    hold = pd.read_csv(config.MODELS / "sms_holdout.csv")
    out: dict[str, Any] = {}
    for label, name in ((0, "real_ham"), (1, "real_spam")):
        sub = hold[hold.label == label]
        if fast:
            sub = sub.head(200)
        ds = [
            engine.check(t, {"payment_terms": "pay_at_property", "direction": "hotel_to_guest"}, record=False) for t in sub.text
        ]
        dec: dict[str, int] = defaultdict(int)
        for d in ds:
            dec[d.decision] += 1
        n = len(ds)
        held = dec["hold"] + dec["block"]
        out[name] = {
            "n": n,
            "decisions": dict(dec),
            "held_or_blocked_rate": round(held / n, 4) if n else None,
            "held_ci95": wilson(held, n),
            "warned_rate": round(dec["warn"] / n, 4) if n else None,
        }
        if label == 0:
            out[name]["examples_held"] = [t for t, d in zip(sub.text, ds, strict=True) if d.decision in ("hold", "block")][:8]
            out[name]["examples_warned"] = [t for t, d in zip(sub.text, ds, strict=True) if d.decision == "warn"][:8]
    return out


def _flagged(nobl: LinkChecker, host: str) -> bool:
    return nobl.check("https://" + host).verdict in ("malicious", "suspicious")


def _legit_range(start: int, stop: int, blocklisted: frozenset[str]) -> list[str]:
    out = []
    if config.TOP_1M.exists():
        with open(config.TOP_1M, encoding="utf-8") as f:
            for i, line in enumerate(f):
                if i < start:
                    continue
                if i >= stop:
                    break
                d = line.strip().lower()
                if d and d not in blocklisted:
                    out.append(d)
    return out


def section_c(fast: bool) -> dict[str, Any]:
    rng = random.Random(3)
    blocklisted = _raw_blocklist()
    nobl = LinkChecker(use_blocklist=False)
    brand = sorted(h for h in blocklisted if "booking" in h)
    rng.shuffle(brand)
    c1 = {"dev": brand[: len(brand) // 2], "heldout": brand[len(brand) // 2 :]}  # dev half was looked at while tuning
    allbl = sorted(blocklisted)
    k = min(3000 if not fast else 300, len(allbl) // 2)
    dev2 = rng.sample(allbl, k)
    seen = set(dev2)
    rest = [h for h in allbl if h not in seen]
    held2 = random.Random(4).sample(rest, min(k, len(rest)))
    ranges = (
        {"dev": (10_000, 110_000), "heldout": (110_000, 210_000)}
        if not fast
        else {"dev": (10_000, 20_000), "heldout": (20_000, 30_000)}
    )
    out: dict[str, Any] = {"booking_themed_phishing_in_feeds": len(brand)}
    for split in ("dev", "heldout"):
        c1_hit = [h for h in c1[split] if _flagged(nobl, h)]
        c2 = dev2 if split == "dev" else held2
        c2_hit = sum(_flagged(nobl, h) for h in c2)
        legit = _legit_range(*ranges[split], blocklisted)
        fps = [d for d in legit if _flagged(nobl, d)]
        brandy = [d for d in legit if any(b in d for b in ("booking", "airbnb", "agoda", "expedia", "priceline"))]
        brandy_fp = [d for d in brandy if _flagged(nobl, d)]
        out[split] = {
            "c1_n": len(c1[split]),
            "c1_detection_rate": round(len(c1_hit) / len(c1[split]), 4) if c1[split] else None,
            "c1_examples_missed": [h for h in c1[split] if h not in set(c1_hit)][:10],
            "c2_n": len(c2),
            "c2_detection_rate": round(c2_hit / len(c2), 4) if c2 else None,
            "c3_ranks": list(ranges[split]),
            "c3_n": len(legit),
            "c3_false_positive_rate": round(len(fps) / len(legit), 5) if legit else None,
            "c3_false_positive_ci95": wilson(len(fps), len(legit)),
            "c3_false_positive_examples": fps[:12],
            "c3_brand_token_n": len(brandy),
            "c3_brand_token_false_positive_rate": round(len(brandy_fp) / len(brandy), 4) if brandy else None,
            "c3_brand_token_fp_examples": brandy_fp[:8],
        }
    with open(config.OPENPHISH, encoding="utf-8") as fh:
        op = [line.strip() for line in fh if line.strip()]
    out["openphish_n"] = len(op)
    out["openphish_heuristic_detection_rate"] = (
        round(sum(nobl.check(u).verdict in ("malicious", "suspicious") for u in op) / len(op), 4) if op else None
    )
    out["note"] = (
        "Heuristics exist for links nobody has reported yet; in production the blocklist runs too. A flagged legit "
        "link is held only when the message also asks for money; otherwise the guest sees a warning."
    )
    return out


ZW = "​"
NEUTRAL = ["sunny", "trail", "harbor", "maple", "river", "stone", "cedar", "lumen", "nova", "atlas"]
MUTATIONS = ("no_urgency", "neutral_new_domain", "leetspeak", "zero_width", "spaced_letters", "combined")


def _mutate(text: str, kind: str, rng: random.Random) -> str:
    from stayguard.signals import URGENCY, sub_links

    if kind in ("no_urgency", "combined"):
        text = URGENCY.sub("", text)
    if kind in ("neutral_new_domain", "combined"):
        text = sub_links(text, lambda _u: f"https://{rng.choice(NEUTRAL)}{rng.choice(NEUTRAL)}.com/r/{rng.randint(100, 999)}")
    if kind in ("leetspeak", "combined"):
        tr = str.maketrans({"a": "4", "e": "3", "o": "0", "i": "1"})
        text = " ".join(w.translate(tr) if len(w) >= 4 and rng.random() < 0.5 and "://" not in w else w for w in text.split())
    if kind == "zero_width":
        text = " ".join(w[: len(w) // 2] + ZW + w[len(w) // 2 :] if len(w) >= 5 and "://" not in w else w for w in text.split())
    if kind == "spaced_letters":
        text = " ".join(" ".join(w) if 4 <= len(w) <= 8 and w.isalpha() and rng.random() < 0.3 else w for w in text.split())
    return text


def section_f(rows: list[dict[str, Any]], engine: Engine) -> dict[str, Any]:
    scams = [x for x in rows if x["label"] == 1]
    legit = [x for x in rows if x["label"] == 0]
    out: dict[str, Any] = {}
    for kind in MUTATIONS:
        rng = random.Random(kind)
        ds = [engine.check(_mutate(x["text"], kind, rng), ctx_for(x), record=False) for x in scams]
        caught = sum(d.decision in ("hold", "block") for d in ds)
        out[kind] = {
            "n": len(scams),
            "catch_rate": round(caught / len(scams), 4) if scams else None,
            "missed_ids": [x["id"] for x, d in zip(scams, ds, strict=True) if d.decision not in ("hold", "block")][:15],
        }
    rng = random.Random(0)
    lz = [engine.check(_mutate(x["text"], "zero_width", rng), ctx_for(x), record=False) for x in legit]
    out["legit_with_zero_width"] = {
        "n": len(legit),
        "held_rate": round(sum(d.decision in ("hold", "block") for d in lz) / len(legit), 4),
        "warned_rate": round(sum(d.decision == "warn" for d in lz) / len(legit), 4),
    }
    return out


def section_e(engine: Engine, scams: list[dict[str, Any]], fast: bool) -> dict[str, Any]:
    hold = pd.read_csv(config.MODELS / "sms_holdout.csv")
    ham = hold[hold.label == 0].text.tolist()
    n_ham, n_scam = (970, 30) if not fast else (97, 3)
    mix = [(t, {"payment_terms": "pay_at_property", "direction": "hotel_to_guest"}) for t in ham[:n_ham]]
    mix += [(x["text"], ctx_for(x)) for x in scams][:n_scam]
    lat, judged, paths = [], [], defaultdict(int)
    for t, c in mix:
        t0 = time.perf_counter()
        d = engine.check(t, c, record=False)
        lat.append((time.perf_counter() - t0) * 1000)
        if d.path == "judges":
            judged.append(t)
        paths[d.path] += 1
    lat.sort()
    share = len(judged) / len(mix)
    per_judged = statistics.mean(judge_cost_estimate_usd(t) for t in judged) if judged else judge_cost_estimate_usd()
    return {
        "n": len(mix),
        "mix": f"{n_ham} SMS test-split messages + {n_scam} held-out scams",
        "paths": dict(paths),
        "judge_share": round(share, 4),
        "p50_ms": round(statistics.median(lat), 2),
        "p95_ms": round(lat[int(0.95 * len(lat))], 2),
        "p99_ms": round(lat[int(0.99 * len(lat))], 2),
        "est_cost_per_judged_message_usd": round(per_judged, 6),
        "est_cost_per_1000_messages_usd": round(share * per_judged * 1000, 4),
        "est_cost_per_1000_if_every_message_went_to_llm_usd": round(judge_cost_estimate_usd() * 1000, 4),
        "price_source": f"Claude Haiku 5.5 ${config.LLM_PRICE_IN_PER_MTOK}/MTok in, ${config.LLM_PRICE_OUT_PER_MTOK}/MTok out "
        "(platform.claude.com/docs/en/about-claude/pricing, checked 2026-10-27)",
        "note": (
            "ESTIMATE, not a bill: input tokens = prompt characters / 4, output = 150 tokens per judge, 2 judges. "
            "Latency is in-process, excludes network and DB, and the judge path ran the offline judge; a hosted "
            "LLM adds roughly 1-3 s to judged messages only."
        ),
    }


def _git(*args: str) -> str:
    try:
        # fixed argv, no shell, read-only git queries about this repository
        cmd = ["git", *args]
        return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=10).stdout.strip() or "unknown"  # noqa: S603
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_info() -> dict[str, Any]:
    from make_manifest import build, manifest_hash

    m = build(config.DATA_RAW)
    return {
        "data_manifest_hash": manifest_hash(m),
        "data_dir": str(config.DATA_RAW),
        "fetched_at": m["fetched_at"],
        "files": {f["file"]: f["sha256"][:12] for f in m["files"]},
    }


# ---------------------------------------------------------------------------------------------------------------
def to_md(r: dict[str, Any]) -> str:
    A, B, C, E, F, S = r["A_messages"], r["B_real_sms"], r["C_links"], r["E_cost_latency"], r["F_robustness"], r["D_sessions"]
    pct = lambda v, d=0: "-" if v is None else f"{v:.{d}%}"  # noqa: E731
    ci = lambda c: "" if not c else f" ({c[0]:.0%}-{c[1]:.0%})"  # noqa: E731
    lines = [
        "# StayGuard evaluation report",
        "",
        f"Generated {r['generated']} at commit `{r['git_commit']}`. Reproduce with `python -m eval.evaluate`.",
        f"Data manifest `{r['data']['data_manifest_hash']}` (feeds fetched {r['data']['fetched_at']}). "
        f"Held-out set sha256 `{r['heldout_sha256'][:16]}...`, committed in `{r['heldout_commit']}`.",
        f"Model thresholds: MODEL_LOW {r['thresholds']['model_low']}, MODEL_HIGH {r['thresholds']['model_high']} "
        f"({r['thresholds']['source']}).",
        "",
        "**Dev** data was looked at while the rules were built, so dev numbers are optimistic. **Held-out** data was not. "
        "Read held-out first.",
        "",
        "## A. Messages: StayGuard vs baselines",
        "",
        f"Dev: {A['dev']['n']} hand-written messages ({A['dev']['n_scam']} scams). Held-out: {A['heldout']['n']} messages "
        f"({A['heldout']['n_scam']} scams) built from cited public scam reports and hotel templates "
        "(`data/curated/HELDOUT_SOURCES.md`).",
        "",
        "| System | Held-out caught | Held-out false holds | Dev caught | Dev false holds |",
        "|---|---|---|---|---|",
    ]
    for k in SYSTEM_NAMES:
        h, d = A["heldout"]["systems"][k], A["dev"]["systems"][k]
        lines.append(
            f"| {k} | {pct(h['catch_rate'])} | {pct(h['false_alarm_rate'])} | "
            f"{pct(d['catch_rate'])} | {pct(d['false_alarm_rate'])} |"
        )
    hf = A["heldout"]["systems"]["stayguard_full"]
    lines += [
        "",
        f"Held-out, StayGuard: caught {pct(hf['catch_rate'])}{ci(hf.get('catch_rate_ci95'))} of scams, falsely held "
        f"{pct(hf['false_alarm_rate'])}{ci(hf.get('false_alarm_rate_ci95'))} of legitimate messages (95% Wilson intervals), "
        f"and {pct(hf.get('legit_warned_rate'))} of legitimate messages were delivered with a warning.",
        "",
    ]
    if r.get("heldout_first_look"):
        fl = r["heldout_first_look"]
        flf = fl["A_messages_heldout"]["systems"]["stayguard_full"]
        lines += [
            f"**First look** (frozen in `eval/heldout_first_look.json`, commit `{fl['git_commit']}`, {fl['generated']}): caught "
            f"{pct(flf['catch_rate'])}, falsely held {pct(flf['false_alarm_rate'])}. Any later change that was motivated by "
            "held-out results makes the current held-out numbers less blind than the first look.",
            "",
        ]
    lines += ["Held-out accuracy by category:", "", "| Category | n | Accuracy |", "|---|---|---|"]
    lines += [f"| {k} | {v['n']} | {pct(v['accuracy'])} |" for k, v in sorted(A["heldout"]["per_category"].items())]
    lines += ["", "Held-out accuracy by language:", "", "| Language | n | Accuracy |", "|---|---|---|"]
    lines += [f"| {k} | {v['n']} | {pct(v['accuracy'])} |" for k, v in sorted(A["heldout"]["per_language"].items())]
    for split in ("heldout", "dev"):
        lines += ["", f"{'Held-out' if split == 'heldout' else 'Dev'} misses, false holds and warned legit messages:", ""]
        lines += [
            f"- `{x['id']}` ({x['category']}, {x['lang']}) label={x['label']} -> **{x['decision']}** via {x['path']} "
            f"{x['reasons']}: {x['text'][:110]}"
            for x in A[split]["errors_and_warnings"]
        ] or ["- none"]
    lines += [
        "",
        "## B. Real everyday messages (UCI SMS test split)",
        "",
        f"- {B['real_ham']['n']} real personal SMS through the full pipeline as hotel->guest on a pay-at-property booking: "
        f"**{pct(B['real_ham']['held_or_blocked_rate'], 2)} held**{ci(B['real_ham']['held_ci95'])}, "
        f"{pct(B['real_ham']['warned_rate'], 2)} delivered with a warning.",
        f"- {B['real_spam']['n']} real spam SMS: {pct(B['real_spam']['held_or_blocked_rate'], 1)} held "
        "(generic spam, not hotel scams).",
        "- Caveat: these are personal SMS, not hotel conversations. They show the system rarely interferes with ordinary "
        "chat; they do not measure false holds on real hotel traffic, which needs platform data.",
    ]
    if B["real_ham"].get("examples_held"):
        lines += ["", "Held:", ""] + [f"- {t[:120]}" for t in B["real_ham"]["examples_held"]]
    lines += [
        "",
        "## C. Links nobody has reported yet (blocklist switched off)",
        "",
        "| | Held-out | Dev (tuned on) |",
        "|---|---|---|",
        f"| C1 Booking look-alike phishing hosts caught | {pct(C['heldout']['c1_detection_rate'], 1)} "
        f"of {C['heldout']['c1_n']} | "
        f"{pct(C['dev']['c1_detection_rate'], 1)} of {C['dev']['c1_n']} |",
        f"| C2 random hosts from the whole feed caught | {pct(C['heldout']['c2_detection_rate'], 1)} "
        f"of {C['heldout']['c2_n']:,} | "
        f"{pct(C['dev']['c2_detection_rate'], 1)} of {C['dev']['c2_n']:,} |",
        f"| C3 legit domains flagged | {pct(C['heldout']['c3_false_positive_rate'], 3)} of {C['heldout']['c3_n']:,} "
        f"(ranks {C['heldout']['c3_ranks'][0]:,}-{C['heldout']['c3_ranks'][1]:,}) | "
        f"{pct(C['dev']['c3_false_positive_rate'], 3)} of "
        f"{C['dev']['c3_n']:,} |",
        f"| C3 legit domains with a travel-brand word flagged | {pct(C['heldout']['c3_brand_token_false_positive_rate'], 1)} of "
        f"{C['heldout']['c3_brand_token_n']} | {pct(C['dev']['c3_brand_token_false_positive_rate'], 1)} "
        f"of {C['dev']['c3_brand_token_n']} |",
        "",
        "C1 hosts were selected because they contain 'booking', which is itself a heuristic feature, so C1 measures "
        "look-alike coverage; C2 is the honest general zero-day number. "
        f"Held-out flagged legit examples: {', '.join(C['heldout']['c3_false_positive_examples'][:8]) or 'none'}. "
        f"Held-out missed look-alikes: {', '.join(C['heldout']['c1_examples_missed'][:6]) or 'none'}.",
        f"OpenPhish ({C['openphish_n']} live URLs, all brands): {pct(C['openphish_heuristic_detection_rate'], 1)} "
        f"by heuristics alone. {C['note']}",
        "",
        "## F. Robustness: scams rewritten to dodge filters",
        "",
        "| Rewrite | Held-out caught | Dev caught |",
        "|---|---|---|",
    ]
    lines += [f"| {k} | {pct(F['heldout'][k]['catch_rate'])} | {pct(F['dev'][k]['catch_rate'])} |" for k in MUTATIONS]
    lines += [
        "",
        "Legit held-out messages with zero-width characters inserted: "
        f"{pct(F['heldout']['legit_with_zero_width']['held_rate'])} held, "
        f"{pct(F['heldout']['legit_with_zero_width']['warned_rate'])} warned.",
        "",
        "## D. Session takeover model (synthetic logins)",
        "",
        f"ROC AUC {S['roc_auc']:.3f}; false alarms at the 'risky' threshold {S['fpr_at_risky']:.2%}.",
        "",
        "| Attack | Caught at risky | Caught at critical |",
        "|---|---|---|",
    ]
    lines += [f"| {k} | {v:.0%} | {S['recall_at_critical'][k]:.0%} |" for k, v in S["recall_at_risky"].items()]
    lines += [
        "",
        "Synthetic data is separable by construction, so this is a plumbing check, not evidence of field performance. "
        "The useful finding is `on_device_malware`: malware on the hotel's own PC produces a normal-looking login, which is "
        "why every message is still checked on its own.",
        "",
        f"## E. Cost and latency ({E['mix']})",
        "",
        f"- Paths: {E['paths']}; share sent to the AI judges: **{pct(E['judge_share'], 1)}**",
        f"- Latency p50 {E['p50_ms']} ms, p95 {E['p95_ms']} ms, p99 {E['p99_ms']} ms",
        f"- **Estimated** LLM cost: ${E['est_cost_per_1000_messages_usd']} per 1,000 messages, vs "
        f"${E['est_cost_per_1000_if_every_message_went_to_llm_usd']} if every message went to the judges "
        f"(${E['est_cost_per_judged_message_usd']} per judged message). Price: {E['price_source']}.",
        f"- {E['note']}",
        "",
        "## Classifier and calibration",
        "",
        f"SMS test split: ROC AUC {r['classifier']['sms_test']['roc_auc']:.3f}, "
        f"precision {r['classifier']['sms_test']['precision']:.1%}, "
        f"recall {r['classifier']['sms_test']['recall']:.1%}. Thresholds chosen on the calibration split by the rule in "
        "`eval/calibrate.py`; reliability diagram in `eval/reliability.png`.",
    ]
    return "\n".join(lines) + "\n"


def headline(r: dict[str, Any]) -> dict[str, Any]:
    """The numbers README/DECISIONS quote. scripts/render_docs.py renders them; tests check they match."""
    A, B, C, E, F = r["A_messages"], r["B_real_sms"], r["C_links"], r["E_cost_latency"], r["F_robustness"]
    # The frozen first blind run sits next to the current numbers: later fixes were made after its misses were seen,
    # so the current held-out numbers are less blind than that first run and must never be quoted without it.
    fl = json.loads(FIRST_LOOK.read_text())["A_messages_heldout"]["systems"]["stayguard_full"] if FIRST_LOOK.exists() else {}
    return {
        "model_low": r["thresholds"]["model_low"],
        "model_high": r["thresholds"]["model_high"],
        "heldout_first_look_caught": fl.get("catch_rate"),
        "heldout_first_look_false_holds": fl.get("false_alarm_rate"),
        "heldout_caught": A["heldout"]["systems"]["stayguard_full"]["catch_rate"],
        "heldout_false_holds": A["heldout"]["systems"]["stayguard_full"]["false_alarm_rate"],
        "heldout_legit_warned": A["heldout"]["systems"]["stayguard_full"]["legit_warned_rate"],
        "heldout_n": A["heldout"]["n"],
        "heldout_n_scam": A["heldout"]["n_scam"],
        "heldout_spam_filter_caught": A["heldout"]["systems"]["baseline_generic_spam_filter"]["catch_rate"],
        "heldout_spam_filter_false_holds": A["heldout"]["systems"]["baseline_generic_spam_filter"]["false_alarm_rate"],
        "heldout_blocklist_caught": A["heldout"]["systems"]["baseline_blocklist_only"]["catch_rate"],
        "heldout_degraded_caught": A["heldout"]["systems"]["stayguard_degraded_llm_down"]["catch_rate"],
        "dev_caught": A["dev"]["systems"]["stayguard_full"]["catch_rate"],
        "dev_false_holds": A["dev"]["systems"]["stayguard_full"]["false_alarm_rate"],
        "sms_ham_held": B["real_ham"]["held_or_blocked_rate"],
        "sms_ham_n": B["real_ham"]["n"],
        "c1_heldout": C["heldout"]["c1_detection_rate"],
        "c1_heldout_n": C["heldout"]["c1_n"],
        "c2_heldout": C["heldout"]["c2_detection_rate"],
        "c3_heldout_fp": C["heldout"]["c3_false_positive_rate"],
        "c3_heldout_n": C["heldout"]["c3_n"],
        "robust_combined_heldout": F["heldout"]["combined"]["catch_rate"],
        "judge_share": E["judge_share"],
        "p50_ms": E["p50_ms"],
        "p95_ms": E["p95_ms"],
        "est_cost_per_1000": E["est_cost_per_1000_messages_usd"],
        "est_cost_per_1000_all_llm": E["est_cost_per_1000_if_every_message_went_to_llm_usd"],
    }


def compare(old_path: Path, new: dict[str, Any], allow_drift: bool) -> int:
    old = json.loads(old_path.read_text())
    oh, nh = old.get("data", {}).get("data_manifest_hash"), new["data"]["data_manifest_hash"]
    if oh != nh and not allow_drift:
        print(f"refusing to compare: data manifest {oh} != {nh} (the feeds changed). Use --allow-drift to compare anyway.")
        return 2
    oh_, nh_ = old.get("headline", {}), new["headline"]
    print(f"{'metric':38} {'old':>10} {'new':>10}")
    for k in nh_:
        print(f"{k:38} {str(oh_.get(k)):>10} {str(nh_.get(k)):>10}")
    return 0


def main(argv: list[str] | None = None) -> dict[str, Any]:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fast", action="store_true", help="small samples (CI)")
    ap.add_argument("--compare", type=Path)
    ap.add_argument("--allow-drift", action="store_true")
    ap.add_argument("--out", type=Path, default=config.EVAL_DIR)
    args = ap.parse_args(argv)
    t0 = time.time()
    print("training classifier ...")
    _, crep, _ = train(save=True)
    print("training session model ...")
    _, srep = train_sessions(save=True)
    sms_tr, _, _ = sms_splits()
    sms_only = build_pipeline().fit(sms_tr.text.map(prep), sms_tr.label)
    engine = Engine()
    engine_nobl = Engine(link_checker=LinkChecker(use_blocklist=False))
    dev = [x for x in load_rows("golden_eval.jsonl") if x.get("split") == "dev"]
    heldout = [x for x in load_rows("heldout_eval.jsonl") if x.get("split") == "heldout"]
    print("A messages ...")
    a = {"dev": section_a(dev, engine, engine_nobl, sms_only), "heldout": section_a(heldout, engine, engine_nobl, sms_only)}
    print("B real sms ...")
    b = section_b(engine, args.fast)
    print("C links ...")
    c = section_c(args.fast)
    print("F robustness ...")
    f = {"dev": section_f(dev, engine), "heldout": section_f(heldout, engine)}
    print("E cost/latency ...")
    e = section_e(engine, [x for x in heldout if x["label"] == 1], args.fast)
    report: dict[str, Any] = {
        "generated": time.strftime("%Y-%m-%d %H:%M"),
        "fast": args.fast,
        "git_commit": _git("rev-parse", "--short", "HEAD"),
        "heldout_sha256": _sha256(config.DATA_CURATED / "heldout_eval.jsonl"),
        "heldout_commit": _git("log", "-1", "--format=%h", "--", "data/curated/heldout_eval.jsonl"),
        "data": manifest_info(),
        "versions": VERSIONS,
        "thresholds": {
            "model_low": config.MODEL_LOW,
            "model_high": config.MODEL_HIGH,
            "source": "eval/calibration.json" if (config.EVAL_DIR / "calibration.json").exists() else "defaults",
        },
        "A_messages": a,
        "B_real_sms": b,
        "C_links": c,
        "D_sessions": srep,
        "E_cost_latency": e,
        "F_robustness": f,
        "classifier": crep.as_dict(),
        "runtime_s": round(time.time() - t0, 1),
    }
    report["headline"] = headline(report)
    if not args.fast and not FIRST_LOOK.exists():
        FIRST_LOOK.write_text(
            json.dumps(
                {
                    "generated": report["generated"],
                    "git_commit": report["git_commit"],
                    "heldout_sha256": report["heldout_sha256"],
                    "A_messages_heldout": a["heldout"],
                    "C_links_heldout": c["heldout"],
                    "F_robustness_heldout": f["heldout"],
                    "note": "First evaluation ever run on the held-out set. Never overwritten.",
                },
                indent=2,
                ensure_ascii=False,
            )
        )
    if FIRST_LOOK.exists():
        report["heldout_first_look"] = json.loads(FIRST_LOOK.read_text())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    (args.out / "report.md").write_text(to_md(report), encoding="utf-8")
    if args.compare:
        rc = compare(args.compare, report, args.allow_drift)
        if rc:
            raise SystemExit(rc)
    return report


if __name__ == "__main__":
    r = main()
    print(json.dumps(r["headline"], indent=1))
