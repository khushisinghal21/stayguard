"""StayGuard evaluation. Run:  python -m eval.evaluate   (writes eval/report.json and eval/report.md)

A. Golden + red-team set (115 hand-written messages, never used for training): StayGuard vs baselines.
B. Real false alarms: 1,394 held-out real SMS from the UCI collection, pushed through the full pipeline
   as if a hotel sent them on a pay-at-property booking (the strictest setting).
C. Links nobody has reported yet: blocklist off; real phishing hosts vs 100k real legit domains that the
   popularity allowlist does not know.
D. Session model (synthetic logins - see stayguard/session_risk.py).
E. Cost and latency on a realistic traffic mix.
F. Robustness: golden scams rewritten (no deadline, fresh brand-free domain, leetspeak, hidden characters).
"""
from __future__ import annotations

import json
import random
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sklearn.metrics import f1_score  # noqa: E402

from stayguard import config  # noqa: E402
from stayguard.classifier import build_pipeline, prep, sms_rows, train  # noqa: E402
from stayguard.engine import Engine  # noqa: E402
from stayguard.links import LinkChecker, _raw_blocklist  # noqa: E402
from stayguard.session_risk import train as train_sessions  # noqa: E402

PROPERTY_DOMAINS = ["lisboncityhotel.pt", "algarveresorthotel.pt"]


def load_golden() -> list[dict]:
    with open(config.DATA_CURATED / "golden_eval.jsonl", encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def ctx_for(x: dict) -> dict:
    return {"payment_terms": x.get("terms", "unknown"), "direction": x.get("direction", "hotel_to_guest"),
            "property_domains": PROPERTY_DOMAINS}


def score(y: list[int], flagged: list[bool], warned: list[bool] | None = None) -> dict:
    tp = sum(1 for a, b in zip(y, flagged) if a and b)
    fn = sum(1 for a, b in zip(y, flagged) if a and not b)
    fp = sum(1 for a, b in zip(y, flagged) if not a and b)
    tn = sum(1 for a, b in zip(y, flagged) if not a and not b)
    out = {"tp": tp, "fn": fn, "fp": fp, "tn": tn,
           "catch_rate": round(tp / (tp + fn), 4) if tp + fn else None,
           "false_alarm_rate": round(fp / (fp + tn), 4) if fp + tn else None,
           "precision": round(tp / (tp + fp), 4) if tp + fp else None,
           "f1": round(f1_score(y, flagged), 4) if any(y) else None}
    if warned is not None:
        legit_warned = sum(1 for a, f, w in zip(y, flagged, warned) if not a and w and not f)
        out["legit_warned_rate"] = round(legit_warned / (fp + tn), 4) if fp + tn else None
    return out


def section_a(engine: Engine, engine_nobl: Engine, sms_only) -> dict:
    gold = load_golden()
    y = [x["label"] for x in gold]
    systems: dict[str, dict] = {}

    # baseline 1: blocklist only
    lc = LinkChecker()
    from stayguard.signals import extract
    bl = [any("KNOWN_PHISHING_DOMAIN" in lc.check(u).reasons for u in extract(x["text"]).urls) for x in gold]
    systems["baseline_blocklist_only"] = score(y, bl)
    # baseline 2: generic spam filter (trained on SMS only)
    sp = [sms_only.predict_proba([prep(x["text"])])[0, 1] >= 0.5 for x in gold]
    systems["baseline_generic_spam_filter"] = score(y, sp)

    def run(eng: Engine, name: str, outage: bool = False) -> list:
        eng.breaker.forced_outage = outage
        ds = [eng.check(x["text"], ctx_for(x), record=False) for x in gold]
        eng.breaker.forced_outage = False
        systems[name] = score(y, [d.decision in ("hold", "block") for d in ds], [d.decision == "warn" for d in ds])
        return ds

    full = run(engine, "stayguard_full")
    rules_only = [any(t.get("decided") for t in d.trace if t["stage"] == "rules") and d.decision in ("hold", "block") for d in full]
    systems["stayguard_rules_only"] = score(y, rules_only)
    run(engine_nobl, "stayguard_zero_day_links_blocklist_off")
    run(engine, "stayguard_degraded_llm_down", outage=True)

    per_cat: dict[str, dict] = defaultdict(lambda: {"n": 0, "correct": 0})
    per_lang: dict[str, dict] = defaultdict(lambda: {"n": 0, "correct": 0})
    paths: dict[str, int] = defaultdict(int)
    errors = []
    for x, d in zip(gold, full):
        flagged = d.decision in ("hold", "block")
        ok = flagged == bool(x["label"])
        for bucket, key in ((per_cat, x["category"]), (per_lang, x["lang"])):
            bucket[key]["n"] += 1
            bucket[key]["correct"] += int(ok)
        paths[d.path] += 1
        if not ok or (x["label"] == 0 and d.decision == "warn"):
            errors.append({"id": x["id"], "label": x["label"], "decision": d.decision, "path": d.path,
                           "reasons": d.reasons, "text": x["text"]})
    for b in (per_cat, per_lang):
        for v in b.values():
            v["accuracy"] = round(v["correct"] / v["n"], 4)
    return {"n": len(gold), "n_scam": sum(y), "n_legit": len(y) - sum(y), "systems": systems,
            "per_category": dict(per_cat), "per_language": dict(per_lang), "paths": dict(paths), "errors_and_warnings": errors}


def section_b(engine: Engine) -> dict:
    hold = pd.read_csv(config.MODELS / "sms_holdout.csv")
    out = {}
    for label, name in ((0, "real_ham"), (1, "real_spam")):
        sub = hold[hold.label == label]
        ds = [engine.check(t, {"payment_terms": "pay_at_property", "direction": "hotel_to_guest"}, record=False) for t in sub.text]
        dec = defaultdict(int)
        for d in ds:
            dec[d.decision] += 1
        n = len(ds)
        out[name] = {"n": n, "decisions": dict(dec), "held_or_blocked_rate": round((dec["hold"] + dec["block"]) / n, 4),
                     "warned_rate": round(dec["warn"] / n, 4)}
        if label == 0:
            out[name]["examples_held"] = [t for t, d in zip(sub.text, ds) if d.decision in ("hold", "block")][:8]
    return out


def section_c() -> dict:
    rng = random.Random(3)
    blocklisted = _raw_blocklist()
    nobl = LinkChecker(use_blocklist=False)
    flagged = lambda h: nobl.check("https://" + h).verdict in ("malicious", "suspicious")  # noqa: E731

    # C1: travel-brand look-alikes withheld from the blocklist. Selected by containing "booking", which is also a
    # heuristic feature, so this measures look-alike coverage, not general zero-day skill (see C2).
    brand = sorted(h for h in blocklisted if "booking" in h)
    rng.shuffle(brand)
    c1 = brand[: len(brand) // 2]
    c1_hit = [h for h in c1 if flagged(h)]
    # C2: random sample of the WHOLE feed (any brand), blocklist off - honest general zero-day number
    allbl = sorted(blocklisted)
    c2 = rng.sample(allbl, 3000)
    c2_hit = sum(flagged(h) for h in c2)
    # C3: false positives on 100k legit domains the popularity allowlist does NOT know (ranks 10,001-110,000)
    legit = []
    if config.TOP_1M.exists():
        with open(config.TOP_1M, encoding="utf-8") as f:
            for i, line in enumerate(f):
                if i < 10000:
                    continue
                if i >= 110000:
                    break
                d = line.strip().lower()
                if d and d not in blocklisted:
                    legit.append(d)
    fps = [d for d in legit if flagged(d)]
    brandy = [d for d in legit if any(b in d for b in ("booking", "airbnb", "agoda", "expedia", "priceline"))]
    brandy_fp = [d for d in brandy if flagged(d)]
    op_lc = LinkChecker(use_blocklist=False)
    op = [l.strip() for l in open(config.OPENPHISH, encoding="utf-8") if l.strip()]
    op_det = sum(op_lc.check(u).verdict in ("malicious", "suspicious") for u in op)
    return {
        "booking_themed_phishing_in_feeds": len(brand),
        "c1_brand_lookalikes_withheld": len(c1),
        "c1_detection_rate": round(len(c1_hit) / len(c1), 4),
        "c2_random_feed_sample": len(c2),
        "c2_detection_rate": round(c2_hit / len(c2), 4),
        "c3_unseen_legit_domains": len(legit),
        "c3_false_positive_rate": round(len(fps) / len(legit), 4) if legit else None,
        "c3_false_positive_examples": fps[:12],
        "c3_legit_with_brand_token": len(brandy),
        "c3_brand_token_false_positive_rate": round(len(brandy_fp) / len(brandy), 4) if brandy else None,
        "c3_brand_token_fp_examples": brandy_fp[:8],
        "openphish_generic_urls": len(op),
        "openphish_heuristic_detection_rate": round(op_det / len(op), 4),
        "note": "In production the blocklist and heuristics run together; heuristics exist for links nobody has reported "
                "yet. A flagged legit link is 'held' only when the message also asks for money; otherwise the guest sees "
                "a warning.",
    }


ZW = "\u200b"
NEUTRAL = ["sunny", "trail", "harbor", "maple", "river", "stone", "cedar", "lumen", "nova", "atlas"]


def _mutate(text: str, kind: str, rng: random.Random) -> str:
    from stayguard.signals import URGENCY, URL_RX
    if kind in ("no_urgency", "combined"):
        text = URGENCY.sub("", text)
    if kind in ("neutral_new_domain", "combined"):
        text = URL_RX.sub(lambda m: f"https://{rng.choice(NEUTRAL)}{rng.choice(NEUTRAL)}.com/r/{rng.randint(100, 999)}", text)
    if kind in ("leetspeak", "combined"):
        tr = str.maketrans({"a": "4", "e": "3", "o": "0", "i": "1"})
        text = " ".join(w.translate(tr) if len(w) >= 4 and rng.random() < 0.5 and "://" not in w else w for w in text.split())
    if kind == "zero_width":
        text = " ".join(w[: len(w) // 2] + ZW + w[len(w) // 2:] if len(w) >= 5 and "://" not in w else w for w in text.split())
    if kind == "spaced_letters":
        text = " ".join(" ".join(w) if 4 <= len(w) <= 8 and w.isalpha() and rng.random() < 0.3 else w for w in text.split())
    return text


def section_f(engine: Engine) -> dict:
    """Robustness: attackers rewrite messages to dodge filters. Catch rate on mutated golden scams."""
    gold = load_golden()
    scams = [x for x in gold if x["label"] == 1]
    legit = [x for x in gold if x["label"] == 0]
    out = {}
    for kind in ("no_urgency", "neutral_new_domain", "leetspeak", "zero_width", "spaced_letters", "combined"):
        rng = random.Random(kind)
        ds = [engine.check(_mutate(x["text"], kind, rng), ctx_for(x), record=False) for x in scams]
        caught = sum(d.decision in ("hold", "block") for d in ds)
        out[kind] = {"n": len(scams), "catch_rate": round(caught / len(scams), 4),
                     "missed_ids": [x["id"] for x, d in zip(scams, ds) if d.decision not in ("hold", "block")][:12]}
    rng = random.Random(0)
    lz = [engine.check(_mutate(x["text"], "zero_width", rng), ctx_for(x), record=False) for x in legit]
    out["legit_with_zero_width"] = {"n": len(legit), "held_rate": round(sum(d.decision in ("hold", "block") for d in lz) / len(legit), 4),
                                    "warned_rate": round(sum(d.decision == "warn" for d in lz) / len(legit), 4)}
    return out


def section_e(engine: Engine, gold: list[dict]) -> dict:
    hold = pd.read_csv(config.MODELS / "sms_holdout.csv")
    ham = hold[hold.label == 0].text.tolist()
    # realistic mix: ~97% normal conversation, ~3% risky messages
    mix = [(t, {"payment_terms": "pay_at_property", "direction": "hotel_to_guest"}) for t in ham[:970]]
    mix += [(x["text"], ctx_for(x)) for x in gold if x["label"] == 1][:30]
    lat, judge_calls, paths = [], 0, defaultdict(int)
    for t, c in mix:
        t0 = time.perf_counter()
        d = engine.check(t, c, record=False)
        lat.append((time.perf_counter() - t0) * 1000)
        judge_calls += int(d.path == "judges")
        paths[d.path] += 1
    lat.sort()
    share = judge_calls / len(mix)
    return {"n": len(mix), "paths": dict(paths), "judge_share": round(share, 4),
            "p50_ms": round(statistics.median(lat), 2), "p95_ms": round(lat[int(0.95 * len(lat))], 2),
            "p99_ms": round(lat[int(0.99 * len(lat))], 2),
            "llm_cost_per_call_usd": config.LLM_COST_PER_CALL_USD,
            "cost_per_1000_messages_usd": round(share * config.LLM_COST_PER_CALL_USD * 1000, 4),
            "cost_per_1000_if_every_message_went_to_llm_usd": round(config.LLM_COST_PER_CALL_USD * 1000, 2),
            "note": "Latency excludes network; judge path measured with the offline judge. With a hosted LLM add ~1-3 s "
                    "to judge-path messages only."}


def to_md(r: dict) -> str:
    a, b, c, e = r["A_golden"], r["B_real_sms"], r["C_zero_day_links"], r["E_cost_latency"]
    s = r["D_sessions"]
    lines = ["# StayGuard evaluation report", "", f"Generated {r['generated']}. Reproduce with `python -m eval.evaluate`.", "",
             "## A. Golden + red-team set", "",
             f"{a['n']} hand-written messages ({a['n_scam']} scams, {a['n_legit']} legitimate) in English, Hindi, Hinglish, Spanish, "
             "Portuguese, French, German and Italian. Never used for training. **Caveat:** written by the same team that wrote the "
             "rules, so these numbers are optimistic; B and C below use real, independent data.", "",
             "| System | Catch rate | False alarms | Legit warned | Precision | F1 |", "|---|---|---|---|---|---|"]
    for k, v in a["systems"].items():
        lines.append(f"| {k} | {v['catch_rate']:.0%} | {v['false_alarm_rate']:.0%} | "
                     f"{'' if v.get('legit_warned_rate') is None else format(v['legit_warned_rate'], '.0%')} | "
                     f"{'' if v['precision'] is None else format(v['precision'], '.0%')} | {'' if v['f1'] is None else v['f1']} |")
    lines += ["", "Accuracy by category:", "", "| Category | n | Accuracy |", "|---|---|---|"]
    lines += [f"| {k} | {v['n']} | {v['accuracy']:.0%} |" for k, v in sorted(a["per_category"].items())]
    lines += ["", "Accuracy by language:", "", "| Language | n | Accuracy |", "|---|---|---|"]
    lines += [f"| {k} | {v['n']} | {v['accuracy']:.0%} |" for k, v in sorted(a["per_language"].items())]
    lines += ["", "Misses, false alarms and warnings on legit messages:", ""]
    lines += [f"- `{x['id']}` label={x['label']} -> **{x['decision']}** via {x['path']} {x['reasons']}: {x['text'][:110]}"
              for x in a["errors_and_warnings"]] or ["- none"]
    lines += ["", "## B. Real messages (UCI SMS Spam Collection, held-out split)", "",
              f"- {b['real_ham']['n']} real everyday messages sent through the full pipeline as hotel->guest on a pay-at-property booking: "
              f"**{b['real_ham']['held_or_blocked_rate']:.2%} held**, {b['real_ham']['warned_rate']:.2%} delivered with a warning.",
              f"- {b['real_spam']['n']} real spam messages: {b['real_spam']['held_or_blocked_rate']:.1%} held/blocked, "
              f"{b['real_spam']['warned_rate']:.1%} warned (generic spam, not hotel scams).",
              "", "Real messages that were held:", ""]
    lines += [f"- {t[:120]}" for t in b["real_ham"].get("examples_held", [])] or ["- none"]
    lines += ["", "## C. Links nobody has reported yet (blocklist switched off)", "",
              f"- C1 travel-brand look-alikes: {c['c1_brand_lookalikes_withheld']} of the {c['booking_themed_phishing_in_feeds']} real "
              f"Booking-themed phishing hosts withheld -> **{c['c1_detection_rate']:.1%}** flagged. (Selected by containing 'booking', "
              "which is itself a heuristic feature - so read this as look-alike coverage.)",
              f"- C2 random sample of {c['c2_random_feed_sample']:,} hosts from the whole 392k feed (every brand and lure): "
              f"**{c['c2_detection_rate']:.1%}** flagged by heuristics alone.",
              f"- C3 false positives on {c['c3_unseen_legit_domains']:,} real legit domains ranked 10,001-110,000 (not in the popularity "
              f"allowlist): **{c['c3_false_positive_rate']:.2%}**; among the {c['c3_legit_with_brand_token']} legit domains containing a travel "
              f"brand token: {c['c3_brand_token_false_positive_rate']:.1%} "
              f"(e.g. {', '.join(c['c3_brand_token_fp_examples'][:5]) or 'none'}).",
              f"- Examples of flagged legit domains: {', '.join(c['c3_false_positive_examples'][:8]) or 'none'}",
              f"- OpenPhish ({c['openphish_generic_urls']} live URLs): {c['openphish_heuristic_detection_rate']:.1%} by heuristics alone.",
              f"- {c['note']}", "",
              "## F. Robustness: scams rewritten to dodge filters", "",
              "| Mutation | Catch rate | Missed |", "|---|---|---|"]
    lines += [f"| {k} | {v['catch_rate']:.0%} | {', '.join(v['missed_ids']) or '-'} |" for k, v in r["F_robustness"].items() if "catch_rate" in v]
    lz = r["F_robustness"]["legit_with_zero_width"]
    lines += ["", f"Legit messages with zero-width characters inserted: {lz['held_rate']:.0%} held, {lz['warned_rate']:.0%} warned.", "",
              "`neutral_new_domain` swaps every link for a fresh, brand-free domain (the hardest case for link checks); "
              "`combined` also strips deadlines and applies leetspeak.", "",
              "## D. Session takeover model (synthetic logins)", "",
              f"ROC AUC {s['roc_auc']:.3f}; false alarms at the 'risky' threshold {s['fpr_at_risky']:.2%}.", "",
              "| Attack | Caught at risky | Caught at critical |", "|---|---|---|"]
    lines += [f"| {k} | {v:.0%} | {s['recall_at_critical'][k]:.0%} |" for k, v in s["recall_at_risky"].items()]
    lines += ["", "Synthetic data is separable by construction, so treat these as a plumbing check. The useful finding is "
              "`on_device_malware`: when malware runs on the hotel's own PC the login looks normal, which is why every message "
              "is still checked on its own.", "",
              "## E. Cost and latency (1,000-message realistic mix: 97% normal, 3% scams)", "",
              f"- Paths: {e['paths']}", f"- Judge (LLM) share: **{e['judge_share']:.1%}**",
              f"- Latency p50 {e['p50_ms']} ms, p95 {e['p95_ms']} ms, p99 {e['p99_ms']} ms",
              f"- LLM cost per 1,000 messages: **${e['cost_per_1000_messages_usd']}** vs ${e['cost_per_1000_if_every_message_went_to_llm_usd']} "
              f"if every message went to an LLM (at ${e['llm_cost_per_call_usd']} per judged message).", f"- {e['note']}", "",
              "## Classifier sanity check (SMS held-out)", "",
              f"ROC AUC {r['classifier']['sms_test']['roc_auc']:.3f}, precision {r['classifier']['sms_test']['precision']:.1%}, "
              f"recall {r['classifier']['sms_test']['recall']:.1%}."]
    return "\n".join(lines) + "\n"


def main() -> dict:
    t0 = time.time()
    print("training classifier ...")
    _, crep, _ = train(save=True)
    print("training session model ...")
    _, srep = train_sessions(save=True)
    sms = sms_rows()
    hold = pd.read_csv(config.MODELS / "sms_holdout.csv")
    sms_tr = sms[~sms.text.isin(set(hold.text))]
    sms_only = build_pipeline().fit(sms_tr.text.map(prep), sms_tr.label)
    engine = Engine()
    engine_nobl = Engine(link_checker=LinkChecker(use_blocklist=False))
    print("A golden ...")
    a = section_a(engine, engine_nobl, sms_only)
    print("B real sms ...")
    b = section_b(engine)
    print("C zero-day links ...")
    c = section_c()
    print("F robustness ...")
    f = section_f(engine)
    print("E cost/latency ...")
    e = section_e(engine, load_golden())
    report = {"generated": time.strftime("%Y-%m-%d %H:%M"), "A_golden": a, "B_real_sms": b, "C_zero_day_links": c,
              "D_sessions": srep, "E_cost_latency": e, "F_robustness": f, "classifier": crep.as_dict(),
              "runtime_s": round(time.time() - t0, 1)}
    (config.EVAL_DIR / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    (config.EVAL_DIR / "report.md").write_text(to_md(report), encoding="utf-8")
    return report


if __name__ == "__main__":
    r = main()
    print(json.dumps({k: r["A_golden"]["systems"][k] for k in r["A_golden"]["systems"]}, indent=1))
    print(json.dumps(r["B_real_sms"], indent=1, ensure_ascii=False)[:1500])
    print(json.dumps(r["C_zero_day_links"], indent=1))
    print(json.dumps(r["E_cost_latency"], indent=1))
    print(json.dumps(r["F_robustness"], indent=1))
