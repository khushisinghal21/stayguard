"""The one blind run on held-out v3 (DECISIONS #43). Usage: make eval-v3  (python -m eval.evaluate_v3)

What it answers, stated before the run (pre-registered here and in DECISIONS #43):

PRIMARY: is the candidate pipeline better than today's system on held-out v3?
    candidate      = multilingual encoder + booking context (encoder_ctx), thresholds from its own calibration,
                     platform-flow warning (DECISIONS #40), model-only holds routed to the judges (DECISIONS #39)
    baseline_today = the system at commit da6d30d: TF-IDF model, thresholds 0.03 / 0.52, no new options
    Two paired exact McNemar tests on the same messages: scams caught (held or blocked), and legitimate messages held.
    p-values are Holm-adjusted across these two. Offline judge in both (the same stand-in all earlier numbers use).

SECONDARY (exploratory, no multiple-comparison claim): one arm per change, each against baseline_today, so the run
shows which change helps or hurts: today's model recalibrated, platform-flow only, routing only, tfidf_ctx, encoder_ctx
alone; the candidate with the judges down; both classifiers alone; and, if STAYGUARD_ANTHROPIC_API_KEY is set, the
candidate with the real prosecutor/defender judges.

Not measured here: network link checks (DECISIONS #42). v3's domains are invented, so every one would come back
"not registered" and the result would say nothing about real links.

Protocol: the run is refused unless the tree is clean, held-out v3 matches its committed hash, no STAYGUARD_* setting
other than the API key is set, every arm's calibration file is committed, and the encoder matches its manifest. The
first run is frozen in eval/heldout_v3_first_look.json and never regenerated. An arm missing from the first look (the
real-judge arm, when the first run had no key) can be added once, from the same commit, with --add-arm. Any later run
writes eval/heldout_v3_rerun_NOT_BLIND.json instead.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from eval.evaluate import _git, _git_rc, _sha256, load_rows, manifest_info, mcnemar_exact, score, validate_rows, wilson  # noqa: E402
from stayguard import config  # noqa: E402
from stayguard.engine import Engine, EngineOptions  # noqa: E402
from stayguard.links import LinkChecker  # noqa: E402

V3_FILE = "heldout_v3.jsonl"
V3_SHA256 = "d260839140ddcb6239aef4057bfd6dc4448fada5fb7d794b3b29db99757ffd36"  # committed in fb2f14a
FIRST_LOOK_V3 = config.EVAL_DIR / "heldout_v3_first_look.json"
RERUN_V3 = config.EVAL_DIR / "heldout_v3_rerun_NOT_BLIND.json"
BASELINE_THRESHOLDS = (0.03, 0.52)  # eval/calibration.json at da6d30d: today's system
PRIMARY = ("candidate", "baseline_today")
ALLOWED_ENV = {"STAYGUARD_ANTHROPIC_API_KEY"}


def _cal(kind: str) -> tuple[float, float]:
    c = config.calibration_for(kind)
    if not c:
        raise SystemExit(f"refusing: {config.calibration_path(kind).name} is missing (run its calibration and commit it)")
    return float(c["model_low"]), float(c["model_high"])


def arm_specs() -> dict[str, dict[str, Any]]:
    """name -> engine options. Order is the report order."""
    lo_recal, hi_recal = _cal("tfidf_recal")
    lo_t, hi_t = _cal("tfidf_ctx")
    lo_e, hi_e = _cal("encoder_ctx")
    b_lo, b_hi = BASELINE_THRESHOLDS
    return {
        "baseline_today": {"classifier": "tfidf", "model_low": b_lo, "model_high": b_hi},
        "today_recalibrated": {"classifier": "tfidf", "model_low": lo_recal, "model_high": hi_recal},
        "today_platform_flow": {"classifier": "tfidf", "model_low": b_lo, "model_high": b_hi, "platform_flow_warn": True},
        "today_route_high": {"classifier": "tfidf", "model_low": b_lo, "model_high": b_hi, "route_model_high_to_judges": True},
        "tfidf_ctx": {"classifier": "tfidf_ctx", "model_low": lo_t, "model_high": hi_t},
        "encoder_ctx": {"classifier": "encoder_ctx", "model_low": lo_e, "model_high": hi_e},
        "candidate": {
            "classifier": "encoder_ctx",
            "model_low": lo_e,
            "model_high": hi_e,
            "platform_flow_warn": True,
            "route_model_high_to_judges": True,
        },
    }


def ctx_for_v3(x: dict[str, Any]) -> dict[str, Any]:
    return {
        "payment_terms": x["terms"],
        "direction": x.get("direction", "hotel_to_guest"),
        "first_in_thread": x.get("first_in_thread"),
        "property_domains": [],
    }


def holm(pvals: dict[str, float]) -> dict[str, float]:
    order = sorted(pvals, key=lambda k: pvals[k])
    m, out, running = len(order), {}, 0.0
    for i, k in enumerate(order):
        running = max(running, min(1.0, (m - i) * pvals[k]))
        out[k] = round(running, 5)
    return out


def gate(add_arm: str | None) -> None:
    rc, top = _git_rc("rev-parse", "--show-toplevel")
    if rc or Path(top).resolve() != ROOT:
        raise SystemExit(f"refusing the blind v3 run: {ROOT} is not the top of its own git repository")
    rc, status = _git_rc("status", "--porcelain")
    if rc or status:
        raise SystemExit("refusing the blind v3 run: the working tree is not clean (commit eval/calibration_*.json first)")
    if _sha256(config.DATA_CURATED / V3_FILE) != V3_SHA256:
        raise SystemExit("refusing: heldout_v3.jsonl differs from the committed file")
    extra = sorted(k for k in os.environ if k.upper().startswith("STAYGUARD_") and k.upper() not in ALLOWED_ENV)
    if extra:
        raise SystemExit(f"refusing the blind v3 run: STAYGUARD_* settings change the system: {extra}")
    for kind in ("tfidf_recal", "tfidf_ctx", "encoder_ctx"):
        _cal(kind)
    if add_arm:
        if not FIRST_LOOK_V3.exists():
            raise SystemExit("--add-arm needs an existing first look")
        fl = json.loads(FIRST_LOOK_V3.read_text())
        if fl["git_commit"] != _git("rev-parse", "HEAD"):
            raise SystemExit(f"--add-arm must run at the first look's commit {fl['git_commit']}")
        if add_arm in fl["systems"]:
            raise SystemExit(f"arm {add_arm} is already in the first look")


def run_arm(eng: Engine, rows: list[dict[str, Any]], outage: bool = False) -> list[Any]:
    eng.breaker.forced_outage = outage
    try:
        return [eng.check(x["text"], ctx_for_v3(x), record=False) for x in rows]
    finally:
        eng.breaker.forced_outage = False


def summarise(rows: list[dict[str, Any]], ds: list[Any]) -> dict[str, Any]:
    y = [int(x["label"]) for x in rows]
    flagged = [d.decision in ("hold", "block") for d in ds]
    out = score(y, flagged, [d.decision == "warn" for d in ds])
    out["catch_rate_ci95"] = wilson(out["tp"], out["tp"] + out["fn"])
    out["false_alarm_rate_ci95"] = wilson(out["fp"], out["fp"] + out["tn"])
    out["fail_closed"] = sum(d.path == "fail_closed" for d in ds)
    out["scams_delivered_clean"] = sum(1 for a, d in zip(y, ds, strict=True) if a and d.decision == "deliver")
    lat = np.array([d.latency_ms for d in ds])
    out["p50_ms"], out["p95_ms"] = round(float(np.percentile(lat, 50)), 2), round(float(np.percentile(lat, 95)), 2)
    out["judge_share"] = round(sum(d.path in ("judges", "degraded") for d in ds) / len(ds), 6)
    groups: dict[str, dict[str, Any]] = defaultdict(lambda: {"n": 0, "held": 0, "warned": 0, "clean": 0})
    for x, d in zip(rows, ds, strict=True):
        outcome = "held" if d.decision in ("hold", "block") else "warned" if d.decision == "warn" else "clean"
        for key in (f"category:{x['category']}", f"lang:{'en' if x['lang'] == 'en' else 'non_en'}|label:{x['label']}"):
            groups[key]["n"] += 1
            groups[key][outcome] += 1
    out["by_group"] = {k: dict(v) for k, v in sorted(groups.items())}
    return out


def paired(rows: list[dict[str, Any]], a: list[Any], b: list[Any]) -> dict[str, Any]:
    fa = [d.decision in ("hold", "block") for d in a]
    fb = [d.decision in ("hold", "block") for d in b]
    s = [i for i, x in enumerate(rows) if x["label"] == 1]
    lg = [i for i, x in enumerate(rows) if x["label"] == 0]
    return {
        "scams_caught": mcnemar_exact([fa[i] for i in s], [fb[i] for i in s]),
        "legit_held": mcnemar_exact([fa[i] for i in lg], [fb[i] for i in lg]),
    }


def main(argv: list[str] | None = None) -> dict[str, Any]:
    ap = argparse.ArgumentParser()
    ap.add_argument("--add-arm", choices=["candidate_real_judges"], help="add the real-judge arm to an existing first look")
    ap.add_argument("--rerun-not-blind", action="store_true", help="run again after the first look (written separately)")
    args = ap.parse_args(argv)
    if FIRST_LOOK_V3.exists() and not (args.add_arm or args.rerun_not_blind):
        raise SystemExit("held-out v3 already had its blind run; use --rerun-not-blind (results are NOT blind)")
    if not args.rerun_not_blind:
        gate(args.add_arm)
    rows = load_rows(V3_FILE)
    validate_rows(rows)
    t0 = time.time()
    links = LinkChecker()  # offline: v3 domains are invented (see module docstring)
    specs = arm_specs()
    key = config.LLM_API_KEY
    if args.add_arm and not key:
        raise SystemExit("--add-arm candidate_real_judges needs STAYGUARD_ANTHROPIC_API_KEY")
    from stayguard.encoder import EncoderUnavailable

    try:
        engines = {name: Engine(link_checker=links, options=EngineOptions(**opts)) for name, opts in specs.items()}
    except EncoderUnavailable as e:
        raise SystemExit(f"refusing: the encoder is not ready ({e}). Run: make encoder") from None
    ds: dict[str, list[Any]] = {}
    # adding the real-judge arm later re-runs only the (deterministic) baseline it is paired with
    for name in ["baseline_today"] if args.add_arm else list(specs):
        ds[name] = run_arm(engines[name], rows)
    if not args.add_arm:
        ds["candidate_judges_down"] = run_arm(engines["candidate"], rows, outage=True)
    if key:
        from stayguard.judges import AnthropicJudge

        real = Engine(link_checker=links, judge=AnthropicJudge(key), options=EngineOptions(**specs["candidate"]))
        ds["candidate_real_judges"] = run_arm(real, rows)
    systems = {name: summarise(rows, d) for name, d in ds.items() if not (args.add_arm and name == "baseline_today")}
    if not args.add_arm:
        y = [x["label"] for x in rows]
        for name, eng in (
            ("baseline_classifier_only", engines["baseline_today"]),
            ("encoder_classifier_only", engines["encoder_ctx"]),
        ):
            p = [eng.clf.score(x["text"], ctx_for_v3(x)) for x in rows]
            systems[name] = score(y, [v >= 0.5 for v in p])
            systems[name]["catch_rate_ci95"] = wilson(systems[name]["tp"], systems[name]["tp"] + systems[name]["fn"])
            systems[name]["false_alarm_rate_ci95"] = wilson(systems[name]["fp"], systems[name]["fp"] + systems[name]["tn"])
    base = ds.get("baseline_today")
    tests: dict[str, Any] = {}
    if base is not None:
        for name, d in ds.items():
            if name != "baseline_today":
                tests[f"{name}_vs_baseline_today"] = paired(rows, d, base)
    if "candidate_vs_baseline_today" in tests:
        prim = tests["candidate_vs_baseline_today"]
        adj = holm({k: prim[k]["p_value"] for k in ("scams_caught", "legit_held")})
        for k, v in adj.items():
            prim[k]["p_value_holm"] = v
    errors = []
    if "candidate" in ds and base is not None:
        for x, c, b in zip(rows, ds["candidate"], base, strict=True):
            if (c.decision in ("hold", "block")) != bool(x["label"]) or (b.decision in ("hold", "block")) != bool(x["label"]):
                errors.append(
                    {
                        "id": x["id"],
                        "label": x["label"],
                        "category": x["category"],
                        "lang": x["lang"],
                        "candidate": [c.decision, c.path, c.reasons],
                        "baseline_today": [b.decision, b.path, b.reasons],
                        "text": x["text"],
                    }
                )
    result = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "git_commit": _git("rev-parse", "HEAD"),
        "heldout_v3_sha256": V3_SHA256,
        "n": len(rows),
        "n_scam": sum(x["label"] for x in rows),
        "n_legit": sum(1 - x["label"] for x in rows),
        "pre_registered_primary": f"{PRIMARY[0]} vs {PRIMARY[1]}: scams caught and legit held, exact McNemar, Holm over 2",
        "arms": {name: {**specs[name]} for name in specs} | {"candidate_judges_down": "candidate with the judges forced down"},
        "systems": systems,
        "paired_tests": tests,
        "differences_and_errors": errors,
        "run_conditions": {
            "classifier_versions": {n: e.clf.version for n, e in engines.items()},
            "judge_provider": engines["candidate"].judge_provider,
            "real_judges": bool(key),
            "data_manifest_hash": manifest_info()["data_manifest_hash"],
            "encoder_manifest": json.loads((config.ENCODER_DIR / "MANIFEST.json").read_text()),
            "seconds": round(time.time() - t0, 1),
        },
    }
    if args.rerun_not_blind:
        RERUN_V3.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    elif args.add_arm:
        fl = json.loads(FIRST_LOOK_V3.read_text())
        fl["systems"][args.add_arm] = systems[args.add_arm]
        fl["paired_tests"].update(result["paired_tests"])
        fl.setdefault("added_arms", {})[args.add_arm] = {"generated": result["generated"], "git_commit": result["git_commit"]}
        FIRST_LOOK_V3.write_text(json.dumps(fl, indent=2, ensure_ascii=False) + "\n")
    else:
        FIRST_LOOK_V3.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(headline(result), indent=2))
    return result


def headline(r: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, s in r["systems"].items():
        out[name] = {
            "caught": f"{s['tp']}/{s['tp'] + s['fn']}",
            "legit_held": f"{s['fp']}/{s['fp'] + s['tn']}",
            **({"p95_ms": s["p95_ms"]} if "p95_ms" in s else {}),
        }
    prim = r["paired_tests"].get("candidate_vs_baseline_today")
    if prim:
        out["PRIMARY candidate vs baseline_today"] = prim
    return out


if __name__ == "__main__":
    main()
