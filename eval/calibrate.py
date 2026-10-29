"""Choose MODEL_LOW / MODEL_HIGH on a calibration split, never on held-out data.

Calibration data: the SMS calibration split (models/sms_calibration.csv, never trained on) + the dev golden set.
Rule (stated before looking at the numbers):
- MODEL_LOW  = the largest threshold at which at most 1% of calibration scams score below it
               (below MODEL_LOW a message is delivered without the judges, so this caps the scams skipped).
- MODEL_HIGH = the smallest threshold at which at most 1% of calibration legitimate messages score above it
               (above MODEL_HIGH a message is held without the judges, so this caps false holds).
Both are clamped to [0.02, 0.98] and MODEL_LOW < MODEL_HIGH.
Writes eval/calibration.json (thresholds, reliability bins) and eval/reliability.png.

Context models (--classifier tfidf_ctx | encoder_ctx, DECISIONS #38/#41) use the same rule on a larger hotel set: the
SMS calibration split + the dev set + held-out v2, retired as a blind set once held-out v3 was frozen. v2 was written by
a separate agent, so it is the least correlated labelled hotel data we have; it is never trained on. These write
eval/calibration_<kind>.json. Held-out v3 is never read here (a test enforces it).

Per-language thresholds were considered (review of v2, item 4) and are only computed for a language with at least
PER_LANGUAGE_MIN scams and PER_LANGUAGE_MIN legitimate calibration rows; the counts are written either way.

Usage: python -m eval.calibrate [--classifier tfidf|tfidf_ctx|encoder_ctx]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from stayguard import config  # noqa: E402
from stayguard.classifier import ScamClassifier  # noqa: E402
from stayguard.signals import detect_language  # noqa: E402

GRID = np.round(np.arange(0.02, 0.981, 0.01), 2)
PER_LANGUAGE_MIN = 30


def calibration_rows() -> pd.DataFrame:
    sms = pd.read_csv(config.MODELS / "sms_calibration.csv")[["text", "label"]].assign(source="sms_calibration")
    dev = [
        json.loads(line)
        for line in (config.DATA_CURATED / "golden_eval.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    dev_df = pd.DataFrame(
        [{"text": r["text"], "label": r["label"], "source": "golden_dev"} for r in dev if r.get("split") == "dev"]
    )
    return pd.concat([sms, dev_df], ignore_index=True)


def _hotel_rows(name: str, source: str) -> pd.DataFrame:
    rows = [json.loads(x) for x in (config.DATA_CURATED / name).read_text(encoding="utf-8").splitlines() if x.strip()]
    return pd.DataFrame(
        [
            {"text": r["text"], "label": r["label"], "source": source, "terms": r.get("terms"), "direction": r.get("direction")}
            for r in rows
        ]
    )


def context_calibration_rows() -> pd.DataFrame:
    """SMS calibration + dev + retired held-out v2, with booking context where the set has it."""
    from stayguard.classifier import sms_splits

    # straight from the seeded split, so a fresh checkout does not need models/sms_calibration.csv first
    sms = sms_splits()[1][["text", "label"]].assign(source="sms_calibration", terms=None, direction=None)
    dev = _hotel_rows("golden_eval.jsonl", "golden_dev")
    v2 = _hotel_rows("heldout_v2.jsonl", "heldout_v2_retired")
    return pd.concat([sms, dev, v2], ignore_index=True)


def per_language(p: np.ndarray, y: np.ndarray, langs: list[str]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for lang in sorted(set(langs)):
        m = np.array([x == lang for x in langs])
        n_scam, n_legit = int(y[m].sum()), int((y[m] == 0).sum())
        entry: dict = {
            "n_scam": n_scam,
            "n_legit": n_legit,
            "eligible": n_scam >= PER_LANGUAGE_MIN and n_legit >= PER_LANGUAGE_MIN,
        }
        if entry["eligible"]:
            entry["model_low"], entry["model_high"] = choose(p[m], y[m])
        out[lang] = entry
    return out


def choose(p: np.ndarray, y: np.ndarray) -> tuple[float, float]:
    scams, legit = p[y == 1], p[y == 0]
    low = max([t for t in GRID if (scams < t).mean() <= 0.01], default=0.02)
    high = min([t for t in GRID if (legit > t).mean() <= 0.01], default=0.98)
    if low >= high:  # never let the bands cross
        low, high = 0.10, 0.90
    return float(low), float(high)


def reliability(p: np.ndarray, y: np.ndarray, bins: int = 10) -> list[dict]:
    edges = np.linspace(0, 1, bins + 1)
    out = []
    for i in range(bins):
        m = (p >= edges[i]) & (p < edges[i + 1] if i < bins - 1 else p <= edges[i + 1])
        if m.sum():
            out.append(
                {
                    "bin": [round(edges[i], 2), round(edges[i + 1], 2)],
                    "n": int(m.sum()),
                    "mean_predicted": round(float(p[m].mean()), 4),
                    "observed_scam_rate": round(float(y[m].mean()), 4),
                }
            )
    return out


def plot(rel_by_source: dict[str, list[dict]], low: float, high: float, path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    colors = {"sms_calibration": "#2a78d6", "golden_dev": "#eb6834"}  # categorical slots 1 and 2
    names = {"sms_calibration": "SMS calibration split", "golden_dev": "Hotel dev set"}
    fig, ax = plt.subplots(figsize=(6.4, 5.2), dpi=150)
    fig.patch.set_facecolor("#fcfcfb")
    ax.set_facecolor("#fcfcfb")
    ax.plot([0, 1], [0, 1], color="#b7b6ae", lw=1, ls="--", zorder=1)
    ax.text(0.83, 0.70, "perfectly calibrated", color="#52514e", fontsize=8, ha="center", rotation=39)
    for src, rows in rel_by_source.items():
        x = [r["mean_predicted"] for r in rows]
        yv = [r["observed_scam_rate"] for r in rows]
        ax.plot(x, yv, color=colors[src], lw=2, marker="o", ms=5, mec="#fcfcfb", mew=1.5, label=names[src], zorder=3)
    for t, label in ((low, f"MODEL_LOW {low:.2f}"), (high, f"MODEL_HIGH {high:.2f}")):
        ax.axvline(t, color="#52514e", lw=1, zorder=2)
        ax.text(t + 0.01, 0.03, label, color="#52514e", fontsize=8, rotation=90, va="bottom")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_xlabel("Model's scam probability (bin average)", color="#52514e")
    ax.set_ylabel("Share that really were scams", color="#52514e")
    ax.set_title("Reliability of the language model", color="#0b0b0b", loc="left", fontsize=11)
    fig.text(
        0.02,
        0.01,
        "Middle bins hold few messages, so they jump; per-bin counts are in eval/calibration.json.",
        color="#52514e",
        fontsize=7,
    )
    ax.grid(color="#e8e7e2", lw=0.6)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color("#b7b6ae")
    ax.tick_params(colors="#52514e", labelsize=8)
    ax.legend(frameon=False, fontsize=8, loc="upper left", labelcolor="#0b0b0b")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def main_context(kind: str) -> dict:
    """kind: tfidf_ctx | encoder_ctx, or tfidf_recal = the ORIGINAL model with thresholds re-chosen on this larger set
    (item 4 on its own, so the v3 run can tell recalibration apart from the new models)."""
    from stayguard.ctx_classifier import load

    clf: Any = ScamClassifier() if kind == "tfidf_recal" else load(kind)
    df = context_calibration_rows()
    p = np.array(
        [
            clf.score(t, {"payment_terms": terms or "unknown", "direction": d or "hotel_to_guest"})
            for t, terms, d in zip(df.text, df.terms, df.direction, strict=True)
        ]
    )
    y = df.label.to_numpy()
    low, high = choose(p, y)
    sources = ("sms_calibration", "golden_dev", "heldout_v2_retired")
    out = {
        "model_low": low,
        "model_high": high,
        "rule": "LOW: <=1% of calibration scams below; HIGH: <=1% of calibration legit above",
        "n": int(len(df)),
        "n_scam": int(y.sum()),
        "by_source": {s: int((df.source == s).sum()) for s in sources},
        "classifier_version": clf.version,
        "classifier_report": getattr(clf, "report", {}),
        "per_language": per_language(p, y, [detect_language(t) for t in df.text]),
        "reliability": {s: reliability(p[(df.source == s).to_numpy()], y[(df.source == s).to_numpy()]) for s in sources},
    }
    config.calibration_path(kind).write_text(json.dumps(out, indent=2) + "\n")
    return out


def main() -> dict:
    if len(sys.argv) > 2 and sys.argv[1] == "--classifier" and sys.argv[2] != "tfidf":
        return main_context(sys.argv[2])
    clf = ScamClassifier()
    df = calibration_rows()
    p = np.array([clf.score(t) for t in df.text])
    y = df.label.to_numpy()
    low, high = choose(p, y)
    rel = {
        src: reliability(p[(df.source == src).to_numpy()], y[(df.source == src).to_numpy()])
        for src in ("sms_calibration", "golden_dev")
    }
    out = {
        "model_low": low,
        "model_high": high,
        "rule": "LOW: <=1% of calibration scams below; HIGH: <=1% of calibration legit above",
        "n": int(len(df)),
        "n_scam": int(y.sum()),
        "by_source": {s: int((df.source == s).sum()) for s in rel},
        "classifier_version": clf.version,
        "reliability": rel,
    }
    (config.EVAL_DIR / "calibration.json").write_text(json.dumps(out, indent=2) + "\n")
    plot(rel, low, high, config.EVAL_DIR / "reliability.png")
    return out


if __name__ == "__main__":
    r = main()
    print(json.dumps({k: v for k, v in r.items() if k != "reliability"}, indent=1))
