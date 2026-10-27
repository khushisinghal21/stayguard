"""Choose MODEL_LOW / MODEL_HIGH on a calibration split, never on held-out data.

Calibration data: the SMS calibration split (models/sms_calibration.csv, never trained on) + the dev golden set.
Rule (stated before looking at the numbers):
- MODEL_LOW  = the largest threshold at which at most 1% of calibration scams score below it
               (below MODEL_LOW a message is delivered without the judges, so this caps the scams skipped).
- MODEL_HIGH = the smallest threshold at which at most 1% of calibration legitimate messages score above it
               (above MODEL_HIGH a message is held without the judges, so this caps false holds).
Both are clamped to [0.02, 0.98] and MODEL_LOW < MODEL_HIGH.
Writes eval/calibration.json (thresholds, reliability bins) and eval/reliability.png.

Usage: python -m eval.calibrate
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from stayguard import config  # noqa: E402
from stayguard.classifier import ScamClassifier  # noqa: E402

GRID = np.round(np.arange(0.02, 0.981, 0.01), 2)


def calibration_rows() -> pd.DataFrame:
    sms = pd.read_csv(config.MODELS / "sms_calibration.csv")[["text", "label"]].assign(source="sms_calibration")
    dev = [json.loads(line) for line in (config.DATA_CURATED / "golden_eval.jsonl").read_text(encoding="utf-8").splitlines()
           if line.strip()]
    dev_df = pd.DataFrame([{"text": r["text"], "label": r["label"], "source": "golden_dev"} for r in dev if r.get("split") == "dev"])
    return pd.concat([sms, dev_df], ignore_index=True)


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
            out.append({"bin": [round(edges[i], 2), round(edges[i + 1], 2)], "n": int(m.sum()),
                        "mean_predicted": round(float(p[m].mean()), 4), "observed_scam_rate": round(float(y[m].mean()), 4)})
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
    ax.text(0.97, 0.9, "perfectly calibrated", color="#52514e", fontsize=8, ha="right", rotation=39)
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


def main() -> dict:
    clf = ScamClassifier()
    df = calibration_rows()
    p = np.array([clf.score(t) for t in df.text])
    y = df.label.to_numpy()
    low, high = choose(p, y)
    rel = {src: reliability(p[(df.source == src).to_numpy()], y[(df.source == src).to_numpy()]) for src in ("sms_calibration", "golden_dev")}
    out = {"model_low": low, "model_high": high, "rule": "LOW: <=1% of calibration scams below; HIGH: <=1% of calibration legit above",
           "n": int(len(df)), "n_scam": int(y.sum()), "by_source": {s: int((df.source == s).sum()) for s in rel},
           "classifier_version": clf.version, "reliability": rel}
    (config.EVAL_DIR / "calibration.json").write_text(json.dumps(out, indent=2) + "\n")
    plot(rel, low, high, config.EVAL_DIR / "reliability.png")
    return out


if __name__ == "__main__":
    r = main()
    print(json.dumps({k: v for k, v in r.items() if k != "reliability"}, indent=1))
