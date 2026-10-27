"""Reconstruct what StayGuard's classifier alone would have caught on held-out v1 at the time of its frozen first look,
and compare it with the full system's frozen first-look result on the same scams (exact McNemar test).

Review rounds 2 and 3 (C1, C11) each reconstructed this by hand and got slightly different numbers. This script makes
it reproducible: it exports the first-look commit with `git archive`, trains that commit's classifier on the same raw
data in a temporary directory, and writes eval/first_look_reconstruction.json.

    python -m eval.reconstruct_first_look            (needs git and data/raw; about a minute)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tarfile
import tempfile
from io import BytesIO
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from eval.evaluate import FIRST_LOOK, mcnemar_exact  # noqa: E402

SCORER = """
import json, sys
from stayguard.classifier import ScamClassifier, train
train(save=True)
clf = ScamClassifier()
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
print(json.dumps({r["id"]: clf.score(r["text"]) for r in rows if r.get("split") == "heldout"}))
"""


def main() -> dict:
    fl = json.loads(FIRST_LOOK.read_text())
    commit = fl["git_commit"]
    first = fl["A_messages_heldout"]
    missed = {e["id"] for e in first["errors_and_warnings"] if e["label"] == 1}
    blob = subprocess.run(["git", "archive", commit], cwd=ROOT, capture_output=True, check=True).stdout  # noqa: S603, S607
    with tempfile.TemporaryDirectory() as tmp:
        with tarfile.open(fileobj=BytesIO(blob)) as tf:
            tf.extractall(tmp, filter="data")
        env = {
            **os.environ,
            "PYTHONPATH": tmp,
            "STAYGUARD_MODELS": str(Path(tmp) / "models"),
            "STAYGUARD_DATA_RAW": str(ROOT / "data" / "raw"),
            "STAYGUARD_DB": str(Path(tmp) / "x.db"),
        }
        out = (
            subprocess.run(  # noqa: S603
                [sys.executable, "-c", SCORER, str(ROOT / "data" / "curated" / "heldout_eval.jsonl")],
                cwd=tmp,
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            .stdout.strip()
            .splitlines()[-1]
        )
        cal = (
            json.loads((Path(tmp) / "eval" / "calibration.json").read_text())
            if (Path(tmp) / "eval" / "calibration.json").exists()
            else {}
        )
    scores = json.loads(out)
    rows = [json.loads(x) for x in (ROOT / "data/curated/heldout_eval.jsonl").read_text().splitlines() if x.strip()]
    scams = [r["id"] for r in rows if r.get("split") == "heldout" and r["label"] == 1]
    result: dict = {"first_look_commit": commit, "n_scams": len(scams), "thresholds": {}}
    for name, high in (("first_look_model_high", cal.get("model_high")), ("current_model_high", None)):
        if high is None:
            from stayguard import config

            high = config.MODEL_HIGH
        full = [s not in missed for s in scams]
        clf = [scores[s] >= high for s in scams]
        result["thresholds"][name] = {
            "model_high": high,
            "full_system_caught": sum(full),
            "classifier_alone_caught": sum(clf),
            "mcnemar": mcnemar_exact(full, clf),
        }
    (ROOT / "eval" / "first_look_reconstruction.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    print(json.dumps(main(), indent=1))
