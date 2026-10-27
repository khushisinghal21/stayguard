"""Docs must quote the latest evaluation, and config must match the calibration it claims to come from."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


def test_docs_numbers_match_report():
    import render_docs

    h = json.loads((ROOT / "eval" / "report.json").read_text())["headline"]
    for p in render_docs.DOCS:
        text = p.read_text(encoding="utf-8")
        assert render_docs.render(text, h) == text, f"{p.name} is out of date: run python scripts/render_docs.py"


def test_readme_has_rendered_results_block():
    assert "<!-- results:start -->" in (ROOT / "README.md").read_text(encoding="utf-8")


def test_thresholds_match_calibration_file():
    from stayguard import config

    cal = json.loads((ROOT / "eval" / "calibration.json").read_text())
    assert (cal["model_low"], cal["model_high"]) == (config.MODEL_LOW, config.MODEL_HIGH)
