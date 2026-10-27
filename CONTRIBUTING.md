# Contributing

## Set up

```bash
pip install --require-hashes -r requirements-dev.lock   # exact, hash-pinned versions (what CI installs)
pip install --no-deps -e .
pre-commit install
```

`pyproject.toml` holds the loose version ranges the code needs; `requirements.lock` (runtime) and
`requirements-dev.lock` (runtime + tools) pin what was actually tested. To refresh the locks:
`pip-compile --generate-hashes --strip-extras -o requirements.lock pyproject.toml` (add `--extra dev` for the dev lock).

## Data

```bash
bash scripts/fetch_data.sh        # downloads the real datasets into data/raw and writes data/MANIFEST.json
bash scripts/snapshot_data.sh     # packs data/raw + manifest so a report can be reproduced later
```

The phishing feeds are live and change daily. A report records the manifest hash of the data it ran on, and
`python -m eval.evaluate --compare old/report.json` refuses to compare reports built on different data unless you pass
`--allow-drift`.

Tests and CI never touch `data/raw`: they use the small snapshot in `tests/fixtures/raw` (see its README).

## Run

```bash
make demo        # STAYGUARD_DEMO_MODE=1 uvicorn stayguard.api:app --port 8000, then open http://localhost:8000
make run         # production mode: internal endpoints need STAYGUARD_API_KEY
docker compose up --build
```

## Check your change

```bash
make lint        # ruff check + ruff format --check
make types       # mypy (strict on the decision path: engine, signals, links, judges, service)
make test        # pytest + coverage gates (85% overall, 95% on engine/signals/links)
```

## Change the evaluation numbers

```bash
python -m eval.calibrate          # only if the classifier changed: re-picks MODEL_LOW/MODEL_HIGH on the calibration split
python -m eval.evaluate           # writes eval/report.json + eval/report.md (about 3 minutes on the full data)
python scripts/render_docs.py     # copies the headline numbers into README.md and DECISIONS.md
```

Never edit numbers in README/DECISIONS by hand (`tests/test_docs_drift.py` fails if you do), and never edit
`eval/report.md` by hand (change `to_md` in `eval/evaluate.py`). Never tune anything on `data/curated/heldout_eval.jsonl`;
if a change was motivated by a held-out failure, say so in DECISIONS.md. `eval/heldout_first_look.json` is never
regenerated.

## Commits

Small, reviewable commits whose message says *why*. Branch from `main`; don't push to it directly.
