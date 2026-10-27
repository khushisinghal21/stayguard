.PHONY: install data train calibrate eval docs run demo test lint types check
install:   ; pip install --require-hashes -r requirements-dev.lock && pip install --no-deps -e .
data:      ; bash scripts/fetch_data.sh
train:     ; python -m stayguard.classifier && python -m stayguard.session_risk
calibrate: ; python -m eval.calibrate
eval:      ; python -m eval.evaluate && python scripts/render_docs.py
docs:      ; python scripts/render_docs.py
run:       ; uvicorn stayguard.api:app --port 8000
demo:      ; STAYGUARD_DEMO_MODE=1 uvicorn stayguard.api:app --port 8000
test:      ; pytest --cov=stayguard --cov-report=json --cov-report=term && python scripts/check_coverage.py coverage.json
lint:      ; ruff check . && ruff format --check .
types:     ; mypy stayguard
check:     lint types test
