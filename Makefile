.PHONY: install install-encoder data train calibrate eval docs run demo test lint types check ctx encoder eval-v3 retrain
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
types:     ; python -m mypy stayguard
check:     lint types test

# --- Pipeline v3 (DECISIONS #38-#43) -----------------------------------------------------------------------------
# The multilingual encoder needs its runtime and its weights (from huggingface.co):
install-encoder: ; pip install --require-hashes -r requirements-encoder.lock && pip install --no-deps -e .
encoder:   ; python scripts/fetch_encoder.py && python -m stayguard.ctx_classifier encoder_ctx && python -m eval.calibrate --classifier encoder_ctx
# TF-IDF + context model, and today's model recalibrated on the larger hotel set:
ctx:       ; python -m stayguard.ctx_classifier tfidf_ctx && python -m eval.calibrate --classifier tfidf_ctx && python -m eval.calibrate --classifier tfidf_recal
# The ONE blind held-out v3 run. Needs a clean tree: commit eval/calibration_encoder_ctx.json after `make encoder`.
eval-v3:   ; python -m eval.evaluate_v3
# Labels from shadow mode -> data/feedback/labelled_queue.jsonl -> retrained context models:
retrain:   ; python -m stayguard.feedback export && $(MAKE) ctx
