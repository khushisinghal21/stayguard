.PHONY: data train eval run test
data:  ; bash scripts/fetch_data.sh
train: ; python -m stayguard.classifier && python -m stayguard.session_risk
eval:  ; python -m eval.evaluate
run:   ; uvicorn stayguard.api:app --port 8000
test:  ; pytest -q
