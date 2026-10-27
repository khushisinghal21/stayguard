FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN test -s data/raw/hotels.csv || (apt-get update && apt-get install -y --no-install-recommends curl && bash scripts/fetch_data.sh)
RUN python -m stayguard.classifier && python -m stayguard.session_risk
EXPOSE 8000
CMD ["uvicorn", "stayguard.api:app", "--host", "0.0.0.0", "--port", "8000"]
