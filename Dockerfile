# syntax=docker/dockerfile:1
# Multi-stage: build wheels from the hash-pinned lockfile, then a slim runtime image as a non-root user.
# scikit-learn/numpy/pandas ship CPU-only manylinux wheels, so no extra index or GPU packages are pulled in.

FROM python:3.13-slim AS build
WORKDIR /build
COPY requirements.lock .
RUN pip wheel --require-hashes --wheel-dir /wheels -r requirements.lock

FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY --from=build /wheels /wheels
RUN pip install --no-index --find-links /wheels /wheels/* && rm -rf /wheels \
 && useradd --create-home --uid 10001 stayguard
COPY --chown=stayguard:stayguard . .
# Only fetch the live feeds if the build context has no data (they are large and change daily; prefer a snapshot).
RUN if [ ! -s data/raw/hotels.csv ]; then \
      apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/* \
      && bash scripts/fetch_data.sh; \
    fi \
 && chown -R stayguard:stayguard /app
USER stayguard
# Build models at image build time so start-up stays fast; checksums are written next to them.
RUN python -m stayguard.classifier >/dev/null && python -m stayguard.session_risk >/dev/null
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"
CMD ["uvicorn", "stayguard.api:app", "--host", "0.0.0.0", "--port", "8000"]
