"""Central configuration. Everything tunable lives here so DECISIONS.md can point at one place."""
from __future__ import annotations

import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# STAYGUARD_DATA_RAW lets tests and CI point at the small checked-in fixture snapshot (tests/fixtures/raw).
DATA_RAW = Path(os.environ.get("STAYGUARD_DATA_RAW", ROOT / "data" / "raw"))
DATA_CURATED = ROOT / "data" / "curated"
MODELS = Path(os.environ.get("STAYGUARD_MODELS", ROOT / "models"))  # tests use a temp dir so they never overwrite real models
EVAL_DIR = ROOT / "eval"
DB_PATH = Path(os.environ.get("STAYGUARD_DB", ROOT / "stayguard.db"))

# --- Real datasets (see scripts/fetch_data.sh for sources) ---------------------
HOTELS_CSV = DATA_RAW / "hotels.csv"                      # Antonio, Almeida & Nunes (2019) hotel booking demand
SMS_TSV = DATA_RAW / "sms.tsv"                            # UCI SMS Spam Collection
PHISH_DOMAINS = DATA_RAW / "phishing-domains-ACTIVE.txt"  # mitchellkrogza/Phishing.Database
OPENPHISH = DATA_RAW / "openphish-feed.txt"               # OpenPhish public feed
TOP_DOMAINS = DATA_RAW / "top-10000-domains.txt"          # top 10k domains (popularity allowlist)
TOP_1M = DATA_RAW / "top-1m.txt"                          # top 1M domains (evaluation only: ranks 10k-110k as unseen legit)

# --- Decision thresholds ---------------------------------------------------------
# MODEL_LOW / MODEL_HIGH come from eval/calibration.json, chosen by eval/calibrate.py on the calibration split only
# (SMS calibration rows + the dev golden set; never the held-out set). 0.10 / 0.90 are the old hand-set values,
# used only when no calibration file exists. A test fails if these drift from the file.
_CAL = EVAL_DIR / "calibration.json"
_cal = json.loads(_CAL.read_text()) if _CAL.exists() else {}
MODEL_LOW = float(_cal.get("model_low", 0.10))    # below -> deliver on the model path
MODEL_HIGH = float(_cal.get("model_high", 0.90))  # above -> hold on the model path
SESSION_RISKY = 0.70     # session risk above this escalates decisions
SESSION_CRITICAL = 0.90  # above this a money ask is blocked and containment is suggested

# --- LLM judges ------------------------------------------------------------------
# Deliberately NOT ANTHROPIC_API_KEY so a key that happens to be in the shell is never used by accident.
LLM_API_KEY = os.environ.get("STAYGUARD_ANTHROPIC_API_KEY", "")
LLM_MODEL = os.environ.get("STAYGUARD_LLM_MODEL", "claude-haiku-5-5")
LLM_TIMEOUT_S = float(os.environ.get("STAYGUARD_LLM_TIMEOUT", "3.0"))
# Price of the default judge model, USD per million tokens. Source: https://platform.claude.com/docs/en/about-claude/pricing
# (Claude Haiku 5.5, prompts up to 100k tokens), checked 2026-10-27. Cost figures in the report are ESTIMATES:
# input tokens are estimated from the real prompt length (chars / 4), output tokens from JUDGE_OUTPUT_TOKENS.
LLM_PRICE_IN_PER_MTOK = float(os.environ.get("STAYGUARD_LLM_PRICE_IN", "0.10"))
LLM_PRICE_OUT_PER_MTOK = float(os.environ.get("STAYGUARD_LLM_PRICE_OUT", "0.50"))
JUDGE_OUTPUT_TOKENS = 150  # assumed per judge reply (max_tokens is 300); two judges per judged message
BREAKER_FAILURES = 3        # consecutive failures before the breaker opens
BREAKER_COOLDOWN_S = 30.0

# --- API access -------------------------------------------------------------------
# Production mode (default): internal and admin endpoints need X-API-Key, and if no key is configured they
# refuse to serve rather than run open. Demo mode turns on the demo-only endpoints (PIN issuing, the scripted
# attack, samples) and, when no key is set, lets the console call everything without one.
API_KEY = os.environ.get("STAYGUARD_API_KEY", "")
DEMO_MODE = os.environ.get("STAYGUARD_DEMO_MODE", "").lower() in ("1", "true", "yes", "on")

# --- Abuse limits ------------------------------------------------------------------
RATE_CHECK_PER_MIN = float(os.environ.get("STAYGUARD_RATE_CHECK_PER_MIN", "1200"))  # /v1/messages/check, per client
RATE_GUEST_PER_MIN = float(os.environ.get("STAYGUARD_RATE_GUEST_PER_MIN", "30"))    # /v1/guest/verify, per client
GUEST_FAILS_PER_RESERVATION = 5      # wrong PINs per reservation within the window before it locks
GUEST_FAILS_PER_CLIENT = 20          # wrong PINs per client across all reservations within the window
GUEST_LOCK_WINDOW_S = 15 * 60

# --- Data protection ---------------------------------------------------------------
RETAIN_RAW = os.environ.get("STAYGUARD_RETAIN_RAW", "").lower() in ("1", "true", "yes", "on")
RAW_RETENTION_DAYS = float(os.environ.get("STAYGUARD_RAW_RETENTION_DAYS", "7"))
AUDIT_ANCHOR_EVERY = int(os.environ.get("STAYGUARD_AUDIT_ANCHOR_EVERY", "20"))

OFFICIAL_DOMAINS = {
    "booking.com", "bstatic.com", "booking.cn", "priceline.com", "agoda.com", "kayak.com",
    "opentable.com", "rentalcars.com", "bookingholdings.com", "momondo.com", "cheapflights.com",
}
