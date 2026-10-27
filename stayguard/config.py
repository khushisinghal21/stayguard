"""Central configuration. Everything tunable lives here so DECISIONS.md can point at one place."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_RAW = ROOT / "data" / "raw"
DATA_CURATED = ROOT / "data" / "curated"
MODELS = ROOT / "models"
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
MODEL_LOW = 0.10    # below -> deliver on the model path
MODEL_HIGH = 0.90   # above -> hold on the model path
SESSION_RISKY = 0.70     # session risk above this escalates decisions
SESSION_CRITICAL = 0.90  # above this a money ask is blocked and containment is suggested

# --- LLM judges ------------------------------------------------------------------
# Deliberately NOT ANTHROPIC_API_KEY so a key that happens to be in the shell is never used by accident.
LLM_API_KEY = os.environ.get("STAYGUARD_ANTHROPIC_API_KEY", "")
LLM_MODEL = os.environ.get("STAYGUARD_LLM_MODEL", "claude-haiku-5-5")
LLM_TIMEOUT_S = float(os.environ.get("STAYGUARD_LLM_TIMEOUT", "3.0"))
LLM_COST_PER_CALL_USD = float(os.environ.get("STAYGUARD_LLM_COST_PER_CALL", "0.0016"))  # 2 judges, ~600 in / 150 out tokens each
BREAKER_FAILURES = 3        # consecutive failures before the breaker opens
BREAKER_COOLDOWN_S = 30.0

# Optional API key for the HTTP API. Empty = open (local demo).
API_KEY = os.environ.get("STAYGUARD_API_KEY", "")

OFFICIAL_DOMAINS = {
    "booking.com", "bstatic.com", "booking.cn", "priceline.com", "agoda.com", "kayak.com",
    "opentable.com", "rentalcars.com", "bookingholdings.com", "momondo.com", "cheapflights.com",
}
