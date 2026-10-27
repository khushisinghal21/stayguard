"""Central configuration. Everything tunable lives here so DECISIONS.md can point at one place.

Environment variables (prefix STAYGUARD_) are read once, through a validated Pydantic settings model, and exposed
as module-level constants so the rest of the code keeps reading `config.X`. A bad value (say
STAYGUARD_LLM_TIMEOUT=fast, or thresholds that cross) stops start-up with a message naming the variable and the
rule it broke, instead of a bare traceback.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import Field, ValidationError, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent
EVAL_DIR = ROOT / "eval"
DATA_CURATED = ROOT / "data" / "curated"

# --- Decision thresholds ---------------------------------------------------------
# MODEL_LOW / MODEL_HIGH come from eval/calibration.json, chosen by eval/calibrate.py on the calibration split only
# (SMS calibration rows + the dev golden set; never the held-out set). 0.10 / 0.90 are the old hand-set values,
# used only when no calibration file exists. A test fails if these drift from the file.
_CAL = EVAL_DIR / "calibration.json"
_cal: dict[str, Any] = json.loads(_CAL.read_text()) if _CAL.exists() else {}


class ConfigError(ValueError):
    """Raised at import when an environment variable is invalid."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="STAYGUARD_", extra="ignore", case_sensitive=False)

    # STAYGUARD_DATA_RAW lets tests and CI point at the small checked-in fixture snapshot (tests/fixtures/raw).
    data_raw: Path = ROOT / "data" / "raw"
    models: Path = ROOT / "models"  # tests use a temp dir so they never overwrite real models
    db: Path = ROOT / "stayguard.db"

    model_low: float = Field(float(_cal.get("model_low", 0.10)), ge=0.0, le=1.0)  # below -> deliver on the model path
    model_high: float = Field(float(_cal.get("model_high", 0.90)), ge=0.0, le=1.0)  # above -> hold on the model path
    session_risky: float = Field(0.70, ge=0.0, le=1.0)  # session risk above this escalates decisions
    session_critical: float = Field(0.90, ge=0.0, le=1.0)  # above this a money ask is blocked and containment is suggested

    # Deliberately NOT ANTHROPIC_API_KEY so a key that happens to be in the shell is never used by accident.
    anthropic_api_key: str = ""
    llm_model: str = "claude-haiku-5-5"
    llm_timeout: float = Field(3.0, gt=0.0, le=60.0)
    llm_price_in: float = Field(0.10, ge=0.0)
    llm_price_out: float = Field(0.50, ge=0.0)

    api_key: str = ""
    demo_mode: bool = False

    rate_check_per_min: float = Field(1200, ge=0.0)  # /v1/messages/check, per client
    rate_guest_per_min: float = Field(30, ge=0.0)  # /v1/guest/verify, per client

    retain_raw: bool = False
    raw_retention_days: float = Field(7, gt=0.0)
    audit_anchor_every: int = Field(20, ge=0)

    @model_validator(mode="after")
    def _ordered(self) -> Settings:
        if not self.model_low < self.model_high:
            raise ValueError(f"MODEL_LOW ({self.model_low}) must be below MODEL_HIGH ({self.model_high})")
        if not self.session_risky < self.session_critical:
            raise ValueError(f"SESSION_RISKY ({self.session_risky}) must be below SESSION_CRITICAL ({self.session_critical})")
        return self


def load_settings() -> Settings:
    try:
        return Settings()
    except ValidationError as e:
        problems = []
        for err in e.errors():
            loc = ".".join(str(p) for p in err["loc"]) or "settings"
            var = f"STAYGUARD_{loc.upper()}" if err["loc"] else "STAYGUARD_* settings"
            problems.append(f"  {var}: {err['msg']} (got {err.get('input')!r})")
        raise ConfigError("Invalid StayGuard configuration:\n" + "\n".join(problems)) from None


_s = load_settings()

DATA_RAW = _s.data_raw
MODELS = _s.models
DB_PATH = _s.db

# --- Real datasets (see scripts/fetch_data.sh for sources) ---------------------
HOTELS_CSV = DATA_RAW / "hotels.csv"  # Antonio, Almeida & Nunes (2019) hotel booking demand
SMS_TSV = DATA_RAW / "sms.tsv"  # UCI SMS Spam Collection
PHISH_DOMAINS = DATA_RAW / "phishing-domains-ACTIVE.txt"  # mitchellkrogza/Phishing.Database
OPENPHISH = DATA_RAW / "openphish-feed.txt"  # OpenPhish public feed
TOP_DOMAINS = DATA_RAW / "top-10000-domains.txt"  # top 10k domains (popularity allowlist)
TOP_1M = DATA_RAW / "top-1m.txt"  # top 1M domains (evaluation only: ranks 10k-110k dev, 110k-210k held-out unseen legit)

MODEL_LOW = _s.model_low  # below -> deliver on the model path
MODEL_HIGH = _s.model_high  # above -> hold on the model path
SESSION_RISKY = _s.session_risky  # session risk above this escalates decisions
SESSION_CRITICAL = _s.session_critical  # above this a money ask is blocked and containment is suggested

# --- LLM judges ------------------------------------------------------------------
# Deliberately NOT ANTHROPIC_API_KEY so a key that happens to be in the shell is never used by accident.
LLM_API_KEY = _s.anthropic_api_key
LLM_MODEL = _s.llm_model
LLM_TIMEOUT_S = _s.llm_timeout
# Price of the default judge model, USD per million tokens. Source: https://platform.claude.com/docs/en/about-claude/pricing
# (Claude Haiku 5.5, prompts up to 100k tokens), checked 2026-10-27. Cost figures in the report are ESTIMATES:
# input tokens are estimated from the real prompt length (chars / 4), output tokens from JUDGE_OUTPUT_TOKENS.
LLM_PRICE_IN_PER_MTOK = _s.llm_price_in
LLM_PRICE_OUT_PER_MTOK = _s.llm_price_out
JUDGE_OUTPUT_TOKENS = 150  # assumed per judge reply (max_tokens is 300); two judges per judged message
BREAKER_FAILURES = 3  # consecutive failures before the breaker opens
BREAKER_COOLDOWN_S = 30.0

# --- API access -------------------------------------------------------------------
# Production mode (default): internal and admin endpoints need X-API-Key, and if no key is configured they
# refuse to serve rather than run open. Demo mode turns on the demo-only endpoints (PIN issuing, the scripted
# attack, samples) and, when no key is set, lets the console call everything without one.
API_KEY = _s.api_key
DEMO_MODE = _s.demo_mode

# --- Abuse limits ------------------------------------------------------------------
RATE_CHECK_PER_MIN = _s.rate_check_per_min  # /v1/messages/check, per client
RATE_GUEST_PER_MIN = _s.rate_guest_per_min  # /v1/guest/verify, per client
GUEST_FAILS_PER_RESERVATION = 5  # wrong PINs per reservation within the window before it locks
GUEST_FAILS_PER_CLIENT = 20  # wrong PINs per client across all reservations within the window
GUEST_LOCK_WINDOW_S = 15 * 60

# --- Data protection ---------------------------------------------------------------
RETAIN_RAW = _s.retain_raw
RAW_RETENTION_DAYS = _s.raw_retention_days
AUDIT_ANCHOR_EVERY = _s.audit_anchor_every

OFFICIAL_DOMAINS = {
    "booking.com",
    "bstatic.com",
    "booking.cn",
    "priceline.com",
    "agoda.com",
    "kayak.com",
    "opentable.com",
    "rentalcars.com",
    "bookingholdings.com",
    "momondo.com",
    "cheapflights.com",
}
