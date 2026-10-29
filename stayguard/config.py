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
# Each classifier kind has its own calibration file (DECISIONS #38): thresholds chosen for one model mean nothing
# for another. "tfidf" keeps the original eval/calibration.json, so today's system is unchanged by default.
CLASSIFIER_KINDS = ("tfidf", "tfidf_ctx", "encoder_ctx")


def calibration_path(kind: str) -> Path:
    return EVAL_DIR / ("calibration.json" if kind == "tfidf" else f"calibration_{kind}.json")


def calibration_for(kind: str) -> dict[str, Any]:
    path = calibration_path(kind)
    return dict(json.loads(path.read_text())) if path.exists() else {}


class ConfigError(ValueError):
    """Raised at import when an environment variable is invalid."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="STAYGUARD_", extra="ignore", case_sensitive=False)

    # STAYGUARD_DATA_RAW lets tests and CI point at the small checked-in fixture snapshot (tests/fixtures/raw).
    data_raw: Path = ROOT / "data" / "raw"
    models: Path = ROOT / "models"  # tests use a temp dir so they never overwrite real models
    db: Path = ROOT / "stayguard.db"

    # Which scam-language model the engine uses (DECISIONS #38). "tfidf" is the original model and the default.
    classifier: str = "tfidf"
    # Where scripts/fetch_encoder.py puts the multilingual encoder (only read when classifier=encoder_ctx).
    encoder_dir: Path = ROOT / "models" / "encoder"
    # None = take the thresholds from the chosen classifier's calibration file (an explicit value still wins).
    model_low: float | None = Field(None, ge=0.0, le=1.0)  # below -> deliver on the model path
    model_high: float | None = Field(None, ge=0.0, le=1.0)  # above -> hold on the model path
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
    audit_anchor_every: int = Field(1, ge=0)  # 1 = anchor every row, so even the last rows can't be deleted unnoticed

    # --- Pipeline options added after held-out v2 (DECISIONS #39-#42). All off by default: each is measured on the
    # blind held-out v3 run before anyone switches it on.
    # A model-only hold (model above MODEL_HIGH, no rule fired) goes to the judges instead; judges down -> still held.
    route_model_high_to_judges: bool = False
    # A money/card mention on a pay-at-property booking that only points the guest to the platform's own flow ("update
    # the card in the Booking.com app", "paid at reception on arrival") is warned, not held, when nothing else is wrong.
    platform_flow_warn: bool = False
    # Shadow mode: decisions are computed, stored and returned with enforced=false, and the platform does not act on them.
    enforce: bool = True
    # Network link checks (domain age over RDAP, following redirects): opt-in, needs outbound network.
    net_checks: bool = False
    net_timeout: float = Field(2.0, gt=0.0, le=10.0)  # per request
    net_budget: float = Field(3.0, gt=0.0, le=30.0)  # all network checks for one message together
    new_domain_days: int = Field(30, ge=1, le=3650)  # registered less than this many days ago = newly registered

    @model_validator(mode="after")
    def _ordered(self) -> Settings:
        if self.classifier not in CLASSIFIER_KINDS:
            raise ValueError(f"CLASSIFIER must be one of {', '.join(CLASSIFIER_KINDS)} (got {self.classifier!r})")
        cal = calibration_for(self.classifier)
        if self.model_low is None:
            self.model_low = float(cal.get("model_low", 0.10))
        if self.model_high is None:
            self.model_high = float(cal.get("model_high", 0.90))
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

CLASSIFIER = _s.classifier
ENCODER_DIR = _s.encoder_dir
# the validator always fills both; the fallbacks only satisfy the type checker
MODEL_LOW: float = _s.model_low if _s.model_low is not None else 0.10  # below -> deliver on the model path
MODEL_HIGH: float = _s.model_high if _s.model_high is not None else 0.90  # above -> hold on the model path
ROUTE_MODEL_HIGH_TO_JUDGES = _s.route_model_high_to_judges
PLATFORM_FLOW_WARN = _s.platform_flow_warn
ENFORCE = _s.enforce
NET_CHECKS = _s.net_checks
NET_TIMEOUT_S = _s.net_timeout
NET_BUDGET_S = _s.net_budget
NEW_DOMAIN_DAYS = _s.new_domain_days
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
# Wrong-PIN limits are per (client, reservation) first, so an attacker who knows a booking can't lock the real guest
# out of the checker by typing wrong PINs (review round 1). A higher per-reservation cap across all clients still
# bounds a distributed brute force, and containment rotates the PINs of exposed guests.
GUEST_FAILS_PER_CLIENT_RESERVATION = 5  # wrong PINs by one client for one reservation within the window
GUEST_FAILS_PER_CLIENT = 20  # wrong PINs per client across all reservations within the window
GUEST_FAILS_PER_RESERVATION_GLOBAL = 50  # wrong PINs for one reservation from all clients within the window
GUEST_LOCK_WINDOW_S = 15 * 60
# Successful checks per reservation per day: the checker runs the live engine, so unlimited checks with one valid PIN
# make it an oracle for tuning scam wording (review round 1). Ten a day is plenty for a real guest.
GUEST_CHECKS_PER_RESERVATION = 10
GUEST_CHECK_WINDOW_S = 24 * 3600

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
