"""Gemini as the judge provider (DECISIONS #44): the request it sends, how each kind of reply is sorted into provider
failure (feeds the breaker) vs unusable-for-this-message (held), free-tier pacing, and provider selection."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest

from stayguard import config
from stayguard.judges import GeminiJudge, JudgeReplyUnusable, JudgeUnavailable, OfflineJudge
from stayguard.signals import extract

ROOT = Path(__file__).resolve().parent.parent
TEXT = "Please pay now"


class Resp:
    def __init__(self, body=None, status=200, headers=None):
        self.body, self.status_code, self.headers = body, status, headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "err", request=httpx.Request("POST", "https://x"), response=httpx.Response(self.status_code)
            )

    def json(self):
        return self.body


def reply(verdict="scam", evidence=("pay",), **extra):
    text = json.dumps({"verdict": verdict, "confidence": 0.8, "evidence": list(evidence), "rationale": "r"})
    return Resp({"candidates": [{"content": {"parts": [{"text": text}]}, "finishReason": "STOP", **extra}]})


def judge(monkeypatch, *responses, **kw):
    """A GeminiJudge whose HTTP calls return `responses` in turn (the last one repeats)."""
    calls = []

    def fake_post(url, timeout, headers, json):  # noqa: A002 - mirrors httpx.post's keyword
        calls.append({"url": url, "headers": headers, "json": json})
        r = responses[min(len(calls) - 1, len(responses) - 1)]
        if isinstance(r, Exception):
            raise r
        return r

    monkeypatch.setattr(httpx, "post", fake_post)
    return GeminiJudge("k", model="m", timeout=1.0, **kw), calls


def rule(j):
    return j.rule(TEXT, extract(TEXT), {"payment_terms": "pay_at_property"}, 0.5, 0.0)


def test_request_shape_and_happy_path(monkeypatch):
    j, calls = judge(monkeypatch, reply())
    r = rule(j)
    assert r.provider == "gemini:m" and r.prosecutor.evidence == ["pay"] and len(calls) == 2
    c = calls[0]
    assert c["url"].endswith("/models/m:generateContent") and c["headers"]["x-goog-api-key"] == "k"
    assert c["json"]["generationConfig"]["responseMimeType"] == "application/json"
    assert "<untrusted_message>" in c["json"]["contents"][0]["parts"][0]["text"]
    roles = sorted(
        "prosecutor" if "prosecutor" in x["json"]["systemInstruction"]["parts"][0]["text"] else "defender" for x in calls
    )
    assert roles == ["defender", "prosecutor"]
    assert all(s["threshold"] == "BLOCK_ONLY_HIGH" for s in c["json"]["safetySettings"])


def test_invented_quotes_are_dropped(monkeypatch):
    j, _ = judge(monkeypatch, reply(evidence=("wire it to my cousin",)))
    assert rule(j).prosecutor.evidence == []


def test_thought_parts_are_ignored(monkeypatch):
    text = json.dumps({"verdict": "legit", "confidence": 0.7, "evidence": [], "rationale": "r"})
    body = {"candidates": [{"content": {"parts": [{"text": "{not json", "thought": True}, {"text": text}]}}]}
    j, _ = judge(monkeypatch, Resp(body))
    assert rule(j).prosecutor.verdict == "legit"


@pytest.mark.parametrize(
    "resp",
    [
        Resp({"promptFeedback": {"blockReason": "SAFETY"}}),
        reply(finishReason="SAFETY"),
        Resp({"candidates": [{"content": {"parts": [{"text": "no json here"}]}}]}),
        Resp({"candidates": [{"content": {}}]}),
    ],
)
def test_content_shaped_failures_hold_the_message_and_spare_the_breaker(monkeypatch, resp):
    j, _ = judge(monkeypatch, resp)
    with pytest.raises(JudgeReplyUnusable):
        rule(j)


@pytest.mark.parametrize(
    "resp",
    [Resp(status=500), Resp(status=429), Resp([]), Resp({"candidates": []}), httpx.ConnectError("down")],
)
def test_provider_failures_are_unavailable(monkeypatch, resp):
    j, _ = judge(monkeypatch, resp)
    with pytest.raises(JudgeUnavailable):
        rule(j)


def test_rate_limits_are_retried_when_asked(monkeypatch):
    slept = []
    monkeypatch.setattr("stayguard.judges.time.sleep", lambda s: slept.append(s))
    j, calls = judge(monkeypatch, Resp(status=429, headers={"retry-after": "2"}), reply(), retries_on_429=2)
    j.timeout = 5.0
    assert j._complete("prosecutor", "x")  # first 429, then an answer
    assert len(calls) == 2 and slept == [2.0]


def test_free_tier_pacing_spaces_requests(monkeypatch):
    slept = []
    clock = [100.0]
    monkeypatch.setattr("stayguard.judges.time.sleep", lambda s: slept.append(round(s, 3)))
    monkeypatch.setattr("stayguard.judges.time.monotonic", lambda: clock[0])
    j, _ = judge(monkeypatch, reply(), min_interval_s=6.0)
    j._complete("prosecutor", "x")
    j._complete("defender", "x")
    assert slept == [6.0]


def test_engine_names_the_provider(engine):
    from stayguard.engine import Engine

    e = Engine.__new__(Engine)
    e.judge = GeminiJudge("k", model="gemini-3.5-flash-lite")
    assert e.judge_provider == "gemini:gemini-3.5-flash-lite"


# ------------------------------------------------------------------------------------------------ provider selection
def test_provider_follows_the_key(monkeypatch):
    from stayguard.config import load_settings

    monkeypatch.setenv("STAYGUARD_GEMINI_API_KEY", "g")
    assert load_settings().judge_provider == "gemini"
    monkeypatch.setenv("STAYGUARD_ANTHROPIC_API_KEY", "a")
    from stayguard.config import ConfigError

    with pytest.raises(ConfigError, match="choose one"):
        load_settings()
    monkeypatch.setenv("STAYGUARD_JUDGE_PROVIDER", "gemini")
    assert load_settings().judge_provider == "gemini"


def test_a_provider_without_its_key_is_refused(monkeypatch):
    from stayguard.config import ConfigError, load_settings

    monkeypatch.setenv("STAYGUARD_JUDGE_PROVIDER", "gemini")
    with pytest.raises(ConfigError, match="GEMINI_API_KEY"):
        load_settings()
    monkeypatch.setenv("STAYGUARD_JUDGE_PROVIDER", "openai")
    with pytest.raises(ConfigError, match="JUDGE_PROVIDER"):
        load_settings()


def test_make_judge_builds_the_chosen_provider(monkeypatch):
    from stayguard.judges import make_judge

    assert isinstance(make_judge(), OfflineJudge)
    monkeypatch.setattr(config, "JUDGE_PROVIDER", "gemini")
    monkeypatch.setattr(config, "GEMINI_API_KEY", "g")
    assert isinstance(make_judge(), GeminiJudge)


def test_cost_estimate_uses_the_configured_providers_prices(monkeypatch):
    from stayguard.engine import judge_cost_estimate_usd

    base = judge_cost_estimate_usd()
    monkeypatch.setattr(config, "JUDGE_PROVIDER", "gemini")
    assert judge_cost_estimate_usd() != base


# ------------------------------------------------------------------------------------------------ the v3 runner
def test_v3_real_judge_arm_is_paced_gemini_and_other_arms_stay_offline(monkeypatch):
    sys.path.insert(0, str(ROOT))
    import eval.evaluate_v3 as ev3

    assert ev3.real_judge(10) is None  # no key: no real-judge arm
    monkeypatch.setattr(config, "JUDGE_PROVIDER", "gemini")
    monkeypatch.setattr(config, "GEMINI_API_KEY", "g")
    j = ev3.real_judge(12)
    assert isinstance(j, GeminiJudge) and j.min_interval_s == 5.0 and j.retries_on_429 == ev3.REAL_JUDGE_RETRIES_ON_429
    assert j.timeout == ev3.REAL_JUDGE_TIMEOUT_S
    assert {"STAYGUARD_GEMINI_API_KEY", "STAYGUARD_JUDGE_PROVIDER"} <= ev3.ALLOWED_ENV
