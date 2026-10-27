"""Judges: quote validation, referee properties, circuit breaker states with a fake clock, the offline judge, and
every way an LLM reply can be malformed (each must be a provider failure, never a crash or a silent pass)."""

from __future__ import annotations

import json
import threading

import httpx
import pytest

from stayguard.judges import (
    PROVIDER_ERRORS,
    AnthropicJudge,
    CircuitBreaker,
    JudgeOpinion,
    JudgeUnavailable,
    OfflineJudge,
    make_judge,
    referee,
    validate_quotes,
)
from stayguard.signals import extract


# ---------------------------------------------------------------------------------------------- quotes + referee
@pytest.mark.parametrize(
    ("quotes", "ok", "bad"),
    [
        (["pay now"], ["pay now"], []),
        (['"Pay   NOW"'], ["Pay   NOW"], []),  # quotes stripped, whitespace and case normalised
        (["send bitcoin"], [], ["send bitcoin"]),
        (["x", ""], [], ["x"]),  # one-character quotes are rejected, empty ignored
    ],
)
def test_validate_quotes(quotes, ok, bad):
    assert validate_quotes(quotes, "Please pay now at the link") == (ok, bad)


def op(role, verdict, conf, n):
    return JudgeOpinion(role, verdict, conf, [f"q{i}" for i in range(n)])


def test_referee_bounds_and_symmetry():
    assert referee(op("p", "scam", 1.0, 3), op("d", "scam", 1.0, 3)) == 1.0
    assert referee(op("p", "legit", 1.0, 3), op("d", "legit", 1.0, 3)) == 0.0
    assert referee(op("p", "scam", 0.5, 1), op("d", "legit", 0.5, 1)) == pytest.approx(0.5)


@pytest.mark.parametrize("side", ["prosecutor", "defender"])
def test_referee_more_valid_evidence_never_weakens_a_side(side):
    other_p, other_d = op("p", "scam", 0.6, 1), op("d", "legit", 0.6, 1)
    prev = None
    for n in range(0, 6):
        if side == "prosecutor":
            p = referee(op("p", "scam", 0.6, n), other_d)
            assert prev is None or p >= prev
        else:
            p = referee(other_p, op("d", "legit", 0.6, n))
            assert prev is None or p <= prev
        prev = p


# ---------------------------------------------------------------------------------------------- breaker
class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def test_breaker_closed_open_half_open_closed():
    clk = Clock()
    b = CircuitBreaker(failures=3, cooldown=30, clock=clk)
    assert b.state == "closed" and b.allow()
    for _ in range(3):
        b.record(False)
    assert b.state == "open" and not b.allow()
    clk.t = 31
    assert b.state == "half-open"
    assert b.allow() and not b.allow()  # exactly one probe
    b.record(True)
    assert b.state == "closed" and b.allow()


def test_breaker_failed_probe_reopens():
    clk = Clock()
    b = CircuitBreaker(failures=1, cooldown=10, clock=clk)
    b.record(False)
    clk.t = 11
    assert b.allow()
    b.record(False)
    assert b.state == "open"


def test_breaker_half_open_admits_one_probe_under_concurrency():
    clk = Clock()
    b = CircuitBreaker(failures=1, cooldown=1, clock=clk)
    b.record(False)
    clk.t = 5
    admitted = []
    barrier = threading.Barrier(16)

    def go():
        barrier.wait()
        admitted.append(b.allow())

    threads = [threading.Thread(target=go) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert admitted.count(True) == 1


def test_forced_outage():
    b = CircuitBreaker()
    b.forced_outage = True
    assert b.state.startswith("open") and not b.allow()


# ---------------------------------------------------------------------------------------------- offline judge
def rule(text, terms="pay_at_property", links=None, model_p=0.5, worst=0.0, direction="hotel_to_guest"):
    ctx = {"payment_terms": terms, "direction": direction}
    if links is not None:
        ctx["links"] = links
    return OfflineJudge().rule(text, extract(text), ctx, model_p, worst)


def test_offline_judge_quotes_exist_and_lean_correctly():
    scam = rule("Please pay the deposit today to keep your room", model_p=0.9)
    assert scam.p_scam > 0.6 and all(
        q.lower() in "please pay the deposit today to keep your room" for q in scam.prosecutor.evidence
    )
    legit = rule("Breakfast is from 7 and parking is free. See you soon!", model_p=0.1)
    assert legit.p_scam < 0.4 and legit.defender.evidence


def test_offline_judge_vouches_per_link():
    url = "https://maps.app.goo.gl/AbC123"
    text = f"We confirm your reservation. Directions: {url}"
    vouched = rule(text, links=[{"url": url, "verdict": "safe", "reasons": ["MAPS_LINK"]}], worst=0.05, model_p=0.9)
    assert url not in vouched.prosecutor.evidence and url in vouched.defender.evidence
    fresh = "https://guest-step.app/s/9"
    unvouched = rule(
        f"Finish it at {fresh}", links=[{"url": fresh, "verdict": "safe", "reasons": ["UNKNOWN_DOMAIN"]}], worst=0.25
    )
    assert fresh in unvouched.prosecutor.evidence
    no_info = rule(f"Finish it at {fresh}", worst=0.25)  # no per-link verdicts: conservative fallback
    assert fresh in no_info.prosecutor.evidence


def test_offline_judge_overpayment_direction():
    text = "I overpaid by mistake, please refund the difference"
    g2h = rule(text, terms="prepaid", direction="guest_to_hotel", model_p=0.5)
    h2g = rule(text, terms="prepaid", direction="hotel_to_guest", model_p=0.5)
    assert g2h.prosecutor.confidence > h2g.prosecutor.confidence


def test_make_judge_offline_without_key():
    assert isinstance(make_judge(), OfflineJudge)


# ---------------------------------------------------------------------------------------------- anthropic judge
class Resp:
    def __init__(self, text=None, status=200, body=None):
        self.text_, self.status, self.body = text, status, body

    def raise_for_status(self):
        if self.status >= 400:
            raise httpx.HTTPStatusError("err", request=httpx.Request("POST", "https://x"), response=httpx.Response(self.status))

    def json(self):
        if self.body is not None:
            return self.body
        return {"content": [{"type": "text", "text": self.text_}]}


def judge_with(monkeypatch, pro, de=None):
    de = de if de is not None else pro

    def fake_post(url, timeout, headers, json):  # noqa: A002 - mirrors httpx.post's keyword
        assert headers["x-api-key"] == "k" and "<untrusted_message>" in json["messages"][0]["content"]
        r = pro if "prosecutor" in json["system"] else de
        if isinstance(r, Exception):
            raise r
        return r

    monkeypatch.setattr(httpx, "post", fake_post)
    return AnthropicJudge("k", model="m", timeout=1.0)


GOOD = Resp(json.dumps({"verdict": "scam", "confidence": 0.8, "evidence": ["pay"], "rationale": "r"}))
TEXT = "Please pay now"


def test_anthropic_happy_path(monkeypatch):
    r = judge_with(monkeypatch, GOOD).rule(TEXT, extract(TEXT), {}, 0.5, 0.0)
    assert r.provider == "anthropic:m" and r.prosecutor.evidence == ["pay"]


@pytest.mark.parametrize(
    "reply",
    [
        Resp("no json here"),
        Resp("[1, 2]"),
        Resp('{"verdict": "maybe", "confidence": 0.5}'),
        Resp('{"verdict": "scam", "confidence": "high"}'),
        Resp('{"verdict": "scam", "confidence": NaN}'),
        Resp('{"verdict": "scam", "confidence": 0.5, "evidence": "pay"}'),
        Resp('{"verdict": "scam", "confidence": 0.5, '),
        Resp(status=529),
        httpx.ConnectTimeout("t"),
    ],
)
def test_anthropic_malformed_replies_are_provider_failures(monkeypatch, reply):
    j = judge_with(monkeypatch, reply)
    with pytest.raises(JudgeUnavailable):
        j.rule(TEXT, extract(TEXT), {}, 0.5, 0.0)


def test_anthropic_confidence_is_clamped(monkeypatch):
    j = judge_with(monkeypatch, Resp('{"verdict": "scam", "confidence": 7, "evidence": []}'))
    assert j.rule(TEXT, extract(TEXT), {}, 0.5, 0.0).prosecutor.confidence == 1.0


def test_anthropic_invented_quotes_are_dropped(monkeypatch):
    reply = Resp(json.dumps({"verdict": "scam", "confidence": 0.9, "evidence": ["pay now", "wire it to Lagos"]}))
    r = judge_with(monkeypatch, reply).rule(TEXT, extract(TEXT), {}, 0.5, 0.0)
    assert r.prosecutor.evidence == ["pay now"] and r.prosecutor.rejected_evidence == ["wire it to Lagos"]


def test_anthropic_bug_is_not_a_provider_failure(monkeypatch):
    # A malformed reply ({"content": None}) is now a provider failure (review round 1, A4); a bug in OUR code after a
    # well-formed reply is still not, so it fails closed instead of taking the degraded path.
    import stayguard.judges as judges_mod

    def buggy(*_a, **_k):
        raise AttributeError("bug in our parsing")

    monkeypatch.setattr(judges_mod, "validate_quotes", buggy)
    j = judge_with(monkeypatch, Resp(json.dumps({"verdict": "scam", "confidence": 0.9, "evidence": ["pay now"]})))
    with pytest.raises(Exception) as ei:
        j.rule(TEXT, extract(TEXT), {}, 0.5, 0.0)
    assert not isinstance(ei.value, PROVIDER_ERRORS)


def test_anthropic_timeout_without_reply(monkeypatch):
    import time as _t

    def slow(*a, **k):
        _t.sleep(2.0)
        return GOOD

    monkeypatch.setattr(httpx, "post", slow)
    j = AnthropicJudge("k", model="m", timeout=0.1)
    with pytest.raises(JudgeUnavailable):
        j.rule(TEXT, extract(TEXT), {}, 0.5, 0.0)
