"""HTTP API: every endpoint in production and demo mode, auth, validation, 409 idempotency conflicts, rate limits,
security headers and the no-stack-trace error handler."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from stayguard import api, config

KEY = "s3cret-test-key"

INTERNAL = [
    ("post", "/v1/messages/check", {"text": "Breakfast is from 7.", "payment_terms": "pay_at_property"}),
    ("post", "/v1/sessions/score", {"property_id": "H1", "user": "u"}),
    ("get", "/v1/properties/H1/reservations", None),
    ("get", "/v1/reservations/R100000/notices", None),
    ("get", "/v1/messages", None),
    ("get", "/v1/cases", None),
    ("get", "/v1/metrics", None),
    ("get", "/v1/audit", None),
    ("get", "/v1/audit/verify", None),
    ("post", "/v1/admin/llm-outage", {"on": False}),
    ("post", "/v1/properties/H1/contain", {"session_id": None}),
    ("post", "/v1/properties/H1/recovered", {}),
]
DEMO_ONLY = [
    ("get", "/v1/samples", None),
    ("post", "/v1/reservations/R100000/demo-pin", None),
]


@pytest.fixture
def mode(monkeypatch, client):
    def _set(demo: bool, key: str = ""):
        monkeypatch.setattr(config, "DEMO_MODE", demo)
        monkeypatch.setattr(config, "API_KEY", key)
        monkeypatch.setattr(api, "limiter", api.TokenBucket())
        return client

    return _set


def call(c, method, path, body, headers=None):
    return (
        getattr(c, method)(path, json=body, headers=headers or {})
        if body is not None
        else getattr(c, method)(path, headers=headers or {})
    )


@pytest.mark.parametrize(("method", "path", "body"), INTERNAL)
def test_internal_endpoints_closed_in_production_without_key(mode, method, path, body):
    assert call(mode(False), method, path, body).status_code == 503


@pytest.mark.parametrize(("method", "path", "body"), INTERNAL)
def test_internal_endpoints_need_the_key(mode, method, path, body):
    c = mode(False, KEY)
    assert call(c, method, path, body).status_code == 401
    assert call(c, method, path, body, {"X-API-Key": "wrong"}).status_code == 401
    assert call(c, method, path, body, {"X-API-Key": KEY}).status_code == 200


@pytest.mark.parametrize(("method", "path", "body"), DEMO_ONLY + [("post", "/v1/demo/simulate-attack", None)])
def test_demo_endpoints_are_404_in_production(mode, method, path, body):
    assert call(mode(False, KEY), method, path, body, {"X-API-Key": KEY}).status_code == 404


@pytest.mark.parametrize(("method", "path", "body"), INTERNAL + DEMO_ONLY)
def test_demo_mode_without_key_is_open(mode, method, path, body):
    assert call(mode(True), method, path, body).status_code == 200


def test_demo_mode_with_key_still_needs_it(mode):
    c = mode(True, KEY)
    assert c.get("/v1/messages").status_code == 401
    assert c.get("/v1/messages", headers={"X-API-Key": KEY}).status_code == 200


def test_public_endpoints_in_production(mode):
    c = mode(False)
    assert c.get("/").status_code == 200
    assert c.get("/static/app.js").status_code == 200
    h = c.get("/healthz").json()
    assert h["ok"] and h["demo_mode"] is False
    r = c.post("/v1/guest/verify", json={"reservation_id": "R100000", "pin": "0000", "text": "hi"})
    assert r.status_code == 200 and r.json()["ok"] in (True, False)


def test_simulate_attack_and_containment_over_http(mode):
    c = mode(True)
    sim = c.post("/v1/demo/simulate-attack").json()
    assert sim["elapsed_ms"] > 0 and len(sim["timeline"]) == 9
    case = c.post("/v1/properties/H2/contain", json={"session_id": sim["attacker_session"]}).json()
    assert case["file"]["guests_warned_total"] >= 6
    rid = case["file"]["guests_warned"][0]
    assert c.get(f"/v1/reservations/{rid}/notices").json()
    assert c.get("/v1/cases").json()[0]["id"] == case["case_id"]


def test_validation_and_not_found(mode):
    c = mode(True)
    assert c.post("/v1/messages/check", json={"text": ""}).status_code == 422
    assert c.post("/v1/messages/check", json={"text": "x" * 5001}).status_code == 422
    assert c.post("/v1/messages/check", json={"text": "hi", "direction": "sideways"}).status_code == 422
    assert c.post("/v1/sessions/score", json={"property_id": "H1", "user": "u", "hour": 25}).status_code == 422
    assert c.post("/v1/sessions/S-nope/reads", json={"reservation_ids": ["R1"]}).status_code == 404
    assert c.post("/v1/properties/NOPE/contain", json={}).status_code == 404
    assert c.post("/v1/reservations/NOPE/demo-pin").status_code == 404
    assert c.get("/v1/properties/H1/reservations?limit=0").status_code == 422


def test_reservations_never_expose_pin_material(mode):
    rows = mode(True).get("/v1/properties/H2/reservations?limit=5").json()
    assert rows and all("pin_hash" not in r and "pin_salt" not in r for r in rows)


def test_idempotency_conflict_is_409(mode):
    c = mode(True)
    body = {"text": "Breakfast is from 7.", "payment_terms": "pay_at_property", "message_id": "api-idem-1"}
    first = c.post("/v1/messages/check", json=body).json()
    again = c.post("/v1/messages/check", json=body).json()
    assert again["idempotent_replay"] and again["decision"] == first["decision"]
    clash = c.post("/v1/messages/check", json={**body, "text": "Please pay 300 EUR by bank transfer today"})
    assert clash.status_code == 409


def test_session_reads_and_score(mode):
    c = mode(True)
    s = c.post("/v1/sessions/score", json={"property_id": "H2", "user": "u", "token_replay": True, "new_asn": True}).json()
    assert s["level"] == "critical" and s["step_up_required"] and s["mitre"]
    assert c.post(f"/v1/sessions/{s['session_id']}/reads", json={"reservation_ids": ["R100000", "R100001"]}).json() == {
        "recorded": 2
    }


def test_rate_limits(mode, monkeypatch):
    c = mode(True)
    monkeypatch.setattr(config, "RATE_GUEST_PER_MIN", 6)  # burst of 1
    body = {"reservation_id": "R100000", "pin": "0000", "text": "hi"}
    codes = [c.post("/v1/guest/verify", json=body).status_code for _ in range(3)]
    assert 429 in codes
    monkeypatch.setattr(config, "RATE_CHECK_PER_MIN", 6)
    codes = [c.post("/v1/messages/check", json={"text": "hi"}).status_code for _ in range(3)]
    assert 429 in codes


def test_token_bucket_refills():
    b = api.TokenBucket()
    assert b.allow("x", "c", 60, now=0.0)
    for _ in range(9):
        b.allow("x", "c", 60, now=0.0)
    assert not b.allow("x", "c", 60, now=0.0)
    assert b.allow("x", "c", 60, now=2.0)
    assert b.allow("x", "c", 0)  # 0 = unlimited


def test_security_headers(mode):
    c = mode(True)
    r = c.get("/")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert "unsafe-inline" not in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert "cdn.jsdelivr.net" in c.get("/docs").headers["content-security-policy"]


def test_llm_outage_switch(mode):
    c = mode(True)
    assert c.post("/v1/admin/llm-outage", json={"on": True}).json()["breaker"].startswith("open")
    assert c.post("/v1/admin/llm-outage", json={"on": False}).json()["breaker"] == "closed"


def test_errors_never_leak_a_stack_trace(mode, monkeypatch, service):
    mode(True)

    def boom():
        raise RuntimeError("secret internals")

    monkeypatch.setattr(service, "cases", boom)
    with TestClient(api.app, raise_server_exceptions=False) as c:
        r = c.get("/v1/cases")
    assert r.status_code == 500 and r.json() == {"error": "internal_error", "detail": "RuntimeError"}
    assert "secret internals" not in r.text


def test_contain_and_recover_errors_map_to_http_codes(mode, service):
    c = mode(True)
    sid = service.score_session("H2", "x", {"hour": 10})["session_id"]
    assert c.post("/v1/properties/H1/contain", json={"session_id": sid}).status_code == 409  # another property's session
    assert c.post("/v1/properties/NOPE/contain", json={}).status_code == 404
    assert c.post("/v1/properties/NOPE/recovered", json={}).status_code == 404


def test_validation_errors_do_not_echo_the_input(mode):
    r = mode(True).post("/v1/messages/check", json={"text": 12345678901234})
    assert r.status_code == 422 and "12345678901234" not in r.text


def test_in_flight_idempotency_key_is_a_retryable_409(mode, monkeypatch):
    from stayguard import service as service_mod

    def in_flight(*_a, **_k):
        raise service_mod.IdempotencyInFlight("m")

    monkeypatch.setattr(api.svc(), "check_message", in_flight)
    r = mode(True).post("/v1/messages/check", json={"text": "hi"})
    assert r.status_code == 409 and r.headers["retry-after"] == "1"
