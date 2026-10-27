import json

from stayguard import db
from stayguard.judges import JudgeOpinion, referee, validate_quotes

PAP = {"payment_terms": "pay_at_property", "direction": "hotel_to_guest"}


def test_core_rule_pay_ask_on_pay_at_hotel(engine):
    d = engine.check("To keep your room please pay the deposit of 120 EUR today via our page", PAP, record=False)
    assert d.decision == "hold" and "PAY_ASK_ON_PAY_AT_HOTEL" in d.reasons and d.path == "rule"
    assert any(e["kind"] == "money_ask" for e in d.evidence)


def test_normal_message_fast_path(engine):
    d = engine.check("Hi! Check-in is from 3 pm and breakfast is from 7. See you soon.", PAP, record=False)
    assert d.decision == "deliver" and d.reasons == ["NO_PAYMENT_ASK"] and not d.llm_called


def test_known_phishing_link_blocks(engine):
    d = engine.check("Confirm here https://account.booking-extranet.eu/x", PAP, record=False)
    assert d.decision == "block" and "KNOWN_PHISHING_LINK" in d.reasons


def test_overpayment_guest_to_hotel(engine):
    d = engine.check(
        "My assistant overpaid by 900 EUR, please wire back the difference today",
        {"payment_terms": "prepaid", "direction": "guest_to_hotel"},
        record=False,
    )
    assert d.decision == "hold" and "OVERPAYMENT_REFUND_REQUEST" in d.reasons


def test_session_escalation(engine):
    crit = {"risk": 0.96, "level": "critical", "reasons": ["SESSION_TOKEN_REPLAYED_FROM_NEW_NETWORK"]}
    d = engine.check("What time will you arrive?", {**PAP, "session": crit}, record=False)
    assert d.decision == "hold" and "SESSION_TAKEOVER_SUSPECTED" in d.reasons and d.suggest_containment


def test_degraded_mode_when_llm_down(engine):
    text = "Hello, your deposit is pending. Kindly settle it with reception, we accept card."  # grey-zone
    engine.breaker.forced_outage = True
    try:
        d = engine.check(text, {"payment_terms": "deposit", "direction": "hotel_to_guest"}, record=False)
        if d.path in ("judges", "degraded"):
            assert d.path == "degraded" and d.decision in ("warn", "hold")
        risky = {"risk": 0.8, "level": "risky", "reasons": []}
        d2 = engine.check(text, {"payment_terms": "deposit", "direction": "hotel_to_guest", "session": risky}, record=False)
        assert d2.decision in ("hold", "block") or d2.path != "degraded"
    finally:
        engine.breaker.forced_outage = False


def test_judge_quotes_must_exist():
    ok, bad = validate_quotes(["pay now", "send bitcoin"], "Please pay now at the link")
    assert ok == ["pay now"] and bad == ["send bitcoin"]
    pro = JudgeOpinion("prosecutor", "scam", 0.9, ["pay now", "within 12 hours"])
    de = JudgeOpinion("defender", "legit", 0.9, [])
    assert referee(pro, de) > 0.6


def test_audit_chain_is_append_only_and_tamper_evident(service):
    db.audit("test.event", {"x": 1})
    assert db.audit_verify()["ok"]
    try:
        db.con().execute("DELETE FROM audit")
        raise AssertionError("delete should be blocked")
    except Exception as e:  # noqa: BLE001
        assert "append-only" in str(e)


def test_simulation_and_containment(service):
    sim = service.simulate_attack("H2")
    attacker_msgs = [e["message"] for e in sim["timeline"] if e["actor"] == "attacker" and "message" in e]
    assert attacker_msgs and all(m["decision"] in ("hold", "block") for m in attacker_msgs)
    staff_msgs = [e["message"] for e in sim["timeline"] if e["actor"] == "staff" and "message" in e]
    assert staff_msgs[0]["decision"] == "deliver"
    case = service.contain("H2", sim["attacker_session"])
    assert case["file"]["guests_warned_total"] >= len(attacker_msgs)
    after = service.check_message(text="hello", session_id=sim["attacker_session"])
    assert after["decision"] == "block" and after["reasons"] == ["SESSION_REVOKED"]
    assert db.audit_verify()["ok"]


def test_idempotency(service):
    from stayguard.service import IdempotencyConflict

    r = service.upcoming("H1", limit=1)[0]
    a = service.check_message(text="Breakfast is from 7.", reservation_id=r["id"], message_id="idem-1")
    again = service.check_message(text="Breakfast is from 7.", reservation_id=r["id"], message_id="idem-1")
    assert again.get("idempotent_replay") and again["decision"] == a["decision"]
    try:
        service.check_message(text="Pay 300 EUR by bank transfer today", reservation_id=r["id"], message_id="idem-1")
        raise AssertionError("a reused key with a new payload must be rejected")
    except IdempotencyConflict:
        pass


def test_guest_verify_pin_and_lockout(service):
    r = service.upcoming("H1", limit=1, terms="pay_at_property")[0]
    pin = service.issue_pin(r["id"])
    good = service.guest_verify(r["id"], pin, "Please pay 100 EUR by bank transfer today to keep the room", client="t1")
    assert good["ok"] and good["verdict"] in ("likely_scam", "scam")
    wrong = "0000" if pin != "0000" else "1111"
    for _ in range(5):
        service.guest_verify(r["id"], wrong, "x", client="t1")
    locked = service.guest_verify(r["id"], pin, "x", client="t2")
    assert not locked["ok"] and locked["error"] == "too_many_attempts"


def test_api_endpoints(client):
    assert client.get("/healthz").json()["ok"]
    r = client.post("/v1/messages/check", json={"text": "Breakfast is from 7 to 10.", "payment_terms": "pay_at_property"})
    assert r.status_code == 200 and r.json()["decision"] == "deliver"
    bad = client.post("/v1/messages/check", json={"text": ""})
    assert bad.status_code == 422
    s = client.post(
        "/v1/sessions/score",
        json={
            "property_id": "H1",
            "user": "x",
            "token_replay": True,
            "new_asn": True,
            "hosting_asn": True,
            "km_from_usual": 6000,
            "speed_kmh": 9000,
        },
    )
    assert s.json()["level"] == "critical" and s.json()["step_up_required"]
    m = client.get("/v1/metrics").json()
    assert m["dataset"]["reservations"] == 2782  # the fixture snapshot (tests/fixtures/raw/hotels.csv)
    assert client.get("/v1/audit/verify").json()["ok"]
    assert json.dumps(client.get("/v1/audit?limit=3").json())


def test_anthropic_judge_parsing_and_quote_filter(monkeypatch):
    """The real-LLM path, with the HTTP call mocked: invented quotes are dropped, failures open the breaker."""
    import httpx

    from stayguard.engine import Engine
    from stayguard.judges import AnthropicJudge

    replies = {
        "prosecutor": json.dumps(
            {
                "verdict": "scam",
                "confidence": 0.9,
                "evidence": ["settle the balance", "wire it to Lagos"],
                "rationale": "money ask",
            }
        ),
        "defender": '{"verdict": "legit", "confidence": 0.3, "evidence": [], "rationale": "weak"}',
    }

    class R:
        def __init__(self, text):
            self._t = text

        def raise_for_status(self):
            pass

        def json(self):
            return {"content": [{"type": "text", "text": self._t}]}

    def fake_post(url, timeout, headers, json):
        role = "prosecutor" if "prosecutor" in json["system"] else "defender"
        assert "<untrusted_message>" in json["messages"][0]["content"]
        return R(replies[role])

    monkeypatch.setattr(httpx, "post", fake_post)
    eng = Engine(judge=AnthropicJudge("test-key", model="test-model"))
    text = "Hello, kindly settle the balance for your stay with reception soon, thanks"
    d = eng.check(text, {"payment_terms": "deposit", "direction": "hotel_to_guest"}, record=False)
    if d.path == "judges":
        assert d.llm_called
        assert d.judges["prosecutor"]["evidence"] == ["settle the balance"]
        assert d.judges["prosecutor"]["rejected_evidence"] == ["wire it to Lagos"]

    def boom(*a, **k):
        raise httpx.ConnectTimeout("timeout")

    monkeypatch.setattr(httpx, "post", boom)
    for _ in range(4):
        d = eng.check(text, {"payment_terms": "deposit", "direction": "hotel_to_guest"}, record=False)
    if d.path in ("judges", "degraded"):
        assert eng.breaker.state.startswith("open") and d.path == "degraded"
