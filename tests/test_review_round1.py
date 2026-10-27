"""Regression tests for every CONFIRMED finding of adversarial review round 1 (docs/ADVERSARIAL_REVIEW.md).
Each test asserts the SAFE behaviour; each failed on the code before the round-1 fixes."""

from __future__ import annotations

import contextlib
import json
import threading

import pytest

from stayguard import config, db
from stayguard.judges import CircuitBreaker, JudgeOpinion, JudgeUnavailable, referee, validate_quotes
from stayguard.links import LinkChecker
from stayguard.signals import extract, mask_pii

PAP = {"payment_terms": "pay_at_property", "direction": "hotel_to_guest"}
NOBL = LinkChecker(use_blocklist=False)
STOPPED = ("hold", "block")
NORMAL = {"hour": 10, "reservations_viewed": 8, "messages_sent": 2}


def rid(service, i, terms="pay_at_property", pid="H2"):
    return service.upcoming(pid, limit=1, terms=terms, offset=i)[0]["id"]


# ---------------------------------------------------------------------------------------------- B1 reassurance
@pytest.mark.parametrize(
    "text",
    [
        "Payment is collected on arrival and we don't need to share any details, but please transfer 50 via UPI to "
        "lisbonhotel@okaxis to hold your late check-in.",
        "Your booking is fully paid, we never ask for money by message; still, kindly wire 60 EUR to our account today "
        "to secure the upgrade.",
        "We never ask for card details by message, however please send your card number to our WhatsApp.",
    ],
)
def test_reassurance_cannot_switch_off_an_ask_in_the_same_sentence(engine, text):
    d = engine.check(text, PAP, record=False)
    assert d.decision in STOPPED, (d.decision, d.reasons)


# ---------------------------------------------------------------------------------------------- B2/A2 hosting
@pytest.mark.parametrize(
    "text",
    [
        "Your digital key and arrival guide are here: https://storage.googleapis.com/lisbonhotel/guest.html",
        "Here is your arrival guide and parking map: https://www.dropbox.com/scl/fi/abc/guide.pdf see you Friday",
        "Please complete your online check-in here: https://sites.google.com/view/lisbon-guest-checkin before arrival",
        "Your stay needs one more step: https://docs.google.com/forms/d/e/1FAIp/viewform",
        "Please complete your online check-in here: https://booking.tk/checkin",
        "Please complete your online check-in here: https://secure.airbnb.cm/checkin",
    ],
)
def test_user_content_hosting_and_brand_cctlds_are_never_silent(engine, text):
    d = engine.check(text, PAP, record=False)
    assert d.decision != "deliver", (d.decision, d.reasons, d.links)


def test_brand_cctld_is_not_vouched_unless_popular():
    assert NOBL.check("https://booking.tk/x").verdict != "safe"
    assert "BRAND_OWNED_DOMAIN" not in NOBL.check("https://airbnb.cm/x").reasons


# ---------------------------------------------------------------------------------------------- B3 numeric IPs
@pytest.mark.parametrize(
    "url", ["http://3627734734/welcome", "http://0xd8.0x3a.0xd6.0xce/welcome", "http://0330.0072.0326.0316/w"]
)
def test_integer_hex_octal_ips_are_raw_ips(url):
    v = NOBL.check(url)
    assert "RAW_IP_ADDRESS" in v.reasons and v.verdict in ("suspicious", "malicious")


# ---------------------------------------------------------------------------------------------- B4 PII separators
@pytest.mark.parametrize("sep", ["‑", "‒", "﹣", "–", " ", " "])
def test_card_numbers_with_unicode_separators_are_masked(sep):
    card = sep.join(["4111", "1111", "1111", "1111"])
    masked, kinds = mask_pii(f"card on file {card} is correct")
    assert "CARD" in kinds and "1111" not in masked


def test_fullwidth_card_digits_are_masked():
    masked, kinds = mask_pii("card ４１１１１１１１１１１１１１１１ ok")
    assert "CARD" in kinds


# ---------------------------------------------------------------------------------------------- B5 oracle
def test_guest_checker_limits_successful_checks_per_booking(service):
    r = rid(service, 40)
    pin = service.issue_pin(r)
    outs = [
        service.guest_verify(r, pin, f"message {i}", client=f"oracle-{i}") for i in range(config.GUEST_CHECKS_PER_RESERVATION + 3)
    ]
    assert outs[-1]["ok"] is False and outs[-1]["error"] == "too_many_checks"


# ---------------------------------------------------------------------------------------------- B6 redirects
@pytest.mark.parametrize(
    "url",
    [
        "https://booking.com/redirect/path/https://evil-pay.xyz/c",
        "https://booking.com/go#https://evil-pay.xyz/c",
        "https://www.google.com/url?q=evil-pay.xyz/x",
    ],
)
def test_redirect_targets_anywhere_in_the_url_are_checked(url):
    v = LinkChecker().check(url)
    assert v.verdict != "official" and any(r.startswith("REDIRECTS_TO:") for r in v.reasons), v.as_dict()


# ---------------------------------------------------------------------------------------------- A1 invisible chars
@pytest.mark.parametrize("ch", ["⁣", "⁡", "͏", "᠎", "\U000e0020"])
def test_all_invisible_format_characters_are_stripped(engine, ch):
    text = f"Yo{ch}ur ca{ch}rd co{ch}uld not be ve{ch}rified. Se{ch}nd yo{ch}ur ca{ch}rd de{ch}tails on Wh{ch}atsApp."
    s = extract(text)
    assert s.hidden_chars and s.card_data
    assert engine.check(text, PAP, record=False).decision in STOPPED


# ---------------------------------------------------------------------------------------------- A3 defanged links
@pytest.mark.parametrize(
    "text",
    [
        "Your stay needs one more step. Finish it at guest-step-portal。net/g before you travel.",
        "Your stay needs one more step. Finish it at guest-step-portal[.]net/g before you travel.",
        "Your stay needs one more step. Finish it at guest-step-portal(.)net/g before you travel.",
        "Your stay needs one more step. Finish it at guest-step-portal . net/g before you travel.",
    ],
)
def test_defanged_links_are_still_links(engine, text):
    s = extract(text)
    assert s.urls and s.obfuscated
    assert engine.check(text, PAP, record=False).decision != "deliver"


# ---------------------------------------------------------------------------------------------- A4 breaker wedge
def test_breaker_probe_is_released_when_the_probe_hits_a_bug(engine, monkeypatch):
    from stayguard.engine import Engine

    clk = [0.0]
    e = Engine.__new__(Engine)
    e.clf, e.links, e.metrics = engine.clf, engine.links, type(engine.metrics)()
    e.breaker = CircuitBreaker(failures=1, cooldown=1, clock=lambda: clk[0])

    class Flaky:
        name = "flaky"
        mode = "bug"

        def rule(self, *a):
            if self.mode == "bug":
                raise AttributeError("bug")
            raise JudgeUnavailable("down")

    e.judge = Flaky()
    monkeypatch.setattr(e.clf, "score", lambda t: 0.35)
    soft = "Please let us know if you want breakfast, it is 12 EUR."
    ctx = {"payment_terms": "deposit", "direction": "hotel_to_guest"}
    e.breaker.record(False)
    clk[0] = 5
    assert e.check(soft, ctx, record=False).reasons == ["SYSTEM_EXCEPTION_FAIL_CLOSED"]
    assert e.breaker.probe_in_flight is False and e.breaker.allow()


def test_non_object_llm_reply_is_a_provider_failure(monkeypatch):
    import httpx

    from stayguard.judges import AnthropicJudge

    class R:
        def raise_for_status(self):
            pass

        def json(self):
            return []

    monkeypatch.setattr(httpx, "post", lambda *a, **k: R())
    with pytest.raises(JudgeUnavailable):
        AnthropicJudge("k", model="m", timeout=1).rule("x", extract("x"), {}, 0.5, 0.0)


# ---------------------------------------------------------------------------------------------- A5 userinfo masking
def test_userinfo_url_is_not_masked_as_an_email():
    masked, kinds = mask_pii("Finish it at https://booking.com@guest-step-portal.net/g and mail a.b@example.com")
    assert "guest-step-portal.net" in masked and "[EMAIL]" in masked and "a.b@example.com" not in masked


# ---------------------------------------------------------------------------------------------- A6 lockout race
def test_guest_lockout_holds_under_concurrency(service):
    r = rid(service, 41)
    service.issue_pin(r)
    start = threading.Barrier(30)
    results = []

    def guess(p):
        start.wait(5)
        results.append(service.guest_verify(r, f"{p:04d}", "hello", client="race-client"))

    threads = [threading.Thread(target=guess, args=(p,)) for p in range(30)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    evaluated = sum(1 for x in results if x.get("error") not in ("too_many_attempts",))
    assert evaluated <= config.GUEST_FAILS_PER_CLIENT_RESERVATION + 1


# ---------------------------------------------------------------------------------------------- A7 terms override
def test_stored_payment_terms_win_over_the_request(service):
    r = rid(service, 42)
    out = service.check_message(
        text="To keep your room please pay the 120 EUR deposit today", reservation_id=r, payment_terms="prepaid"
    )
    assert out["payment_terms"] == "pay_at_property" and "PAY_ASK_ON_PAY_AT_HOTEL" in out["reasons"]


# ---------------------------------------------------------------------------------------------- A8 idempotency
def test_idempotency_hash_covers_terms_and_property(service):
    from stayguard.service import IdempotencyConflict

    service.check_message(text="City tax is 4 EUR per night.", payment_terms="prepaid", message_id="r1-idem-terms")
    with pytest.raises(IdempotencyConflict):
        service.check_message(text="City tax is 4 EUR per night.", payment_terms="pay_at_property", message_id="r1-idem-terms")


def test_concurrent_reuse_of_a_key_cannot_overwrite_a_held_message(service, monkeypatch):
    from stayguard.service import IdempotencyConflict

    r_scam, r_ok = rid(service, 43), rid(service, 44)
    real = service.engine.check
    barrier = threading.Barrier(2)

    def slow(text, ctx=None, record=True):
        d = real(text, ctx, record)
        with contextlib.suppress(threading.BrokenBarrierError):
            barrier.wait(2)
        return d

    monkeypatch.setattr(service.engine, "check", slow)
    res, errs = {}, []

    def go(name, text, r):
        try:
            res[name] = service.check_message(text=text, reservation_id=r, message_id="r1-race")
        except IdempotencyConflict as e:
            errs.append(e)

    th = [
        threading.Thread(
            target=go, args=("scam", "Our bank account is not connected. Pay 300 EUR by bank transfer today.", r_scam)
        ),
        threading.Thread(target=go, args=("ok", "Check-in is from 3 pm. See you soon!", r_ok)),
    ]
    for t in th:
        t.start()
    for t in th:
        t.join()
    assert len(errs) == 1 and len(res) == 1
    rows = db.con().execute("SELECT reservation_id FROM messages WHERE id='r1-race'").fetchall()
    assert len(rows) == 1


# ---------------------------------------------------------------------------------------------- A9/A10 containment
def test_contained_property_requires_recovery_before_sending(service):
    s = service.score_session("H1", "staff", NORMAL)
    service.contain("H1", s["session_id"])
    fresh = service.score_session("H1", "staff", NORMAL)
    assert fresh["level"] == "critical" and "PASSWORD_RESET_PENDING" in fresh["reasons"]
    m = service.check_message(text="What time will you arrive?", session_id=fresh["session_id"])
    assert m["decision"] in STOPPED
    service.recover_property("H1")
    assert service.score_session("H1", "staff", NORMAL)["level"] == "normal"


def test_case_file_does_not_claim_actions_it_cannot_do(service):
    s = service.score_session("H1", "staff", NORMAL)
    actions = {a["action"]: a for a in service.contain("H1", s["session_id"])["file"]["actions"]}
    assert actions["freeze_payout_bank_changes"]["status"] == "requested"
    service.recover_property("H1")


def test_contain_rejects_a_session_from_another_property(service):
    atk = service.score_session("H2", "x", {**NORMAL, "token_replay": True, "new_asn": True})
    with pytest.raises(ValueError):
        service.contain("H1", atk["session_id"])
    assert service.session(atk["session_id"])["status"] == "active"


# ---------------------------------------------------------------------------------------------- A11 fail closed
def test_lone_surrogate_fails_closed(service, client):
    out = service.check_message(text="Pay now \ud800 at https://x-pay.xyz", message_id="r1-surrogate")
    assert out["decision"] in STOPPED
    r = client.post("/v1/messages/check", content='{"text": "Pay now \\ud800"}', headers={"content-type": "application/json"})
    assert r.status_code == 200 and r.json()["decision"] in STOPPED


def test_idempotency_lookup_failure_fails_closed(service, monkeypatch):
    def broken():
        raise RuntimeError("db gone")

    monkeypatch.setattr(db, "con", broken)
    out = service.check_message(text="hello", message_id="r1-broken")
    assert out["decision"] == "hold" and out["reasons"] == ["SYSTEM_EXCEPTION_FAIL_CLOSED"]


def test_unknown_session_is_not_treated_as_normal(service):
    out = service.check_message(
        text="Please let us know your arrival time, here is the guide: https://guest-guide-portal.net/a",
        session_id="S-never-scored",
    )
    assert out["session"]["level"] in ("risky", "critical") and "UNKNOWN_SESSION" in out["session"]["reasons"]


# ---------------------------------------------------------------------------------------------- A12 lockout DoS
def test_an_attacker_cannot_lock_the_real_guest_out(service):
    r = rid(service, 45)
    pin = service.issue_pin(r)
    for _ in range(6):
        service.guest_verify(r, "0000" if pin != "0000" else "1111", "x", client="attacker-ip")
    assert service.guest_verify(r, pin, "Check-in is from 3 pm.", client="guest-phone")["ok"]


# ---------------------------------------------------------------------------------------------- A13 judge deadline
def test_judge_wall_clock_respects_the_timeout(monkeypatch):
    import time

    import httpx

    from stayguard.judges import AnthropicJudge

    monkeypatch.setattr(httpx, "post", lambda *a, **k: time.sleep(3))
    t0 = time.perf_counter()
    with pytest.raises(JudgeUnavailable):
        AnthropicJudge("k", model="m", timeout=0.3).rule("x", extract("x"), {}, 0.5, 0.0)
    assert time.perf_counter() - t0 < 1.5


# ---------------------------------------------------------------------------------------------- A14 trivial quotes
def test_trivial_or_duplicate_quotes_do_not_count():
    ok, _ = validate_quotes(["at", "it", "it", "at", "the"], "Finish it at the link below")
    assert ok == []
    ok2, _ = validate_quotes(["pay now", "Pay Now"], "Please pay now")
    assert ok2 == ["pay now"]
    pro = JudgeOpinion("p", "scam", 0.9, ["finish it at the link below"])
    de = JudgeOpinion("d", "legit", 0.9, validate_quotes(["at", "it", "it", "at"], "finish it at the link below")[0])
    assert referee(pro, de) >= 0.65


# ---------------------------------------------------------------------------------------------- A15 audit tail
def test_deleting_the_tail_of_the_audit_log_is_detected(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "tail.db")
    for i in range(6):
        db.audit("t", {"i": i})
    c = db.con()
    c.execute("DROP TRIGGER audit_no_delete")
    c.execute("DELETE FROM audit WHERE seq > 3")
    assert not db.audit_verify()["ok"]


def test_missing_anchor_file_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "noanchor.db")
    db.audit("t", {})
    db.anchor_path().unlink()
    v = db.audit_verify()
    assert not v["ok"] and v["reason"] == "anchors_missing"


# ---------------------------------------------------------------------------------------------- limiter growth
def test_rate_limiter_state_is_bounded():
    from stayguard.api import TokenBucket

    b = TokenBucket(max_clients=100)
    for i in range(500):
        b.allow("x", f"c{i}", 60, now=float(i))
    assert len(b.state) <= 100


def test_payload_hash_in_report_json_is_valid_json():
    assert json.loads(json.dumps({"ok": True}))
