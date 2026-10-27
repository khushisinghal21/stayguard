"""Regression tests for the confirmed findings of adversarial review round 2 (docs/ADVERSARIAL_REVIEW.md).
Each failed before its fix."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from stayguard.links import LinkChecker

ROOT = Path(__file__).resolve().parent.parent
PAP = {"payment_terms": "pay_at_property", "direction": "hotel_to_guest"}
STOPPED = ("hold", "block")


def run(engine, text, ctx=PAP):
    return engine.check(text, dict(ctx), record=False)


# ---------------------------------------------------------------------------------------------- B1 reassurance, no comma
@pytest.mark.parametrize(
    "text",
    [
        "Your stay is fully paid at the property and we never charge a thing just confirm your card number here so the room "
        "stays held",
        "Thanks for booking with us and no deposit is needed at all just share 50 via UPI to lisbonhotel@okaxis to hold your "
        "room",
        "Everything is paid at the property and nothing is due now just send the 30 reais by Pix to our account today",
        "You pay at the property so there is nothing to worry about just send 50 eur by bank transfer now please.",
        "Your stay is paid at the property confirm your card number here so the room stays held",
    ],
)
def test_reassurance_joined_without_punctuation_cannot_hide_an_ask(engine, text):
    d = run(engine, text)
    assert d.decision in STOPPED, (d.decision, d.reasons)


@pytest.mark.parametrize(
    "text",
    [
        "We will never ask you to send money by bank transfer or share your card number.",
        "You pay at the property and parking is 15 EUR per day, payable at the front desk.",
        "Nothing to pay now and you can pay the driver directly in cash.",
        "Swift check-in: just show your passport at reception.",
    ],
)
def test_reassurances_and_mentions_are_still_not_holds(engine, text):
    assert run(engine, text).decision not in STOPPED


@pytest.mark.parametrize("rail", ["Pix", "Revolut", "Zelle", "Bizum", "BLIK", "MB Way", "Alipay", "PayPal"])
def test_other_payment_rails_are_off_platform_payment(engine, rail):
    d = run(engine, f"Please send the 40 EUR deposit by {rail} today to keep your room.")
    assert "OFF_PLATFORM_PAYMENT" in d.reasons and d.decision in STOPPED


# ---------------------------------------------------------------------------------------------- B2 tenant pages on popular sites
@pytest.mark.parametrize(
    "url",
    [
        "https://ourlisbonhotel.wordpress.com",
        "https://script.google.com/macros/s/AKfycbxabc/exec",
        "https://medium.com/@lisbonhotel/checkin",
        "https://github.com/lisbonhotel/checkin",
    ],
)
def test_pages_anyone_can_publish_on_popular_platforms_are_not_vouched(url):
    v = LinkChecker(use_blocklist=False).check(url)
    assert "POPULAR_DOMAIN" not in v.reasons and v.verdict != "safe", (v.verdict, v.reasons)


def test_tenant_link_with_an_instruction_is_never_delivered_clean(engine):
    d = run(engine, "Hi! You can pre-register your arrival details here: https://ourlisbonhotel.wordpress.com")
    assert d.decision != "deliver", (d.decision, d.reasons)


def test_service_subdomains_of_popular_sites_keep_the_discount():
    lc = LinkChecker(use_blocklist=False)
    assert lc.check("https://en.wikipedia.org/wiki/Lisbon").verdict == "safe"
    assert lc.check("https://www.instagram.com/lisboncityhotel/").verdict == "safe"


# ---------------------------------------------------------------------------------------------- C1/C5/C6 evaluation
def _ev():
    sys.path.insert(0, str(ROOT))
    from eval import evaluate

    return evaluate


def test_mcnemar_exact_matches_known_values():
    ev = _ev()
    # 0 vs 14 discordant pairs: p = 2 * 0.5**14
    assert ev.mcnemar_exact([False] * 14, [True] * 14)["p_value"] == round(2 * 0.5**14, 5)
    assert ev.mcnemar_exact([True, False], [True, False])["p_value"] == 1.0


def test_malformed_evaluation_rows_are_refused():
    ev = _ev()
    good = {"id": "x", "text": "t", "label": 1, "terms": "prepaid", "category": "c", "lang": "en", "split": "s"}
    ev.validate_rows([good])
    for broken in ({**good, "terms": "unknown"}, {k: v for k, v in good.items() if k != "terms"}, {**good, "label": 2}):
        with pytest.raises(SystemExit):
            ev.validate_rows([broken])


def test_blind_set_cannot_be_peeked_at_with_fast():
    ev = _ev()
    with pytest.raises(SystemExit, match="cannot be combined"):
        ev.main(["--fast", "--heldout-v2", "--out", str(ROOT / "nonexistent-should-not-be-written")])


# ---------------------------------------------------------------------------------------------- A1 reassurance, any joiner
@pytest.mark.parametrize(
    "text",
    [
        "You pay at the hotel and the deposit of 50 EUR is sent via UPI to lisbonhotel@okaxis before you arrive.",
        "No prepayment needed and the room deposit is paid by bank transfer before arrival.",
        "We never ask for card details by email so just reply here with the card number and expiry for the incidentals.",
        "We never ask for card details by email plus reply here with the card number and expiry for the incidentals.",
    ],
)
@pytest.mark.parametrize("outage", [False, True])
def test_a_reassurance_never_delivers_a_card_or_rail_mention_clean(engine, text, outage):
    engine.breaker.forced_outage = outage
    try:
        d = run(engine, text)
    finally:
        engine.breaker.forced_outage = False
    assert d.decision != "deliver", (d.decision, d.reasons)


# ---------------------------------------------------------------------------------------------- A2 backslash URLs
def test_backslash_userinfo_url_is_checked_as_the_host_a_browser_visits(engine):
    from stayguard.domains import host_of

    assert host_of("https://keyroom-lisboa.xyz\\@www.booking.com/k") == "keyroom-lisboa.xyz"
    d = run(engine, "Your digital key is ready. Open the guest area: https://keyroom-lisboa.xyz\\@www.booking.com/k")
    assert d.decision != "deliver" and all(link["verdict"] != "official" for link in d.as_dict()["links"])


# ---------------------------------------------------------------------------------------------- A3 nested redirects
@pytest.mark.parametrize(
    "url",
    [
        "https://www.booking.com/redirect/https://www.booking.com/redirect/https://keyroom-lisboa.xyz/k",
        "https://www.booking.com/r?u=https://www.booking.com/?x=https://keyroom-lisboa.xyz/k",
        "https://www.booking.com/r?a=https://booking.com&b=https://booking.com&c=https://booking.com&u=https://keyroom-lisboa.xyz/k",
        "https://www.booking.com/redirect?url=https%253A%252F%252Fkeyroom-lisboa.xyz%252Fk",
    ],
)
def test_every_nested_or_extra_redirect_target_is_checked(url):
    v = LinkChecker(use_blocklist=False).check(url)
    assert v.verdict != "official" and any(r.startswith("REDIRECTS_TO:keyroom-lisboa.xyz") for r in v.reasons), v.reasons


# ---------------------------------------------------------------------------------------------- A4 free hosts, redirectors
@pytest.mark.parametrize(
    "url",
    [
        "https://lisbonstay.github.io",
        "https://lisbonstay.blogspot.com",
        "https://lisbonstay.z6.web.core.windows.net/",
        "https://www.bing.com/ck/a?u=a1aHR0cHM6Ly9ldmlsLnh5eg",
    ],
)
def test_free_hosts_and_encoded_redirectors_are_never_safe(engine, url):
    assert LinkChecker(use_blocklist=False).check(url).verdict != "safe"
    assert run(engine, f"Your stay is almost ready. Open the guest area here: {url}").decision != "deliver"


# ---------------------------------------------------------------------------------------------- A5 breaker via content
def test_unusable_judge_reply_holds_the_message_and_leaves_the_breaker_alone(monkeypatch):
    from stayguard.engine import Engine
    from stayguard.judges import JudgeReplyUnusable, OfflineJudge

    class Truncating(OfflineJudge):
        def rule(self, *a, **k):
            raise JudgeReplyUnusable("truncated")

    e = Engine(judge=Truncating())
    text = "Your stay is almost ready. Finish it at https://guest-step-portal.net/g before you travel."
    for _ in range(5):
        d = run(e, text)
        assert d.decision == "hold" and "JUDGE_REPLY_UNUSABLE" in d.reasons, d.reasons
    assert e.breaker.failures == 0 and e.breaker.state == "closed"


def test_public_health_check_does_not_reveal_the_breaker(client):
    assert "breaker" not in client.get("/healthz").json()


# ---------------------------------------------------------------------------------------------- A6 fullwidth
def test_fullwidth_instruction_is_not_delivered_clean(engine):
    assert run(engine, "Ｃｏｍｐｌｅｔｅ online check-in here: https://lisbon-stay.com/k").decision != "deliver"


# ---------------------------------------------------------------------------------------------- A7 PII
@pytest.mark.parametrize(
    "card", ["4111/1111/1111/1111", "4111_1111_1111_1111", "4111,1111,1111,1111", "4111111111111111exp1227cvv123"]
)
def test_card_numbers_with_any_separator_are_masked(card):
    from stayguard.signals import mask_pii

    out, kinds = mask_pii(f"Here is my card {card} thanks")
    assert "4111" not in out and "CARD" in kinds


def test_emails_in_link_paths_are_masked_but_userinfo_hosts_are_kept():
    from stayguard.signals import mask_pii

    out, _ = mask_pii("receipt to https://lisboncityhotel.pt/r?to=jane.doe@gmail.com and https://booking.com@evil.net/x")
    assert "jane.doe@gmail.com" not in out and "booking.com@evil.net" in out


# ---------------------------------------------------------------------------------------------- A8 audit verify under load
def test_audit_verify_is_not_fooled_by_concurrent_appends(tmp_path, monkeypatch):
    import threading

    from stayguard import config, db

    monkeypatch.setattr(config, "DB_PATH", tmp_path / "a.db")
    monkeypatch.setattr(config, "AUDIT_ANCHOR_EVERY", 1)
    db.audit("t", {"i": -1})
    stop = threading.Event()

    def writer():
        i = 0
        while not stop.is_set():
            db.audit("t", {"i": i})
            i += 1

    th = threading.Thread(target=writer)
    th.start()
    try:
        results = [db.audit_verify()["ok"] for _ in range(30)]
    finally:
        stop.set()
        th.join()
    assert all(results)


# ---------------------------------------------------------------------------------------------- A9 containment race
def test_containment_flag_is_read_inside_the_session_insert_transaction(service, monkeypatch):
    import inspect

    from stayguard.service import Service

    # The race needs an interleaving the test can't force portably, so check the structure that closes it: the flag is
    # read with the transaction's connection, not through a separate read before it (review round 2, A9)...
    src = inspect.getsource(Service._score_session)
    assert "self.property(" not in src and "password_reset_required FROM properties" in src
    # ... and the behaviour: containment that commits just before the insert is seen.
    s = service.score_session("H2", "staff", {"hour": 10})
    real = service.sessions.score

    def score_then_contain(ev):
        out = real(ev)
        service.contain("H2", s["session_id"])
        return out

    monkeypatch.setattr(service.sessions, "score", score_then_contain)
    try:
        fresh = service.score_session("H2", "staff", {"hour": 10})
        assert fresh["level"] == "critical" and "PASSWORD_RESET_PENDING" in fresh["reasons"]
    finally:
        monkeypatch.setattr(service.sessions, "score", real)
        service.recover_property("H2")


# ---------------------------------------------------------------------------------------------- A10 one probe
def test_only_the_probe_can_free_the_probe_slot():
    from stayguard.judges import CircuitBreaker

    t = [0.0]
    b = CircuitBreaker(failures=1, cooldown=1, clock=lambda: t[0])
    early = b.allow()  # starts while closed
    assert early == "closed"
    b.record(False, probe=False)  # another call fails: open
    t[0] = 5
    assert b.allow() == "probe"
    b.release_probe(probe=early == "probe")  # the early call hits a bug
    assert b.allow() == ""  # still only one probe


# ---------------------------------------------------------------------------------------------- A11 overlapping quotes
def test_overlapping_quotes_count_once():
    from stayguard.judges import validate_quotes

    ok, _ = validate_quotes(
        ["hotel", "the hotel", "hotel.", "at the hotel", "welcoming"], "We look forward to welcoming you at the hotel."
    )
    assert sorted(ok) == ["at the hotel", "welcoming"]
