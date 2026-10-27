"""Regression tests for the confirmed findings of adversarial review round 3 (docs/ADVERSARIAL_REVIEW.md).
Each failed on the reviewed commit 4581705 unless its docstring says otherwise."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from stayguard.links import LinkChecker
from stayguard.signals import extract, mask_pii

ROOT = Path(__file__).resolve().parent.parent
PAP = {"payment_terms": "pay_at_property", "direction": "hotel_to_guest"}
STOPPED = ("hold", "block")


def run(engine, text, ctx=PAP, outage=False):
    engine.breaker.forced_outage = outage
    try:
        return engine.check(text, dict(ctx), record=False)
    finally:
        engine.breaker.forced_outage = False


# ---------------------------------------------------------------------------------------------- B1 passive demands
@pytest.mark.parametrize(
    "text",
    [
        "A 50 EUR arrival fee is payable to our account frontdesk@ourhotel-mail.com ahead of check-in to keep your room.",
        "The 50 EUR city tax can be settled to our account frontdesk@ourhotel-mail.com before you arrive. See you Friday!",
        "Welcome! The 50 EUR tourist levy goes to our account frontdesk@ourhotel-mail.com before you arrive.",
        "The 50 EUR deposit can be sent by Yape to 987 654 321 before you arrive.",
    ],
)
@pytest.mark.parametrize("outage", [False, True])
def test_a_payment_written_as_a_fact_is_still_a_demand(engine, text, outage):
    d = run(engine, text, outage=outage)
    assert d.decision in STOPPED and "PAY_ASK_ON_PAY_AT_HOTEL" in d.reasons, (d.decision, d.reasons)


@pytest.mark.parametrize(
    "text",
    [
        "City tax of 2 EUR per night is payable at the hotel on arrival.",
        "Parking costs 15 EUR per day, payable at the front desk.",
        "Breakfast is 12 EUR per person and is paid on departure.",
    ],
)
def test_pay_at_hotel_mentions_are_not_demands(engine, text):
    assert run(engine, text).decision == "deliver"


# ---------------------------------------------------------------------------------------------- B2 phone handoff
def test_a_phone_handoff_is_flagged_and_judged_never_fast_pathed(engine):
    text = (
        "Welcome! We look forward to seeing you on Friday. Breakfast is 7 to 10am and check-in is from 3pm. To arrange "
        "an early check-in, just give our front desk a quick ring on +351 211 234 567 and ask for Maria."
    )
    assert extract(text).phone_handoff
    d = run(engine, text)
    assert d.path in ("judges", "degraded"), (d.path, d.reasons)  # the judges decide; residual in ADVERSARIAL_REVIEW


# ---------------------------------------------------------------------------------------------- A1 reassurance again
@pytest.mark.parametrize(
    "text",
    [
        "Your stay is fully paid at the property pay the 80 EUR city tax at https://lisbon-citytax.com/r/88 before arrival",
        "Pay the 80 EUR city tax today to keep the room as you won't be charged anything else",
        "Your booking is fully paid at the hotel to keep it pay the 80 EUR city tax today",
    ],
)
@pytest.mark.parametrize("outage", [False, True])
def test_an_ask_before_or_after_a_reassurance_is_never_delivered_clean(engine, text, outage):
    d = run(engine, text, outage=outage)
    assert d.decision != "deliver", (d.decision, d.reasons)


# ---------------------------------------------------------------------------------------------- A2 judge input length
def test_judges_see_everything_a_rule_saw():
    from stayguard import judges
    from stayguard.api import MessageIn

    assert MessageIn.model_fields["text"].metadata[1].max_length <= judges.MAX_JUDGE_CHARS


# ---------------------------------------------------------------------------------------------- A3 obfuscated + reassured
def test_a_leetspeak_card_request_next_to_a_reassurance_is_not_delivered_clean(engine):
    for outage in (False, True):
        d = run(engine, "You will not be charged at the property until we receive your c@rd numb3r", outage=outage)
        assert d.decision != "deliver", (outage, d.decision, d.reasons)


def test_a_plain_reassured_card_request_is_at_least_warned_whatever_the_judge_says(engine):
    d = run(engine, "You will not be charged at the property until we receive your card number")
    assert d.decision != "deliver", d.reasons


# ---------------------------------------------------------------------------------------------- A4 tenant subdomains
@pytest.mark.parametrize(
    "url",
    [
        "https://lisbonhotel.livejournal.com/arrival",
        "https://www.lisbonhotel.livejournal.com/arrival",
        "https://support.lisbonhotel.atlassian.net/x",
    ],
)
def test_tenants_on_popular_platforms_are_never_safe_even_behind_www(url):
    v = LinkChecker(use_blocklist=False).check(url)
    assert v.verdict != "safe" and "POPULAR_DOMAIN" not in v.reasons, (v.verdict, v.reasons)


def test_language_subdomains_of_popular_sites_stay_safe():
    assert LinkChecker(use_blocklist=False).check("https://pt.wikipedia.org/wiki/Lisboa").verdict == "safe"


# ---------------------------------------------------------------------------------------------- A5 containment in flight
def test_a_message_in_flight_when_containment_commits_is_not_delivered(service, monkeypatch):
    s = service.score_session("H2", "staff", {"hour": 10})
    real = service.engine.check

    def check_then_contain(text, ctx=None, record=True):
        d = real(text, ctx, record)
        service.contain("H2", s["session_id"])  # containment commits while the message is being decided
        return d

    monkeypatch.setattr(service.engine, "check", check_then_contain)
    try:
        out = service.check_message(text="Check-in is from 3 pm.", session_id=s["session_id"], message_id="r3-inflight")
    finally:
        monkeypatch.setattr(service.engine, "check", real)
        service.recover_property("H2")
    assert out["decision"] == "block" and "SESSION_REVOKED" in out["reasons"]


# ---------------------------------------------------------------------------------------------- A6 scheme-less userinfo
def test_schemeless_userinfo_link_is_not_masked_as_an_email():
    out, kinds = mask_pii("Open the guest area: www.booking.com@keyroom-lisboa.com/k")
    assert "keyroom-lisboa.com" in out and "EMAIL" not in kinds


# ---------------------------------------------------------------------------------------------- A7 redirect after host
@pytest.mark.parametrize(
    "url",
    [
        "https://www.booking.com?u=https://keyroom-lisboa.xyz/k",
        "https://www.booking.com#https://keyroom-lisboa.xyz/k",
        "https://www.booking.com:443?u=https://keyroom-lisboa.xyz/k",
    ],
)
def test_redirect_target_right_after_the_host_is_checked(url):
    v = LinkChecker(use_blocklist=False).check(url)
    assert v.verdict != "official", v.reasons


# ---------------------------------------------------------------------------------------------- A8 card separators
@pytest.mark.parametrize(
    "card", ["4111 / 1111 / 1111 / 1111", "4111|1111|1111|1111", "4111*1111*1111*1111", "4111:1111:1111:1111"]
)
def test_cards_with_wider_separators_are_masked(card):
    out, kinds = mask_pii(f"Here is my card as asked: {card} exp 12/27")
    assert "1111" not in out and "CARD" in kinds


# ---------------------------------------------------------------------------------------------- A9 anchor before commit
def test_a_failed_anchor_write_rolls_the_audit_row_back(tmp_path, monkeypatch):
    from stayguard import config, db

    monkeypatch.setattr(config, "DB_PATH", tmp_path / "a.db")
    monkeypatch.setattr(config, "AUDIT_ANCHOR_EVERY", 1)
    db.audit("t", {"i": 0})

    def broken(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr(db, "_write_anchor", broken)
    with pytest.raises(OSError):
        db.audit("t", {"i": 1})
    assert db.con().execute("SELECT COUNT(*) FROM audit").fetchone()[0] == 1  # no unanchored committed row


# ---------------------------------------------------------------------------------------------- C1 emoji
@pytest.mark.parametrize(
    "text",
    [
        "Thanks, see you tomorrow ❤️",
        "Family room for 👨‍👩‍👧 is ready ☀️",
        "Welcome 🏴󠁧󠁢󠁳󠁣󠁴󠁿 friends! Press 1️⃣ for reception",
        "आपका स्वागत है, क्षमा करें",
    ],
)
def test_emoji_and_script_joiners_are_not_obfuscation(engine, text):
    assert not extract(text).hidden_chars
    assert run(engine, text).decision == "deliver"


def test_real_hidden_characters_are_still_flagged():
    assert extract("Pay‍ment").hidden_chars and extract("ca⁣rd").hidden_chars and extract("c️ard").hidden_chars


# ---------------------------------------------------------------------------------------------- C2 lexicon additions tested
@pytest.mark.parametrize(
    "text",
    [
        "Proszę o przelew 200 PLN dzisiaj, aby utrzymać rezerwację.",
        "Rezervasyonunuzu korumak için lütfen 500 TL havale yapın.",
        "Пожалуйста, сделайте перевод 3000 рублей сегодня.",
        "本日中に5000円をお振込みください。振込先は下記の口座です。",
    ],
)
def test_round_two_transfer_words_are_off_platform_payment(text):
    assert extract(text).off_platform_payment


# ---------------------------------------------------------------------------------------------- C3 one-shot v2 protocol
def _ev():
    sys.path.insert(0, str(ROOT))
    from eval import evaluate

    return evaluate


def test_committed_v2_file_is_the_one_the_protocol_expects():
    ev = _ev()
    assert ev._sha256(ROOT / "data" / "curated" / "heldout_v2.jsonl") == ev.V2_SHA256


def test_frozen_v2_first_look_matches_the_committed_data_if_it_exists():
    ev = _ev()
    if not ev.FIRST_LOOK_V2.exists():
        pytest.skip("held-out v2 has not had its blind run yet")
    fl = json.loads(ev.FIRST_LOOK_V2.read_text())
    assert fl["heldout_v2_sha256"] == ev.V2_SHA256 and fl["git_commit"] not in ("", "unknown")
