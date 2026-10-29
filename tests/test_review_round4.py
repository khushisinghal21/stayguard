"""Regression tests for the confirmed findings of adversarial review round 4 (docs/ADVERSARIAL_REVIEW.md).
Run against the reviewed commit fef130a they fail, except where a docstring says otherwise."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

from stayguard.links import LinkChecker, embedded_targets
from stayguard.signals import extract, mask_pii

ROOT = Path(__file__).resolve().parent.parent
PAP = {"payment_terms": "pay_at_property", "direction": "hotel_to_guest"}
STOPPED = ("hold", "block")


def run(engine, text, outage=False):
    engine.breaker.forced_outage = outage
    try:
        return engine.check(text, dict(PAP), record=False)
    finally:
        engine.breaker.forced_outage = False


# ---------------------------------------------------------------------------------------------- A1 between reassurances
@pytest.mark.parametrize(
    "text",
    [
        "The city tax is 2 EUR per night, your stay is fully paid send the 80 EUR deposit to reservas.lisboa.stay@gmail.com "
        "today as you won't be charged anything at the property.",
        "Breakfast is 12 EUR, the 80 EUR cleaning fee is payable to frontdesk.lisbon@gmail.com before arrival as the room "
        "itself is fully paid.",
    ],
)
@pytest.mark.parametrize("outage", [False, True])
def test_an_ask_between_or_before_reassurances_is_held(engine, text, outage):
    d = run(engine, text, outage)
    assert d.decision in STOPPED and "PAY_ASK_ON_PAY_AT_HOTEL" in d.reasons, (d.decision, d.reasons)


# ---------------------------------------------------------------------------------------------- A2 format characters
def test_every_default_ignorable_format_character_is_stripped():
    text = "Your card could not be verified. Send your card details on WhatsApp"
    sneaky = " ".join(w[:2] + "\U0001bca1" + w[2:] if len(w) > 3 else w for w in text.split())
    s = extract(sneaky)
    assert s.card_data and s.off_platform_contact and s.hidden_chars


# ---------------------------------------------------------------------------------------------- A3 on-site payments
@pytest.mark.parametrize(
    "text",
    [
        "Parking costs 15 EUR per day, payable via the front desk on arrival.",
        "The city tax of 2 EUR per person per night is payable by card or cash when you check in.",
        "Pets are welcome for a fee of 10 EUR per night, payable by card at check-in.",
        "Airport transfers cost 35 EUR and can be booked in advance; you pay the driver.",
        "If you'd like breakfast (12 EUR), please let us know before arrival.",
        "Late check-out until 2 pm is 20 EUR; just tell us in advance.",
    ],
)
def test_ordinary_on_site_payment_messages_are_not_held(engine, text):
    assert run(engine, text).decision not in STOPPED


# ---------------------------------------------------------------------------------------------- A4 NFKC expansion
def test_masking_never_expands_the_text():
    text = "ﷺ" * 300 + " Complete it here: https://guest-step-portal.net/g"
    masked, _ = mask_pii(text)
    assert len(masked) <= len(text) and "guest-step-portal.net" in masked


# ---------------------------------------------------------------------------------------------- A5 containment race
def test_a_message_committed_while_containment_reads_is_in_the_case_file(service, monkeypatch):
    import threading

    s = service.score_session("H2", "staff", {"hour": 10})
    rid = service.upcoming("H2", limit=1)[0]["id"]
    real = service.session
    box: dict = {}

    def send():
        box["msg"] = service.check_message(text="Check-in is from 3 pm.", reservation_id=rid, session_id=s["session_id"])

    def session_then_message(sid):
        # while containment is gathering what goes into the case file, another request sends a message
        if sid == s["session_id"] and "th" not in box:
            box["th"] = threading.Thread(target=send)
            box["th"].start()
            time.sleep(0.3)  # give it every chance to commit in the gap, as it could before round 4
        return real(sid)

    monkeypatch.setattr(service, "session", session_then_message)
    try:
        case = service.contain("H2", s["session_id"])
    finally:
        monkeypatch.setattr(service, "session", real)
    box["th"].join(10)
    service.recover_property("H2")
    msg = box["msg"]
    in_file = msg["message_id"] in [m["id"] for m in case["file"]["messages"]]
    # either it landed before the revoke and is in the case file, or after it and was blocked; never delivered unseen
    assert in_file or msg["decision"] == "block", (msg["decision"], in_file)


# ---------------------------------------------------------------------------------------------- A6 CPU
def test_a_message_full_of_links_is_checked_quickly(engine):
    text = ("aa.io " * 600 + "bb[.]io " * 600)[:5000]
    t0 = time.perf_counter()
    run(engine, text)
    assert time.perf_counter() - t0 < 0.8


# ---------------------------------------------------------------------------------------------- A7 short tenant names
@pytest.mark.parametrize(
    "url", ["https://lh.webnode.com/checkin", "https://apps.webnode.com/x", "https://www.lh.over-blog.com/x"]
)
def test_short_or_service_named_tenants_are_not_vouched(url):
    v = LinkChecker(use_blocklist=False).check(url)
    assert v.verdict != "safe" and "POPULAR_DOMAIN" not in v.reasons, (v.verdict, v.reasons)


# ---------------------------------------------------------------------------------------------- A8 redirect forms
@pytest.mark.parametrize(
    "url",
    [
        "https://www.booking.com/r?u=//guest-portal-lx.xyz/c",
        "https://www.booking.com/r?u=https:/guest-portal-lx.xyz/c",
        "https://www.booking.com/r?u=/%5Cevil-pay.xyz/c",
        "https://www.booking.com/r/evil-pay.xyz/c",
    ],
)
def test_browser_redirect_forms_are_extracted(url):
    assert embedded_targets(url)
    assert LinkChecker(use_blocklist=False).check(url).verdict != "official"


def test_ordinary_official_paths_have_no_embedded_target():
    assert embedded_targets("https://www.booking.com/hotel/pt/lisbon-city.html") == []


# ---------------------------------------------------------------------------------------------- A9 rolled-back anchor
def test_a_rolled_back_anchor_does_not_poison_verification(tmp_path, monkeypatch):
    from stayguard import config, db

    monkeypatch.setattr(config, "DB_PATH", tmp_path / "a.db")
    monkeypatch.setattr(config, "AUDIT_ANCHOR_EVERY", 1)
    for i in range(3):
        db.audit("t", {"i": i})
    real = db._write_anchor

    def anchor_then_fail(seq, h):
        real(seq, h)
        raise OSError("commit failed after the anchor was written")

    monkeypatch.setattr(db, "_write_anchor", anchor_then_fail)
    with pytest.raises(OSError):
        db.audit("t", {"i": 3})
    monkeypatch.setattr(db, "_write_anchor", real)
    db.audit("t", {"i": 4})  # reuses the rolled-back seq
    assert db.audit_verify()["ok"]


# ---------------------------------------------------------------------------------------------- A10 audit = stored
def test_audit_records_the_decision_that_was_stored(service, monkeypatch):
    from stayguard import db

    s = service.score_session("H2", "staff", {"hour": 10})
    real = service.engine.check

    def check_then_contain(text, ctx=None, record=True):
        d = real(text, ctx, record)
        service.contain("H2", s["session_id"])
        return d

    monkeypatch.setattr(service.engine, "check", check_then_contain)
    try:
        out = service.check_message(text="Check-in is from 3 pm.", session_id=s["session_id"], message_id="r4-audit")
    finally:
        monkeypatch.setattr(service.engine, "check", real)
        service.recover_property("H2")
    row = (
        db.con()
        .execute("SELECT payload FROM audit WHERE kind='message.decision' AND payload LIKE '%r4-audit%' ORDER BY seq DESC")
        .fetchone()
    )
    assert json.loads(row[0])["decision"] == out["decision"] == "block"


# ---------------------------------------------------------------------------------------------- A11 security reminders
def test_a_security_reminder_is_not_warned(engine):
    d = run(
        engine, "Hi Anna, see you on Friday. Payment is taken at the property; we will never ask for your card details by chat."
    )
    assert d.decision == "deliver", d.reasons


# ---------------------------------------------------------------------------------------------- C1 rendering after v2
def _ev():
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "scripts"))
    from eval import evaluate

    return evaluate


def test_readme_renders_with_a_frozen_v2_run():
    """Simulates the post-run state with v1's section in the v2 slot: the README must render without new code."""
    ev = _ev()
    import render_docs

    report = json.loads((ROOT / "eval" / "report.json").read_text())
    fake = {"A_messages_heldout_v2": report["A_messages"]["heldout"]}
    h = {**report["headline"], **ev.headline_v2(fake)}
    table = render_docs.results_table(h)
    assert "Held-out v2" in table and "n/a" not in table.split("Held-out v1")[0]


# ---------------------------------------------------------------------------------------------- C3/C4 blind-run gate
def test_blind_run_refuses_environment_overrides(monkeypatch):
    ev = _ev()
    monkeypatch.setattr(ev, "_git_rc", lambda *a: (0, str(ROOT)) if a[0] == "rev-parse" else (0, ""))
    monkeypatch.setenv("STAYGUARD_ANTHROPIC_API_KEY", "sk-test")
    with pytest.raises(SystemExit, match="environment overrides"):
        ev.blind_run_gate()


def test_blind_run_refuses_a_dirty_tree_or_a_foreign_repository(monkeypatch):
    ev = _ev()
    monkeypatch.setattr(ev, "_git_rc", lambda *a: (0, "/somewhere/else") if a[0] == "rev-parse" else (0, ""))
    with pytest.raises(SystemExit, match="not the top"):
        ev.blind_run_gate()
    monkeypatch.setattr(ev, "_git_rc", lambda *a: (0, str(ROOT)) if a[0] == "rev-parse" else (0, "?? stray.txt"))
    with pytest.raises(SystemExit, match="not clean"):
        ev.blind_run_gate()


def test_frozen_v2_run_is_tracked_and_records_its_conditions():
    ev = _ev()
    if not ev.FIRST_LOOK_V2.exists():
        pytest.skip("held-out v2 has not had its blind run yet")
    fl = json.loads(ev.FIRST_LOOK_V2.read_text())
    c = fl["conditions"]
    assert c["judge_provider"].startswith("offline") and not c["environment_overrides"]
    rc, out = ev._git_rc("ls-files", "--error-unmatch", "eval/heldout_v2_first_look.json")
    assert rc == 0, "commit the frozen v2 run immediately"


# ---------------------------------------------------------------------------------------------- C9 isolation test
def test_no_heldout_text_reaches_training_or_calibration():
    """Added because HARDENING_PLAN claimed this test existed (round 4, C9). Compares texts only; prints nothing."""
    sys.path.insert(0, str(ROOT))
    from eval.calibrate import calibration_rows
    from stayguard.classifier import hotel_training_rows, sms_splits

    held = set()
    # the original model's training and calibration never see any held-out set; the context models' rows are checked
    # in tests/test_pipeline_v3.py (they train on retired v1 and calibrate on retired v2, DECISIONS #39/#41)
    for name in ("heldout_eval.jsonl", "heldout_v2.jsonl", "heldout_v3.jsonl"):
        for line in (ROOT / "data" / "curated" / name).read_text().splitlines():
            if line.strip():
                held.add(json.loads(line)["text"].strip().lower())
    train = {str(t).strip().lower() for t in sms_splits()[0].text} | {str(t).strip().lower() for t in hotel_training_rows().text}
    cal = {str(t).strip().lower() for t in calibration_rows().text}
    assert not (held & train) and not (held & cal)


def test_wallet_names_are_not_an_instruction_to_pay(engine):
    """Found on held-out v1 after the round-4 fixes (v1 is not blind; recorded in docs/ADVERSARIAL_REVIEW.md)."""
    d = run(engine, "Please note we are a cash-free hotel; you can pay at check-in by card or Apple Pay.")
    assert not extract("you can pay at check-in by card or Apple Pay").reassured_sensitive and d.decision != "hold"


# ---------------------------------------------------------------------------------------------- B (reduced scope)
@pytest.mark.parametrize("text", [("a" + ".a" * 2499)[:5000], ("a-" * 2500)[:5000]])
def test_long_word_runs_do_not_backtrack_quadratically(engine, text):
    from stayguard.signals import EMAIL_RX

    t0 = time.perf_counter()
    EMAIL_RX.search(text)
    assert time.perf_counter() - t0 < 0.02  # ~0.1 s per pattern before the bound
    t0 = time.perf_counter()
    run(engine, text)
    assert time.perf_counter() - t0 < 0.3


def test_phone_handoff_with_other_separators_is_still_judged(engine):
    t = "For an early check-in please ring our reception on 21·12·34·56·78 any time before 3pm."
    assert extract(t).phone_handoff
    assert run(engine, t).path in ("judges", "degraded")
