"""The pipeline changes measured on held-out v3 (DECISIONS #38-#43): engine options, the platform-flow warning,
routing model-only holds to the judges, the context models, the encoder adapter, shadow mode and the feedback queue,
network link checks, and the v3 runner itself (on substitute data: v3 is never read by tests except its hash)."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from stayguard import config
from stayguard.engine import Engine, EngineOptions
from stayguard.judges import JudgeOpinion, JudgeReplyUnusable, JudgeUnavailable, Ruling
from stayguard.signals import extract

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_ENCODER = ROOT / "tests" / "fixtures" / "encoder"
PAP = {"payment_terms": "pay_at_property", "direction": "hotel_to_guest"}
PREPAID = {"payment_terms": "prepaid", "direction": "hotel_to_guest"}
RISKY = {"risk": 0.8, "level": "risky", "reasons": []}

# Genuine pay-at-property messages of the kind held-out v2 held by mistake (v2 is retired; these are rewritten).
PLATFORM_LEGIT = [
    "Dear guest, the credit card on your reservation was declined. Booking.com will send you a request to update your "
    "card details. Please do this in your Booking.com account or app. Please do not send card details in this chat.",
    "Please note that at check-in we take a pre-authorisation of EUR 100 on your credit card as a security deposit.",
    "Hi! The card you gave is only a guarantee. We will not charge it before you arrive; payment is taken at reception.",
    "We noticed we charged the city tax twice at check-out, so we have refunded EUR 12.60 to your card today.",
]
# Scam shapes that must never be platform-routed.
PLATFORM_SCAMS = [
    "Booking.com requires a deposit of 200 EUR. Reply here with your card number and CVV to keep the room.",
    "Please update your card in the app within 24 hours: https://booking-verify-22.com/app",
    "Pay the 120 EUR deposit by bank transfer to IBAN PT50 0002 0123 1234 5678 9015 4, details in your Booking.com account.",
    "Your card was declined. Contact us on WhatsApp +351 912 000 111 to pay the deposit before arrival.",
    "Please send your card details so we can pre-authorise the booking.",
    "We will not charge you at check-in; pay 80 EUR before arrival to confirm your booking.",
    "Kindly settle the 150 EUR security deposit in your booking today or it will be cancelled.",
    "To confirm, pay 80 EUR before arrival. Nothing is charged at check-in.",
]


class FixedClf:
    version = "fixed-test"

    def __init__(self, p: float) -> None:
        self.p = p

    def score(self, text, ctx=None):
        return self.p

    def top_terms(self, text, k=5):
        return []


class Judge:
    name = "stub"

    def __init__(self, p=None, exc=None):
        self.p, self.exc, self.calls = p, exc, 0

    def rule(self, masked, sig, ctx, model_p, link_worst):
        self.calls += 1
        if self.exc:
            raise self.exc
        return Ruling(
            self.p, JudgeOpinion("prosecutor", "scam", 0.5, []), JudgeOpinion("defender", "legit", 0.9, []), "stub", 0.0
        )


def make(engine, p_model=None, judge=None, **opts):
    clf = FixedClf(p_model) if p_model is not None else engine.clf
    return Engine(link_checker=engine.links, judge=judge or Judge(0.1), options=EngineOptions(**opts), clf=clf)


# ------------------------------------------------------------------------------------------------ engine options
def test_options_default_to_todays_system(engine):
    o = EngineOptions()
    assert (o.classifier, o.model_low, o.model_high) == ("tfidf", config.MODEL_LOW, config.MODEL_HIGH)
    assert not o.route_model_high_to_judges and not o.platform_flow_warn
    assert engine.versions["options"] == f"low={config.MODEL_LOW:g},high={config.MODEL_HIGH:g}"


def test_crossed_thresholds_are_refused(engine):
    with pytest.raises(ValueError, match="model_low"):
        make(engine, model_low=0.6, model_high=0.5)


def test_thresholds_are_per_engine(engine):
    text = "Please let us know if you want breakfast, it is 12 EUR."
    strict = make(engine, p_model=0.6, model_low=0.03, model_high=0.52)
    loose = make(engine, p_model=0.6, model_low=0.03, model_high=0.75)
    assert strict.check(text, PREPAID, record=False).reasons == ["MODEL_HIGH_RISK"]
    assert loose.check(text, PREPAID, record=False).path == "judges"


def test_decision_carries_its_engine_versions(engine):
    e = make(engine, platform_flow_warn=True)
    d = e.check("Breakfast is from 7.", PAP, record=False)
    assert d.as_dict()["versions"]["options"].endswith("platform_flow")


def test_unknown_classifier_is_a_config_error(monkeypatch):
    from stayguard.config import ConfigError, load_settings

    monkeypatch.setenv("STAYGUARD_CLASSIFIER", "bert")
    with pytest.raises(ConfigError, match="CLASSIFIER"):
        load_settings()


def test_each_classifier_has_its_own_calibration_file():
    assert config.calibration_path("tfidf").name == "calibration.json"
    assert config.calibration_path("tfidf_ctx").name == "calibration_tfidf_ctx.json"
    assert config.calibration_for("no_such_kind") == {}


# ------------------------------------------------------------------------------------------------ platform flow
@pytest.mark.parametrize("text", PLATFORM_LEGIT)
def test_platform_routed_money_mentions_are_recognised(text):
    assert extract(text).platform_flow_only


@pytest.mark.parametrize("text", PLATFORM_SCAMS)
def test_scam_shapes_are_never_platform_warned(engine, text):
    e = make(engine, platform_flow_warn=True)
    d = e.check(text, PAP, record=False)
    assert d.decision in ("hold", "block") and "PLATFORM_FLOW_MONEY_MENTION" not in d.reasons


@pytest.mark.parametrize("text", PLATFORM_LEGIT)
def test_platform_flow_warns_instead_of_holding_only_when_switched_on(engine, text):
    off = make(engine, p_model=0.3, platform_flow_warn=False).check(text, PAP, record=False)
    on = make(engine, p_model=0.3, judge=Judge(0.1), platform_flow_warn=True).check(text, PAP, record=False)
    if off.decision == "hold":  # the refund note is already delivered today; the others were held
        assert on.decision == "warn" and "PLATFORM_FLOW_MONEY_MENTION" in on.reasons and on.guest_banner
    else:
        assert on.decision == off.decision


def test_platform_flow_warning_is_a_floor_the_model_and_judges_can_raise(engine):
    text = PLATFORM_LEGIT[0]
    assert make(engine, p_model=0.99, platform_flow_warn=True).check(text, PAP, record=False).decision == "hold"
    assert make(engine, p_model=0.3, judge=Judge(0.9), platform_flow_warn=True).check(text, PAP, record=False).decision == "hold"


def test_platform_flow_on_a_risky_session_is_held(engine):
    d = make(engine, p_model=0.3, platform_flow_warn=True).check(PLATFORM_LEGIT[1], {**PAP, "session": RISKY}, record=False)
    assert d.decision == "hold" and "RISKY_SESSION" in d.reasons


def test_platform_flow_needs_every_money_sentence_routed():
    t = "You can update your card in the app. Also please pay the 50 EUR deposit before arrival to confirm."
    assert not extract(t).platform_flow_only


# ------------------------------------------------------------------------------------------------ routing
def test_model_only_hold_goes_to_judges_when_routed(engine):
    text = "Please let us know if you want breakfast, it is 12 EUR."
    j = Judge(0.1)
    d = make(engine, p_model=0.99, judge=j, route_model_high_to_judges=True).check(text, PREPAID, record=False)
    assert j.calls == 1 and d.decision == "deliver" and d.path == "judges"


def test_routed_model_hold_is_still_held_when_judges_are_down(engine):
    text = "Please let us know if you want breakfast, it is 12 EUR."
    e = make(engine, p_model=0.99, judge=Judge(exc=JudgeUnavailable("down")), route_model_high_to_judges=True)
    d = e.check(text, PREPAID, record=False)
    assert d.decision == "hold" and d.reasons == ["MODEL_HIGH_RISK"] and d.path == "degraded"


def test_routed_model_hold_with_unusable_reply_is_held(engine):
    text = "Please let us know if you want breakfast, it is 12 EUR."
    e = make(engine, p_model=0.99, judge=Judge(exc=JudgeReplyUnusable("x")), route_model_high_to_judges=True)
    assert e.check(text, PREPAID, record=False).decision == "hold"


def test_routing_never_reaches_rule_holds(engine):
    j = Judge(0.0)
    d = make(engine, p_model=0.99, judge=j, route_model_high_to_judges=True).check(
        "Please send 300 EUR by bank transfer", PREPAID, record=False
    )
    assert d.decision == "hold" and j.calls == 0


def test_without_routing_a_model_high_is_held_without_judges(engine):
    j = Judge(0.0)
    d = make(engine, p_model=0.99, judge=j).check(
        "Please let us know if you want breakfast, it is 12 EUR.", PREPAID, record=False
    )
    assert d.reasons == ["MODEL_HIGH_RISK"] and j.calls == 0


# ------------------------------------------------------------------------------------------------ context models
def test_context_features_read_the_booking_not_guess_it():
    from stayguard.ctx_classifier import CTX_FEATURES, ctx_vector

    v = dict(zip(CTX_FEATURES, ctx_vector("Call us on +351 912 000 111", {"payment_terms": "deposit"}), strict=True))
    assert v["terms_deposit"] == 1 and v["has_phone"] == 1 and v["first_in_thread"] == 0 and v["follow_up"] == 0
    v = dict(zip(CTX_FEATURES, ctx_vector("hi", {"first_in_thread": False, "direction": "guest_to_hotel"}), strict=True))
    assert v["terms_unknown"] == 1 and v["follow_up"] == 1 and v["guest_to_hotel"] == 1


def test_rule_signals_are_not_model_features():
    """DECISIONS #39: the model double-counting the rules' signals added false holds."""
    from stayguard.ctx_classifier import CTX_FEATURES

    assert not {"money_ask", "card_data", "off_platform_payment", "off_platform_contact"} & set(CTX_FEATURES)


@pytest.fixture(scope="module")
def tfidf_ctx():
    from stayguard.ctx_classifier import load

    return load("tfidf_ctx")


def test_tfidf_ctx_trains_and_scores(tfidf_ctx):
    p = tfidf_ctx.score("URGENT: verify your card within 24h at http://x-pay.top or the booking is cancelled", PAP)
    q = tfidf_ctx.score("Breakfast is served from 7 to 10 in the garden.", PAP)
    assert 0 <= q < p <= 1 and tfidf_ctx.report["C"] in (0.25, 1.0, 4.0, 16.0, 64.0)
    assert tfidf_ctx.top_terms("URGENT verify your card now") and "cv_log_loss" in tfidf_ctx.report


def test_context_model_file_from_another_version_is_refused(tfidf_ctx):
    from stayguard.ctx_classifier import ContextClassifier

    with pytest.raises(RuntimeError, match="retrain"):
        ContextClassifier.from_state({**tfidf_ctx.state(), "version": "tfidf-ctx-0"})


def test_engine_can_run_the_context_model(engine, tfidf_ctx):
    e = Engine(
        link_checker=engine.links, options=EngineOptions(classifier="tfidf_ctx", model_low=0.05, model_high=0.85), clf=tfidf_ctx
    )
    d = e.check("Please pay the 200 EUR deposit by bank transfer today", PAP, record=False)
    assert d.decision == "hold" and e.versions["classifier"] == "tfidf-ctx-1"


def _texts(rows):
    return {" ".join(str(t).lower().split()) for t in rows}


def _jsonl_texts(name):
    return _texts(json.loads(x)["text"] for x in (ROOT / "data" / "curated" / name).read_text().splitlines() if x.strip())


def test_v3_never_reaches_any_training_or_calibration_rows():
    sys.path.insert(0, str(ROOT))
    from eval.calibrate import calibration_rows, context_calibration_rows
    from stayguard.ctx_classifier import training_rows

    v3 = _jsonl_texts("heldout_v3.jsonl")
    train = _texts(training_rows().text)
    assert not v3 & train
    assert not v3 & _texts(context_calibration_rows().text) and not v3 & _texts(calibration_rows().text)
    # calibration sets are never trained on
    assert not _jsonl_texts("golden_eval.jsonl") & train and not _jsonl_texts("heldout_v2.jsonl") & train


def test_v3_file_is_the_frozen_one():
    import hashlib

    sys.path.insert(0, str(ROOT))
    from eval.evaluate_v3 import V3_SHA256

    assert hashlib.sha256((ROOT / "data" / "curated" / "heldout_v3.jsonl").read_bytes()).hexdigest() == V3_SHA256


# ------------------------------------------------------------------------------------------------ encoder
def test_missing_encoder_fails_at_start_up_not_per_message(tmp_path, monkeypatch):
    from stayguard import ctx_classifier
    from stayguard.encoder import EncoderUnavailable

    monkeypatch.setattr(config, "ENCODER_DIR", tmp_path)
    with pytest.raises(EncoderUnavailable, match="fetch_encoder"):
        ctx_classifier.make_classifier("encoder_ctx")


def test_encoder_files_must_match_the_manifest(tmp_path):
    import shutil

    from stayguard.encoder import Encoder, EncoderUnavailable

    shutil.copytree(FIXTURE_ENCODER, tmp_path / "enc")
    (tmp_path / "enc" / "tokenizer.json").write_text("{}")
    with pytest.raises(EncoderUnavailable, match="does not match"):
        Encoder(tmp_path / "enc")


needs_ort = pytest.mark.skipif(
    not all(__import__("importlib.util").util.find_spec(m) for m in ("onnxruntime", "tokenizers")),
    reason="encoder runtime not installed (requirements-encoder.lock)",
)


@needs_ort
def test_encoder_embeds_normalised_vectors_and_padding_does_not_leak():
    import numpy as np

    from stayguard.encoder import Encoder

    enc = Encoder(FIXTURE_ENCODER)
    alone = enc.embed(["pay now"])
    padded = enc.embed(["pay now", "please pay the deposit now your card check-in is from 3 pm"])
    assert np.allclose(np.linalg.norm(padded, axis=1), 1.0, atol=1e-5)
    assert np.allclose(alone[0], padded[0], atol=1e-5)  # pad rows hold 100.0 in the fixture: they must be masked out
    assert enc.embed([]).shape[0] == 0 and enc.version == "test/tiny-encoder@fixture"


@needs_ort
def test_encoder_ctx_trains_and_runs_in_the_engine(engine):
    from stayguard.ctx_classifier import ContextClassifier, training_rows
    from stayguard.encoder import Encoder

    rows = training_rows().sample(600, random_state=1)
    m = ContextClassifier("encoder_ctx", encoder=Encoder(FIXTURE_ENCODER)).fit(rows)
    e = Engine(link_checker=engine.links, options=EngineOptions(classifier="encoder_ctx", model_low=0.05, model_high=0.85), clf=m)
    d = e.check("Breakfast is from 7.", PAP, record=False)
    assert 0.0 <= d.model_p <= 1.0 and m.top_terms("anything") == [] and m.report["encoder"] == "test/tiny-encoder@fixture"


# ------------------------------------------------------------------------------------------------ shadow + feedback
def test_decisions_are_enforced_by_default(service):
    out = service.check_message(text="Breakfast is from 7.", payment_terms="prepaid")
    assert out["enforced"] is True


def test_shadow_mode_returns_the_same_decision_unenforced(service, monkeypatch):
    t = "Please send 300 EUR by bank transfer to confirm."
    enforced = service.check_message(text=t, payment_terms="pay_at_property")
    monkeypatch.setattr(config, "ENFORCE", False)
    shadow = service.check_message(text=t, payment_terms="pay_at_property")
    assert shadow["enforced"] is False and shadow["decision"] == enforced["decision"] == "hold"


def test_fail_closed_is_enforced_even_in_shadow_mode(monkeypatch):
    from stayguard.service import fail_closed_response

    monkeypatch.setattr(config, "ENFORCE", False)
    assert fail_closed_response("m", "Boom")["enforced"] is True


def test_first_in_thread_is_worked_out_from_stored_messages(service):
    from stayguard import db

    rid = db.con().execute("SELECT id FROM reservations LIMIT 1").fetchone()[0]
    first = service.check_message(text="Welcome! Check-in is from 3 pm.", reservation_id=rid)
    second = service.check_message(text="Parking is free.", reservation_id=rid)
    assert second["first_in_thread"] is False and first["first_in_thread"] in (True, False)
    assert service.check_message(text="Hi", reservation_id=rid, first_in_thread=True)["first_in_thread"] is True


def test_labels_feed_the_queue_and_the_shadow_report(service, tmp_path):
    from stayguard import db, feedback

    scam = service.check_message(text="Please pay the 90 EUR deposit by bank transfer today.", payment_terms="pay_at_property")
    legit = service.check_message(text="Our pool is open from 9 to 6.", payment_terms="prepaid")
    split = service.check_message(text="Late check-out is 20 EUR, tell us if you want it.", payment_terms="prepaid")
    assert service.label_message(scam["message_id"], "scam", "guest")
    assert service.label_message(legit["message_id"], "legit", "hotel")
    service.label_message(split["message_id"], "scam", "guest")
    service.label_message(split["message_id"], "legit", "hotel")
    assert service.label_message("M-nope", "scam", "guest") is None
    with pytest.raises(ValueError):
        service.label_message(scam["message_id"], "maybe", "guest")
    out = tmp_path / "q.jsonl"
    res = feedback.export(out)
    ids = {json.loads(x)["id"] for x in out.read_text().splitlines()}
    assert scam["message_id"] in ids and legit["message_id"] in ids and split["message_id"] not in ids
    assert res["needs_review_conflicting_labels"] >= 1
    rep = feedback.report()
    assert rep["scams"] >= 1 and rep["legit"] >= 1 and "not a random sample" in rep["note"]
    # an analyst settles the disagreement
    service.label_message(split["message_id"], "legit", "analyst")
    feedback.export(out)
    assert split["message_id"] in {json.loads(x)["id"] for x in out.read_text().splitlines()}
    assert db.con().execute("SELECT COUNT(*) FROM audit WHERE kind='message.labelled'").fetchone()[0] >= 5


def test_feedback_never_exports_an_evaluation_message(service, tmp_path):
    from stayguard import feedback

    dev = json.loads((ROOT / "data" / "curated" / "golden_eval.jsonl").read_text().splitlines()[0])["text"]
    m = service.check_message(text=dev, payment_terms="prepaid")
    service.label_message(m["message_id"], "legit", "analyst")
    res = feedback.export(tmp_path / "q.jsonl")
    assert res["dropped_matching_evaluation_sets"] >= 1


def test_label_resolution_rules():
    from stayguard.feedback import resolve

    assert resolve([{"id": 1, "created": 1, "label": 1, "source": "guest"}]) == 1
    assert (
        resolve([{"id": 1, "created": 1, "label": 1, "source": "guest"}, {"id": 2, "created": 2, "label": 0, "source": "hotel"}])
        is None
    )
    assert (
        resolve(
            [
                {"id": 1, "created": 1, "label": 1, "source": "analyst"},
                {"id": 2, "created": 2, "label": 0, "source": "analyst"},
                {"id": 3, "created": 3, "label": 1, "source": "guest"},
            ]
        )
        == 0
    )


def test_feedback_cli(capsys):
    from stayguard import feedback

    assert feedback.main(["report"]) == 0 and "labelled" in capsys.readouterr().out
    assert feedback.main(["nonsense"]) == 2


def test_label_endpoint(client):
    h = {"X-API-Key": config.API_KEY} if config.API_KEY else {}
    m = client.post("/v1/messages/check", json={"text": "Breakfast is at 8.", "payment_terms": "prepaid"}, headers=h).json()
    assert m["enforced"] is True
    ok = client.post(f"/v1/messages/{m['message_id']}/label", json={"label": "legit", "source": "hotel"}, headers=h)
    assert ok.status_code == 200 and ok.json()["label"] == "legit"
    assert client.post("/v1/messages/M-missing/label", json={"label": "legit", "source": "hotel"}, headers=h).status_code == 404
    assert (
        client.post(f"/v1/messages/{m['message_id']}/label", json={"label": "x", "source": "hotel"}, headers=h).status_code == 422
    )


# ------------------------------------------------------------------------------------------------ network checks
def _net(handler, resolver=lambda h: ["93.184.216.34"], days=None):
    from stayguard.netcheck import NetChecker

    now = datetime(2026, 10, 29, tzinfo=UTC)
    return NetChecker(transport=httpx.MockTransport(handler), resolver=resolver, now=lambda: now, timeout=1.0)


def _rdap(days_ago):
    reg = (datetime(2026, 10, 29, tzinfo=UTC) - timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")
    return {"events": [{"eventAction": "registration", "eventDate": reg}]}


def _far():
    import time

    return time.monotonic() + 5


def test_redirects_are_followed_hop_by_hop_to_a_pinned_public_address():
    seen = []

    def handler(req):
        seen.append((str(req.url), req.headers["host"], req.extensions.get("sni_hostname")))
        if req.headers["host"] == "bit.ly":
            return httpx.Response(301, headers={"location": "https://fresh-guest-pay.com/x"})
        return httpx.Response(200)

    chain = _net(handler).follow("https://bit.ly/abc", _far())
    assert chain == ["https://bit.ly/abc", "https://fresh-guest-pay.com/x"]
    assert seen[0][0].startswith("https://93.184.216.34") and seen[0][1:] == ("bit.ly", "bit.ly")


@pytest.mark.parametrize("addr", ["10.0.0.5", "127.0.0.1", "169.254.169.254", "::1", "192.168.1.1", "::ffff:10.0.0.1"])
def test_private_addresses_are_never_contacted(addr):
    calls = []
    n = _net(lambda req: calls.append(req) or httpx.Response(200), resolver=lambda h: [addr])
    assert n.follow("https://bit.ly/x", _far()) == ["https://bit.ly/x"] and not calls


def test_a_redirect_into_the_private_network_stops_the_chain():
    def handler(req):
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data"})

    calls = []

    def resolver(h):
        calls.append(h)
        return ["93.184.216.34"]

    chain = _net(handler, resolver=resolver).follow("https://bit.ly/y", _far())
    assert chain[-1].startswith("http://169.254.169.254") and len(chain) == 2  # recorded, never requested


@pytest.mark.parametrize("url", ["https://bit.ly:8443/x", "ftp://bit.ly/x", "https://user:pw@bit.ly/x"])
def test_odd_ports_schemes_and_credentials_are_refused(url):
    calls = []
    assert _net(lambda r: calls.append(r) or httpx.Response(200)).follow(url, _far()) == [url] and not calls


def test_spent_budget_stops_network_checks():
    calls = []
    assert _net(lambda r: calls.append(r) or httpx.Response(301, headers={"location": "/b"})).follow("https://bit.ly/z", 0.0) == [
        "https://bit.ly/z"
    ]
    assert not calls


def test_domain_age_from_rdap_and_its_failures():
    def handler(req):
        path = req.url.path
        if path.endswith("new-domain.com"):
            return httpx.Response(200, json=_rdap(3))
        if path.endswith("old-domain.com"):
            return httpx.Response(200, json=_rdap(4000))
        if path.endswith("nobody.com"):
            return httpx.Response(404)
        return httpx.Response(500)

    n = _net(handler)
    assert n.domain_age("new-domain.com", _far()).days == pytest.approx(3, abs=0.01)
    assert n.domain_age("old-domain.com", _far()).status == "registered"
    assert n.domain_age("nobody.com", _far()).status == "unregistered"
    assert n.domain_age("broken.com", _far()).status == "unknown"


def test_link_checker_with_network_only_makes_links_worse():
    from stayguard.links import LinkChecker

    def handler(req):
        host, path = req.headers["host"], req.url.path
        if host == "bit.ly":
            return httpx.Response(301, headers={"location": "https://fresh-guest-pay.com/pay"})
        if path.endswith("fresh-guest-pay.com"):
            return httpx.Response(200, json=_rdap(2))
        if path.endswith("calm-old-site.com"):
            return httpx.Response(200, json=_rdap(5000))
        return httpx.Response(500)

    lc = LinkChecker(use_blocklist=False, net=_net(handler))
    short = lc.check("https://bit.ly/q1", deadline=_far())
    assert "REDIRECTS_TO:fresh-guest-pay.com" in short.reasons and any(r.startswith("NEWLY_REGISTERED") for r in short.reasons)
    assert short.verdict == "suspicious"
    old = lc.check("https://calm-old-site.com/menu", deadline=_far())
    offline = LinkChecker(use_blocklist=False).check("https://calm-old-site.com/menu")
    assert old.score == offline.score and old.verdict == offline.verdict
    broken = lc.check("https://unreachable-registry.org/x", deadline=_far())
    assert (
        "NETCHECK_UNAVAILABLE" in broken.reasons
        and broken.score >= LinkChecker(use_blocklist=False).check("https://unreachable-registry.org/x").score
    )


def test_official_links_never_touch_the_network():
    from stayguard.links import LinkChecker

    calls = []
    lc = LinkChecker(net=_net(lambda r: calls.append(r) or httpx.Response(500)))
    assert lc.check("https://www.booking.com/mybooking", deadline=_far()).verdict == "official" and not calls


def test_rdap_answers_are_cached():
    calls = []

    def handler(req):
        calls.append(1)
        return httpx.Response(200, json=_rdap(10))

    n = _net(handler)
    n.domain_age("cached-domain.com", _far())
    n.domain_age("cached-domain.com", _far())
    assert len(calls) == 1


# ------------------------------------------------------------------------------------------------ the v3 runner
def test_holm_adjustment():
    sys.path.insert(0, str(ROOT))
    from eval.evaluate_v3 import holm

    assert holm({"a": 0.01, "b": 0.04}) == {"a": 0.02, "b": 0.04}
    assert holm({"a": 0.03, "b": 0.02}) == {"b": 0.04, "a": 0.04}


def test_blind_v3_run_is_refused_on_a_dirty_tree_or_with_settings(monkeypatch):
    sys.path.insert(0, str(ROOT))
    import eval.evaluate_v3 as ev3

    monkeypatch.setattr(ev3, "_git_rc", lambda *a: (0, str(ROOT)) if a[0] == "rev-parse" else (0, " M x"))
    with pytest.raises(SystemExit, match="not clean"):
        ev3.gate(None)
    monkeypatch.setattr(ev3, "_git_rc", lambda *a: (0, str(ROOT)) if a[0] == "rev-parse" else (0, ""))
    monkeypatch.setenv("STAYGUARD_PLATFORM_FLOW_WARN", "1")
    with pytest.raises(SystemExit, match="STAYGUARD_"):
        ev3.gate(None)


def test_v3_runner_end_to_end_on_substitute_rows(monkeypatch, tmp_path, tfidf_ctx):
    """Runs the whole v3 runner on the dev set standing in for v3 (v3 itself is never read by tests)."""
    if not all(__import__("importlib.util").util.find_spec(m) for m in ("onnxruntime", "tokenizers")):
        pytest.skip("encoder runtime not installed")
    sys.path.insert(0, str(ROOT))
    import eval.evaluate_v3 as ev3

    dev = [json.loads(x) for x in (ROOT / "data" / "curated" / "golden_eval.jsonl").read_text().splitlines() if x.strip()][:40]
    for i, r in enumerate(dev):
        r["first_in_thread"] = i % 2 == 0
    monkeypatch.setattr(ev3, "load_rows", lambda name: dev)
    monkeypatch.setattr(ev3, "FIRST_LOOK_V3", tmp_path / "first.json")
    monkeypatch.setattr(ev3, "RERUN_V3", tmp_path / "rerun.json")
    monkeypatch.setattr(ev3, "gate", lambda add_arm: None)
    monkeypatch.setattr(config, "ENCODER_DIR", FIXTURE_ENCODER)
    real_cal = config.calibration_for
    monkeypatch.setattr(
        config,
        "calibration_for",
        lambda kind: {"model_low": 0.05, "model_high": 0.85} if kind == "encoder_ctx" else real_cal(kind),
    )
    r = ev3.main([])
    assert (tmp_path / "first.json").exists() and r["n"] == 40
    assert {"baseline_today", "candidate", "candidate_judges_down", "encoder_classifier_only"} <= set(r["systems"])
    prim = r["paired_tests"]["candidate_vs_baseline_today"]
    assert "p_value_holm" in prim["scams_caught"] and "p_value_holm" in prim["legit_held"]
    with pytest.raises(SystemExit, match="already had its blind run"):
        ev3.main([])
    ev3.main(["--rerun-not-blind"])
    assert (tmp_path / "rerun.json").exists()
    assert r["run_conditions"]["real_judges"] is None


def test_v3_runner_with_a_gemini_key_keeps_every_other_arm_offline(monkeypatch, tmp_path, tfidf_ctx):
    """Regression: with a key in the environment, Engine() picked the real judge for EVERY arm, today's system
    included, so the pre-registered comparison would silently have changed. Found while adding Gemini (DECISIONS #44)."""
    if not all(__import__("importlib.util").util.find_spec(m) for m in ("onnxruntime", "tokenizers")):
        pytest.skip("encoder runtime not installed")
    sys.path.insert(0, str(ROOT))
    import eval.evaluate_v3 as ev3

    dev = [json.loads(x) for x in (ROOT / "data" / "curated" / "golden_eval.jsonl").read_text().splitlines() if x.strip()][:12]
    monkeypatch.setattr(ev3, "load_rows", lambda name: dev)
    monkeypatch.setattr(ev3, "FIRST_LOOK_V3", tmp_path / "first.json")
    monkeypatch.setattr(ev3, "gate", lambda add_arm: None)
    monkeypatch.setattr(config, "ENCODER_DIR", FIXTURE_ENCODER)
    monkeypatch.setattr(config, "JUDGE_PROVIDER", "gemini")
    monkeypatch.setattr(config, "GEMINI_API_KEY", "g")
    real_cal = config.calibration_for
    monkeypatch.setattr(
        config,
        "calibration_for",
        lambda kind: {"model_low": 0.05, "model_high": 0.85} if kind == "encoder_ctx" else real_cal(kind),
    )
    calls = []

    def fake_post(url, timeout, headers, json):  # noqa: A002 - mirrors httpx.post's keyword
        calls.append(url)
        body = {"verdict": "legit", "confidence": 0.6, "evidence": [], "rationale": "r"}
        return httpx.Response(
            200,
            json={"candidates": [{"content": {"parts": [{"text": __import__("json").dumps(body)}]}}]},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    r = ev3.main(["--judge-rpm", "600000"])
    assert r["run_conditions"]["judge_provider"] == "offline-deterministic"
    assert r["run_conditions"]["real_judges"].startswith("gemini:") and "candidate_real_judges" in r["systems"]
    judged = r["systems"]["candidate_real_judges"]["paths"].get("judges", 0)
    assert len(calls) == 2 * judged  # only the real-judge arm called Gemini: two judges per judged message
