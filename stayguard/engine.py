"""The decision router: guardrails -> fast rules -> small model -> judges -> session escalation.

Cheap, explainable checks run first; the expensive judges only see what the rules and the model could not
settle. Every decision carries reason codes, quoted evidence, the path that decided it, and a stage trace.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field

from . import config
from .classifier import ScamClassifier
from .judges import CircuitBreaker, JudgeUnavailable, OfflineJudge, make_judge
from .links import LinkChecker
from .signals import detect_language, extract, mask_pii

log = logging.getLogger("stayguard.engine")
RANK = {"deliver": 0, "warn": 1, "hold": 2, "block": 3}
VERSIONS = {"engine": "1.0.0", "rules": "2026-10-27", "classifier": ScamClassifier.version, "links": "feeds+heuristics-1"}

BANNERS = {
    "en": "Safety check: this message mentions payment. Booking.com never asks you to share card details or pay "
          "through a link in chat. Only pay inside the Booking.com app or at the property.",
    "hi": "सुरक्षा जांच: यह संदेश भुगतान के बारे में है। Booking.com कभी भी चैट में कार्ड की जानकारी या लिंक से "
          "भुगतान नहीं मांगता। केवल Booking.com ऐप में या होटल पर ही भुगतान करें।",
    "hinglish": "Safety check: is message me payment ki baat hai. Booking.com kabhi chat me card details ya link se "
                "payment nahi maangta. Sirf Booking.com app me ya hotel pe hi pay karein.",
}

REASON_TEXT = {
    "NO_PAYMENT_ASK": "No payment request and no risky links.",
    "PAY_ASK_ON_PAY_AT_HOTEL": "Asks for payment, but this booking is paid at the property - nothing is due before arrival.",
    "CARD_DATA_REQUEST": "Asks for card or bank details in chat. Real hotels never need this.",
    "OFF_PLATFORM_PAYMENT": "Asks for payment by transfer, UPI, gift card, crypto or wire - outside the platform.",
    "OFF_PLATFORM_CONTACT": "Moves payment to WhatsApp, Telegram, phone or another website.",
    "KNOWN_PHISHING_LINK": "Link is on a live phishing blocklist.",
    "LOOKALIKE_DOMAIN": "Link imitates a booking brand on a domain the brand does not own.",
    "UNVERIFIED_LINK": "Contains a link we cannot verify (shortener or unknown site).",
    "PROMPT_INJECTION_ATTEMPT": "Contains instructions aimed at the AI reviewer. Real hotels don't write this.",
    "OBFUSCATED_TEXT": "Uses hidden characters or look-alike letters to dodge filters.",
    "OVERPAYMENT_REFUND_REQUEST": "Claims an overpayment and asks for money back outside the platform.",
    "MODEL_LOW_RISK": "Language model sees normal hotel language.",
    "MODEL_HIGH_RISK": "Language model sees strong scam language.",
    "JUDGES_SCAM": "AI judges agree on scam, with quoted evidence.",
    "JUDGES_UNSURE": "AI judges are split - delivered with a warning.",
    "JUDGES_LEGIT": "AI judges agree it is a normal message.",
    "DEGRADED_WARN": "AI review unavailable - delivered with a warning (normal session).",
    "DEGRADED_RISKY_SESSION": "AI review unavailable and the sender's session is risky - held.",
    "RISKY_SESSION": "Sender's login looks unusual, so the decision was made one step stricter.",
    "SYSTEM_EXCEPTION_FAIL_CLOSED": "StayGuard hit an internal error, so the message is held for review rather than delivered.",
    "SESSION_TAKEOVER_SUSPECTED": "Sender's login looks taken over. Nothing goes out until the hotel re-confirms with a passkey.",
}


@dataclass
class Decision:
    decision: str
    confidence: float
    reasons: list[str]
    path: str
    evidence: list[dict]
    links: list[dict]
    model_p: float | None
    session: dict | None
    judges: dict | None
    language: str
    pii_masked: list[str]
    masked_text: str
    guest_banner: str | None
    suggest_containment: bool
    trace: list[dict] = field(default_factory=list)
    latency_ms: float = 0.0
    llm_called: bool = False

    def as_dict(self) -> dict:
        return {"decision": self.decision, "confidence": round(self.confidence, 3), "reasons": self.reasons,
                "explanations": [REASON_TEXT.get(r, r) for r in self.reasons], "path": self.path,
                "evidence": self.evidence, "links": self.links,
                "model_p": None if self.model_p is None else round(self.model_p, 4), "session": self.session,
                "judges": self.judges, "language": self.language, "pii_masked": self.pii_masked,
                "masked_text": self.masked_text, "guest_banner": self.guest_banner,
                "suggest_containment": self.suggest_containment, "trace": self.trace,
                "latency_ms": round(self.latency_ms, 2), "llm_called": self.llm_called, "versions": VERSIONS}


def judge_cost_estimate_usd(message: str = "x" * 200) -> float:
    """ESTIMATED cost of judging one message with two LLM judges at the configured price (see config.py)."""
    from .judges import BRIEFS, SYSTEM
    total = 0.0
    for role, brief in BRIEFS.items():
        prompt_chars = len(SYSTEM.format(role=role, brief=brief)) + len(message) + 200  # 200 = context + tags
        total += (prompt_chars / 4) * config.LLM_PRICE_IN_PER_MTOK / 1e6
        total += config.JUDGE_OUTPUT_TOKENS * config.LLM_PRICE_OUT_PER_MTOK / 1e6
    return total


def _touches_money_or_links(asks_for_money: bool, links: list, worst_link_score: float) -> bool:
    """True when the message asks for money/card data, or carries any link that is not official (score > 0)."""
    has_unofficial_link = bool(links) and worst_link_score > 0.0
    return asks_for_money or has_unofficial_link


class Metrics:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        self.total = 0
        self.by_decision = {k: 0 for k in RANK}
        self.by_path: dict[str, int] = {}
        self.latencies: list[float] = []
        self.llm_calls = 0
        self.judge_failures = 0
        self.fail_closed = 0

    def judge_failed(self) -> None:
        with self.lock:
            self.judge_failures += 1

    def record(self, d: Decision) -> None:
        with self.lock:
            self.total += 1
            self.by_decision[d.decision] += 1
            self.by_path[d.path] = self.by_path.get(d.path, 0) + 1
            self.latencies.append(d.latency_ms)
            self.latencies = self.latencies[-5000:]
            self.llm_calls += int(d.llm_called)
            self.fail_closed += int(d.path == "fail_closed")

    def snapshot(self, judge_provider: str) -> dict:
        with self.lock:
            lat = sorted(self.latencies)
            pct = lambda q: round(lat[min(len(lat) - 1, int(q * len(lat)))], 2) if lat else 0.0  # noqa: E731
            share = self.llm_calls / self.total if self.total else 0.0
            return {"total": self.total, "by_decision": dict(self.by_decision), "by_path": dict(self.by_path),
                    "p50_ms": pct(0.5), "p95_ms": pct(0.95), "judge_share": round(share, 4),
                    "judge_failures": self.judge_failures, "fail_closed": self.fail_closed, "judge_provider": judge_provider,
                    "est_cost_per_1000_usd": round(share * judge_cost_estimate_usd() * 1000, 4),
                    "est_cost_per_1000_if_all_llm_usd": round(judge_cost_estimate_usd() * 1000, 4)}


class Engine:
    def __init__(self, link_checker: LinkChecker | None = None, judge=None) -> None:
        self.clf = ScamClassifier()
        self.links = link_checker or LinkChecker()
        self.judge = judge or make_judge()
        self.breaker = CircuitBreaker()
        self.metrics = Metrics()

    # ------------------------------------------------------------------------------------------
    def check(self, text: str, ctx: dict | None = None, record: bool = True) -> Decision:
        """Decide on one message. Never raises: any internal error holds the message (fail closed)."""
        t0 = time.perf_counter()
        partial: dict = {"trace": [], "evidence": []}
        try:
            d = self._check(text, dict(ctx or {}), t0, partial)
        except Exception as exc:  # noqa: BLE001 - an unexpected error must hold the message, never deliver it
            log.exception("engine failed closed: %s", type(exc).__name__)
            partial["trace"].append({"stage": "error", "ms": 0.0, "error": type(exc).__name__})
            d = Decision("hold", 1.0, ["SYSTEM_EXCEPTION_FAIL_CLOSED"], "fail_closed", partial["evidence"],
                         partial.get("links", []), partial.get("model_p"), (ctx or {}).get("session"), None,
                         partial.get("lang", "en"), partial.get("pii", []), partial.get("masked", ""), None, False,
                         partial["trace"], (time.perf_counter() - t0) * 1000, False)
        if record:
            self.metrics.record(d)
        return d

    def _check(self, text: str, ctx: dict, t0: float, partial: dict) -> Decision:
        trace: list[dict] = partial["trace"]

        def stage(name: str, start: float, **out) -> None:
            trace.append({"stage": name, "ms": round((time.perf_counter() - start) * 1000, 3), **out})

        terms = ctx.get("payment_terms", "unknown")
        direction = ctx.get("direction", "hotel_to_guest")
        session = ctx.get("session") or {"risk": 0.0, "level": "normal", "reasons": []}
        ctx["session_level"] = session.get("level")

        # 1. guardrails --------------------------------------------------------------------
        s = time.perf_counter()
        masked, pii = mask_pii(text)
        partial.update(masked=masked, pii=pii)
        sig = extract(text)
        lang = detect_language(text)
        partial["lang"] = lang
        stage("guardrails", s, pii_masked=pii, injection=sig.injection, hidden_chars=sig.hidden_chars)

        # 2. links -------------------------------------------------------------------------
        s = time.perf_counter()
        lv = [self.links.check(u, set(ctx.get("property_domains", []))) for u in sig.urls]
        worst = max((v.score for v in lv), default=0.0)
        stage("links", s, checked=len(lv), worst=round(worst, 3))

        partial["links"] = [v.as_dict() for v in lv]
        decision, reasons, path = "deliver", [], "rule"
        evidence: list[dict] = partial["evidence"]

        def ev(kind: str, quotes: list[str]) -> None:
            for q in quotes[:3]:
                evidence.append({"kind": kind, "quote": q})

        def escalate(to: str, reason: str) -> None:
            nonlocal decision
            if RANK[to] > RANK[decision]:
                decision = to
            if reason not in reasons:
                reasons.append(reason)

        # 3. fast rules --------------------------------------------------------------------
        s = time.perf_counter()
        if sig.injection:
            escalate("hold", "PROMPT_INJECTION_ATTEMPT"); ev("injection", sig.evidence.get("injection", []))
        if sig.hidden_chars or sig.mixed_script or sig.obfuscated:
            escalate("warn", "OBFUSCATED_TEXT")
            ev("obfuscation", sig.evidence.get("mixed_script", []) + sig.evidence.get("hidden_chars", []) + sig.evidence.get("deobfuscated", []))
        for v in lv:
            if "KNOWN_PHISHING_DOMAIN" in v.reasons:
                escalate("block", "KNOWN_PHISHING_LINK"); ev("link", [v.host])
            elif v.verdict == "malicious":
                escalate("block" if sig.money_ask else "hold", "LOOKALIKE_DOMAIN"); ev("link", [v.host])
            elif v.verdict == "suspicious":
                escalate("hold" if (sig.money_ask or sig.soft_money_ask or sig.verify_lure) else "warn", "UNVERIFIED_LINK"); ev("link", [v.host])
        if direction == "hotel_to_guest":
            if sig.money_ask and terms == "pay_at_property":
                escalate("hold", "PAY_ASK_ON_PAY_AT_HOTEL"); ev("money_ask", sig.evidence.get("money_ask", []))
            if sig.card_data:
                escalate("hold", "CARD_DATA_REQUEST"); ev("card_data", sig.evidence.get("card_data", []))
            if sig.off_platform_payment:
                escalate("hold", "OFF_PLATFORM_PAYMENT"); ev("off_platform", sig.evidence.get("off_platform_payment", []))
            if (sig.money_ask or sig.soft_money_ask) and sig.off_platform_contact:
                escalate("hold", "OFF_PLATFORM_CONTACT"); ev("off_platform", sig.evidence.get("off_platform_contact", []))
        else:
            if sig.overpayment and (sig.off_platform_payment or sig.money_ask or sig.soft_money_ask or sig.urgency):
                escalate("hold", "OVERPAYMENT_REFUND_REQUEST"); ev("overpayment", sig.evidence.get("overpayment", []))
        if sig.evidence.get("urgency") and evidence:
            ev("urgency", sig.evidence["urgency"])
        # "quiet" = nothing that a scam needs: no money, no card, no off-platform move, no pressure-plus-link.
        # Brand-free fresh domains score as 'safe', so a deadline or verification lure next to ANY non-official
        # link still goes to the model/judges instead of the fast path.
        unofficial_link = any(v.verdict != "official" for v in lv)
        quiet = not (sig.money_ask or sig.soft_money_ask or sig.card_data or sig.off_platform_payment or
                     sig.off_platform_contact or sig.impersonation or sig.overpayment or sig.injection or sig.obfuscated or
                     (sig.verify_lure and (sig.urgency or unofficial_link)) or (sig.urgency and unofficial_link)
                     ) and all(v.verdict in ("official", "safe") for v in lv)
        rule_decided = bool(reasons) and decision != "warn"
        stage("rules", s, decided=rule_decided, reasons=list(reasons))

        # 4. small model -------------------------------------------------------------------
        s = time.perf_counter()
        model_p = self.clf.score(text)
        partial["model_p"] = model_p
        stage("model", s, p=round(model_p, 4))

        judges_out, llm_called = None, False
        if not rule_decided:
            if quiet and not reasons:
                path = "rule"; reasons.append("NO_PAYMENT_ASK")
            elif model_p < config.MODEL_LOW and worst < 0.3:
                path = "model"; escalate("deliver", "MODEL_LOW_RISK")
            elif model_p > config.MODEL_HIGH:
                path = "model"; escalate("hold", "MODEL_HIGH_RISK")
                ev("model_terms", self.clf.top_terms(text))
            else:
                # 5. judges ----------------------------------------------------------------
                s = time.perf_counter()
                ruling = None
                if self.breaker.allow():
                    # Only provider problems (timeout, HTTP, unparseable reply) count as "judges unavailable" and
                    # feed the breaker. Anything else is a bug in our code: it propagates to check(), which holds
                    # the message, instead of quietly delivering it under the degraded policy.
                    try:
                        ruling = self.judge.rule(masked, sig, ctx, model_p, worst)
                        llm_called = not isinstance(self.judge, OfflineJudge)
                        self.breaker.record(True)
                    except JudgeUnavailable:
                        self.breaker.record(False)
                        self.metrics.judge_failed()
                if ruling:
                    path = "judges"
                    judges_out = ruling.as_dict()
                    if ruling.p_scam >= 0.65:
                        escalate("hold", "JUDGES_SCAM")
                    elif ruling.p_scam >= 0.4:
                        escalate("warn", "JUDGES_UNSURE")
                    else:
                        reasons.append("JUDGES_LEGIT")
                    for q in ruling.prosecutor.evidence[:3] if ruling.p_scam >= 0.4 else ruling.defender.evidence[:3]:
                        evidence.append({"kind": "judge_quote", "quote": q})
                    stage("judges", s, provider=ruling.provider, p_scam=round(ruling.p_scam, 3))
                else:
                    path = "degraded"
                    if session.get("risk", 0) >= config.SESSION_RISKY:
                        escalate("hold", "DEGRADED_RISKY_SESSION")
                    else:
                        escalate("warn", "DEGRADED_WARN")
                    stage("judges", s, provider="unavailable", breaker=self.breaker.state)

        # unverified links never go out silently
        if decision == "deliver" and worst >= 0.3:
            escalate("warn", "UNVERIFIED_LINK")

        # 6. session escalation ------------------------------------------------------------
        s = time.perf_counter()
        risk = float(session.get("risk", 0.0))
        touches_money = _touches_money_or_links(sig.money_ask or sig.soft_money_ask or sig.card_data, lv, worst)
        suggest = False
        if risk >= config.SESSION_CRITICAL:
            # a session that looks taken over gets nothing out until the hotel re-confirms with a passkey
            escalate("block" if (touches_money or decision != "deliver") else "hold", "SESSION_TAKEOVER_SUSPECTED")
            suggest = True
        elif risk >= config.SESSION_RISKY:
            # one step stricter: a warning becomes a hold; a clean delivery that involves money or links gets a warning
            if decision == "warn":
                escalate("hold", "RISKY_SESSION")
            elif decision == "deliver" and touches_money:
                escalate("warn", "RISKY_SESSION")
        if decision in ("hold", "block") and risk >= config.SESSION_RISKY:
            suggest = True
        stage("session", s, risk=round(risk, 3), level=session.get("level"))

        conf = {"rule": 0.97, "model": max(model_p, 1 - model_p), "degraded": 0.5}.get(path)
        if path == "judges" and judges_out:
            conf = 0.5 + abs(judges_out["p_scam"] - 0.5)
        banner = None
        if decision == "warn" and direction == "hotel_to_guest":
            banner = BANNERS.get(lang, BANNERS["en"])

        return Decision(decision, float(conf or 0.9), reasons, path, evidence, [v.as_dict() for v in lv], model_p,
                        session, judges_out, lang, pii, masked, banner, suggest, trace,
                        (time.perf_counter() - t0) * 1000, llm_called)

    @property
    def judge_provider(self) -> str:
        return getattr(self.judge, "name", "unknown") if not hasattr(self.judge, "model") else f"anthropic:{self.judge.model}"
