"""Text signals: multilingual lexicons (EN / HI / Hinglish / ES / PT / FR / DE / IT), PII masking and
prompt-injection guardrails.

Every detector returns evidence as exact substrings of the ORIGINAL message, so anything we show an
analyst (or hand to an LLM judge as a quote) can be verified against the raw text.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field

from .domains import is_public_host

# ----------------------------------------------------------------------------------------------
# Normalisation
# ----------------------------------------------------------------------------------------------
ZERO_WIDTH = re.compile("[​-‏⁠﻿­]")
# Cyrillic / Greek letters that look Latin. Used to unmask "Вооking" style spoofing.
CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ј": "j",
        "В": "B",
        "К": "K",
        "М": "M",
        "Н": "H",
        "О": "O",
        "Р": "P",
        "С": "C",
        "Т": "T",
        "Х": "X",
        "ο": "o",
        "α": "a",
        "ν": "v",
        "ρ": "p",
        "Ο": "O",
        "Α": "A",
        "Β": "B",
        "Ε": "E",
        "Κ": "K",
    }
)


def normalise(text: str) -> str:
    """NFKC + strip zero-width characters + map look-alike letters. Keeps length roughly stable."""
    t = unicodedata.normalize("NFKC", text)
    t = ZERO_WIDTH.sub("", t)
    return t.translate(CONFUSABLES)


def has_mixed_script_word(text: str) -> list[str]:
    """Words mixing Latin with Cyrillic/Greek letters (classic homoglyph spoof)."""
    hits = []
    for w in re.findall(r"\w{3,}", text):
        scripts = set()
        for ch in w:
            if ch.isascii() and ch.isalpha():
                scripts.add("latin")
            elif "Ѐ" <= ch <= "ӿ":
                scripts.add("cyrillic")
            elif "Ͱ" <= ch <= "Ͽ":
                scripts.add("greek")
        if "latin" in scripts and len(scripts) > 1:
            hits.append(w)
    return hits


# ----------------------------------------------------------------------------------------------
# Lexicons
# ----------------------------------------------------------------------------------------------
def _rx(*parts: str) -> re.Pattern[str]:
    return re.compile("|".join(f"(?:{p})" for p in parts), re.IGNORECASE)


# Words that talk about money at all.
PAY_TERMS = _rx(
    r"\bpay(?:ment|ments|ing)?\b",
    r"\bprepay(?:ment)?\b",
    r"\bdeposit\b",
    r"\bcharge[ds]?\b",
    r"\bamount due\b",
    r"\boutstanding (?:balance|amount)\b",
    r"\bbalance\b",
    r"\bsettle\b",
    r"\bfee\b",
    r"[€$£₹]\s?\d[\d,.]*",
    r"\b(?:eur|usd|gbp|inr|rs\.?)\s?\d[\d,.]*",
    r"\b\d[\d,.]*\s?(?:eur|euros?|usd|rupees|rs)\b",
    r"भुगतान",
    r"पेमेंट",
    r"पैसे",
    r"रुपये",
    r"राशि",
    r"\bpaise\b",
    r"\bpaisa\b",
    r"\bbhugtan\b",
    r"\bpayment\s?kar",
    r"\bpay\s?kar",
    r"\bpago\b",
    r"\bpagar\b",
    r"\babonar\b",
    r"\bpagamento\b",
    r"\bpaiement\b",
    r"\bpayer\b",
    r"\brégler\b",
    r"\bzahlung\b",
    r"\bbezahlen\b",
    r"\bpagare\b",
)

# Requests for card or bank data. A hotel never needs these over chat.
CARD_DATA = _rx(
    r"card (?:details|number|info(?:rmation)?|data)",
    r"(?:credit|debit|bank) card",
    r"\bcvv\b",
    r"\bcvc\b",
    r"security code",
    r"expiry date",
    r"bank (?:details|account details|information)",
    r"\biban\b",
    r"\bswift\b",
    r"re-?enter (?:your )?(?:card|payment)",
    r"verify (?:your )?(?:card|payment (?:method|details))",
    r"card verification",
    r"update (?:your )?(?:card|payment (?:method|details|information))",
    r"card (?:confirmation|check|validation|verification test)",
    r"(?:confirm|validate|re-?validate|check) (?:your |the )?(?:payment )?card",
    r"enter (?:your |the )?card",
    r"card (?:used|you used) for the (?:booking|reservation)",
    r"(?:confirm|validat|re-?validat|check|verify|verifi)\w* (?:your |the )?(?:payment |credit |debit )?card",
    r"(?:confirm|verific|valid)\w* (?:o |el |la |os |los )?(?:seu |su )?(?:cartão|tarjeta)",
    r"(?:vérifi|confirm|valid)\w* (?:votre |la )?carte",
    r"(?:verific|conferm|convalid)\w* (?:la )?(?:sua )?carta",
    r"karte\w* (?:bestätigen|verifizieren|prüfen)",
    r"कार्ड (?:की )?(?:जानकारी|डिटेल्स|नंबर)",
    r"बैंक (?:की )?(?:जानकारी|डिटेल्स)",
    r"card (?:ki )?details",
    r"card number bhej",
    r"card ki jankari",
    r"datos de (?:la )?tarjeta",
    r"número de (?:la )?tarjeta",
    r"dados do cartão",
    r"número do cartão",
    r"coordonnées bancaires",
    r"numéro de carte",
    r"kartendaten",
    r"kreditkartendaten",
    r"dati della carta",
)

# Payment rails that move money off-platform with no buyer protection.
OFF_PLATFORM_PAYMENT = _rx(
    r"bank transfer",
    r"wire (?:transfer|the|it|money)?",
    r"\bwestern union\b",
    r"\bmoneygram\b",
    r"gift ?cards?",
    r"\bcrypto\b",
    r"\bbitcoin\b",
    r"\busdt\b",
    r"\bupi\b",
    r"\bpaytm\b",
    r"\bgpay\b",
    r"\bphonepe\b",
    r"\b[\w.-]+@(?:ok\w+|ybl|paytm|upi|ibl|axl)\b",
    r"transfer (?:the )?(?:money|amount|payment|funds)",
    r"ट्रांसफर",
    r"यूपीआई",
    r"transfer kar",
    r"jama kar",
    r"जमा कर",
    r"transferencia",
    r"transferência",
    r"virement",
    r"überweisung",
    r"bonifico",
)

# Moving the conversation or payment away from the platform.
OFF_PLATFORM_CONTACT = _rx(
    r"\bwhats\s?app\b",
    r"\btelegram\b",
    r"\bwa\.me\b",
    r"\bsignal app\b",
    r"personal (?:account|email|number)",
    r"outside (?:of )?(?:booking|the (?:platform|app))",
    r"(?:is|isn'?t|not) (?:connected|linked) (?:to|with)",
    r"(?:another|different|separate|our own) (?:website|site|link|portal|payment page)",
    r"directly to (?:our|my) (?:bank|account)",
    r"call (?:me|us) (?:on|at) \+?\d",
    r"bahar se",
    r"alag (?:website|link)",
)

URGENCY = _rx(
    r"within \d+\s?(?:hours?|hrs?|h|minutes?|mins?)\b",
    r"\bin \d+\s?(?:hours?|hrs?|minutes?)\b",
    r"\b(?:12|24|48) ?(?:hours?|hrs?|h)\b",
    r"\bimmediately\b",
    r"\burgent(?:ly)?\b",
    r"\basap\b",
    r"right away",
    r"as soon as possible",
    r"\btoday\b",
    r"(?:will|would) be (?:automatically )?cancell?ed",
    r"cancel(?:l)?(?:ing|ation of)? your (?:booking|reservation|stay)",
    r"last chance",
    r"final (?:notice|reminder|warning)",
    r"failure to",
    r"\botherwise\b",
    r"तुरंत",
    r"अभी",
    r"रद्द",
    r"\babhi\b",
    r"\bturant\b",
    r"\bjaldi\b",
    r"cancel ho jaye\w*",
    r"cancel kar d",
    r"\bwarna\b",
    r"cancelada",
    r"urgente",
    r"inmediatamente",
    r"imediatamente",
    r"annulée",
    r"immédiatement",
    r"storniert",
    r"dringend",
    r"\bsofort\b",
    r"cancellata",
    r"immediatamente",
)

VERIFY_LURE = _rx(
    r"\bverif(?:y|ication|ied)\b",
    r"confirm (?:your )?(?:booking|reservation|identity|card|details|payment)",
    r"security check",
    r"\bvalidat(?:e|ion)\b",
    r"re-?confirm",
    r"suspicious activity",
    r"unauthori[sz]ed access",
    r"सत्यापन",
    r"verify kar",
    r"confirm kar",
    r"verificar",
    r"vérifier",
    r"bestätigen",
    r"verificare",
)

IMPERSONATION = _rx(
    r"booking\.?com (?:team|support|security|customer (?:service|support)|partner (?:help|support))",
    r"on behalf of booking",
    r"booking (?:security|support) (?:team|department)",
)

OVERPAYMENT = _rx(
    r"over-?paid",
    r"over-?payment",
    r"paid (?:too much|extra|more than)",
    r"sent (?:you )?(?:extra|more|too much|the wrong amount)",
    r"refund (?:me )?the (?:difference|excess|extra|balance|remaining)",
    r"return the (?:excess|extra|difference|rest)",
    r"(?:my|our) (?:assistant|secretary|travel agent|company) (?:paid|sent|made)",
    r"by mistake",
    r"wire (?:back|the (?:rest|difference|balance))",
    r"send (?:back|the (?:rest|difference))",
)

# Words that make a sentence an instruction to act, as opposed to a mention.
ACTION = _rx(
    r"\bplease\b",
    r"\bkindly\b",
    r"\bmust\b",
    r"\bneed to\b",
    r"\bneeds to\b",
    r"\brequired\b",
    r"\bhave to\b",
    r"\bclick\b",
    r"\bcomplete\b",
    r"\bmake (?:a |the )?payment\b",
    r"\bpay now\b",
    r"\bpay (?:the|this|your)\b",
    r"\bcan you pay\b",
    r"\bsend\b",
    r"\bprovide\b",
    r"\bfollow (?:the|this) link\b",
    r"\bvia (?:the|this) link\b",
    r"\bbelow\b",
    r"\bhere:\s",
    r"\bshould\b",
    r"कृपया",
    r"करें",
    r"\bkaro\b",
    r"\bkarein\b",
    r"\bkariye\b",
    r"\bbhejo\b",
    r"\bbhejein\b",
    r"\bkar do\b",
    r"por favor",
    r"debe",
    r"deve",
    r"veuillez",
    r"bitte",
    r"si prega",
)

# "... to confirm / secure / keep your booking": payment presented as the condition for keeping the stay.
GOAL = _rx(
    r"to (?:confirm|secure|guarantee|keep|hold|avoid|unlock|validate|verify|complete|reactivate|release)",
    r"(?:confirm|guarantee|secure) (?:your|the) (?:booking|reservation|room|stay)",
    r"ke liye",
    r"के लिए",
    r"para (?:confirmar|garantir|garantizar|manter|mantener)",
    r"pour (?:confirmer|garantir)",
    r"um (?:ihre|die) buchung",
    r"per (?:confermare|garantire)",
)

# Sentences that reassure ("you pay at the hotel", "nothing to pay now") are not asks.
REASSURE = _rx(
    r"pa(?:y|id|yable) (?:at|on|in) (?:the )?(?:property|hotel|check-?in|reception|arrival|front desk|desk)",
    r"pa(?:y|id) (?:the )?(?:driver|guide|taxi|restaurant)",
    r"(?:paid|payable|collected|taken) (?:locally|on site|on arrival)",
    r"(?:no|nothing to) (?:pay|payment|prepayment|deposit)",
    r"(?:not|never) (?:be )?(?:charged|ask)",
    r"no (?:payment|prepayment|deposit) (?:is )?(?:needed|required|necessary)",
    r"won'?t (?:be )?charge",
    r"payment (?:is|will be) (?:taken|collected|made) (?:at|on) (?:check-?in|arrival|the property)",
    r"never (?:ask|take|request|need)(?:s)? (?:you )?(?:for )?",
    r"(?:don'?t|do not) (?:need to )?(?:share|send|give)",
    r"already (?:been )?paid",
    r"fully paid",
    r"(?:in|through|via|on) (?:the )?booking\.?com (?:app|website|account|extranet)",
    r"pago en el (?:hotel|alojamiento)",
    r"paiement (?:à|sur) place",
    r"zahlung (?:vor ort|im hotel)",
    r"pagamento (?:no hotel|na chegada)",
    r"pagamento (?:é|e) feito no hotel",
    r"pago se (?:hace|realiza) en el",
    r"booking\.?com se ho (?:chuka|gaya)",
    r"(?:ho chuka|already) (?:hai )?.{0,20}(?:kuch )?pay nahi",
    r"pay nahi karna",
    r"check-?in (?:pe|par) (?:hi )?pay",
    r"hotel (?:pe|par) (?:hi )?pay",
)

INJECTION = _rx(
    r"ignore (?:all |any |the )?(?:previous|prior|above|earlier|preceding) (?:instructions|rules|messages|prompts?)",
    r"disregard (?:all |any |the )?(?:previous|prior|above|earlier)",
    r"system prompt",
    r"you are now\b",
    r"(?:classify|mark|label|treat|flag) (?:this|it|the message) as "
    r"(?:safe|legit(?:imate)?|genuine|not (?:spam|a scam|fraud)|benign)",
    r"(?:this|the) message (?:is|has been) (?:verified|approved|whitelisted|safe)",
    r"\bas an ai\b",
    r"developer mode",
    r"</?\s*(?:system|assistant|user|instructions?)\s*>",
    r"\[/?INST\]",
    r"<\|",
    r"BEGIN (?:SYSTEM|ADMIN)",
    r"(?:note|message) (?:to|for) (?:the )?(?:ai|model|llm|classifier|filter|moderator|reviewer)",
    r"pichle (?:sab )?instructions? ignore",
    r"पिछले निर्देश",
)

# Candidate links: anything with a scheme or www., or a dotted name. Scheme-less candidates are then validated
# against the public-suffix list (domains.is_public_host) instead of a hand-written TLD list, which used to miss
# whole countries (.ro, .pl, .ws ...) and cut `.com.br` down to `.com`.
URL_RX = re.compile(
    r"(?:(?:https?|hxxps?)://|www\.)[^\s<>\"')\]]+"
    r"|(?<![\w.-])[\w-]+(?:\.[\w-]+)+(?:/[^\s<>\"')\]]*)?",
    re.IGNORECASE,
)


# ----------------------------------------------------------------------------------------------
# PII masking (what an external LLM is allowed to see)
# ----------------------------------------------------------------------------------------------
def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


CARD_RX = re.compile(r"\b(?:\d[ -]?){13,19}\b")
EMAIL_RX = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
UPI_RX = re.compile(r"\b[\w.-]+@(?:ok\w+|ybl|paytm|upi|ibl|axl)\b", re.IGNORECASE)
IBAN_RX = re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,3})?\b")
PHONE_RX = re.compile(r"(?<![\w/-])(?!\d{4}-\d{2}-\d{2}\b)\+?\d[\d\s().-]{7,}\d\b")
AADHAAR_RX = re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b")


def mask_pii(text: str) -> tuple[str, list[str]]:
    """Replace card numbers (Luhn-checked), IBANs, UPI IDs, e-mails, ID numbers and phones with tokens."""
    kinds: list[str] = []

    def card_sub(m: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", m.group())
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            kinds.append("CARD")
            return "[CARD]"
        return m.group()

    out = CARD_RX.sub(card_sub, text)
    for rx, tok in ((IBAN_RX, "IBAN"), (UPI_RX, "UPI"), (EMAIL_RX, "EMAIL"), (AADHAAR_RX, "ID"), (PHONE_RX, "PHONE")):
        out, n = rx.subn(f"[{tok}]", out)
        kinds += [tok] * n
    return out, kinds


# ----------------------------------------------------------------------------------------------
# Signal extraction
# ----------------------------------------------------------------------------------------------
SENTENCE_SPLIT = re.compile(r"(?<=[.!?।])\s+|\n+")


@dataclass
class TextSignals:
    money_ask: bool = False  # strong: pay + instruction + (link | deadline | goal | verification | off-platform)
    soft_money_ask: bool = False  # pay + instruction only ("you can pay the driver")
    money_mention: bool = False
    card_data: bool = False
    off_platform_payment: bool = False
    off_platform_contact: bool = False
    urgency: bool = False
    verify_lure: bool = False
    impersonation: bool = False
    overpayment: bool = False
    injection: bool = False
    hidden_chars: bool = False
    obfuscated: bool = False  # leetspeak / spaced letters hid a signal
    mixed_script: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    evidence: dict[str, list[str]] = field(default_factory=dict)

    def add(self, kind: str, spans: list[str]) -> None:
        if spans:
            bucket = self.evidence.setdefault(kind, [])
            for s in spans:
                if s not in bucket:
                    bucket.append(s)

    @property
    def scam_flags(self) -> int:
        return sum(
            [
                self.money_ask,
                self.card_data,
                self.off_platform_payment,
                self.off_platform_contact,
                self.urgency,
                self.verify_lure,
                self.impersonation,
                self.injection,
                bool(self.mixed_script),
                self.obfuscated,
            ]
        )


BRAND_MENTIONS = {"booking.com", "airbnb.com", "agoda.com", "expedia.com", "priceline.com", "kayak.com", "hotels.com"}


def _accept_candidate(m: re.Match[str], text: str) -> str | None:
    u = m.group().rstrip(".,;:!?")
    if not u:
        return None
    if re.match(r"(?:https?|hxxps?)://|www\.", u, re.IGNORECASE):
        return u
    if u.lower() in BRAND_MENTIONS:
        return None
    host_part = u.split("/", 1)[0]
    end = m.start() + len(u)
    if "/" not in u and end < len(text) and text[end] == "@":
        return None  # userinfo before an @ (booking.com@evil.xyz): the real host comes after the @
    if not is_public_host(host_part.lower()):
        return None
    tld = host_part.rsplit(".", 1)[-1]
    if tld[:1].isupper() and tld[1:].islower():
        return None  # "today.So" / "room.In": a missing space after a full stop, not a domain
    return u


def _links(text: str) -> list[str]:
    """Links in text, ignoring bare brand mentions such as 'Booking.com' and the domain part of e-mail addresses."""
    out = []
    for m in URL_RX.finditer(text):
        if m.start() > 0 and text[m.start() - 1] == "@" and "/" not in m.group():
            continue  # e-mail address domain
        u = _accept_candidate(m, text)
        if u:
            out.append(u)
    return out


def sub_links(text: str, repl: str | Callable[[str], str]) -> str:
    """Replace every accepted link with repl(link) (a string or a callable)."""
    out, pos = [], 0
    for m in URL_RX.finditer(text):
        if m.start() > 0 and text[m.start() - 1] == "@" and "/" not in m.group():
            continue
        u = _accept_candidate(m, text)
        if not u:
            continue
        out.append(text[pos : m.start()])
        out.append(repl(u) if callable(repl) else repl)
        pos = m.start() + len(u)
    out.append(text[pos:])
    return "".join(out)


def _spans(rx: re.Pattern[str], text: str) -> list[str]:
    return [m.group().strip() for m in rx.finditer(text) if m.group().strip()]


LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
SPACED = re.compile(r"\b(?:[A-Za-z][ .\-_*·]){2,}[A-Za-z]\b")


def deobfuscate(t: str) -> str:
    """Undo filter-dodging tricks: 'p a y m e n t' -> 'payment', 'c@rd d3tails' -> 'card details'.
    Leet mapping only touches tokens that are mostly letters, so prices, dates and phone numbers survive."""
    t = SPACED.sub(lambda m: re.sub(r"[ .\-_*·]", "", m.group()), t)

    def fix(tok: str) -> str:
        letters = sum(c.isalpha() for c in tok)
        odd = sum(c in "013457@$" for c in tok)
        if letters >= 2 and odd and letters >= odd and "://" not in tok and "." not in tok.strip(".,!?"):
            return tok.translate(LEET)
        return tok

    return re.sub(r"\S+", lambda m: fix(m.group()), t)


BOOL_FLAGS = (
    "money_ask",
    "soft_money_ask",
    "money_mention",
    "card_data",
    "off_platform_payment",
    "off_platform_contact",
    "urgency",
    "verify_lure",
    "impersonation",
    "overpayment",
    "injection",
)


def extract(text: str) -> TextSignals:
    t = normalise(text)  # evidence quotes come from the normalised text, which equals the original for clean input
    s = _extract(t)
    s.hidden_chars = bool(ZERO_WIDTH.search(text))
    s.mixed_script = has_mixed_script_word(text)
    d = deobfuscate(t)
    if d != t:
        s2 = _extract(d)
        gained = [f for f in BOOL_FLAGS if getattr(s2, f) and not getattr(s, f)]
        for f in gained:
            setattr(s, f, True)
            s.add(f, s2.evidence.get(f, []))
        if gained:
            s.obfuscated = True
            s.add("deobfuscated", [w for w in d.split() if w not in t.split()][:4])
    if s.hidden_chars:
        s.add("hidden_chars", ["zero-width characters"])
    if s.mixed_script:
        s.add("mixed_script", s.mixed_script)
    return s


def _extract(t: str) -> TextSignals:
    s = TextSignals()
    s.urls = _links(t)
    for kind, rx in (
        ("card_data", CARD_DATA),
        ("off_platform_payment", OFF_PLATFORM_PAYMENT),
        ("off_platform_contact", OFF_PLATFORM_CONTACT),
        ("urgency", URGENCY),
        ("verify_lure", VERIFY_LURE),
        ("impersonation", IMPERSONATION),
        ("overpayment", OVERPAYMENT),
        ("injection", INJECTION),
    ):
        spans = _spans(rx, t)
        setattr(s, kind, bool(spans))
        s.add(kind, spans)

    # Sentence-level reading. A money ASK needs payment words plus an instruction in the same sentence,
    # and a reassuring sentence ("you pay at the property", "we never ask for card details") is not an ask.
    card_spans, rail_spans, unreassured_pay = [], [], []
    for sent in SENTENCE_SPLIT.split(t):
        reassured = bool(REASSURE.search(sent))
        if reassured:
            s.add("reassurance", _spans(REASSURE, sent))
        if not reassured:
            card_spans += _spans(CARD_DATA, sent)
            rail_spans += _spans(OFF_PLATFORM_PAYMENT, sent)
        pay = _spans(PAY_TERMS, sent)
        if not pay:
            continue
        s.money_mention = True
        if reassured:
            continue
        unreassured_pay += pay
        link_here = bool(_links(sent))
        if ACTION.search(sent) or link_here:
            s.soft_money_ask = True
            strong = (
                link_here
                or bool(URGENCY.search(sent))
                or bool(GOAL.search(sent))
                or bool(s.urls)
                or s.verify_lure
                or s.off_platform_contact
            )
            if strong:
                s.money_ask = True
                s.add("money_ask", pay + _spans(ACTION, sent)[:2] + _spans(GOAL, sent)[:1])
            else:
                s.add("soft_money_ask", pay)
    # Message-level fallback: "A guarantee payment of EUR 214 is pending. Complete it now: <link>" spreads the
    # money words and the instruction across sentences.
    if (
        s.money_mention
        and not s.money_ask
        and s.urls
        and unreassured_pay
        and (ACTION.search(t) or GOAL.search(t) or URGENCY.search(t))
    ):
        s.money_ask = s.soft_money_ask = True
        s.add("money_ask", unreassured_pay[:3])
    s.card_data, s.off_platform_payment = bool(card_spans), bool(rail_spans)
    s.evidence.pop("card_data", None)
    s.evidence.pop("off_platform_payment", None)
    s.add("card_data", card_spans)
    s.add("off_platform_payment", rail_spans)
    if s.card_data or s.off_platform_payment:
        s.money_ask = True
    return s


def detect_language(text: str) -> str:
    if re.search(r"[ऀ-ॿ]", text):
        return "hi"
    low = text.lower()
    hinglish = sum(
        w in low.split()
        for w in ("hai", "karo", "kar", "aapka", "aapki", "apna", "nahi", "bhejo", "jaldi", "abhi", "warna", "ki", "ke", "ho")
    )
    if hinglish >= 2:
        return "hinglish"
    for lang, words in (
        ("es", (" el ", " la ", " su ", " por ", " reserva")),
        ("pt", (" você", " sua ", " reserva", " não ")),
        ("fr", (" vous ", " votre ", " réservation")),
        ("de", (" ihre ", " sie ", " buchung")),
        ("it", (" la sua ", " prenotazione", " vostra ")),
    ):
        if sum(w in f" {low} " for w in words) >= 2:
            return lang
    return "en"
