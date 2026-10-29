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

from .domains import EXTRACT, is_public_host

# ----------------------------------------------------------------------------------------------
# Normalisation
# ----------------------------------------------------------------------------------------------
# Every invisible "default ignorable" character, not only the zero-width ones: invisible operators (U+2061-2064),
# the combining grapheme joiner (U+034F), the Mongolian vowel separator, bidi controls, variation selectors and the
# tag block. Review round 1 got a card-details scam delivered by sprinkling U+2063 inside words.
_ZW_LISTED = (
    "\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u206f"
    "\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufffb\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0000-\U000e0fff"
)
# Round 4 (A2): U+1BCA0-1BCA3 were missing, so the list is now completed from the Unicode database: every format
# character (category Cf) except the visible "prepended concatenation marks" used in Arabic, Syriac and Kaithi numbers.
_VISIBLE_CF = set("\u0600\u0601\u0602\u0603\u0604\u0605\u06dd\u070f\u0890\u0891\u08e2\U000110bd\U000110cd")
_CF = "".join(re.escape(chr(c)) for c in range(0x110000) if unicodedata.category(chr(c)) == "Cf" and chr(c) not in _VISIBLE_CF)
ZERO_WIDTH = re.compile(f"[{_ZW_LISTED}{_CF}]")
_FLAG_TAGS = re.compile("\U0001f3f4[\U000e0020-\U000e007e]+\U000e007f")  # subdivision flags (England, Scotland)


def _is_pictograph(ch: str) -> bool:
    return unicodedata.category(ch) in ("So", "Sk") or "\U0001f3fb" <= ch <= "\U0001f3ff"


def _is_latinish(ch: str) -> bool:
    return ch.isalpha() and unicodedata.name(ch, "").split(" ")[0] in ("LATIN", "CYRILLIC", "GREEK")


def has_suspicious_invisibles(text: str) -> bool:
    """Invisible characters that only make sense as filter evasion. Review round 3 (C1): the round-1 list also covers
    the variation selector every phone puts after ❤️ ☺️ ☀️ and the joiner inside 👨‍👩‍👧, so ordinary emoji turned
    legitimate messages into "obfuscated" ones - and no evaluation set contained a single emoji. Emoji sequences,
    subdivision flags and the joiners Indic and Arabic scripts need are benign; the characters are still stripped
    before matching either way."""
    t = _FLAG_TAGS.sub("", text)
    for i, ch in enumerate(t):
        if not ZERO_WIDTH.match(ch):
            continue
        prev, nxt = (t[i - 1] if i else ""), (t[i + 1] if i + 1 < len(t) else "")
        if ch in "\ufe0e\ufe0f" and prev and not prev.isalpha():
            continue  # emoji / text presentation selector after a symbol or keycap digit
        if ch == "\u200d" and (_is_pictograph(prev) or prev in "\ufe0f") and nxt and _is_pictograph(nxt):
            continue  # emoji ZWJ sequence
        if ch in "\u200c\u200d" and prev.isalpha() and nxt.isalpha() and not (_is_latinish(prev) or _is_latinish(nxt)):
            continue  # ZWJ / ZWNJ inside Devanagari, Arabic, Persian ... words
        return True
    return False


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
    """NFKC + strip zero-width characters + map look-alike letters. Keeps length roughly stable.

    Look-alike mapping is applied only to words that MIX Latin with Cyrillic/Greek ("Вooking"). Mapping every
    word would turn real Russian or Greek text into Latin-Cyrillic soup that no Russian pattern can match."""
    t = unicodedata.normalize("NFKC", text)
    t = ZERO_WIDTH.sub("", t)
    return re.sub(r"\w+", lambda m: m.group().translate(CONFUSABLES) if _mixes_scripts(m.group()) else m.group(), t)


def _mixes_scripts(word: str) -> bool:
    latin = any(ch.isascii() and ch.isalpha() for ch in word)
    other = any("\u0370" <= ch <= "\u04ff" for ch in word)
    return latin and other


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
    # review round 2: amounts in other currencies ("30 reais by Pix") were not money words at all
    r"[¥₽₺₩₱]\s?\d[\d,.]*|\bR\$\s?\d[\d,.]*",
    r"\b\d[\d,.]*\s?(?:reais|brl|pln|zł|zl|złotych|try|tl|lira|liras|jpy|yen|rub|rubles?|roubles?|aed|dirhams?|chf|"
    r"francs?|sek|nok|dkk|kr|czk|huf|mxn|pesos?|ars|cop|thb|baht|idr|rupiah|myr|ringgit|sgd|aud|cad|zar|rand)\b",
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
    r"\bswift(?:/bic)?\s*(?:code|number)\b",  # not "swift check-in" (found while fixing review round 2)
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
    # Card verification beyond the eight main languages (red-team corpus B01-B09). Two-sided so word order
    # doesn't matter; still sentence-level and still switched off by a reassuring sentence.
    r"(?:tarjeta|cartão)\w*.{0,30}(?:verific|confirm|valid)",
    r"(?:kaart|creditcard)\w*.{0,40}(?:bevestig|verifie|controle)",
    r"(?:bevestig|verifieer)\w*.{0,20}(?:kaart|creditcard)",
    r"kart\w*.{0,40}(?:potwierd|weryfik|doğrula)",
    r"(?:potwierd|weryfik|doğrula)\w*.{0,30}kart",
    r"(?:تأكيد|التحقق).{0,30}بطاق",
    r"بطاق.{0,30}(?:تأكيد|التحقق)",
    r"(?:验证|驗證|确认|確認).{0,10}(?:银行卡|信用卡|卡)",
    r"(?:银行卡|信用卡).{0,10}(?:验证|驗證|确认|確認)",
    r"カード.{0,15}(?:確認|認証)",
    r"(?:確認|認証).{0,10}カード",
    r"(?:подтверд|провер)\w*.{0,30}карт",
    r"карт\w*.{0,30}(?:подтверд|провер)",
    r"(?:bekräfta|verifiera)\w*.{0,20}kort",
    r"kort\w*.{0,30}(?:bekräfta|verifiera)",
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
    r"\bqr(?: code)?\b.{0,60}\b(?:bank(?:ing)?|pay(?:ment)?|wallet|card)\b",  # pay-by-QR, not "scan the QR for Wi-Fi"
    r"\b(?:bank(?:ing)?|payment) app\b.{0,40}\bqr\b",
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
    r"(?<![\w.-])[\w.-]{1,64}@(?:ok\w+|ybl|paytm|upi|ibl|axl)\b",  # bounded: unbounded was O(n^2) (round 4, B F2)
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
    # review round 2: other instant-payment rails and wallets (Pix was missing entirely)
    # "pix" alone is also slang for pictures: the bare word held a personal SMS in the evaluation's SMS test split
    # (recorded in DECISIONS #34), so it needs payment context
    r"\b(?:via|by|por|pelo|pela|com|with|using|chave|key|código|codigo)\s+(?:o\s+)?pix\b|\bpix\s+(?:key|code|copia|"
    r"payment|transfer|keys?)\b|\bpix\b.{0,40}\b(?:reais|r\$|brl)",
    r"\brevolut\b",
    r"\bwise\.com\b|\bvia wise\b|\bwise transfer\b",
    r"\bzelle\b",
    r"\bvenmo\b",
    r"\bcash ?app\b",
    r"\bskrill\b",
    r"\bbizum\b",
    r"\bblik\b",
    r"\bmb ?way\b",
    r"\balipay\b",
    r"\bwe ?chat ?pay\b",
    r"\bpaypal(?:\.me)?\b",
    r"\bpayoneer\b",
    r"\biban\b",
    r"\bswift(?:/bic)? code\b|\bbic code\b",
    r"\bsepa\b",
    r"\bprzelew\w*",
    r"\bhavale\b|\beft\b",
    r"перевод\w*|переве\w*",
    r"振込|转账|轉帳|汇款",
)

# Moving the conversation or payment away from the platform.
# A phone number spelled out in words ("double four, seven seven zero zero, ...") only exists to dodge filters.
_DIGIT_WORD = r"(?:zero|oh|one|two|three|four|five|six|seven|eight|nine|double \w+|triple \w+)"
SPELLED_NUMBER = re.compile(rf"\b{_DIGIT_WORD}(?:[\s,.-]+{_DIGIT_WORD}){{6,}}\b", re.IGNORECASE)

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
    # "within N hours" in languages the rest of the lexicon doesn't cover (nl, sv, pl, tr, ar, zh, ja, ru, ...)
    r"\d{1,2}\s?(?:uur|timmar|timer|godzin|saat|ساعة|ساعات|小时|小時|時間|часов|часа|tuntia|óra|hodin|ώρες)",
    r"geannuleerd|vervalt|avboka|anulowan|iptal edil|إلغاء|取消|キャンセル|отмен",
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
    # "we confirm your reservation" is the hotel confirming, not a request to the guest
    r"(?<!we )(?<!happy to )(?<!pleased to )(?<!can )confirm (?:your )?(?:booking|reservation|identity|card|details|payment)",
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
    r"pagu[ée] (?:de más|dos veces)",
    r"devuelvan? la diferencia",
    r"pay[ée] (?:deux fois|en trop|de trop)",
    r"rembourser (?:l'excédent|la différence)",
    r"paguei (?:a mais|duas vezes)",
    r"devolver a diferença",
    r"zu viel (?:bezahlt|überwiesen)",
    r"doppelt bezahlt",
    r"pagato (?:due volte|in più)",
    r"restituire la differenza",
    r"ज़्यादा भुगतान",
    r"ज्यादा भुगतान",
    r"zyada payment",
    r"galti se .{0,20}(?:payment|transfer)",
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

# Review round 3: "give our front desk a ring on <number>" moved the guest to a phone call with no signal at all (only
# "call us on" was known). A phone handoff is common and legitimate, so it is its own flag: it never takes the quiet
# fast path or the model's low-risk path, and the judges decide; it is not a hard rule.
# Any up-to-three non-word characters between digits (a middle dot "21·12·34", keycap marks), not only " ()./-"
# (round 4, B F1: other separators removed the message from the judges).
_PHONE_NO = r"(?:\+|\b00)?\d(?:[^\w\n]{0,3}\d){7,}"
PHONE_HANDOFF = _rx(
    rf"\b(?:ring|call|phone|dial|text|sms|contact|reach)\b[^\n]{{0,40}}?{_PHONE_NO}",
    r"(?:\+|\b00)\d(?:[^\w\n]{0,3}\d){7,}[^.!?\n]{0,30}\b(?:ring|call|phone|dial|text)\b",
)

# A payment written as a fact rather than an instruction ("a 50 EUR fee is payable to our account x@y before
# arrival") is still a demand when it names where the money goes or says it is due before arrival. Review round 3:
# passive phrasing has no verb from ACTION, so it was only a "mention" and was delivered clean.
PAY_DESTINATION = _rx(
    # "to/into" only: "payable by card at check-in" / "payable via the front desk" are on-site payments, which round 4
    # (A3) showed this pattern hard-held
    r"\b(?:payable|settled?|transferred|credited|deposited|remitted|wired)\s+(?:to|into)\b(?!\s+(?:the\s+)?(?:hotel|property|"
    r"reception|front desk|driver)\b)",
    # generic verbs only with an explicit destination ("go to the cinema" held a personal SMS in the SMS test split;
    # recorded in DECISIONS #34)
    r"\b(?:paid|sent|due|goes|go)\s+(?:to|into|by|via)\s+(?:our|my|this|the hotel'?s?)\b",
    r"\b(?:to|into)\s+(?:our|the hotel'?s?|my|this)\s+(?:account|wallet|number|e-?mail)\b",
)
_PRE = (
    r"(?:\b(?:before|ahead of|prior to|in advance of)\s+(?:your\s+|the\s+)?(?:arrival|check-?in|you arrive|your stay|travel)"
    r"|\bin advance\b|\bantes de (?:su |la |a )?(?:llegada|chegada|check-?in)|\bavant (?:votre |l'|l’)?(?:arrivée|check-?in)"
    r"|\bvor (?:ihrer |der )?(?:anreise|ankunft))"
)
_PAY_VERB = r"\b(?:pay|paid|payable|settle[ds]?|transfer(?:red)?|send|sent|due|remit(?:ted)?|charged?|deposit(?:ed)?)\b"
# "Due before arrival" only when a payment verb sits next to the timing: "let us know before arrival" about a 12 EUR
# breakfast was hard-held in round 4 (A3).
PRE_ARRIVAL = re.compile(rf"{_PAY_VERB}[^.!?;\n]{{0,40}}{_PRE}|{_PRE}[^.!?;\n]{{0,25}}{_PAY_VERB}", re.IGNORECASE)
# An e-mail address right after a payment verb is a destination ("send the deposit to x@y"); an e-mail elsewhere in a
# sentence that mentions a price is not.
PAY_TO_EMAIL = re.compile(rf"{_PAY_VERB}[^.!?\n]{{0,60}}[\w.+-]{{1,64}}@[\w-]{{1,63}}\.[\w.-]{{1,253}}", re.IGNORECASE)


def _is_money_ask_sentence(sent: str) -> bool:
    if not PAY_TERMS.search(sent):
        return False
    return bool(
        PAY_DESTINATION.search(sent)
        or PRE_ARRIVAL.search(sent)
        or PAY_TO_EMAIL.search(sent)
        or _links(sent)
        or (ACTION.search(sent) and (URGENCY.search(sent) or GOAL.search(sent)))
    )


_OBJECT_BREAK = re.compile(r"\b(?:until|unless|once|after|before|so|then|but|however|first|only if|instead)\b", re.IGNORECASE)


def _unanchored_sensitive(clause: str) -> list[str]:
    """Card / rail mentions in a reassuring clause that are NOT the object of the reassurance: further than 60
    characters from it, or separated from it by "until / unless / once / so / then ..."."""
    ms = list(REASSURE.finditer(clause))
    out = []
    for rx in (CARD_DATA, OFF_PLATFORM_PAYMENT):
        for m in rx.finditer(clause):
            near = [r for r in ms if r.end() <= m.start() and m.start() - r.end() <= 60]
            if not near or any(_OBJECT_BREAK.search(clause[r.end() : m.start()]) for r in near):
                out.append(m.group())
    return out


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
    r"\[/?\s*(?:system|assistant|instructions?|admin)\s*\]",
    r"output (?:the |a )?(?:verdict|label|classification)",
    r"(?:respond|answer|reply) that this (?:text|message) is",
    r"skip (?:the )?review",
    r"pre-?approved by",
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


# Any single separator between digits, and no word boundary needed: "4111/1111/1111/1111" and "4111111111111111exp"
# reached storage before (review round 2, A7). Luhn-checked in mask_pii.
# Up to three non-alphanumeric characters (or underscores) between digits: round 3 (A8) showed "4111 / 1111 / ..." and
# "|", "*", ":", "+" separators still got through the round-2 single-separator form.
CARD_RX = re.compile(r"(?<!\d)\d(?:(?:[^\w\n]|_){0,3}\d){12,18}(?!\d)")
# Local parts bounded to 64 characters and anchored: "[\w.+-]+@" backtracked quadratically over a long run of word
# characters with no "@" (5,000 characters of "a.a.a." took ~0.5 s per check; review round 4, B F2).
EMAIL_RX = re.compile(r"(?<![\w.+-])[\w.+-]{1,64}@[\w-]{1,63}\.[\w.-]{1,253}\b")
UPI_RX = re.compile(r"(?<![\w.-])[\w.-]{1,64}@(?:ok\w+|ybl|paytm|upi|ibl|axl)\b", re.IGNORECASE)
IBAN_RX = re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,3})?\b")
PHONE_RX = re.compile(r"(?<![\w/-])(?!\d{4}-\d{2}-\d{2}\b)\+?\d[\d\s().-]{7,}\d\b")
AADHAAR_RX = re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b")


_DASHES = re.compile(r"[\u2010-\u2015\u2212\ufe58\ufe63\uff0d]")
_SPACES = re.compile(r"[\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]")


def _pii_view(text: str) -> str:
    """What the PII regexes run on: NFKC (fullwidth digits -> ASCII), invisible characters removed, and every Unicode
    dash or space turned into its ASCII form. Review round 1 got 4111\u20111111\u20111111\u20111111 (non-breaking
    hyphens) past masking and into storage."""
    # NFKC one character at a time, keeping only one-to-one folds (fullwidth digits -> ASCII). Whole-text NFKC let one
    # character become up to 18 (U+FDFA), so a 384-character message became 5,144 and pushed its link past what the
    # judges are shown (round 4, A4).
    t = "".join(f if len(f := unicodedata.normalize("NFKC", ch)) == 1 else ch for ch in text)
    t = ZERO_WIDTH.sub("", t)
    t = _DASHES.sub("-", t)
    return _SPACES.sub(" ", t)


def mask_pii(text: str) -> tuple[str, list[str]]:
    """Replace card numbers (Luhn-checked), IBANs, UPI IDs, e-mails, ID numbers and phones with tokens.

    The masked text is built from a normalised view of the message (see _pii_view), so separators and digit forms
    can't hide a number. Links are kept intact: `https://booking.com@evil.net/x` is a URL with a userinfo part, not an
    e-mail, and masking it would hide the real host from the judges."""
    kinds: list[str] = []
    text = _pii_view(text)
    link_spans = [
        (m.start(), m.start() + len(u)) for m in URL_RX.finditer(text) if (u := _accept_candidate(m, text)) and "://" in u
    ]

    def authority_end(a: int, b: int) -> int:
        body = text[a:b]
        start = body.find("://") + 3
        ends = [i for i in (body.find(c, start) for c in "/?#\\") if i != -1]
        return a + (min(ends) if ends else len(body))

    authority_spans = [(a, authority_end(a, b)) for a, b in link_spans]

    def card_sub(m: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", m.group())
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            kinds.append("CARD")
            return "[CARD]"
        return m.group()

    def email_sub(m: re.Match[str]) -> str:
        # "www.booking.com@evil.com/k" with no scheme is a link too (review round 3, A6): an e-mail is never followed by
        # a path and doesn't start with "www."
        if text[m.end() : m.end() + 1] == "/" or m.group().lower().startswith("www."):
            return m.group()
        if any(a <= m.start() < b for a, b in authority_spans):
            return m.group()  # in a link's authority: userinfo, not an e-mail. Path and query e-mails are masked (round 2)
        kinds.append("EMAIL")
        return "[EMAIL]"

    out = EMAIL_RX.sub(email_sub, text)  # first, while link positions still match the text
    out = CARD_RX.sub(card_sub, out)
    for rx, tok in ((IBAN_RX, "IBAN"), (UPI_RX, "UPI"), (AADHAAR_RX, "ID"), (PHONE_RX, "PHONE")):
        out, n = rx.subn(f"[{tok}]", out)
        kinds += [tok] * n
    return out, kinds


# ----------------------------------------------------------------------------------------------
# Signal extraction
# ----------------------------------------------------------------------------------------------
SENTENCE_SPLIT = re.compile(r"(?<=[.!?।])\s+|\n+")
# Clause boundaries inside a sentence: punctuation and contrast words ("..., but please transfer ...").
# Review round 2: joining the reassurance and the ask with "and" / "so" / "just" and no comma kept them in one clause,
# so the whole ask was dropped with the reassurance. Connectives that start a new instruction now split too.
CLAUSE_SPLIT = re.compile(
    r"[,;:]\s*|\s+(?=(?:but|however|still|though|although|yet|except|instead|anyway|nevertheless|pero|mais|aber|ma|mas"
    r"|and|so|just|simply|then|now|please|kindly|plus|also|y|e|et|und|und dann|então|entonces|donc|dann|quindi|bas|aur|toh)\b)",
    re.IGNORECASE,
)
# An instruction verb inside a reassured clause, AFTER the reassurance, that is not itself negated or an infinitive
# ("we never ask you to send ..."): "Your stay is paid at the property confirm your card number here" is still an ask.
IMPERATIVE_WORDS = (
    r"confirm|share|send|transfer|wire|enter|provide|update|verify|give|deposit|top up|scan|reply|forward|type|write|"
    r"pay|settle|complete|click|tap|open|visit|fill(?: in)?|submit"  # pay/settle/complete/click: review round 3, A1
)
# "Apple Pay" / "Google Pay" are wallet names, not an instruction to pay (found on held-out v1 after round 4; recorded in
# docs/ADVERSARIAL_REVIEW.md round 4)
IMPERATIVE = re.compile(
    rf"(?<!\bto )(?<!\bnot )(?<!n't )(?<!\bnever )(?<!apple )(?<!google )(?<!samsung )\b(?:{IMPERATIVE_WORDS})\b",
    re.IGNORECASE,
)


# --- Platform-routed money mentions (DECISIONS #40) ---------------------------------------------------------------
# A sentence that mentions money or a card but sends the guest only to the platform's own flow (the app, their account,
# the reception on arrival) or says nothing will be charged. Held-out v2 (retired as a blind set once v3 was frozen)
# showed 8 of its 10 false holds were genuine messages like this held by the payment-terms rules. Following such an
# instruction cannot pay a criminal: there is no link, no account number and no contact to pay through. The engine only
# uses this when every money/card sentence is routed this way and nothing else in the message is wrong.
PLATFORM_FLOW = _rx(
    # the platform app or account: "in the app", "in your Booking.com account", "on Booking.com", "through the platform"
    r"\b(?:in|via|through|on|using|under)\s+(?:the\s+|your\s+|ihrem\s+|ihr\s+|su\s+|tu\s+|votre\s+|sua\s+|seu\s+)?"
    r"(?:booking(?:\.com)?[\s-]?)?(?:app|application|account|extranet|platform|konto|cuenta|compte|conta"
    r"|aplicaci[oó]n|aplicativo|applicazione|anwendung)\b",
    r"\b(?:the|your)\s+booking(?:\.com)?\s+(?:app|account)\b",
    r"\b(?:on|via|through)\s+booking(?:\.com)?\b",
    r"\bbooking(?:\.com)?\s+will\s+(?:send|ask|request|contact|charge|refund)",
    # paid in person: "at check-in", "at reception", "on arrival", "when you check in", "after check-out"
    r"\b(?:at|during)\s+(?:the\s+)?(?:check-?in|check-?out|reception|front\s+desk)\b",
    r"\b(?:on|upon)\s+(?:your\s+)?arrival\b",
    r"\bwhen\s+you\s+(?:arrive|check\s+in)\b",
    r"\bafter\s+(?:your\s+)?check-?out\b",
    # nothing taken now: guarantees, pre-authorisations, refunds
    r"\b(?:will\s+not|won't|do\s+not|don't|never|not)\s+(?:be\s+)?charge[ds]?\b",
    r"\bnothing\s+is\s+charged\b",
    r"\bonly\s+(?:as\s+)?a\s+guarantee\b",
    r"\bpre-?authori[sz]",
    r"\brefund(?:ed)?\b",
    # a status report, not an ask: "the card on your reservation was declined" (what to do next must still be routed)
    r"\b(?:was|has\s+been|were|got)\s+(?:declined|refused|rejected)\b",
    # the same in the languages the lexicons already cover
    r"\b(?:en|a)\s+la\s+(?:app|recepci[oó]n|llegada)\b",
    r"\bal\s+llegar\b",
    r"\b(?:dans|sur)\s+l['’]application\b",
    r"\b(?:[àa]\s+la\s+r[ée]ception|[àa]\s+l['’]arriv[ée]e)\b",
    r"\bin\s+der\s+app\b",
    r"\b(?:an\s+der\s+rezeption|bei\s+(?:der\s+)?anreise)\b",
    r"\b(?:no|pelo)\s+(?:app|aplicativo)\b",
    r"\bna\s+(?:chegada|recep[cç][aã]o)\b",
    r"\bnell['’]app\b",
    r"\b(?:all['’]arrivo|alla\s+reception)\b",
)
# Asking for the card itself in the chat ("reply with your card number") is never platform-routed, unless negated
# ("please do not send card details here").
CARD_SEND = re.compile(
    r"(?<!will )\b(?:send|share|provide|reply\s+with|type|write|give|forward|text|enter)\b[^.!?\n]{0,40}"
    r"\b(?:card|cvv|cvc|iban|account\s+number|security\s+code)",
    re.IGNORECASE,
)
_NEGATED_SEND = re.compile(
    r"\b(?:do\s+not|don't|never|please\s+don't|no\s+need\s+to|not)\s+(?:\w+\s+){0,2}(?:send|share|provide|reply|type|write|give|forward|text|enter)\b"
    r"|\bsenden\s+sie\s+(?:uns\s+)?keine\b|\bno\s+(?:nos\s+)?env[ií]e|\bn['’]envoyez\s+(?:pas|jamais)\b|\bn[ãa]o\s+(?:nos\s+)?envie\b"
    r"|\bnon\s+(?:ci\s+)?invi(?:ate|are)\b",
    re.IGNORECASE,
)
# "we will not charge it before you arrive", "nothing is charged in advance": a pre-arrival phrase under a negation is a
# guarantee, not a demand
_NO_CHARGE = re.compile(
    r"\b(?:will\s+not|won't|do\s+not|don't|never|nothing\s+is|not)\s+(?:be\s+)?charge[ds]?(?:\s+\w+){0,3}?\s+"
    r"(?:before\s+(?:you\s+)?(?:arrive|arrival|check\s+in|check-in)|in\s+advance|prior\s+to\s+(?:your\s+)?arrival)\b",
    re.IGNORECASE,
)


def _only_negated_pre_arrival(sent: str) -> bool:
    """Every pre-arrival match lies wholly inside a negated-charge phrase."""
    spans = [m.span() for m in _NO_CHARGE.finditer(sent)]
    return all(any(a <= m.start() and m.end() <= b for a, b in spans) for m in PRE_ARRIVAL.finditer(sent))


def _platform_routed(sent: str) -> bool:
    """True if this money/card sentence only points to the platform's own flow (see PLATFORM_FLOW)."""
    if OFF_PLATFORM_PAYMENT.search(sent) or _links(sent) or PAY_DESTINATION.search(sent) or PAY_TO_EMAIL.search(sent):
        return False
    if PRE_ARRIVAL.search(sent) and not _only_negated_pre_arrival(sent):
        return False
    negated_send = bool(_NEGATED_SEND.search(sent))
    if CARD_SEND.search(sent) and not negated_send:
        return False
    # a bare "please don't send card details in this chat" is a safety reminder, routed by definition
    return bool(PLATFORM_FLOW.search(sent)) or (negated_send and not PAY_TERMS.search(sent))


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
    # a card or payment-rail mention that was set aside only because a reassurance shared its clause; the engine never
    # delivers such a message on the quiet fast path (review round 2, A1/B1)
    reassured_sensitive: bool = False
    phone_handoff: bool = False  # "ring us on <number>": judged, never fast-pathed (review round 3)
    # every sentence that mentions money or a card only points to the platform's own flow (DECISIONS #40)
    platform_flow_only: bool = False
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
    if "/" not in u and len(EXTRACT(host_part.lower()).domain) < 2:
        return None  # "U.CALL", "K.k.how": a one-letter name with no path is a typo, not a link (t.co/abc keeps its path)
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


_DEFANG = re.compile(
    r"\s*(?:\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}|[\u3002\uff61\uff0e])\s*", re.IGNORECASE
)
_SPACED_DOT = re.compile(r"(?<=[\w-])\s+\.\s+(?=[a-z]{2,10}\b)", re.IGNORECASE)


def refang(t: str) -> str:
    """Undo link defanging: 'evil[.]com', 'evil(.)com', 'evil{dot}com', ideographic full stops, 'evil . com'."""
    t = _DEFANG.sub(".", t)
    return _SPACED_DOT.sub(".", t)


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
    "reassured_sensitive",  # carried over from the de-obfuscated reading too (review round 3, A3)
    "phone_handoff",
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
    s.hidden_chars = has_suspicious_invisibles(text)
    # Fullwidth Latin letters ("Ｃｏｍｐｌｅｔｅ") are NFKC-folded before matching; a hotel has no reason to write them, so
    # they are obfuscation (review round 2, A6).
    if re.search(r"[\uff21-\uff3a\uff41-\uff5a]", text):
        s.obfuscated = True
        s.add("deobfuscated", ["fullwidth letters"])
    s.mixed_script = has_mixed_script_word(text)
    d = deobfuscate(t)
    # Links written to dodge extraction: "guest-step-portal\u3002net", "[.]", "(.)", " . ". Browsers and chat apps
    # turn several of these back into a working link, so they are links, and writing them that way is evidence.
    r = refang(t)
    if r != t:
        known = set(_links(t)) | set(s.urls)  # computed once: per-link recomputation was quadratic (round 4, A6)
        hidden = [u for u in _links(r) if u not in known]
        if hidden:
            s.urls += hidden
            s.obfuscated = True
            s.add("deobfuscated", ["link written to dodge filters: " + hidden[0]])
            s3 = _extract(r)
            for f in BOOL_FLAGS:
                if getattr(s3, f) and not getattr(s, f):
                    setattr(s, f, True)
                    s.add(f, s3.evidence.get(f, []))
    spelled = [m.group() for m in SPELLED_NUMBER.finditer(t)]
    if spelled:
        s.off_platform_contact = s.obfuscated = True
        s.add("off_platform_contact", spelled[:1])
        s.add("deobfuscated", ["phone number spelled out in words"])
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
    trigger_sents: list[str] = []  # sentences whose money or card words count (for platform_flow_only)
    shadow_ask = False
    sensitive_in_calm: list[str] = []
    for full in SENTENCE_SPLIT.split(t):
        # Reassurance only covers the clause it is in. Review round 1: "Payment is collected on arrival and we don't
        # need to share any details, but please transfer 50 via UPI ..." was delivered because one reassuring phrase
        # switched off the whole sentence. The rest of the sentence is read without the reassuring clauses.
        clauses = [c for c in CLAUSE_SPLIT.split(full) if c and c.strip()]
        calm = [c for c in clauses if REASSURE.search(c)]
        for c in calm:
            s.add("reassurance", _spans(REASSURE, c))
        sent = " ".join(c for c in clauses if not REASSURE.search(c))
        for c in calm:
            # Every stretch of the clause outside the reassurances is read: before the first, between them, after the
            # last. Round 3 read only the head and tail, and only for imperative verbs; round 4 (A1) hid "send the 80
            # EUR deposit to x@y" between two reassurances and a passive "is payable to x@y" before one.
            ms = list(REASSURE.finditer(c))
            bounds = [0] + [x for m in ms for x in (m.start(), m.end())] + [len(c)]
            for i in range(0, len(bounds), 2):
                seg = c[bounds[i] : bounds[i + 1]]
                # A stretch whose instruction is the reassurance's own object ("never ask you to send ... or share ...")
                # is skipped: it follows a reassurance and starts "to/for <verb>".
                obj = i > 0 and re.match(
                    rf"\s*(?:you\s+)?(?:to|for)\s+(?:\w+\s+){{0,2}}?(?:{IMPERATIVE_WORDS})\b", seg, re.IGNORECASE
                )
                demand = PAY_DESTINATION.search(seg) or PAY_TO_EMAIL.search(seg) or PRE_ARRIVAL.search(seg)
                if (IMPERATIVE.search(seg) and not obj) or demand:
                    sent += " " + seg
        here_card, here_rail = _spans(CARD_DATA, sent), _spans(OFF_PLATFORM_PAYMENT, sent)
        card_spans += here_card
        rail_spans += here_rail
        if here_card or here_rail or PAY_TERMS.search(sent):
            trigger_sents.append(sent)
        # Shadow reading of the whole sentence, reassurance included: if it reads as a payment ask but the filtered
        # sentence doesn't, a reassurance hid it. Round 3 (A1) showed layer 3 only covered card and rail words, so a plain
        # "pay the 80 EUR tax at <link>" next to "fully paid at the property" was delivered clean.
        # (round 4, A1: the "not PAY_TERMS in sent" condition let any harmless price elsewhere in the sentence switch this
        # off, so it now asks only whether the whole sentence reads as an ask that the filtered one doesn't)
        if (
            calm
            and PAY_TERMS.search(full)
            # the reassurance's own words ("you pay the driver") are not the instruction we are looking for
            and (
                IMPERATIVE.search(REASSURE.sub(" ", full))
                or _links(full)
                or PAY_DESTINATION.search(full)
                or PAY_TO_EMAIL.search(full)
            )
            and not _is_money_ask_sentence(sent)
        ):
            shadow_ask = True
        for c in calm:
            sensitive_in_calm += _unanchored_sensitive(c)
        if any(PAY_TERMS.search(c) for c in calm):
            s.money_mention = True
        pay = _spans(PAY_TERMS, sent)
        if not pay:
            continue
        s.money_mention = True
        unreassured_pay += pay
        link_here = bool(_links(sent))
        if PAY_DESTINATION.search(sent) or PRE_ARRIVAL.search(sent) or PAY_TO_EMAIL.search(sent):
            s.money_ask = s.soft_money_ask = True
            s.add("money_ask", pay[:2] + _spans(PAY_DESTINATION, sent)[:1] + _spans(PRE_ARRIVAL, sent)[:1])
            continue
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
        trigger_sents.append(t)  # a money ask spread across sentences is never platform-routed
    s.platform_flow_only = bool(trigger_sents) and all(_platform_routed(x) for x in trigger_sents)
    if s.platform_flow_only:
        s.add("platform_flow", [m.group() for x in trigger_sents for m in PLATFORM_FLOW.finditer(x)][:3])
    s.card_data, s.off_platform_payment = bool(card_spans), bool(rail_spans)
    s.phone_handoff = bool(PHONE_HANDOFF.search(t))
    if s.phone_handoff:
        s.add("phone_handoff", _spans(PHONE_HANDOFF, t)[:1])
    # A card or rail mention inside a reassuring clause counts only when it is not the reassurance's own object: "we
    # never ask for your card details" is a reminder, "you won't be charged until we receive your card number" is not.
    # Round 4 (A11): any card word used to trigger the banner floor, warning genuine security reminders.
    s.reassured_sensitive = (not (card_spans or rail_spans) and bool(sensitive_in_calm)) or (shadow_ask and not s.money_ask)
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
