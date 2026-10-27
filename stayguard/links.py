"""Link checker.

Two layers:
1. Reputation: exact host match against 392k live phishing domains (Phishing.Database) + the OpenPhish feed.
2. Heuristics for links nobody has reported yet: brand look-alikes (booking.com-hotela.eu), typosquats
   (b00king, bookimg), punycode, risky TLDs, free site builders, shorteners, raw IPs, lure words.
   Popularity (top-10k domains) pulls the score down to keep false alarms low.

Layer 2 is what matters on day zero, so the evaluation holds back a slice of the real Booking-themed
phishing domains from layer 1 and measures how many layer 2 still catches.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from rapidfuzz import fuzz

from . import config
from .domains import EXTRACT as _EXTRACT
from .domains import host_of, is_numeric_ip_host, is_public_host, registered_domain

# "hotels" and "kayak" are deliberately absent: fuzzy-matching them would flag every hotel's own site.
BRANDS = {
    "booking": "booking.com",
    "airbnb": "airbnb.com",
    "agoda": "agoda.com",
    "expedia": "expedia.com",
    "priceline": "priceline.com",
    "tripadvisor": "tripadvisor.com",
}
# brand tokens that are allowed to appear inside hostnames only as fuzzy look-alikes (too generic as substrings)
SUBSTRING_BRANDS = ("booking", "boking", "bookng", "bkng", "airbnb", "agoda", "expedia", "priceline")
BRAND_SAFE_SUFFIXES = {"com", "net", "org"}
BRAND_OWNED = {
    "expediapartnercentral.com",
    "expediagroup.com",
    "vrbo.com",
    "hotels.com",
    "trivago.com",
    "airbnb.com",
    "agoda.net",
    "booking.net",
    "tripadvisor.com",
    "skyscanner.net",
    "workingatbooking.com",
    "bookingholdings.com",
}
INSTITUTIONAL = ("edu", "gov", "mil", "int", "ac.uk", "gov.uk", "ac.in", "gov.in", "edu.au", "gov.pt", "gc.ca")
RISKY_TLDS = {
    "xyz",
    "top",
    "live",
    "quest",
    "icu",
    "click",
    "link",
    "help",
    "lol",
    "rentals",
    "homes",
    "world",
    "shop",
    "online",
    "site",
    "sbs",
    "cfd",
    "buzz",
    "rest",
    "bar",
    "cyou",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "pw",
    "su",
    "fun",
    "space",
    "website",
    "today",
    "support",
    "services",
    "guide",
    "store",
    "info",
    "zip",
    "mov",
}
FREE_HOSTING = (
    "vercel.app",
    "netlify.app",
    "webflow.io",
    "framer.app",
    "framer.website",
    "000webhostapp.com",
    "pages.dev",
    "workers.dev",
    "github.io",
    "firebaseapp.com",
    "web.app",
    "glitch.me",
    "weebly.com",
    "wixsite.com",
    "blogspot.com",
    "ngrok.io",
    "ngrok-free.app",
    "trycloudflare.com",
    "herokuapp.com",
    "onrender.com",
    "replit.app",
    "repl.co",
    "surge.sh",
    "sites.google.com",
    "forms.gle",
    "carrd.co",
    "square.site",
    "godaddysites.com",
    "mystrikingly.com",
    "eu.org",
    "duckdns.org",
    "kalit.ai",
)
SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "cutt.ly",
    "is.gd",
    "rb.gy",
    "shorturl.at",
    "ow.ly",
    "t.ly",
    "tiny.cc",
    "s.id",
    "rebrand.ly",
    "bl.ink",
    "v.gd",
    "qrco.de",
    "lnkd.in",
    "shorte.st",
    "tr.im",
    "buff.ly",
}
# Popular services where anyone can publish a page or form. Their domains are in the top-10k list, so without this the
# popularity discount made `docs.google.com/forms/...` or a public cloud-storage page "safe" (review round 1).
USER_CONTENT_HOSTS = (
    "docs.google.com",
    "drive.google.com",
    "storage.googleapis.com",
    "firebasestorage.googleapis.com",
    "googleusercontent.com",
    "s3.amazonaws.com",
    "amazonaws.com",
    "blob.core.windows.net",
    "dropbox.com",
    "dropboxusercontent.com",
    "onedrive.live.com",
    "1drv.ms",
    "sharepoint.com",
    "notion.site",
    "canva.site",
    "linktr.ee",
    "wetransfer.com",
    "we.tl",
    "box.com",
    "mediafire.com",
    "mega.nz",
    "forms.office.com",
    "jotform.com",
    "typeform.com",
    "airtable.com",
    "t.me",
    "wa.me",
)
# Country TLDs that are free or heavily abused; a brand name on them is never assumed to be the brand's own site.
ABUSED_CCTLDS = {"tk", "ml", "ga", "cf", "gq", "cm", "ws", "cc", "to", "nu", "la", "pw", "su"}
KNOWN_SAFE_HOSTS = {"maps.app.goo.gl", "goo.gl"}  # google maps share links (path-checked below)
LURE_WORDS = re.compile(
    r"verif|confirm|secure|check-?in|checkin|extranet|admin|guest|payment|pay|login|signin|"
    r"account|update|refund|support|help|invoice|id\d{3,}|reserv|arrival|card|wallet|unlock",
    re.IGNORECASE,
)


def _load_lines(path: Path) -> set[str]:
    if not path.exists():
        return set()
    with open(path, encoding="utf-8", errors="ignore") as f:
        return {ln.strip().lower() for ln in f if ln.strip() and not ln.startswith("#")}


@lru_cache(maxsize=1)
def _top_domains() -> frozenset[str]:
    return frozenset(_load_lines(config.TOP_DOMAINS))


@lru_cache(maxsize=1)
def _raw_blocklist() -> frozenset[str]:
    hosts = _load_lines(config.PHISH_DOMAINS)
    for url in _load_lines(config.OPENPHISH):
        h = urlsplit(url if "://" in url else "http://" + url).hostname
        if h:
            hosts.add(h.lower())
    # Never let a feed error block a popular or official domain outright.
    top = _top_domains()
    return frozenset(
        h
        for h in hosts
        if h not in top and registered_domain(h) not in config.OFFICIAL_DOMAINS and h.removeprefix("www.") not in top
    )


@dataclass
class LinkVerdict:
    url: str
    host: str
    registered_domain: str
    verdict: str  # official | safe | unknown | suspicious | malicious
    score: float
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "host": self.host,
            "registered_domain": self.registered_domain,
            "verdict": self.verdict,
            "score": round(self.score, 3),
            "reasons": self.reasons,
        }


EMBEDDED_URL = re.compile(r"(?:https?|hxxps?)://[^\s&#]+", re.IGNORECASE)
PARAM_VALUE = re.compile(r"[?&#;](?:[\w.-]*=)?([^&#\s]+)")


def embedded_targets(url: str) -> list[str]:
    """Other URLs a link carries, wherever they are: in the path (`/redirect/https://evil`), the query string, the
    fragment (`#https://evil`), or as a scheme-less parameter value (`google.com/url?q=evil.net/x`). Review round 1:
    only the query string used to be checked, so path and fragment redirects on official domains passed as official."""
    host = host_of(url)
    rest = unquote(url.split(host, 1)[1] if host and host in url.lower() else url)
    rest = rest[rest.find("/") :] if "/" in rest else rest
    out = EMBEDDED_URL.findall(rest)
    for m in PARAM_VALUE.finditer(rest):
        v = m.group(1)
        if "://" not in v and "." in v and is_public_host(host_of(v)):
            out.append(v)
    return out


class LinkChecker:
    def __init__(self, exclude_hosts: set[str] | None = None, use_blocklist: bool = True, extra_official: set[str] | None = None):
        self.exclude = {h.lower() for h in (exclude_hosts or set())}
        self.use_blocklist = use_blocklist
        self.official = set(config.OFFICIAL_DOMAINS) | {d.lower() for d in (extra_official or set())}

    @property
    def blocklist_size(self) -> int:
        return len(_raw_blocklist())

    def _blocklisted(self, host: str) -> bool:
        if not self.use_blocklist:
            return False
        bl = _raw_blocklist()
        parts = host.split(".")
        for i in range(len(parts) - 1):
            cand = ".".join(parts[i:])
            if cand in bl and cand not in self.exclude:
                return True
        return False

    def check(self, url: str, property_domains: set[str] | None = None) -> LinkVerdict:
        """Check a link. If it carries another URL in its query string (an open redirect, even on an official
        domain), the embedded URL is checked too and the worse verdict wins."""
        outer = self._check(url, property_domains)
        inner_urls = embedded_targets(url)
        worst = outer
        for inner in inner_urls[:3]:
            v = self._check(inner, property_domains)
            if v.score > worst.score or (worst.verdict == "official" and v.verdict != "official"):
                worst = LinkVerdict(
                    url, outer.host, outer.registered_domain, v.verdict, max(v.score, 0.3), [f"REDIRECTS_TO:{v.host}", *v.reasons]
                )
        return worst

    def _check(self, url: str, property_domains: set[str] | None = None) -> LinkVerdict:
        host = host_of(url)
        rd = registered_domain(host) if host else ""
        reasons: list[str] = []
        official = self.official | {d.lower() for d in (property_domains or set())}

        if not host:
            return LinkVerdict(url, host, rd, "unknown", 0.3, ["UNPARSEABLE_URL"])
        if rd in official or host in official:
            return LinkVerdict(url, host, rd, "official", 0.0, ["OFFICIAL_DOMAIN"])
        ext = _EXTRACT(host)
        last = (ext.suffix or "").rsplit(".", 1)[-1]
        if (
            ext.domain in BRANDS
            and (
                ext.suffix in BRAND_SAFE_SUFFIXES
                or len(ext.suffix) == 2
                or re.fullmatch(r"(?:co|com)\.[a-z]{2}", ext.suffix or "")
            )
            and last not in ABUSED_CCTLDS
            and last not in RISKY_TLDS
            and not self._blocklisted(host)
        ):
            # airbnb.es, expedia.co.in: usually the brand's own country site. Vouched for (safe) only when the domain is
            # also in the popularity list; otherwise "unknown" (0.3), so a message using it is never delivered without a
            # warning. Review round 1 showed booking.tk / airbnb.cm being trusted on the strength of the name alone.
            if rd in _top_domains() or host in _top_domains():
                return LinkVerdict(url, host, rd, "safe", 0.05, ["BRAND_OWNED_DOMAIN"])
            return LinkVerdict(url, host, rd, "unknown", 0.3, ["BRAND_COUNTRY_DOMAIN"])
        if rd in BRAND_OWNED:
            return LinkVerdict(url, host, rd, "safe", 0.05, ["BRAND_OWNED_DOMAIN"])
        if self._blocklisted(host):
            return LinkVerdict(url, host, rd, "malicious", 1.0, ["KNOWN_PHISHING_DOMAIN"])
        if host in KNOWN_SAFE_HOSTS and ("/maps" in url or host == "maps.app.goo.gl"):
            return LinkVerdict(url, host, rd, "safe", 0.05, ["MAPS_LINK"])

        score = 0.0
        # integer / hex / octal forms count too (http://3627734734/ resolves like http://216.58.214.206/)
        is_ip = is_numeric_ip_host(host)
        if is_ip:
            score += 0.6
            reasons.append("RAW_IP_ADDRESS")

        labels = host.split(".")
        tld = labels[-1] if labels else ""

        # brand inside a hostname that the brand does not own
        if not is_ip:
            hn = host.replace("0", "o").replace("1", "l")
            brand_hit = next((b for b in SUBSTRING_BRANDS if b in hn), None)
            if brand_hit:
                # "booking" is also an ordinary word (trybooking.com, safaribookings.com). It only counts as brand
                # abuse when it stands alone as a token: booking-checkin.com, account.booking-extranet.eu.
                standalone = re.search(rf"(?:^|[.\-_\d]){brand_hit}s?(?:$|[.\-_\d])", hn)
                if standalone:
                    score += 0.55
                    reasons.append("BRAND_IN_FOREIGN_DOMAIN")
                else:
                    score += 0.15
                    reasons.append("BRAND_WORD_IN_DOMAIN")
            if re.search(r"(?:booking|airbnb|agoda|expedia|priceline)\.com[-.]", host) and not host.endswith(".booking.com"):
                score += 0.25
                reasons.append("DOMAIN_IN_SUBDOMAIN")
            # typosquat of a brand label (bookimg, bookinq, b0oking) - fuzzy on every label
            if not brand_hit:
                tokens = [t for lab in labels[:-1] for t in [lab, *re.split(r"[-_]", lab)]]
                for lab in tokens:
                    for b in BRANDS:
                        if len(lab) >= 5 and lab != b and fuzz.ratio(lab, b) >= 80:
                            score += 0.45  # needs one more signal to reach 'suspicious' (brookings.edu is not booking)
                            reasons.append("TYPOSQUAT")
                            break
                    if "TYPOSQUAT" in reasons:
                        break
            if "xn--" in host or not host.isascii():
                try:
                    decoded = host if not host.isascii() else host.encode().decode("idna")
                except UnicodeError:
                    decoded = host
                labels_dec = decoded.split(".")[:-1] or [decoded]
                spoof = any(
                    any("a" <= ch <= "z" for ch in lab) and any("\u0370" <= ch <= "\u04ff" for ch in lab) for lab in labels_dec
                )  # one label mixing Latin with Greek/Cyrillic look-alikes
                if spoof:  # bооking.com with Cyrillic о
                    score += 0.45
                    reasons.append("PUNYCODE_MIXED_SCRIPT")
                else:  # a genuine Cyrillic / Hindi / Chinese domain
                    score += 0.1
                    reasons.append("INTERNATIONAL_DOMAIN")
            if tld in RISKY_TLDS:
                score += 0.2
                reasons.append("RISKY_TLD")
            if any(host == fh or host.endswith("." + fh) for fh in FREE_HOSTING):
                score += 0.25
                reasons.append("FREE_SITE_BUILDER")
            if rd in SHORTENERS or host in SHORTENERS:
                score += 0.35
                reasons.append("URL_SHORTENER_HIDES_DESTINATION")
            if any(host == uc or host.endswith("." + uc) for uc in USER_CONTENT_HOSTS):
                score += 0.35
                reasons.append("USER_CONTENT_HOST")
            lure = set(m.group().lower() for m in LURE_WORDS.finditer(host))
            if lure:
                score += min(0.3, 0.15 * len(lure))
                reasons.append("LURE_WORDS_IN_HOST")
            if host.replace("xn--", "").count("-") >= 2 or re.search(r"\d{4,}", host):
                score += 0.1
                reasons.append("MACHINE_GENERATED_LOOK")
            if (ext.suffix or "") in INSTITUTIONAL or (ext.suffix or "").split(".")[0] in ("edu", "gov", "ac"):
                score -= 0.3
                reasons.append("INSTITUTIONAL_DOMAIN")
            popular = rd in _top_domains() or host in _top_domains()
            hosted = any(r in reasons for r in ("FREE_SITE_BUILDER", "URL_SHORTENER_HIDES_DESTINATION", "USER_CONTENT_HOST"))
            if popular and not hosted:
                score -= 0.35
                reasons.append("POPULAR_DOMAIN")
            elif not popular:
                score += 0.1
                reasons.append("UNKNOWN_DOMAIN")
        if url.lower().startswith("http://"):
            score += 0.05
            reasons.append("NO_HTTPS")

        score = max(0.0, min(1.0, score))
        verdict = "suspicious" if score >= 0.6 else ("unknown" if score >= 0.3 else "safe")
        if verdict == "suspicious" and any(
            r in reasons for r in ("BRAND_IN_FOREIGN_DOMAIN", "TYPOSQUAT", "PUNYCODE_MIXED_SCRIPT")
        ):
            verdict = "malicious"
        return LinkVerdict(url, host, rd, verdict, score, reasons)
