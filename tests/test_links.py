"""Link checker: reputation layer, every heuristic, and the false positives that were fixed on real data."""

from pathlib import Path

import pytest

from stayguard import config
from stayguard.domains import host_of, is_public_host, registered_domain
from stayguard.links import LinkChecker, _load_lines, _raw_blocklist, _top_domains

LC = LinkChecker()
NOBL = LinkChecker(use_blocklist=False)


@pytest.mark.parametrize(
    "url",
    ["https://www.booking.com/mybooking", "https://admin.booking.com/hotel", "https://secure.booking.com", "booking.com/x"],
)
def test_official(url):
    v = LC.check(url)
    assert v.verdict == "official" and v.score == 0.0


def test_property_domain_is_official():
    assert NOBL.check("https://www.lisboncityhotel.pt/menu", {"lisboncityhotel.pt"}).verdict == "official"
    assert LinkChecker(extra_official={"myhotel.pt"}).check("https://myhotel.pt").verdict == "official"


def test_known_phishing_host():
    v = LC.check("https://booking.com-hotela.eu/pay")
    assert v.verdict == "malicious" and v.reasons == ["KNOWN_PHISHING_DOMAIN"]


def test_excluded_host_falls_back_to_heuristics():
    v = LinkChecker(exclude_hosts={"booking.com-hotela.eu"}).check("https://booking.com-hotela.eu/pay")
    assert "KNOWN_PHISHING_DOMAIN" not in v.reasons and v.verdict == "malicious"


def test_blocklist_never_contains_popular_or_official_domains():
    bl = _raw_blocklist()
    assert not (bl & _top_domains())
    assert not any(registered_domain(h) in config.OFFICIAL_DOMAINS for h in list(bl)[:20000])


# ---------------------------------------------------------------------------------------------- heuristics
@pytest.mark.parametrize(
    ("url", "verdict", "reason"),
    [
        ("https://booking.com-hotela.eu/pay", "malicious", "DOMAIN_IN_SUBDOMAIN"),
        ("https://booking-checkin-guest.com", "malicious", "BRAND_IN_FOREIGN_DOMAIN"),
        ("https://secure-bookimg.com/verify", "malicious", "TYPOSQUAT"),
        ("https://bоoking.com/pay", "malicious", "PUNYCODE_MIXED_SCRIPT"),
        ("https://guest-verify-id4821.xyz/card", "suspicious", "RISKY_TLD"),
        ("http://185.22.1.4/pay", "suspicious", "RAW_IP_ADDRESS"),
        ("https://bit.ly/3x", "unknown", "URL_SHORTENER_HIDES_DESTINATION"),
        ("https://stay-guarantee.vercel.app/x", "unknown", "FREE_SITE_BUILDER"),
    ],
)
def test_heuristic_verdicts(url, verdict, reason):
    v = NOBL.check(url)
    assert v.verdict == verdict and reason in v.reasons, v.as_dict()


# False positives found on 100k real legit domains, fixed, and kept here as regressions.
@pytest.mark.parametrize(
    "url",
    [
        "https://airbnb.es",
        "https://expedia.co.in",
        "https://expediapartnercentral.com",
        "https://workingatbooking.com",
        "https://brookings.edu",
        "https://trybooking.com",
        "https://safaribookings.com",
        "https://xn--h1aekdm.uz",
        "https://maps.app.goo.gl/AbC123",
        "https://instagram.com/hotel",
        "https://wikipedia.org",
    ],
)
def test_legit_domains_not_flagged(url):
    assert NOBL.check(url).verdict in ("safe", "unknown"), NOBL.check(url).as_dict()


def test_typosquat_alone_needs_a_second_signal():
    v = NOBL.check("https://bookimg.com")
    assert "TYPOSQUAT" in v.reasons and v.verdict == "unknown"


def test_genuine_idn_is_low_risk():
    v = NOBL.check("https://xn--80aalfncidfg2a1bp.kz")
    assert "INTERNATIONAL_DOMAIN" in v.reasons and v.verdict in ("safe", "unknown")


def test_popular_and_institutional_lower_the_score():
    assert "POPULAR_DOMAIN" in NOBL.check("https://wikipedia.org").reasons
    assert "INSTITUTIONAL_DOMAIN" in NOBL.check("https://some-college.ac.uk").reasons


def test_http_adds_risk():
    assert "NO_HTTPS" in NOBL.check("http://hotel-alfama.com").reasons
    assert NOBL.check("http://hotel-alfama.com").score > NOBL.check("https://hotel-alfama.com").score


def test_open_redirect_on_official_domain_is_not_official():
    v = LC.check("https://www.booking.com/redirect?url=https://evil-pay.xyz/c")
    assert v.verdict != "official" and any(r.startswith("REDIRECTS_TO:") for r in v.reasons)
    encoded = LC.check("https://www.booking.com/r?u=https%3A%2F%2Fbooking-checkin-guest.com%2Fx")
    assert encoded.verdict == "malicious"


def test_unparseable_url():
    assert LC.check("http://[::1").reasons == ["UNPARSEABLE_URL"]


# ---------------------------------------------------------------------------------------------- host parsing
@pytest.mark.parametrize(
    ("url", "host"),
    [
        ("hxxps://Evil.XYZ/pay", "evil.xyz"),
        ("https://booking.com@evil-pay.xyz/x", "evil-pay.xyz"),
        ("https://booking-verify.xyz./pay", "booking-verify.xyz"),
        ("https://%62ooking-verify.com/pay", "booking-verify.com"),
        ("evil.xyz:8443/x", "evil.xyz"),
        ("http://[::1", ""),
    ],
)
def test_host_of(url, host):
    assert host_of(url) == host


@pytest.mark.parametrize(
    ("host", "ok"),
    [("evil.xyz", True), ("reserva.com.br", True), ("10.0.0.1", True), ("localhost", False), ("a.b", False), ("x.123", False)],
)
def test_is_public_host(host, ok):
    assert is_public_host(host) is ok


def test_load_lines_missing_file(tmp_path: Path):
    assert _load_lines(tmp_path / "nope.txt") == set()
