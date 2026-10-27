"""Domain parsing shared by text signals and the link checker.

Uses the public-suffix list bundled with tldextract (no network), so multi-part suffixes such as `.com.br`
and `.co.uk`, and every country TLD, are recognised without a hand-maintained list.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, urlsplit

import tldextract

EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # offline: bundled public-suffix snapshot


def registered_domain(host: str) -> str:
    ext = EXTRACT(host)
    rd = ext.top_domain_under_public_suffix if hasattr(ext, "top_domain_under_public_suffix") else ext.registered_domain
    return (rd or host).lower()


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def host_of(url: str) -> str:
    """Hostname a browser would actually visit: handles hxxp, missing scheme, userinfo (`booking.com@evil.xyz`),
    percent-encoding, ports and a trailing dot."""
    u = url.strip()
    u = re.sub(r"^hxxp", "http", u, flags=re.IGNORECASE)
    if "://" not in u:
        u = "http://" + u
    try:
        host = urlsplit(u).hostname or ""
    except ValueError:
        return ""
    return unquote(host).lower().rstrip(".")


def is_public_host(host: str) -> bool:
    """True if `host` ends in a real public suffix with a registrable name in front of it (or is an IP)."""
    if not host or "." not in host:
        return False
    if is_ip(host):
        return True
    ext = EXTRACT(host)
    return bool(ext.suffix) and bool(ext.domain) and any(ch.isalpha() for ch in ext.domain)
