"""Network link checks: domain age over RDAP and following redirects (DECISIONS #42).

Two gaps the offline link checker cannot close: a link shortener hides where it goes, and a brand-free domain that was
registered yesterday looks exactly like an old, harmless one. Both need the network. This module is off unless
STAYGUARD_NET_CHECKS=1, and it can only make a link look worse, never better:

- follow(url): the redirect chain of a shortener or open redirector, up to MAX_HOPS, so the real destination can be
  checked by the offline rules (and its age looked up).
- domain_age(domain): days since registration, from the registry's RDAP record (via the rdap.org bootstrap).
  Registered under NEW_DOMAIN_DAYS ago -> NEWLY_REGISTERED_DOMAIN. No record -> DOMAIN_NOT_REGISTERED.

Fetching attacker-chosen URLs from a server is dangerous (server-side request forgery), so:
- only http/https on ports 80/443, no credentials in the URL, no cookies, no request body;
- the host is resolved here and every address must be public (no loopback, private, link-local, multicast or
  reserved ranges), and the connection goes to that checked address (Host header + TLS SNI carry the name), so a
  second DNS answer cannot redirect it inside the network (DNS rebinding);
- redirects are followed by this code, hop by hop, with the same checks on every hop; response bodies are never read
  except the small RDAP JSON;
- every request has a timeout, and all checks for one message share a time budget (STAYGUARD_NET_BUDGET).
Any failure (timeout, refused address, bad reply) returns "unknown" and the link keeps its offline verdict.
Results are cached for an hour.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from . import config

MAX_HOPS = 5
RDAP_BOOTSTRAP = "https://rdap.org/domain/"
CACHE_TTL_S = 3600.0
MAX_RDAP_BYTES = 256_000
USER_AGENT = "StayGuard-linkcheck/1.0 (+security screening; no tracking)"

Resolver = Callable[[str], list[str]]


class Refused(Exception):
    """The URL or the address it resolves to is not one we will connect to."""


def system_resolver(host: str) -> list[str]:
    return sorted({str(info[4][0]) for info in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)})


def public_address(addr: str) -> bool:
    ip = ipaddress.ip_address(addr)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return bool(ip.is_global) and not (ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local)


@dataclass
class AgeResult:
    status: str  # registered | unregistered | unknown
    days: float | None = None


class NetChecker:
    def __init__(
        self,
        transport: httpx.BaseTransport | None = None,
        resolver: Resolver = system_resolver,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        timeout: float | None = None,
    ) -> None:
        self.client = httpx.Client(
            transport=transport, follow_redirects=False, trust_env=False, headers={"User-Agent": USER_AGENT}
        )
        self.resolve, self.clock, self.now = resolver, clock, now
        self.timeout = config.NET_TIMEOUT_S if timeout is None else timeout
        self._cache: dict[tuple[str, str], tuple[float, Any]] = {}
        self._lock = threading.Lock()

    # -- caching -------------------------------------------------------------------------------------------------
    def _cached(self, kind: str, key: str) -> Any | None:
        with self._lock:
            hit = self._cache.get((kind, key))
            if hit and self.clock() - hit[0] < CACHE_TTL_S:
                return hit[1]
        return None

    def _store(self, kind: str, key: str, value: Any) -> Any:
        with self._lock:
            if len(self._cache) > 50_000:
                self._cache.clear()
            self._cache[(kind, key)] = (self.clock(), value)
        return value

    # -- one safe request ----------------------------------------------------------------------------------------
    def _request(self, method: str, url: str, deadline: float) -> httpx.Response:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
            raise Refused("scheme, host or credentials")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if port not in (80, 443):
            raise Refused("port")
        host = parts.hostname.lower()
        try:
            addrs = [host] if _is_ip(host) else self.resolve(host)
        except OSError as e:
            raise Refused("does not resolve") from e
        if not addrs or not all(public_address(a) for a in addrs):
            raise Refused("non-public address")
        left = deadline - self.clock()
        if left <= 0:
            raise TimeoutError("network budget spent")
        addr = addrs[0]
        netloc = f"[{addr}]" if ":" in addr else addr
        pinned = parts._replace(netloc=f"{netloc}:{port}").geturl()
        return self.client.request(
            method,
            pinned,
            headers={"Host": host, "Accept": "*/*"},
            extensions={"sni_hostname": host},  # TLS is verified against the name, while the socket goes to the checked IP
            timeout=httpx.Timeout(min(self.timeout, left)),
        )

    # -- redirects -----------------------------------------------------------------------------------------------
    def follow(self, url: str, deadline: float) -> list[str]:
        """The redirect chain starting at url (url first). Stops at MAX_HOPS, a non-redirect, or any failure."""
        cached = self._cached("follow", url)
        if cached is not None:
            return list(cached)
        chain = [url]
        try:
            while len(chain) <= MAX_HOPS:
                r = self._request("HEAD", chain[-1], deadline)
                if r.status_code in (405, 501):  # some shorteners only answer GET; the body is never read
                    r = self._request("GET", chain[-1], deadline)
                r.close()
                loc = r.headers.get("location")
                if r.status_code not in (301, 302, 303, 307, 308) or not loc:
                    break
                nxt = urljoin(chain[-1], loc)
                if nxt in chain:
                    break
                chain.append(nxt)
        except (Refused, TimeoutError, httpx.HTTPError, ValueError):
            pass  # keep what we learned so far
        return list(self._store("follow", url, tuple(chain)))

    # -- domain age ----------------------------------------------------------------------------------------------
    def domain_age(self, domain: str, deadline: float) -> AgeResult:
        cached = self._cached("age", domain)
        if cached is not None:
            return AgeResult(*cached)
        res = self._rdap(domain, deadline)
        if res.status != "unknown":  # failures are not cached: the next message may get an answer
            self._store("age", domain, (res.status, res.days))
        return res

    def _rdap(self, domain: str, deadline: float) -> AgeResult:
        url = RDAP_BOOTSTRAP + domain
        try:
            for _ in range(MAX_HOPS):
                r = self._request("GET", url, deadline)
                if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("location"):
                    url = urljoin(url, r.headers["location"])
                    r.close()
                    continue
                if r.status_code == 404:
                    return AgeResult("unregistered")
                if r.status_code != 200 or len(r.content) > MAX_RDAP_BYTES:
                    return AgeResult("unknown")
                for ev in r.json().get("events", []):
                    if ev.get("eventAction") == "registration" and ev.get("eventDate"):
                        reg = datetime.fromisoformat(str(ev["eventDate"]).replace("Z", "+00:00"))
                        if reg.tzinfo is None:
                            reg = reg.replace(tzinfo=UTC)
                        return AgeResult("registered", max(0.0, (self.now() - reg).total_seconds() / 86400))
                return AgeResult("unknown")
        except (Refused, TimeoutError, httpx.HTTPError, ValueError, KeyError, TypeError):
            return AgeResult("unknown")
        return AgeResult("unknown")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False
