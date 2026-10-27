"""HTTP API (FastAPI).

Run the demo console:  STAYGUARD_DEMO_MODE=1 uvicorn stayguard.api:app --port 8000  ->  http://localhost:8000

Access model
- Public: the console page, static files, /healthz, /v1/guest/verify (PIN-protected and rate-limited).
- Internal (the messaging platform, the extranet, analysts): need X-API-Key. In production mode with no key
  configured they answer 503 instead of running open.
- Demo-only (404 unless STAYGUARD_DEMO_MODE=1): issuing a PIN, the scripted attack, samples.
- Demo mode with no key configured lets the console call internal endpoints without a key (local use only).
"""

from __future__ import annotations

import hmac
import json
import threading
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__, config, db
from .logs import setup_logging
from .service import IdempotencyConflict, IdempotencyInFlight, Service, fail_closed_response

STATIC = Path(__file__).parent / "static"
_svc: Service | None = None
_svc_lock = threading.Lock()


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    setup_logging()
    svc()  # load models + feeds before the first request
    yield


app = FastAPI(
    title="StayGuard API",
    version=__version__,
    lifespan=lifespan,
    description="Stops reservation-hijack scams sent from compromised hotel accounts.",
)


def svc() -> Service:
    """One Service per process. Double-checked lock: concurrent cold requests must not each load the models and
    the 392k-domain blocklist."""
    global _svc
    if _svc is None:
        with _svc_lock:
            if _svc is None:
                _svc = Service()
    return _svc


# ---------------------------------------------------------------- access control
def internal(x_api_key: str | None = Header(default=None)) -> None:
    if config.API_KEY:
        if not x_api_key or not hmac.compare_digest(x_api_key, config.API_KEY):
            raise HTTPException(401, "missing or wrong X-API-Key")
        return
    if config.DEMO_MODE:
        return  # local demo with no key configured
    raise HTTPException(503, "STAYGUARD_API_KEY is not configured; internal endpoints are disabled")


def demo_only() -> None:
    if not config.DEMO_MODE:
        raise HTTPException(404, "Not Found")


# ---------------------------------------------------------------- rate limiting
class TokenBucket:
    """In-process token bucket per (bucket, client). Good enough for one process; use Redis for several.

    State is bounded: a client that rotates source addresses used to grow the dict without limit (review round 1). When
    full, the least recently seen half is dropped; a dropped client restarts with a full bucket, which is the same as a
    client that has been idle, so nothing is lost but memory."""

    def __init__(self, max_clients: int = 50_000) -> None:
        self.state: dict[tuple[str, str], tuple[float, float]] = {}
        self.lock = threading.Lock()
        self.max_clients = max_clients

    def allow(self, bucket: str, client: str, per_min: float, now: float | None = None) -> bool:
        if per_min <= 0:
            return True
        now = time.monotonic() if now is None else now
        cap = max(1.0, per_min / 6)  # burst = 10 seconds' worth
        with self.lock:
            tokens, last = self.state.get((bucket, client), (cap, now))
            tokens = min(cap, tokens + (now - last) * per_min / 60)
            ok = tokens >= 1
            self.state.pop((bucket, client), None)  # re-insert so dict order is least- to most-recently seen
            self.state[(bucket, client)] = (tokens - 1 if ok else tokens, now)
            if len(self.state) > self.max_clients:
                for key in list(self.state)[: len(self.state) - self.max_clients // 2]:
                    del self.state[key]
            return ok


limiter = TokenBucket()


def client_id(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def rate_limited(bucket: str, per_min: Callable[[], float]) -> Callable[[Request], None]:
    def dep(request: Request) -> None:
        if not limiter.allow(bucket, client_id(request), per_min()):
            raise HTTPException(429, "rate limit exceeded", headers={"Retry-After": "10"})

    return dep


# ---------------------------------------------------------------- security headers
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)


@app.middleware("http")
async def security_headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    resp = await call_next(request)
    resp.headers.setdefault(
        "Content-Security-Policy",
        CSP
        if not request.url.path.startswith("/docs")
        else CSP.replace("script-src 'self'", "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net")
        .replace("style-src 'self'", "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net")
        .replace("img-src 'self' data:", "img-src 'self' data: https://fastapi.tiangolo.com"),
    )
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    return resp


# ---------------------------------------------------------------- schemas
class MessageIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=5000)
    reservation_id: str | None = None
    session_id: str | None = None
    direction: Literal["hotel_to_guest", "guest_to_hotel"] = "hotel_to_guest"
    payment_terms: Literal["pay_at_property", "prepaid", "deposit", "unknown"] | None = None
    property_id: str | None = None
    message_id: str | None = Field(
        None,
        max_length=128,
        description=(
            "Idempotency key. Re-sending the same id with the same payload returns the first decision; "
            "the same id with a different payload is rejected with 409."
        ),
    )


class SessionIn(BaseModel):
    property_id: str
    user: str
    hour: int = Field(12, ge=0, le=23)
    is_new_device: bool = False
    km_from_usual: float = Field(0, ge=0)
    speed_kmh: float = Field(0, ge=0)
    new_asn: bool = False
    hosting_asn: bool = False
    reservations_viewed: int = Field(0, ge=0)
    messages_sent: int = Field(0, ge=0)
    distinct_guests_messaged: int | None = Field(None, ge=0)
    token_replay: bool = False
    failed_logins_1h: int = Field(0, ge=0)
    payout_change: bool = False


class ReadsIn(BaseModel):
    reservation_ids: list[str] = Field(..., min_length=1, max_length=5000)


class GuestVerifyIn(BaseModel):
    reservation_id: str = Field(..., max_length=32)
    pin: str = Field(..., min_length=1, max_length=6)
    text: str = Field(..., min_length=1, max_length=5000)


class ContainIn(BaseModel):
    session_id: str | None = None
    actor: str = "analyst"


class OutageIn(BaseModel):
    on: bool


# ---------------------------------------------------------------- pages
@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/healthz")
def health() -> dict[str, Any]:
    s = svc()
    return {
        "ok": True,
        "version": __version__,
        "demo_mode": config.DEMO_MODE,
        "judge_provider": s.engine.judge_provider,
        # breaker state is internal only (/v1/metrics): on the public health check it told an attacker exactly when
        # the judges were down (review round 2, A5)
        "blocklist_size": s.engine.links.blocklist_size,
    }


# ---------------------------------------------------------------- internal API
@app.post(
    "/v1/messages/check", dependencies=[Depends(internal), Depends(rate_limited("check", lambda: config.RATE_CHECK_PER_MIN))]
)
def check_message(body: MessageIn) -> dict[str, Any]:
    try:
        return svc().check_message(**body.model_dump())
    except IdempotencyInFlight:
        raise HTTPException(409, "message_id is still being processed; retry shortly", headers={"Retry-After": "1"}) from None
    except IdempotencyConflict:
        raise HTTPException(409, "message_id was already used for a different message") from None


@app.post("/v1/sessions/score", dependencies=[Depends(internal)])
def score_session(body: SessionIn) -> dict[str, Any]:
    ev = body.model_dump(exclude={"property_id", "user"})
    if ev["distinct_guests_messaged"] is None:
        ev.pop("distinct_guests_messaged")
    return svc().score_session(body.property_id, body.user, ev)


@app.post("/v1/sessions/{session_id}/reads", dependencies=[Depends(internal)])
def record_reads(session_id: str, body: ReadsIn) -> dict[str, Any]:
    if not db.con().execute("SELECT 1 FROM sessions WHERE id=?", (session_id,)).fetchone():
        raise HTTPException(404, "unknown session")
    return {"recorded": svc().record_reads(session_id, body.reservation_ids)}


@app.post("/v1/properties/{property_id}/contain", dependencies=[Depends(internal)])
def contain(property_id: str, body: ContainIn) -> dict[str, Any]:
    try:
        return svc().contain(property_id, body.session_id, body.actor)
    except KeyError:
        raise HTTPException(404, "unknown property") from None
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None


@app.post("/v1/properties/{property_id}/recovered", dependencies=[Depends(internal)])
def recovered(property_id: str, body: ContainIn) -> dict[str, Any]:
    """Analyst confirms the password reset and passkey enrolment happened; new sessions are then scored normally."""
    try:
        return svc().recover_property(property_id, body.actor)
    except KeyError:
        raise HTTPException(404, "unknown property") from None


@app.get("/v1/properties/{property_id}/reservations", dependencies=[Depends(internal)])
def reservations(
    property_id: str, limit: int = Query(25, ge=1, le=200), terms: str | None = None, offset: int = Query(0, ge=0)
) -> list[dict[str, Any]]:
    rows = svc().upcoming(property_id, limit=limit, terms=terms, offset=offset)
    return [{k: v for k, v in r.items() if k not in ("pin_salt", "pin_hash")} for r in rows]


@app.get("/v1/reservations/{rid}/notices", dependencies=[Depends(internal)])
def notices(rid: str) -> list[dict[str, Any]]:
    return [dict(r) for r in db.con().execute("SELECT * FROM guest_notices WHERE reservation_id=? ORDER BY created DESC", (rid,))]


@app.get("/v1/messages", dependencies=[Depends(internal)])
def messages(limit: int = Query(50, ge=1, le=500)) -> list[dict[str, Any]]:
    # `text` is the PII-masked text; raw text (if retained at all) is never served
    rows = db.con().execute(
        "SELECT id, created, property_id, reservation_id, session_id, direction, text, decision, reasons, path "
        "FROM messages ORDER BY created DESC LIMIT ?",
        (limit,),
    )
    return [{**dict(r), "reasons": json.loads(r["reasons"])} for r in rows]


@app.get("/v1/cases", dependencies=[Depends(internal)])
def cases() -> list[dict[str, Any]]:
    return svc().cases()


@app.get("/v1/metrics", dependencies=[Depends(internal)])
def metrics() -> dict[str, Any]:
    s = svc()
    out: dict[str, Any] = {
        "live": s.engine.metrics.snapshot(s.engine.judge_provider),
        "breaker": s.engine.breaker.state,
        "dataset": db.dataset_facts(),
        "blocklist_size": s.engine.links.blocklist_size,
        "classifier": s.engine.clf.report,
        "session_model": s.sessions.report,
    }
    rep = config.EVAL_DIR / "report.json"
    if rep.exists():
        out["evaluation"] = json.loads(rep.read_text())
    return out


@app.get("/v1/audit", dependencies=[Depends(internal)])
def audit(limit: int = Query(50, ge=1, le=500)) -> list[dict[str, Any]]:
    return db.audit_tail(limit)


@app.get("/v1/audit/verify", dependencies=[Depends(internal)])
def audit_verify() -> dict[str, Any]:
    return db.audit_verify()


@app.post("/v1/admin/llm-outage", dependencies=[Depends(internal)])
def llm_outage(body: OutageIn) -> dict[str, Any]:
    s = svc()
    s.engine.breaker.forced_outage = body.on
    db.audit("admin.llm_outage", {"on": body.on})
    return {"breaker": s.engine.breaker.state}


# ---------------------------------------------------------------- public: guest check
@app.post("/v1/guest/verify", dependencies=[Depends(rate_limited("guest", lambda: config.RATE_GUEST_PER_MIN))])
def guest_verify(body: GuestVerifyIn, request: Request) -> dict[str, Any]:
    return svc().guest_verify(body.reservation_id, body.pin, body.text, client=client_id(request))


# ---------------------------------------------------------------- demo only
SAMPLE_IDS = ["g002", "g019", "g031", "g046", "g054", "g121", "g124", "g126", "g138", "g102", "g035", "g010"]


@app.get("/v1/samples", dependencies=[Depends(demo_only)])
def samples() -> list[dict[str, Any]]:
    """A few messages from the dev golden set for the console's 'Check a message' tab."""
    rows = [
        json.loads(line)
        for line in (config.DATA_CURATED / "golden_eval.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    by_id = {r["id"]: r for r in rows}
    return [by_id[i] for i in SAMPLE_IDS if i in by_id]


@app.post("/v1/reservations/{rid}/demo-pin", dependencies=[Depends(demo_only), Depends(internal)])
def demo_pin(rid: str) -> dict[str, Any]:
    """Issue a fresh PIN for a reservation and return it once. Stands in for the platform showing the guest their
    PIN in the app; PINs are stored hashed, so there is no way to read an existing one."""
    pin = svc().issue_pin(rid)
    if pin is None:
        raise HTTPException(404)
    return {"reservation_id": rid, "pin": pin}


@app.post("/v1/demo/simulate-attack", dependencies=[Depends(demo_only), Depends(internal)])
def simulate(property_id: str = "H2") -> dict[str, Any]:
    t0 = time.perf_counter()
    out = svc().simulate_attack(property_id)
    out["elapsed_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return out


@app.exception_handler(RequestValidationError)
def _invalid(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Validation errors never echo the submitted values: they can hold message text and PII, and a lone surrogate in
    the echo crashed the error renderer itself with a 500 (review round 1). A message text that cannot be decoded is a
    message we cannot check, so the check endpoint holds it rather than returning an error a caller might ignore."""
    errors = [{"loc": list(e.get("loc", ())), "type": e.get("type", ""), "msg": e.get("msg", "")} for e in exc.errors()]
    if request.url.path == "/v1/messages/check" and any(e["type"] == "string_unicode" for e in errors):
        return JSONResponse(fail_closed_response(None, "UndecodableText"), status_code=200)
    return JSONResponse({"detail": errors}, status_code=422)


@app.exception_handler(Exception)
def _err(_: Request, exc: Exception) -> JSONResponse:  # never leak stack traces to clients
    return JSONResponse({"error": "internal_error", "detail": type(exc).__name__}, status_code=500)
