"""HTTP API (FastAPI). Run: uvicorn stayguard.api:app --port 8000  ->  http://localhost:8000 for the console."""
from __future__ import annotations

import json
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__, config, db
from .service import Service

STATIC = Path(__file__).parent / "static"
_svc: Service | None = None


@asynccontextmanager
async def lifespan(_app):
    svc()  # load models + feeds before the first request
    yield


app = FastAPI(title="StayGuard API", version=__version__, lifespan=lifespan,
              description="Stops reservation-hijack scams sent from compromised hotel accounts.")


def svc() -> Service:
    global _svc
    if _svc is None:
        _svc = Service()
    return _svc


def auth(x_api_key: str | None = Header(default=None)) -> None:
    if config.API_KEY and x_api_key != config.API_KEY:
        raise HTTPException(401, "missing or wrong X-API-Key")


# ---------------------------------------------------------------- schemas
class MessageIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=5000)
    reservation_id: str | None = None
    session_id: str | None = None
    direction: Literal["hotel_to_guest", "guest_to_hotel"] = "hotel_to_guest"
    payment_terms: Literal["pay_at_property", "prepaid", "deposit", "unknown"] | None = None
    property_id: str | None = None
    message_id: str | None = Field(None, description="Idempotency key. Re-sending the same id returns the first decision.")


class SessionIn(BaseModel):
    property_id: str
    user: str
    hour: int = Field(12, ge=0, le=23)
    is_new_device: bool = False
    km_from_usual: float = 0
    speed_kmh: float = 0
    new_asn: bool = False
    hosting_asn: bool = False
    reservations_viewed: int = 0
    messages_sent: int = 0
    distinct_guests_messaged: int | None = None
    token_replay: bool = False
    failed_logins_1h: int = 0
    payout_change: bool = False


class GuestVerifyIn(BaseModel):
    reservation_id: str
    pin: str = Field(..., min_length=1, max_length=6)
    text: str = Field(..., min_length=1, max_length=5000)


class ContainIn(BaseModel):
    session_id: str | None = None
    actor: str = "analyst"


class OutageIn(BaseModel):
    on: bool


# ---------------------------------------------------------------- endpoints
@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/healthz")
def health() -> dict:
    s = svc()
    return {"ok": True, "version": __version__, "judge_provider": s.engine.judge_provider,
            "breaker": s.engine.breaker.state, "blocklist_size": s.engine.links.blocklist_size}


@app.post("/v1/messages/check", dependencies=[Depends(auth)])
def check_message(body: MessageIn) -> dict:
    return svc().check_message(**body.model_dump())


@app.post("/v1/sessions/score", dependencies=[Depends(auth)])
def score_session(body: SessionIn) -> dict:
    ev = body.model_dump(exclude={"property_id", "user"})
    if ev["distinct_guests_messaged"] is None:
        ev.pop("distinct_guests_messaged")
    return svc().score_session(body.property_id, body.user, ev)


@app.post("/v1/guest/verify")
def guest_verify(body: GuestVerifyIn) -> dict:
    return svc().guest_verify(body.reservation_id, body.pin, body.text)


@app.post("/v1/properties/{property_id}/contain", dependencies=[Depends(auth)])
def contain(property_id: str, body: ContainIn) -> dict:
    try:
        return svc().contain(property_id, body.session_id, body.actor)
    except KeyError:
        raise HTTPException(404, "unknown property")


@app.get("/v1/properties/{property_id}/reservations", dependencies=[Depends(auth)])
def reservations(property_id: str, limit: int = Query(25, le=200), terms: str | None = None, offset: int = 0) -> list[dict]:
    return svc().upcoming(property_id, limit=limit, terms=terms, offset=offset)


@app.get("/v1/reservations/{rid}/notices", dependencies=[Depends(auth)])
def notices(rid: str) -> list[dict]:
    return [dict(r) for r in db.con().execute("SELECT * FROM guest_notices WHERE reservation_id=? ORDER BY created DESC", (rid,))]


@app.get("/v1/reservations/{rid}/demo-pin", dependencies=[Depends(auth)])
def demo_pin(rid: str) -> dict:
    """Demo helper so the console can fill the guest checker. Would not exist in production."""
    r = svc().reservation(rid)
    if not r:
        raise HTTPException(404)
    return {"reservation_id": rid, "pin": r["pin"]}


SAMPLE_IDS = ["g002", "g019", "g031", "g046", "g054", "g121", "g124", "g126", "g138", "g102", "g035", "g010"]


@app.get("/v1/samples")
def samples() -> list[dict]:
    """A few messages from the golden set for the console's 'Try a message' tab."""
    rows = [json.loads(l) for l in (config.DATA_CURATED / "golden_eval.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    by_id = {r["id"]: r for r in rows}
    return [by_id[i] for i in SAMPLE_IDS if i in by_id]


@app.get("/v1/messages", dependencies=[Depends(auth)])
def messages(limit: int = 50) -> list[dict]:
    rows = db.con().execute("SELECT id, created, property_id, reservation_id, session_id, direction, text, decision, reasons, path "
                            "FROM messages ORDER BY created DESC LIMIT ?", (limit,))
    return [{**dict(r), "reasons": json.loads(r["reasons"])} for r in rows]


@app.get("/v1/cases", dependencies=[Depends(auth)])
def cases() -> list[dict]:
    return svc().cases()


@app.get("/v1/metrics", dependencies=[Depends(auth)])
def metrics() -> dict:
    s = svc()
    out = {"live": s.engine.metrics.snapshot(s.engine.judge_provider), "breaker": s.engine.breaker.state,
           "dataset": db.dataset_facts(), "blocklist_size": s.engine.links.blocklist_size,
           "classifier": s.engine.clf.report, "session_model": s.sessions.report}
    rep = config.EVAL_DIR / "report.json"
    if rep.exists():
        out["evaluation"] = json.loads(rep.read_text())
    return out


@app.get("/v1/audit", dependencies=[Depends(auth)])
def audit(limit: int = 50) -> list[dict]:
    return db.audit_tail(limit)


@app.get("/v1/audit/verify", dependencies=[Depends(auth)])
def audit_verify() -> dict:
    return db.audit_verify()


@app.post("/v1/admin/llm-outage", dependencies=[Depends(auth)])
def llm_outage(body: OutageIn) -> dict:
    s = svc()
    s.engine.breaker.forced_outage = body.on
    db.audit("admin.llm_outage", {"on": body.on})
    return {"breaker": s.engine.breaker.state}


@app.post("/v1/demo/simulate-attack", dependencies=[Depends(auth)])
def simulate(property_id: str = "H2") -> dict:
    t0 = time.perf_counter()
    out = svc().simulate_attack(property_id)
    out["elapsed_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return out


@app.exception_handler(Exception)
def _err(_, exc: Exception) -> JSONResponse:  # never leak stack traces to clients
    return JSONResponse({"error": "internal_error", "detail": type(exc).__name__}, status_code=500)
