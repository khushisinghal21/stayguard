"""SQLite storage (Postgres in production; the schema is plain SQL so it ports directly).

Reservations are the REAL rows of the Hotel Booking Demand dataset (119,390 bookings at a resort hotel in the
Algarve and a city hotel in Lisbon). Two changes only, both for the demo: arrival dates are shifted +10 years
so some stays are upcoming, and guests get a synthetic display name (the dataset has no names, by design).
`deposit_type` gives the payment terms that the core rule depends on:
    No Deposit -> pay_at_property   Non Refund -> prepaid   Refundable -> deposit
"""
from __future__ import annotations

import hashlib
import json
import random
import sqlite3
import threading
import time
from contextlib import contextmanager

import pandas as pd

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS properties (
  id TEXT PRIMARY KEY, name TEXT, city TEXT, country TEXT, domains TEXT,
  payout_frozen_until REAL DEFAULT 0, password_reset_required INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS reservations (
  id TEXT PRIMARY KEY, property_id TEXT, guest_name TEXT, guest_country TEXT, arrival_date TEXT,
  nights INTEGER, adults INTEGER, children INTEGER, deposit_type TEXT, payment_terms TEXT, adr REAL,
  total_eur REAL, market_segment TEXT, channel TEXT, status TEXT, pin TEXT, pin_rotated_at REAL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_res_prop ON reservations(property_id, arrival_date);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, property_id TEXT, user TEXT, created REAL, event TEXT, risk REAL, level TEXT,
  reasons TEXT, status TEXT DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY, created REAL, property_id TEXT, reservation_id TEXT, session_id TEXT, direction TEXT,
  text TEXT, decision TEXT, reasons TEXT, path TEXT, result TEXT
);
CREATE INDEX IF NOT EXISTS ix_msg_session ON messages(session_id);
CREATE TABLE IF NOT EXISTS guest_notices (
  id INTEGER PRIMARY KEY AUTOINCREMENT, created REAL, reservation_id TEXT, case_id TEXT, text TEXT
);
CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY, created REAL, property_id TEXT, session_id TEXT, status TEXT, summary TEXT, file TEXT
);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, payload TEXT, prev_hash TEXT, hash TEXT
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TABLE IF NOT EXISTS idempotency (key TEXT PRIMARY KEY, created REAL, response TEXT);
"""

TERMS = {"No Deposit": "pay_at_property", "Non Refund": "prepaid", "Refundable": "deposit"}
MONTHS = {m: i for i, m in enumerate(["January", "February", "March", "April", "May", "June", "July", "August",
                                       "September", "October", "November", "December"], 1)}
FIRST = ["Sarah", "Ahmed", "Priya", "Lukas", "Maria", "Tom", "Aisha", "João", "Chen", "Elena", "Rahul", "Sophie",
         "Omar", "Anna", "Carlos", "Marta", "Pierre", "Giulia", "Hannah", "Diego", "Inês", "Noah", "Ana", "Ravi"]
LAST = ["S.", "K.", "M.", "R.", "P.", "L.", "D.", "F.", "B.", "C.", "G.", "N."]
PROPERTIES = [
    ("H1", "Algarve Resort Hotel", "Faro", "PRT", ["algarveresorthotel.pt"]),
    ("H2", "Lisbon City Hotel", "Lisbon", "PRT", ["lisboncityhotel.pt"]),
]

_lock = threading.RLock()


def connect() -> sqlite3.Connection:
    con = sqlite3.connect(config.DB_PATH, check_same_thread=False, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    return con


_con: sqlite3.Connection | None = None


def con() -> sqlite3.Connection:
    global _con
    if _con is None:
        _con = connect()
        _con.executescript(SCHEMA)
    return _con


@contextmanager
def tx():
    with _lock:
        c = con()
        c.execute("BEGIN")
        try:
            yield c
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise


def seed(force: bool = False) -> dict:
    c = con()
    n = c.execute("SELECT COUNT(*) FROM reservations").fetchone()[0]
    if n and not force:
        return {"reservations": n, "seeded": False}
    df = pd.read_csv(config.HOTELS_CSV)
    rng = random.Random(42)
    today = time.strftime("%Y-%m-%d")
    rows = []
    for i, r in enumerate(df.itertuples(index=False)):
        nights = int(r.stays_in_weekend_nights + r.stays_in_week_nights)
        date = f"{int(r.arrival_date_year) + 10:04d}-{MONTHS[r.arrival_date_month]:02d}-{int(r.arrival_date_day_of_month):02d}"
        children = 0 if pd.isna(r.children) else int(r.children)
        status = r.reservation_status
        if date >= today:  # stays in the (shifted) future have not happened yet
            status = "Canceled" if r.is_canceled else "Confirmed"
        country = "UNK" if pd.isna(r.country) else str(r.country)
        rows.append((f"R{i + 100000}", "H1" if r.hotel == "Resort Hotel" else "H2",
                     f"{rng.choice(FIRST)} {rng.choice(LAST)}", country, date, nights, int(r.adults), children,
                     r.deposit_type, TERMS[r.deposit_type], float(r.adr), round(float(r.adr) * max(nights, 1), 2),
                     r.market_segment, r.distribution_channel, status, f"{rng.randint(0, 9999):04d}"))
    with tx() as t:
        t.execute("DELETE FROM reservations")
        t.execute("DELETE FROM properties")
        t.executemany("INSERT INTO reservations (id, property_id, guest_name, guest_country, arrival_date, nights, adults, "
                      "children, deposit_type, payment_terms, adr, total_eur, market_segment, channel, status, pin) "
                      "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        for pid, name, city, country, domains in PROPERTIES:
            t.execute("INSERT INTO properties (id, name, city, country, domains) VALUES (?,?,?,?,?)",
                      (pid, name, city, country, json.dumps(domains)))
    return {"reservations": len(rows), "seeded": True}


def dataset_facts() -> dict:
    c = con()
    total = c.execute("SELECT COUNT(*) FROM reservations").fetchone()[0]
    by_terms = {r[0]: r[1] for r in c.execute("SELECT payment_terms, COUNT(*) FROM reservations GROUP BY 1")}
    by_prop = {r[0]: r[1] for r in c.execute("SELECT property_id, COUNT(*) FROM reservations GROUP BY 1")}
    countries = c.execute("SELECT COUNT(DISTINCT guest_country) FROM reservations").fetchone()[0]
    online = c.execute("SELECT COUNT(*) FROM reservations WHERE market_segment='Online TA'").fetchone()[0]
    return {"reservations": total, "by_payment_terms": by_terms, "by_property": by_prop, "guest_countries": countries,
            "share_pay_at_property": round(by_terms.get("pay_at_property", 0) / total, 4) if total else 0,
            "share_online_travel_agent": round(online / total, 4) if total else 0}


# ----------------------------------------------------------------------------------------------
# Tamper-evident audit log: each row hashes the previous row's hash + its own content.
# ----------------------------------------------------------------------------------------------
def _h(prev: str, ts: float, kind: str, payload: str) -> str:
    return hashlib.sha256(f"{prev}|{ts:.6f}|{kind}|{payload}".encode()).hexdigest()


def audit(kind: str, payload: dict) -> str:
    with tx() as t:
        row = t.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row[0] if row else "GENESIS"
        ts = time.time()
        body = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
        h = _h(prev, ts, kind, body)
        t.execute("INSERT INTO audit (ts, kind, payload, prev_hash, hash) VALUES (?,?,?,?,?)", (ts, kind, body, prev, h))
    return h


def audit_verify() -> dict:
    prev, n = "GENESIS", 0
    for r in con().execute("SELECT seq, ts, kind, payload, prev_hash, hash FROM audit ORDER BY seq"):
        if r["prev_hash"] != prev or _h(prev, r["ts"], r["kind"], r["payload"]) != r["hash"]:
            return {"ok": False, "broken_at_seq": r["seq"], "checked": n}
        prev, n = r["hash"], n + 1
    return {"ok": True, "checked": n, "head": prev}


def audit_tail(limit: int = 50) -> list[dict]:
    rows = con().execute("SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
    return [{**dict(r), "payload": json.loads(r["payload"])} for r in rows]


def reset_runtime() -> None:
    """Clear demo state (sessions, messages, cases, notices) but keep reservations and the audit log."""
    with tx() as t:
        for tbl in ("sessions", "messages", "guest_notices", "cases", "idempotency"):
            t.execute(f"DELETE FROM {tbl}")
        t.execute("UPDATE properties SET payout_frozen_until=0, password_reset_required=0")
