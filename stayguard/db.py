"""SQLite storage (Postgres in production; the schema is plain SQL so it ports directly).

Reservations are the REAL rows of the Hotel Booking Demand dataset (119,390 bookings at a resort hotel in the
Algarve and a city hotel in Lisbon). Changes, all for the demo: arrival years are shifted so the dataset's last year
lands next year (2017 -> 2027 when run in 2026), so some stays are always upcoming (their status becomes
Confirmed/Canceled), and guests get a synthetic display name (the dataset has
no names, by design). `deposit_type` gives the payment terms that the core rule depends on:
    No Deposit -> pay_at_property   Non Refund -> prepaid   Refundable -> deposit

Security notes
- Guest PINs come from `secrets`, and only a salted SHA-256 of each PIN is stored. A 4-digit PIN is still only
  10,000 guesses if the database leaks; the real protection is the attempt limit in `guest_attempts`.
- Messages are stored PII-masked. Raw text is kept only when `STAYGUARD_RETAIN_RAW=1`, in its own column, and
  `purge_raw_text()` deletes it after the retention period.
- Each thread gets its own connection (FastAPI runs sync endpoints in a thread pool, and one sqlite3 connection
  shared across threads is not safe for concurrent reads). Writes are still serialised through `_lock`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import random
import secrets
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pandas as pd

from . import config

SCHEMA_VERSION = 2
SCHEMA = """
CREATE TABLE IF NOT EXISTS properties (
  id TEXT PRIMARY KEY, name TEXT, city TEXT, country TEXT, domains TEXT,
  payout_frozen_until REAL DEFAULT 0, password_reset_required INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS reservations (
  id TEXT PRIMARY KEY, property_id TEXT, guest_name TEXT, guest_country TEXT, arrival_date TEXT,
  nights INTEGER, adults INTEGER, children INTEGER, deposit_type TEXT, payment_terms TEXT, adr REAL,
  total_eur REAL, market_segment TEXT, channel TEXT, status TEXT,
  pin_salt TEXT, pin_hash TEXT, pin_rotated_at REAL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_res_prop ON reservations(property_id, arrival_date);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, property_id TEXT, user TEXT, created REAL, event TEXT, risk REAL, level TEXT,
  reasons TEXT, status TEXT DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS reservation_reads (
  session_id TEXT, reservation_id TEXT, ts REAL, PRIMARY KEY (session_id, reservation_id)
);
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY, created REAL, property_id TEXT, reservation_id TEXT, session_id TEXT, direction TEXT,
  text TEXT, raw_text TEXT, decision TEXT, reasons TEXT, path TEXT, result TEXT
);
CREATE INDEX IF NOT EXISTS ix_msg_session ON messages(session_id);
CREATE INDEX IF NOT EXISTS ix_msg_res ON messages(reservation_id);
CREATE TABLE IF NOT EXISTS guest_notices (
  id INTEGER PRIMARY KEY AUTOINCREMENT, created REAL, reservation_id TEXT, case_id TEXT, text TEXT
);
CREATE TABLE IF NOT EXISTS guest_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, client TEXT, reservation_id TEXT, ok INTEGER
);
CREATE INDEX IF NOT EXISTS ix_attempt_res ON guest_attempts(reservation_id, ts);
CREATE INDEX IF NOT EXISTS ix_attempt_client ON guest_attempts(client, ts);
CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY, created REAL, property_id TEXT, session_id TEXT, status TEXT, summary TEXT, file TEXT
);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, payload TEXT, prev_hash TEXT, hash TEXT
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TABLE IF NOT EXISTS idempotency (key TEXT PRIMARY KEY, created REAL, payload_hash TEXT, response TEXT);
"""
RUNTIME_TABLES = (
    "properties",
    "reservations",
    "sessions",
    "reservation_reads",
    "messages",
    "guest_notices",
    "guest_attempts",
    "cases",
    "idempotency",
)

TERMS = {"No Deposit": "pay_at_property", "Non Refund": "prepaid", "Refundable": "deposit"}
MONTHS = {
    m: i
    for i, m in enumerate(
        [
            "January",
            "February",
            "March",
            "April",
            "May",
            "June",
            "July",
            "August",
            "September",
            "October",
            "November",
            "December",
        ],
        1,
    )
}
FIRST = [
    "Sarah",
    "Ahmed",
    "Priya",
    "Lukas",
    "Maria",
    "Tom",
    "Aisha",
    "João",
    "Chen",
    "Elena",
    "Rahul",
    "Sophie",
    "Omar",
    "Anna",
    "Carlos",
    "Marta",
    "Pierre",
    "Giulia",
    "Hannah",
    "Diego",
    "Inês",
    "Noah",
    "Ana",
    "Ravi",
]
LAST = ["S.", "K.", "M.", "R.", "P.", "L.", "D.", "F.", "B.", "C.", "G.", "N."]
PROPERTIES = [
    ("H1", "Algarve Resort Hotel", "Faro", "PRT", ["algarveresorthotel.pt"]),
    ("H2", "Lisbon City Hotel", "Lisbon", "PRT", ["lisboncityhotel.pt"]),
]

_lock = threading.RLock()  # serialises writes
_local = threading.local()  # one connection per thread
_init_lock = threading.Lock()
_initialised: set[str] = set()


def _connect() -> sqlite3.Connection:
    c = sqlite3.connect(config.DB_PATH, check_same_thread=False, isolation_level=None, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=10000")
    return c


def _ensure_schema(c: sqlite3.Connection) -> None:
    key = str(config.DB_PATH)
    if key in _initialised:
        return
    with _init_lock:
        if key in _initialised:
            return
        version = c.execute("PRAGMA user_version").fetchone()[0]
        has_tables = c.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='reservations'").fetchone()[0]
        if has_tables and version < SCHEMA_VERSION:
            # Old demo schema (plaintext PINs, raw message text). Rebuild everything except the audit log,
            # which is append-only by design and stays compatible.
            for tbl in RUNTIME_TABLES:
                c.execute(f"DROP TABLE IF EXISTS {tbl}")
        c.executescript(SCHEMA)
        c.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        _initialised.add(key)


def con() -> sqlite3.Connection:
    c: sqlite3.Connection | None = getattr(_local, "con", None)
    path = str(config.DB_PATH)
    if c is None or getattr(_local, "path", None) != path:
        c = _connect()
        _local.con, _local.path = c, path
    _ensure_schema(c)
    return c


@contextmanager
def tx() -> Iterator[sqlite3.Connection]:
    with _lock:
        c = con()
        c.execute("BEGIN IMMEDIATE")
        try:
            yield c
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise


# ----------------------------------------------------------------------------------------------
# PINs
# ----------------------------------------------------------------------------------------------
def new_pin() -> str:
    return f"{secrets.randbelow(10_000):04d}"


def hash_pin(pin: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{pin}".encode()).hexdigest()


def pin_matches(pin: str, salt: str | None, pin_hash: str | None) -> bool:
    if not salt or not pin_hash:
        return False
    return hmac.compare_digest(hash_pin(str(pin).strip().zfill(4), salt), pin_hash)


def set_pin(t: sqlite3.Connection, reservation_id: str) -> str:
    """Give a reservation a fresh random PIN. Returns the PIN once; only its hash is stored."""
    pin, salt = new_pin(), secrets.token_hex(8)
    t.execute(
        "UPDATE reservations SET pin_salt=?, pin_hash=?, pin_rotated_at=? WHERE id=?",
        (salt, hash_pin(pin, salt), time.time(), reservation_id),
    )
    return pin


# ----------------------------------------------------------------------------------------------
# Seeding from the real dataset
# ----------------------------------------------------------------------------------------------
def seed(force: bool = False) -> dict[str, Any]:
    c = con()
    n = c.execute("SELECT COUNT(*) FROM reservations").fetchone()[0]
    if n and not force:
        return {"reservations": n, "seeded": False}
    df = pd.read_csv(config.HOTELS_CSV)
    names = random.Random(42)  # noqa: S311 - display names only; PINs come from `secrets`
    today = time.strftime("%Y-%m-%d")
    # A fixed +10 years would leave no upcoming stays after Aug 2027; shifting relative to today keeps the demo alive.
    shift = int(time.strftime("%Y")) + 1 - int(df.arrival_date_year.max())
    rows = []
    for i, r in enumerate(df.itertuples(index=False)):
        nights = int(r.stays_in_weekend_nights + r.stays_in_week_nights)
        date = f"{int(r.arrival_date_year) + shift:04d}-{MONTHS[r.arrival_date_month]:02d}-{int(r.arrival_date_day_of_month):02d}"
        children = 0 if pd.isna(r.children) else int(r.children)
        status = r.reservation_status
        if date >= today:  # stays in the (shifted) future have not happened yet
            status = "Canceled" if r.is_canceled else "Confirmed"
        country = "UNK" if pd.isna(r.country) else str(r.country)
        salt = secrets.token_hex(8)
        rows.append(
            (
                f"R{i + 100000}",
                "H1" if r.hotel == "Resort Hotel" else "H2",
                f"{names.choice(FIRST)} {names.choice(LAST)}",
                country,
                date,
                nights,
                int(r.adults),
                children,
                r.deposit_type,
                TERMS[r.deposit_type],
                float(r.adr),
                round(float(r.adr) * max(nights, 1), 2),
                r.market_segment,
                r.distribution_channel,
                status,
                salt,
                hash_pin(new_pin(), salt),
            )
        )
    with tx() as t:
        t.execute("DELETE FROM reservations")
        t.execute("DELETE FROM properties")
        t.executemany(
            "INSERT INTO reservations (id, property_id, guest_name, guest_country, arrival_date, nights, adults, "
            "children, deposit_type, payment_terms, adr, total_eur, market_segment, channel, status, pin_salt, "
            "pin_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
        for pid, name, city, country, domains in PROPERTIES:
            t.execute(
                "INSERT INTO properties (id, name, city, country, domains) VALUES (?,?,?,?,?)",
                (pid, name, city, country, json.dumps(domains)),
            )
    return {"reservations": len(rows), "seeded": True}


def dataset_facts() -> dict[str, Any]:
    c = con()
    total = c.execute("SELECT COUNT(*) FROM reservations").fetchone()[0]
    by_terms = {r[0]: r[1] for r in c.execute("SELECT payment_terms, COUNT(*) FROM reservations GROUP BY 1")}
    by_prop = {r[0]: r[1] for r in c.execute("SELECT property_id, COUNT(*) FROM reservations GROUP BY 1")}
    countries = c.execute("SELECT COUNT(DISTINCT guest_country) FROM reservations").fetchone()[0]
    online = c.execute("SELECT COUNT(*) FROM reservations WHERE market_segment='Online TA'").fetchone()[0]
    return {
        "reservations": total,
        "by_payment_terms": by_terms,
        "by_property": by_prop,
        "guest_countries": countries,
        "share_pay_at_property": round(by_terms.get("pay_at_property", 0) / total, 4) if total else 0,
        "share_online_travel_agent": round(online / total, 4) if total else 0,
    }


# ----------------------------------------------------------------------------------------------
# Raw-text retention
# ----------------------------------------------------------------------------------------------
def purge_raw_text(now: float | None = None) -> int:
    """Delete raw message text older than the retention period. Returns rows purged."""
    cutoff = (now or time.time()) - config.RAW_RETENTION_DAYS * 86400
    with tx() as t:
        cur = t.execute("UPDATE messages SET raw_text=NULL WHERE raw_text IS NOT NULL AND created < ?", (cutoff,))
        return cur.rowcount


# ----------------------------------------------------------------------------------------------
# Tamper-evident audit log: each row hashes the previous row's hash + its own content.
# The chain catches edits, reordering and deleted rows in the middle. It cannot catch someone who drops the
# triggers and rewrites the whole chain, or who deletes rows from the end - so the head (seq, hash) is also
# appended to a separate anchor file every AUDIT_ANCHOR_EVERY rows. That raises the bar (both files must be
# forged consistently); real tamper-proofing needs an external write-once store.
# ----------------------------------------------------------------------------------------------
def _h(prev: str, ts: float, kind: str, payload: str) -> str:
    return hashlib.sha256(f"{prev}|{ts:.6f}|{kind}|{payload}".encode()).hexdigest()


def anchor_path() -> Path:
    return Path(str(config.DB_PATH) + ".anchors")


def audit(kind: str, payload: dict[str, Any]) -> str:
    with tx() as t:
        row = t.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row["hash"] if row else "GENESIS"
        ts = time.time()
        body = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
        h = _h(prev, ts, kind, body)
        cur = t.execute("INSERT INTO audit (ts, kind, payload, prev_hash, hash) VALUES (?,?,?,?,?)", (ts, kind, body, prev, h))
        seq = int(cur.lastrowid or 0)
    if config.AUDIT_ANCHOR_EVERY and seq % config.AUDIT_ANCHOR_EVERY == 0:
        anchor_audit()
    return h


def anchor_audit() -> dict[str, Any] | None:
    """Append the current head (seq, hash) to the anchor file."""
    row = con().execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
    if not row:
        return None
    entry = {"seq": row["seq"], "hash": row["hash"], "ts": time.time()}
    with _lock, open(anchor_path(), "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def audit_verify() -> dict[str, Any]:
    prev, n = "GENESIS", 0
    hashes: dict[int, str] = {}
    for r in con().execute("SELECT seq, ts, kind, payload, prev_hash, hash FROM audit ORDER BY seq"):
        if r["prev_hash"] != prev or _h(prev, r["ts"], r["kind"], r["payload"]) != r["hash"]:
            return {"ok": False, "broken_at_seq": r["seq"], "checked": n, "reason": "chain"}
        prev, n = r["hash"], n + 1
        hashes[r["seq"]] = r["hash"]
    anchors = 0
    p = anchor_path()
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            a = json.loads(line)
            anchors += 1
            if hashes.get(a["seq"]) != a["hash"]:
                return {"ok": False, "broken_at_seq": a["seq"], "checked": n, "reason": "anchor_mismatch"}
    return {"ok": True, "checked": n, "anchors_checked": anchors, "head": prev}


def audit_tail(limit: int = 50) -> list[dict[str, Any]]:
    rows = con().execute("SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
    return [{**dict(r), "payload": json.loads(r["payload"])} for r in rows]


def reset_runtime() -> None:
    """Demo only: clear sessions, messages, cases and notices, keeping reservations and the audit log."""
    with tx() as t:
        for tbl in ("sessions", "reservation_reads", "messages", "guest_notices", "guest_attempts", "cases", "idempotency"):
            t.execute(f"DELETE FROM {tbl}")  # noqa: S608 - tbl comes from the fixed tuple above, never from input
        t.execute("UPDATE properties SET payout_frozen_until=0, password_reset_required=0")
