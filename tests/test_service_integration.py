"""Service-level integration: real wiring, mocked externals only."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from stayguard import api, config, db
from stayguard.judges import JudgeUnavailable

ROOT = Path(__file__).resolve().parent.parent


def upcoming(service, terms="pay_at_property", n=1, offset=0):
    rows = service.upcoming("H1", limit=n, terms=terms, offset=offset)
    assert len(rows) == n
    return rows


# ---------------------------------------------------------------------------------------------- every decision
def test_every_decision_through_the_service(service):
    rid = upcoming(service)[0]["id"]
    deliver = service.check_message(text="Check-in is from 3 pm.", reservation_id=rid)
    hold = service.check_message(text="To keep your room please pay the 120 EUR deposit today", reservation_id=rid)
    block = service.check_message(text="Confirm here https://account.booking-extranet.eu/x", reservation_id=rid)
    # a shortener can't be followed offline, so it is delivered with a warning (the photo link used here before is held
    # since the de-duplicated retrain, DECISIONS #30)
    warn = service.check_message(text="Here is the guest guide: https://bit.ly/3xYz", reservation_id=rid)
    assert [deliver["decision"], warn["decision"], hold["decision"], block["decision"]] == ["deliver", "warn", "hold", "block"]
    assert hold["payment_terms"] == "pay_at_property" and hold["reservation"]["id"] == rid
    stored = db.con().execute("SELECT decision, text FROM messages WHERE id=?", (hold["message_id"],)).fetchone()
    assert stored["decision"] == "hold"


def test_degraded_path_through_the_service(service, monkeypatch):
    class Down:
        name = "down"

        def rule(self, *a):
            raise JudgeUnavailable("down")

    monkeypatch.setattr(service.engine, "judge", Down())
    monkeypatch.setattr(service.engine.clf, "score", lambda t, ctx=None: 0.35)
    out = service.check_message(text="Please let us know if you want breakfast, it is 12 EUR.", payment_terms="deposit")
    assert out["path"] == "degraded" and out["decision"] == "warn"


# ---------------------------------------------------------------------------------------------- fail closed
def test_storage_failure_fails_closed(service, monkeypatch):
    def broken_tx():
        raise RuntimeError("disk full")

    monkeypatch.setattr(db, "tx", broken_tx)
    out = service.check_message(text="My card is 4111 1111 1111 1111, check-in is at 3.")
    assert out["decision"] == "hold" and out["reasons"] == ["SYSTEM_EXCEPTION_FAIL_CLOSED"] and out["error"] == "RuntimeError"
    assert "4111" not in json.dumps(out)


def test_session_lookup_failure_fails_closed(service, monkeypatch):
    def broken(sid):
        raise RuntimeError("db gone")

    monkeypatch.setattr(service, "session", broken)
    out = service.check_message(text="Check-in is from 3 pm.", session_id="S-x")
    assert out["decision"] == "hold" and out["path"] == "fail_closed"
    last = db.audit_tail(1)[0]
    assert last["kind"] == "message.fail_closed" and last["payload"]["error"] == "RuntimeError"


def test_revoked_session_cannot_send(service):
    s = service.score_session("H1", "u", {"hour": 10})
    db.con().execute("UPDATE sessions SET status='revoked' WHERE id=?", (s["session_id"],))
    out = service.check_message(text="hello", session_id=s["session_id"])
    assert out["decision"] == "block" and out["reasons"] == ["SESSION_REVOKED"]


# ---------------------------------------------------------------------------------------------- containment
def test_containment_warns_exactly_read_and_messaged_guests(service):
    rows = service.upcoming("H1", limit=6)
    read, messaged, untouched = [r["id"] for r in rows[:3]], rows[3]["id"], [r["id"] for r in rows[4:]]
    s = service.score_session("H1", "u", {"hour": 3, "token_replay": True, "new_asn": True, "reservations_viewed": 10})
    service.record_reads(s["session_id"], read)
    service.check_message(text="Please pay the deposit today", reservation_id=messaged, session_id=s["session_id"])
    pins_before = {
        r: db.con().execute("SELECT pin_hash FROM reservations WHERE id=?", (r,)).fetchone()[0] for r in read + untouched
    }
    case = service.contain("H1", s["session_id"])["file"]
    assert set(case["guests_warned"]) == {*read, messaged}
    assert case["unattributed_reads"] == 10 - 3 and case["needs_manual_review"]
    for r in read:
        assert db.con().execute("SELECT pin_hash FROM reservations WHERE id=?", (r,)).fetchone()[0] != pins_before[r]
    for r in untouched:
        assert db.con().execute("SELECT pin_hash FROM reservations WHERE id=?", (r,)).fetchone()[0] == pins_before[r]
        assert (
            not db.con()
            .execute("SELECT 1 FROM guest_notices WHERE reservation_id=? AND case_id=?", (r, case["case_id"]))
            .fetchone()
        )
    prop = db.con().execute("SELECT payout_frozen_until, password_reset_required FROM properties WHERE id='H1'").fetchone()
    assert prop["payout_frozen_until"] > time.time() + 70 * 3600 and prop["password_reset_required"] == 1
    assert service.check_message(text="hi", session_id=s["session_id"])["reasons"] == ["SESSION_REVOKED"]
    assert db.audit_verify()["ok"]


def test_containment_unknown_property(service):
    with pytest.raises(KeyError):
        service.contain("NOPE", None)


# ---------------------------------------------------------------------------------------------- guest check
def test_rotated_pin_invalidates_the_old_one(service):
    rid = upcoming(service, offset=10)[0]["id"]
    old = service.issue_pin(rid)
    new = service.issue_pin(rid)
    text = "Breakfast is from 7."
    assert service.guest_verify(rid, new, text, client="rot")["ok"]
    if old != new:
        assert not service.guest_verify(rid, old, text, client="rot")["ok"]


def test_one_client_cannot_sweep_many_reservations(service):
    rows = service.upcoming("H1", limit=25, offset=20)
    results = [service.guest_verify(r["id"], "0000", "x", client="sweeper")["error"] for r in rows]
    assert results.count("too_many_attempts") >= 1 and results.index("too_many_attempts") <= config.GUEST_FAILS_PER_CLIENT


def test_guest_check_reports_whether_the_platform_sent_it(service):
    rid = upcoming(service, offset=50)[0]["id"]
    text = "Please pay the deposit today via https://booking-checkin-guest.com"
    service.check_message(text=text, reservation_id=rid)
    pin = service.issue_pin(rid)
    out = service.guest_verify(rid, pin, text, client="g")
    assert (
        out["sent_through_platform"]
        and out["platform_decision"] in ("hold", "block")
        and out["verdict"] in ("scam", "likely_scam")
    )
    assert service.guest_verify("R-nope", "1234", "x", client="g")["error"] == "not_found"
    assert service.issue_pin("R-nope") is None


# ---------------------------------------------------------------------------------------------- concurrency
def test_cold_concurrent_requests_build_one_service(monkeypatch):
    built = []

    class Slow:
        def __init__(self):
            time.sleep(0.05)
            built.append(1)

    monkeypatch.setattr(api, "_svc", None)
    monkeypatch.setattr(api, "Service", Slow)
    barrier = threading.Barrier(8)
    got = []

    def go():
        barrier.wait()
        got.append(api.svc())

    threads = [threading.Thread(target=go) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(built) == 1 and len({id(s) for s in got}) == 1


def test_parallel_reads_and_writes_do_not_corrupt_sqlite(service):
    errors = []
    rid = upcoming(service, offset=60)[0]["id"]

    def writer(i):
        try:
            for j in range(10):
                db.audit("stress", {"i": i, "j": j})
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    def reader():
        try:
            for _ in range(30):
                service.reservation(rid)
                db.audit_tail(5)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)] + [threading.Thread(target=reader) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors and db.audit_verify()["ok"]


# ---------------------------------------------------------------------------------------------- eval harness
def test_eval_harness_writes_the_schema_the_console_reads(tmp_path):
    env = {**os.environ, "STAYGUARD_DB": str(tmp_path / "e.db")}
    subprocess.run(  # noqa: S603 - fixed argv: this interpreter running our own eval module
        [sys.executable, "-m", "eval.evaluate", "--fast", "--out", str(tmp_path)],
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
    )
    rep = json.loads((tmp_path / "report.json").read_text())
    assert (tmp_path / "report.md").exists() and rep["fast"] is True

    # Every field the Results tab reads (stayguard/static/app.js) must exist in a real report.
    js = (ROOT / "stayguard" / "static" / "app.js").read_text()
    block = js[js.index("loaders.results = async") : js.index("loaders.audit")]
    roots = {
        "A": "A_messages",
        "B": "B_real_sms",
        "C": "C_links",
        "D": "D_sessions",
        "E": "E_cost_latency",
        "F": "F_robustness",
        "FL": "heldout_first_look",
    }
    keys = {"SYS": None, "MUT": None}
    sys_keys = re.findall(r'(\w+): "', block[block.index("const SYS") : block.index("};", block.index("const SYS"))])
    mut_keys = re.findall(r'(\w+): "', block[block.index("const MUT") : block.index("};", block.index("const MUT"))])
    keys["SYS"], keys["MUT"] = sys_keys, mut_keys
    paths = set(re.findall(r"\b(A|B|C|D|E|F|FL)\.([\w.]+(?:\[k\])?[\w.]*)", block))
    assert paths, "no report fields found in app.js"

    def resolve(obj, parts, k_values):
        if not parts:
            return True
        head, rest = parts[0], parts[1:]
        if head == "toLocaleString":
            return True
        if head.endswith("[k]"):
            name = head[:-3]
            sub = obj[name] if name else obj
            return all(resolve(sub[k], rest, k_values) for k in k_values)
        return head in obj and resolve(obj[head], rest, k_values)

    for root, path in paths:
        parts = path.split(".")
        k_values = keys["MUT"] if root == "F" else keys["SYS"] if root == "A" else list(rep["D_sessions"]["recall_at_risky"])
        assert resolve(rep[roots[root]], parts, k_values), f"app.js reads {root}.{path}, missing from report.json"
