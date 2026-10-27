"""Session-risk floors and features, the database (PINs, audit chain, anchors, retention, schema migration,
seeding) and configuration validation."""

from __future__ import annotations

import json
import sqlite3

import pytest

from stayguard import config, db
from stayguard.session_risk import SessionRiskModel, featurise

NORMAL = {"hour": 10, "is_new_device": False, "km_from_usual": 2, "speed_kmh": 0, "reservations_viewed": 8, "messages_sent": 2}


# ---------------------------------------------------------------------------------------------- session risk
@pytest.fixture(scope="module")
def model():
    return SessionRiskModel()


@pytest.mark.parametrize(
    ("event", "reason", "floor"),
    [
        ({"token_replay": True, "new_asn": True}, "SESSION_TOKEN_REPLAYED_FROM_NEW_NETWORK", 0.95),
        ({"speed_kmh": 5000}, "IMPOSSIBLE_TRAVEL", 0.8),
        ({"payout_change": True, "is_new_device": True}, "PAYOUT_CHANGE_FROM_NEW_DEVICE", 0.9),
        ({"is_new_device": True, "reservations_viewed": 120}, "NEW_DEVICE_BULK_RESERVATION_READ", 0.75),
        ({"is_new_device": True, "km_from_usual": 3000}, "NEW_DEVICE_NEW_COUNTRY", 0.7),
    ],
)
def test_hard_rule_floors(model, event, reason, floor):
    s = model.score({**NORMAL, **event})
    assert reason in s.reasons and s.risk >= floor and s.rule_floor >= floor


def test_replay_on_same_network_is_not_a_takeover_floor(model):
    s = model.score({**NORMAL, "token_replay": True})
    assert "SESSION_TOKEN_REPLAYED_FROM_NEW_NETWORK" not in s.reasons


def test_normal_login_is_normal(model):
    s = model.score(NORMAL)
    assert s.level == "normal" and s.risk < config.SESSION_RISKY


def test_levels_follow_thresholds(model):
    crit = model.score({**NORMAL, "token_replay": True, "hosting_asn": True})
    assert crit.level == "critical"


def test_batch_equals_single(model):
    evs = [NORMAL, {**NORMAL, "hour": 3}, {**NORMAL, "speed_kmh": 9000, "is_new_device": True}]
    batch = model.score_many(evs)
    for ev, b in zip(evs, batch, strict=True):
        assert model.score(ev).as_dict() == b.as_dict()


@pytest.mark.parametrize(("hour", "offset"), [(7, 0.0), (23, 0.0), (12, 0.0), (3, 4.0), (0, 1.0), (6, 1.0)])
def test_hour_offset_boundaries(hour, offset):
    assert featurise({"hour": hour})["hour_offset"] == offset


def test_featurise_zero_reads_and_defaults():
    f = featurise({})
    assert f["guest_fanout"] == 0.0 and f["hour_offset"] == 0.0 and f["token_replay"] == 0.0


# ---------------------------------------------------------------------------------------------- fresh database
@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "t.db")
    yield tmp_path / "t.db"


def test_pins_are_random_hashed_and_verifiable(fresh_db):
    c = db.con()
    c.execute("INSERT INTO reservations (id) VALUES ('R1'), ('R2')")
    with db.tx() as t:
        p1 = db.set_pin(t, "R1")
        db.set_pin(t, "R2")
    cols = [r[1] for r in c.execute("PRAGMA table_info(reservations)")]
    assert "pin" not in cols
    rows = {r["id"]: r for r in c.execute("SELECT * FROM reservations")}
    assert p1 not in json.dumps([dict(r) for r in rows.values()])  # no plaintext anywhere in the row
    assert db.pin_matches(p1, rows["R1"]["pin_salt"], rows["R1"]["pin_hash"])
    wrong = next(p for p in ("0000", "1111") if p != p1)
    assert not db.pin_matches(wrong, rows["R1"]["pin_salt"], rows["R1"]["pin_hash"])
    assert not db.pin_matches(p1, None, None)
    assert rows["R1"]["pin_salt"] != rows["R2"]["pin_salt"]


def test_pins_do_not_follow_a_seeded_rng(fresh_db, monkeypatch):
    import random

    # Re-seeding Python's random module (what made the old PINs predictable) must not make PINs repeat.
    random.seed(42)
    first = [db.new_pin() for _ in range(20)]
    random.seed(42)
    second = [db.new_pin() for _ in range(20)]
    assert first != second
    pins = {db.new_pin() for _ in range(200)}
    assert len(pins) > 150 and all(len(p) == 4 and p.isdigit() for p in pins)


def tamper(sql):
    c = db.con()
    c.execute("DROP TRIGGER audit_no_update")
    c.execute("DROP TRIGGER audit_no_delete")
    c.execute(sql)


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE audit SET payload='{\"x\": 999}' WHERE seq=2",
        "DELETE FROM audit WHERE seq=2",
        "UPDATE audit SET ts=ts+1 WHERE seq=3",
    ],
    ids=["edited", "missing", "reordered"],
)
def test_audit_verify_detects_tampering(fresh_db, monkeypatch, sql):
    monkeypatch.setattr(config, "AUDIT_ANCHOR_EVERY", 0)
    for i in range(4):
        db.audit("t", {"x": i})
    assert db.audit_verify()["ok"]
    tamper(sql)
    assert not db.audit_verify()["ok"]


def test_audit_triggers_block_update_and_delete(fresh_db):
    db.audit("t", {"x": 1})
    for sql in ("UPDATE audit SET kind='y'", "DELETE FROM audit"):
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            db.con().execute(sql)


def test_anchors_catch_a_rewritten_chain(fresh_db, monkeypatch):
    monkeypatch.setattr(config, "AUDIT_ANCHOR_EVERY", 2)
    for i in range(4):
        db.audit("t", {"x": i})
    assert db.audit_verify()["anchors_checked"] == 2
    # rewrite the whole chain consistently (what an attacker with file access could do) ...
    c = db.con()
    c.execute("DROP TRIGGER audit_no_update")
    prev = "GENESIS"
    for r in c.execute("SELECT seq, ts, kind FROM audit ORDER BY seq").fetchall():
        body = json.dumps({"x": "forged"})
        h = db._h(prev, r["ts"], r["kind"], body)
        c.execute("UPDATE audit SET payload=?, prev_hash=?, hash=? WHERE seq=?", (body, prev, h, r["seq"]))
        prev = h
    # ... the chain is self-consistent again, but the anchor file still remembers the real heads
    v = db.audit_verify()
    assert not v["ok"] and v["reason"] == "anchor_mismatch"


def test_anchor_without_rows(fresh_db):
    assert db.anchor_audit() is None


def test_purge_raw_text(fresh_db):
    c = db.con()
    c.execute("INSERT INTO messages (id, created, text, raw_text) VALUES ('old', 0, 'm', 'raw'), ('new', ?, 'm', 'raw')", (9e12,))
    assert db.purge_raw_text() == 1
    rows = {r["id"]: r["raw_text"] for r in c.execute("SELECT id, raw_text FROM messages")}
    assert rows == {"old": None, "new": "raw"}


def test_old_schema_is_rebuilt_but_audit_kept(tmp_path, monkeypatch):
    path = tmp_path / "old.db"
    raw = sqlite3.connect(path)
    raw.executescript(
        "CREATE TABLE reservations (id TEXT, pin TEXT); INSERT INTO reservations VALUES ('R1', '1234');"
        "CREATE TABLE audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, payload TEXT, prev_hash TEXT, hash TEXT);"
        "INSERT INTO audit (ts, kind, payload, prev_hash, hash) VALUES (1, 'k', '{}', 'GENESIS', 'h');"
    )
    raw.commit()
    raw.close()
    monkeypatch.setattr(config, "DB_PATH", path)
    c = db.con()
    cols = [r[1] for r in c.execute("PRAGMA table_info(reservations)")]
    assert "pin" not in cols and "pin_hash" in cols
    assert c.execute("SELECT COUNT(*) FROM audit").fetchone()[0] == 1


def test_seed_maps_deposit_type_to_terms(fresh_db):
    out = db.seed()
    assert out["seeded"] and db.seed()["seeded"] is False
    pairs = set(db.con().execute("SELECT deposit_type, payment_terms FROM reservations").fetchall())
    assert {tuple(p) for p in pairs} <= {(k, v) for k, v in db.TERMS.items()}
    facts = db.dataset_facts()
    assert facts["reservations"] == out["reservations"] and 0 < facts["share_pay_at_property"] < 1


def test_reset_runtime_keeps_reservations_and_audit(fresh_db):
    db.seed()
    db.audit("t", {})
    db.con().execute("INSERT INTO sessions (id) VALUES ('S1')")
    db.reset_runtime()
    c = db.con()
    assert c.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    assert c.execute("SELECT COUNT(*) FROM reservations").fetchone()[0] > 0
    assert c.execute("SELECT COUNT(*) FROM audit").fetchone()[0] == 1


def test_maintenance_cli(fresh_db, capsys):
    from stayguard import maintenance

    db.audit("t", {})
    assert maintenance.main(["anchor"]) == 0
    assert maintenance.main(["verify-audit"]) == 0
    assert maintenance.main(["purge"]) == 0
    assert '"ok": true' in capsys.readouterr().out


# ---------------------------------------------------------------------------------------------- config
@pytest.mark.parametrize(
    ("env", "fragment"),
    [
        ({"STAYGUARD_LLM_TIMEOUT": "fast"}, "STAYGUARD_LLM_TIMEOUT"),
        ({"STAYGUARD_MODEL_LOW": "1.5"}, "STAYGUARD_MODEL_LOW"),
        ({"STAYGUARD_MODEL_LOW": "0.8", "STAYGUARD_MODEL_HIGH": "0.2"}, "must be below MODEL_HIGH"),
        ({"STAYGUARD_SESSION_RISKY": "0.95", "STAYGUARD_SESSION_CRITICAL": "0.9"}, "must be below SESSION_CRITICAL"),
        ({"STAYGUARD_RAW_RETENTION_DAYS": "0"}, "STAYGUARD_RAW_RETENTION_DAYS"),
    ],
)
def test_config_rejects_bad_values(monkeypatch, env, fragment):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(config.ConfigError) as ei:
        config.load_settings()
    assert fragment in str(ei.value)


def test_config_defaults_are_valid(monkeypatch):
    s = config.load_settings()
    assert 0 <= s.model_low < s.model_high <= 1 and s.session_risky < s.session_critical
