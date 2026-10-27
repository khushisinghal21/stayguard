# Hardening plan

Branch `hardening/stayguard`, from `73b010d`. Baseline in `docs/baselines/before/`:
20 tests passing, 85% line coverage, 41 ruff errors, 15 files not ruff-formatted, 2 mypy errors.
Every Phase 1 defect below was reproduced before fixing (`docs/baselines/before/repro.txt`).

Format: **defect → fix → verification**. Status is updated as work lands.

## Phase 1 — correctness and security

1. **Predictable PINs (1.1).** Reproduced: replaying `random.Random(42)` predicted the first three PINs exactly.
   → `secrets.randbelow`, per-row salt, store `sha256(salt‖pin)` only, `hmac.compare_digest`. The demo PIN endpoint
   can no longer read a PIN, so it *issues* a fresh one (rotate + return once), as a real platform would send a PIN
   to the guest. Honest limit: a 4-digit PIN hash falls to 10k guesses if the DB leaks; the real protection is the
   attempt limit (item 11).
   → Tests: no plaintext PIN in the DB; same seed state gives unrelated PINs; verify accepts the issued PIN only.
2. **Open demo/admin endpoints (1.2).** Reproduced: `/demo-pin` returned PIN 0409 with no key; `/v1/messages` and
   `/v1/admin/llm-outage` answered 200.
   → `STAYGUARD_DEMO_MODE` (default off). Demo-only (404 when off): `demo-pin`, `simulate-attack`, `samples`.
   Internal/admin endpoints need `X-API-Key`; with demo mode off and no key configured they refuse (503, fail closed)
   rather than open. Public: `/`, static, `/healthz`, `/v1/guest/verify`.
   → Tests for every endpoint in both modes.
3. **Idempotency bypass (1.3).** Reproduced: `k1` delivered "Breakfast is from 7", then the same key with a bank
   transfer demand also returned `deliver`.
   → Store `sha256(text, reservation_id, session_id, direction)` with the key; same key + different payload → 409 and
   an audit row. Rewrite `test_idempotency` to assert the safe behaviour.
4. **Evaluation tuned on its test sets (1.4).** Confirmed from the session history: rules were changed after reading
   golden-set misses and mutation misses; link rules were changed after reading C3 false-positive examples;
   `MODEL_LOW/HIGH` were hand-set.
   → (a) Golden set frozen as `split: dev`. (b) New `data/curated/heldout_eval.jsonl`, ≥120 messages built from cited,
   publicly reported scam wordings and real hotel-message templates, committed **before** its first evaluation (commit
   hash recorded in the report). (c) **Deviation from the brief:** C3 cannot be split as 10k–60k / 60k–110k because both
   halves were read while tuning. Dev = ranks 10,001–110,000 (seen); held-out = 110,001–210,000 (never examined).
   C1 held-out = the half of the Booking-themed hosts that was never evaluated (the old C1 half becomes dev). C2 gets a
   disjoint second sample. (d) SMS split into train/calibration/test; thresholds chosen on calibration (SMS calibration +
   dev golden set) by a stated rule, saved to `eval/calibration.json` with a reliability diagram; config defaults read
   from it. (e) Report prints dev and held-out side by side; headline = held-out. Disclosure added to README and
   DECISIONS.
   → Verified by the report structure and a test that the held-out rows are never read by calibration or tuning code.
5. **Unreproducible live feeds (1.5).** → `scripts/make_manifest.py` writes `data/MANIFEST.json` (file, URL, fetch
   time, lines, SHA-256); `fetch_data.sh` calls it; the eval stores the manifest hash and `--compare` refuses
   different manifests without `--allow-drift`; `scripts/snapshot_data.sh` packs the frozen snapshot (release asset).
   → Tests for manifest creation, mismatch refusal, and `--allow-drift`.
6. **Judge errors swallowed; breaker half-open; unlocked counter (1.6).** Reproduced: a `KeyError` in the judge became
   `DEGRADED_WARN` (delivered) and counted as a provider failure.
   → Provider problems (`JudgeUnavailable`, HTTP, timeout, bad JSON/schema) → degraded policy + breaker. Anything else
   → `hold / SYSTEM_EXCEPTION_FAIL_CLOSED`, logged with traceback, breaker untouched. Half-open admits one probe.
   Counter under the metrics lock.
   → Tests with a buggy judge, a timing-out judge, a fake clock for breaker states, concurrent half-open.
7. **No top-level fail-closed; dead code (1.7).** Reproduced: an exception in the classifier propagated out of
   `Engine.check`.
   → `Engine.check` wraps the pipeline; any internal error → `hold / SYSTEM_EXCEPTION_FAIL_CLOSED` keeping the evidence
   gathered so far. `Service.check_message` likewise fails closed if storage fails and still tries to audit.
   Remove the dead branch; make `touches_money` explicit with parentheses and a named helper.
   → Fault injection at signals, links, classifier, judges, session lookup, DB write.
8. **Links never extracted (1.8).** Reproduced: `booking-verify.ro/pay`, `guest-pay.pl/x`, `hotel-pay.ws`,
   `stay-pay.lat` gave no links; `reserva-cartao.com.br/pay` was cut to `reserva-cartao.com`.
   → Candidate regex + validation against the public-suffix list bundled with `tldextract` (multi-part suffixes
   handled). Scheme-less candidates whose TLD is Title-case (`room.In`) are rejected as sentence boundaries.
   → Regression tests for each missed TLD and for "e.g.", "Mr.Smith", "12.50", "a.m.", "today.So".
9. **Containment warns the wrong guests (1.9).** Confirmed in `service.py:172`: the first N upcoming reservations by
   date stand in for "what the attacker read".
   → `reservation_reads` table + `POST /v1/sessions/{id}/reads` (the extranet reports reads). Containment warns exactly
   reads ∪ messaged; if telemetry reports more reads than were recorded, the case file states the unattributed count
   and asks for manual review instead of guessing. The demo records the attacker's actual reads.
   → Integration test: only read/messaged guests get notices.
10. **PII at rest; audit chain forgeable (1.10).** Reproduced: a card number came back from `/v1/messages`.
    → Store masked text; raw text only with `STAYGUARD_RETAIN_RAW=1`, in a separate column purged after
    `STAYGUARD_RAW_RETENTION_DAYS`; `python -m stayguard.maintenance purge`. Guest check compares masked texts.
    Audit anchoring: every N rows (and on demand) the head `(seq, hash)` is appended to a separate anchor file;
    `maintenance verify-audit` checks chain + anchors. DECISIONS #10 states the remaining limit (someone who can
    rewrite both files can still forge; production needs WORM/external log).
    → Tests: masked storage, purge, anchor mismatch detection.
11. **Concurrency and storage (1.11).** Reproduced: four cold threads built four `Service`s.
    → Double-checked lock in `api.svc()`; per-thread SQLite connections (WAL, `busy_timeout`), writes still serialized;
    guest-check attempts persisted (`guest_attempts`), lockout per reservation (5 failures / 15 min) and per client
    (20 failures / hour); token buckets on `/v1/messages/check` and `/v1/guest/verify` (configurable).
    → Concurrency test (one service), read/write stress test, lockout and rate-limit tests.
12. **Doc drift (1.12).** Found: README latency "~3/~5 ms" vs report p95 6.05 ms; DECISIONS "99.8% of normal traffic"
    (the report's mix includes 3% scams, so it is 99.8% of *all* mixed traffic); README "warn every guest the attacker
    could see" (see 9); README and DECISIONS quote numbers by hand.
    → README results table and the numbers DECISIONS cites are rendered from `eval/report.json` by
    `scripts/render_docs.py` between markers; a test fails if the rendered block differs. Decision for each drift:
    the report wins over prose.
13. **Hygiene (1.13).** Secret scan of the tree and all history: clean (no keys, tokens or `.env`).
    → Model checksums written on train and verified before `joblib.load` (mismatch → retrain, never load). Security
    headers + strict CSP middleware; fonts self-hosted (`@fontsource` woff2) so the CSP needs no third-party origin.
    → Tests for headers and checksum refusal.

## Phase 2 — engineering

14. `pyproject.toml` (metadata, loose ranges) + `requirements.lock` (pip-compile, hashes); README says install the lock.
15. ruff lint + format; fix all; justified per-line ignores only.
16. mypy strict on engine, signals, links, judges, service; standard elsewhere; path to strict recorded in pyproject.
17. Pydantic `BaseSettings` config with bounds (0 ≤ thresholds ≤ 1, timeout > 0) and cross-field checks
    (`MODEL_LOW < MODEL_HIGH`, `SESSION_RISKY < SESSION_CRITICAL`); comments kept verbatim.
18. Logging with a context-var trace id (`message_id` / `session_id` / `case_id`); masked text only, never raw text or PINs.
19. CI workflow: ruff, mypy, pytest + coverage gates, fast offline eval on checked-in fixtures (`tests/fixtures/raw`),
    `STAYGUARD_DATA_RAW` env to point the app at them.
20. Dockerfile: multi-stage, non-root, healthcheck, CPU wheels, lockfile install; compose sets demo mode explicitly.
21. pre-commit: ruff, ruff-format, mypy, detect-secrets.
22. `CONTRIBUTING.md`, `CLAUDE.md` (invariants).

## Phase 3 — tests

23. Unit tests (table-driven): signals (all lexicons × languages, historical false positives as regressions,
    deobfuscation round-trips), links, engine reason codes + precedence + quiet truth table + banners, judges
    (quotes, referee monotonicity, breaker with fake clock, Anthropic parsing edge cases), session risk floors and
    batch==single, db (audit verify on edit/reorder/delete, triggers, seeding map), config validation.
24. Integration: every decision × path through `Service`; fault injection; every endpoint in both modes; containment;
    guest check; eval harness on fixtures (schema the Results tab reads); concurrency.
25. Adversarial corpus `tests/adversarial/` (lexicon-free scams, unsupported languages, judge injection, PII formats,
    URL evasion, session evasion, reverse scam). Failures recorded as known limitations, not deleted.
26. Coverage gates: ≥85% overall, ≥95% on engine, signals, links; enforced in CI; suite under ~2 minutes offline.

## Status

Updated as each item lands — see the bottom of this file.
