# StayGuard — rules for agents working in this repo

StayGuard decides whether a message on a booking platform is delivered, delivered with a warning, held, or blocked.
A wrong "deliver" can cost a guest real money. These invariants must hold after every change; tests enforce most of them.

## Safety invariants

1. **Fail closed.** `Engine.check` never raises: any internal error returns `hold` with `SYSTEM_EXCEPTION_FAIL_CLOSED`.
   `Service.check_message` does the same if storage fails. Never add a path where an exception leads to `deliver`.
2. **The payment-terms rule is never weakened.** A real payment ask on a `pay_at_property` booking is held
   (`PAY_ASK_ON_PAY_AT_HOTEL`). Changes may make it stricter, not looser, without a DECISIONS.md entry and a test.
3. **Judges act only where no hard rule fired.** Rules that hold or block are final; the judges can never release a
   held message. Only provider failures (`JudgeUnavailable`, HTTP, timeout, bad JSON) may trigger the degraded policy;
   anything else is a bug and must fail closed.
4. **Judge quotes must exist in the message.** `validate_quotes` drops anything not found verbatim in the masked text.
5. **PII is masked before any LLM call, log line or stored message.** Raw text is stored only with
   `STAYGUARD_RETAIN_RAW=1`, and purged after the retention period. Never log raw text, PINs or keys.
6. **PINs** come from `secrets` and are stored only as salted hashes.
7. **Production mode is closed by default.** Internal endpoints need `X-API-Key`; with no key configured they return
   503. Demo-only endpoints return 404 unless `STAYGUARD_DEMO_MODE=1`.
8. **The audit log is append-only and hash-chained.** Never UPDATE or DELETE it; never bypass `db.audit`.

## Honesty invariants

9. **No fabricated metrics.** Every number in README.md and DECISIONS.md comes from `eval/report.json` via
   `scripts/render_docs.py`. Every number in `eval/report.md` comes from `eval/evaluate.py`. Assumptions (prices,
   token counts) are labelled as estimates with a source.
10. **The blind set is never used for tuning.** Held-out v3 (`data/curated/heldout_v3.jsonl`) must not be read, and must
    not inform rules, lexicons, thresholds, training or calibration, until its one run is frozen in
    `eval/heldout_v3_first_look.json` (DECISIONS #43). v1 and v2 are spent (DECISIONS #28, #37) and retired: v1 into the
    context models' training rows, v2 into their calibration rows. If a change was motivated by a held-out result,
    record that in DECISIONS.md. Never regenerate any `eval/heldout*_first_look.json`.
11. **Leakage.** The original classifier trains on `train_seeds.jsonl` + the SMS train split only; the context models
    (`ctx_classifier.py`) add retired v1 and the feedback queue. Dev, v2, v3 and the SMS calibration/test splits are
    never trained on. Tests enforce both.
12. **Keep the "why" comments.** When you change code a comment explains, update the comment; never delete the reasoning.

## Commands

`make lint`, `make types`, `make test`, `make eval`. Tests run offline on `tests/fixtures/raw`.
