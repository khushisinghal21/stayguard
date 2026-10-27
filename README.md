# StayGuard

**Stops reservation-hijack scams sent from compromised hotel accounts — before the guest sees them.**

Criminals phish hotel staff, steal their extranet session, read upcoming reservations, then message guests
*through the real booking platform*: "your card failed, re-confirm within 12 hours or we cancel". The message
comes from the real hotel, in the real app, about the real booking, so guests trust it. A blocklist can't help
when the link is new, and a spam filter can't help when the account is genuine.

StayGuard checks three things together:

1. **Is this login really the hotel?** Session-takeover scoring (stolen cookie replay, impossible travel, a new
   device bulk-reading reservations, payout-detail changes).
2. **Does this message make sense for this booking?** The core rule: *87.6% of real bookings are paid at the
   hotel, so a message demanding payment before arrival on one of those is a scam, whatever the wording.*
   Then links, card and bank requests, off-platform payment, prompt injection and obfuscation, a small
   multilingual model, and two AI judges only for the unclear cases.
3. **Contain it in one click.** Log out every session, force a passkey, freeze payout changes for 72 h, rotate the
   PINs of, and warn, every guest whose booking the attacker's session opened (as reported by the extranet) or
   messaged, and write the case file with MITRE ATT&CK mapping. If login telemetry says the session read more
   bookings than were reported, the case file says so and asks for manual review instead of guessing.

Guests get a **"Is this really from my hotel?"** check, and hotels are protected from the reverse scam too
(fake guests "overpaying" and asking for a refund by wire).

## Real data

| Dataset | What it's used for | Size |
|---|---|---|
| [Hotel Booking Demand](https://github.com/rfordatascience/tidytuesday/tree/master/data/2020/2020-02-11) (Antonio, Almeida & Nunes, 2019) | Reservations in the database; `deposit_type` gives payment terms for the core rule | 119,390 bookings, 2 hotels, 178 guest countries |
| [UCI SMS Spam Collection](https://archive.ics.uci.edu/dataset/228/sms+spam+collection) | Trains the language model; held-out real messages measure false alarms | 5,574 messages |
| [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) (active domains) | Live phishing blocklist; 363 real Booking-themed hosts for testing | 392,178 domains |
| [OpenPhish public feed](https://github.com/openphish/public_feed) | Blocklist + generic phishing test | 300 URLs |
| [Top 1M domains](https://github.com/zer0h/top-1000000-domains) | Top 10k = popularity allowlist; ranks 10k–110k = dev and 110k–210k = held-out legit domains for false-positive tests | 1M domains |

Hand-written by us (and labelled as such): hotel message seeds for training (EN/HI/Hinglish/ES/PT/FR/DE/IT); a
115-message **dev** set written alongside the rules; a 124-message **held-out** set built from cited public scam
reports (`data/curated/HELDOUT_SOURCES.md`) and committed before its first run; a red-team corpus
(`tests/adversarial/corpus.py`); and synthetic login telemetry (real account-takeover logs are private). Every live
feed is pinned by SHA-256 in `data/MANIFEST.json`, and reports refuse to compare across different feed snapshots.

## Results (rendered from `eval/report.json` by `scripts/render_docs.py`)

<!-- results:start -->
| | |
|---|---|
| Held-out scams caught, first blind run (frozen before any held-out result was seen) | **66.7%** of 66 (wrongly held 1.7%) |
| Held-out scams caught now (after later fixes; the first run's misses had been seen, so less blind) | 86.4% of 66 |
| Held-out legitimate messages wrongly held / delivered with a warning (now) | 1.7% / 1.7% |
| Same held-out set: generic spam filter caught / wrongly held | 27.3% / 3.5% |
| Same held-out set: phishing blocklist alone caught | 0% |
| Held-out scams caught with the AI judges down | 74.2% |
| Held-out scams caught after rewriting (no deadline + fresh domain + leetspeak) | 63.6% |
| Dev set (written alongside the rules): caught / wrongly held | 100% / 0% |
| Real everyday SMS wrongly held (1,207 messages, domain-shifted) | 0% |
| Unseen legit domains flagged (99,969 domains, ranks 110k-210k) | 0.006% |
| Unseen Booking look-alike phishing hosts flagged, blocklist off (182 hosts) | 88.5% |
| Random phishing hosts from the whole feed flagged, blocklist off | 3.7% |
| Messages sent to the AI judges / estimated LLM cost per 1,000 messages | 0.7% / $0.0014 (vs $0.1988 if every message went to the judges) |
| Latency p50 / p95 (in-process, offline judge) | 2.0 ms / 3.4 ms |
<!-- results:end -->

### Honest caveats

1. **Read held-out, not dev, and quote the first blind run.** Until 27 Oct 2026 every message number here came from
   a set written alongside the rules and used to tune them (100% caught, 0% false holds). A separately written
   held-out set, built from cited public scam reports and committed before its first run, caught
   <!-- num:heldout_first_look_caught -->66.7%<!-- /num --> of scams on that first blind run (frozen in
   `eval/heldout_first_look.json`). Later fixes were driven by a separate red-team corpus, but the held-out misses
   had already been seen, so today's <!-- num:heldout_caught -->86.4%<!-- /num --> is less blind than that first run.
2. **The held-out set has the same author as the rules.** Citing outside wording and freezing the first look reduce the
   bias; they don't remove it. Real validation needs labelled platform traffic.
3. **The SMS false-alarm test is domain-shifted.** Personal SMS rarely ask for money, so 0% held there shows StayGuard
   rarely interferes with ordinary chat. It does not measure false holds on real hotel traffic.
4. **The login model runs on synthetic data**, which is separable by construction. It scores **0%** on malware running
   on the hotel's own PC (the login looks normal), which is why every message is still checked on its own.
5. **Cost is an estimate** from the published Claude Haiku 5.5 price and estimated token counts, not a bill.
6. **Thresholds** (`MODEL_LOW`/`MODEL_HIGH`) are chosen on a calibration split by a stated rule (`eval/calibrate.py`),
   never on held-out data.
7. **The AI judges in every number are the offline deterministic stand-in.** No real LLM judge was run for these
   results; with `STAYGUARD_ANTHROPIC_API_KEY` set the judges change and the numbers would need re-measuring.

### Known limitations (each pinned by a test that fails the day it is fixed)

- **Lexicon-free lures with a fresh, brand-free domain** ("Your stay needs one more step. Finish it at
  `<new domain>` before you travel.") are delivered *with a warning*, not held: red-team case A02, a strict xfail in
  `tests/adversarial/test_redteam.py`.
- **Languages outside the lexicons** rely on the model and judges; held-out misses are listed in `eval/report.md`.
- **Shorteners** are never followed (no network), so they get a warning, not a verdict.
- **The guest-check PIN** is 4 digits: if the database leaked, the salted hashes fall to 10,000 guesses. The real
  protection is the attempt limit (5 per booking, 20 per client, per 15 minutes).

## Run it

```bash
pip install --require-hashes -r requirements.lock && pip install --no-deps -e .   # pinned, hash-checked
bash scripts/fetch_data.sh                    # real datasets into data/raw (+ data/MANIFEST.json)
python -m eval.evaluate                       # trains both models, writes eval/report.md + report.json (~3 min)
STAYGUARD_DEMO_MODE=1 uvicorn stayguard.api:app --port 8000   # console at http://localhost:8000
```

Or `docker compose up --build` (demo mode on), then open http://localhost:8000.

**Demo vs production mode.** Production mode is the default: the platform-facing endpoints need an `X-API-Key`
(`STAYGUARD_API_KEY`), and without a configured key they refuse to serve instead of running open. Demo mode
(`STAYGUARD_DEMO_MODE=1`) adds the console's demo endpoints (issuing a guest PIN, the scripted attack, samples) and,
if no key is set, lets the console call everything without one. Never run demo mode on a public host.

**Optional: real LLM judges.** Set `STAYGUARD_ANTHROPIC_API_KEY` (and optionally `STAYGUARD_LLM_MODEL`). Without
it a deterministic offline judge runs in their place, so everything works with no key and no network; the UI
says which one is active.

Development: see `CONTRIBUTING.md` (`make lint types test`). Agents: see `CLAUDE.md` for the invariants.

## The console (http://localhost:8000)

- **Live attack** — replays a hijack against real upcoming bookings: normal staff message delivered, attacker logs
  in with a stolen cookie at 03:12, six scams (English, Hindi, Hinglish + prompt injection, real phishing
  domains from the feed, a fresh look-alike) are stamped HELD/BLOCKED. "Log everyone out and warn guests" runs
  containment.
- **Check a message** — type anything; see the decision, highlighted evidence, each pipeline step with its
  timing, judge arguments, link verdicts. Toggle "AI judges down" to show the safe fallback.
- **Guest view** — the guest-facing check (reservation number + PIN, lockout after 5 tries).
- **Results** — the evaluation, live from `eval/report.json`.
- **Audit log** — hash-chained, append-only (SQLite triggers reject UPDATE/DELETE); "Verify the chain".

## API

| Endpoint | Purpose |
|---|---|
| `POST /v1/messages/check` | Decide on a message: `deliver` / `warn` / `hold` / `block`, with reason codes, quoted evidence, path, trace, versions. `message_id` makes it idempotent. |
| `POST /v1/sessions/score` | Score an extranet login/session for takeover risk; returns `step_up_required`. |
| `POST /v1/sessions/{id}/reads` | The extranet reports which reservations a session opened (used by containment). |
| `POST /v1/guest/verify` | Guest check by reservation number + PIN (public; rate-limited and locked after repeated wrong PINs). |
| `POST /v1/properties/{id}/contain` | One-click containment; returns the case file. |
| `GET /v1/metrics` | Live counters, path share, p50/p95, cost per 1,000, dataset facts, evaluation. |
| `GET /v1/audit`, `GET /v1/audit/verify` | Tamper-evident audit trail. |
| `POST /v1/admin/llm-outage` | Simulate the LLM provider going down. |
| `POST /v1/demo/simulate-attack`, `POST /v1/reservations/{id}/demo-pin`, `GET /v1/samples` | Demo mode only (404 otherwise). |

Interactive docs at `/docs`. Everything except the console, `/healthz` and `/v1/guest/verify` needs `X-API-Key`
in production mode. A reused `message_id` with a different payload is rejected with 409.

## How a message is decided

```
message ──► guardrails ──► links ──► fast rules ──► small model ──► AI judges ──► login risk ──► decision
            mask PII       392k      payment terms   TF-IDF+LR      prosecutor     takeover score
            injection      blocklist card/bank asks  <LOW deliver   vs defender,   makes it stricter,
            hidden chars   look-alike off-platform   >HIGH hold     quotes must    critical = nothing
            leetspeak      typosquat overpayment     else ─────────►exist in text  goes out
```

Cheap and explainable first; the judges only see what nothing else could settle
(<!-- num:judge_share -->0.7%<!-- /num --> of the evaluation's realistic mix). The model thresholds (LOW <!-- num:model_low -->0.26<!-- /num -->,
HIGH <!-- num:model_high -->0.46<!-- /num -->) come from `eval/calibration.json`. If the judges time out or the circuit breaker is open: normal login → deliver with a
warning; risky login → hold. Any *other* internal error holds the message (`SYSTEM_EXCEPTION_FAIL_CLOSED`).

## Layout

```
stayguard/      signals.py (lexicons, PII, injection, deobfuscation)  links.py  domains.py  classifier.py
                session_risk.py  judges.py  engine.py (router)  service.py  db.py  api.py  maintenance.py  static/
data/raw/       downloaded datasets (pinned by data/MANIFEST.json)
data/curated/   train seeds, dev set (golden_eval.jsonl), held-out set (heldout_eval.jsonl + HELDOUT_SOURCES.md)
eval/           evaluate.py, calibrate.py, report.md/json, calibration.json, heldout_first_look.json (frozen)
tests/          unit, integration and tests/adversarial (red-team corpus); offline on tests/fixtures/raw
docs/           HARDENING_PLAN.md, MESSAGE_TRACE.md, ADVERSARIAL_REVIEW.md, baselines/
DECISIONS.md    why each choice was made           CLAUDE.md  invariants agents must keep
```
