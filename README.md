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
3. **Contain it in one click.** Log out every session, force a passkey, freeze payout changes for 72 h, rotate
   reservation PINs, warn every guest the attacker could see, and write the case file with MITRE ATT&CK mapping.

Guests get a **"Is this really from my hotel?"** check, and hotels are protected from the reverse scam too
(fake guests "overpaying" and asking for a refund by wire).

## Real data

| Dataset | What it's used for | Size |
|---|---|---|
| [Hotel Booking Demand](https://github.com/rfordatascience/tidytuesday/tree/master/data/2020/2020-02-11) (Antonio, Almeida & Nunes, 2019) | Reservations in the database; `deposit_type` gives payment terms for the core rule | 119,390 bookings, 2 hotels, 178 guest countries |
| [UCI SMS Spam Collection](https://archive.ics.uci.edu/dataset/228/sms+spam+collection) | Trains the language model; held-out real messages measure false alarms | 5,574 messages |
| [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) (active domains) | Live phishing blocklist; 363 real Booking-themed hosts for testing | 392,178 domains |
| [OpenPhish public feed](https://github.com/openphish/public_feed) | Blocklist + generic phishing test | 300 URLs |
| [Top 1M domains](https://github.com/zer0h/top-1000000-domains) | Top 10k = popularity allowlist; ranks 10k–110k = unseen legit domains for false-positive tests | 1M domains |

Hand-written by us (and labelled as such): hotel message seeds for training (EN/HI/Hinglish/ES/PT/FR/DE/IT),
a separate 115-message golden + red-team set, and synthetic login telemetry (real account-takeover logs are private).

## Results (from `eval/report.md`)

| | |
|---|---|
| Real everyday messages wrongly held (1,207 held-out SMS, strictest setting) | **0.00%** |
| Real legit domains flagged (99,967 domains outside the top 10k) | **0.01%** |
| Real Booking look-alike phishing hosts caught with the blocklist **off** | **91%** |
| Scams caught (golden set) — StayGuard vs generic spam filter vs blocklist | **100%** vs 62% vs 17% |
| Normal messages held (golden set) — StayGuard vs generic spam filter | **0%** vs 24% |
| Scams still caught after rewriting (no deadline + fresh domain + leetspeak) | **95%** |
| Scams caught with the AI judges down | **97%** |
| Share of messages that need an LLM / LLM cost per 1,000 messages | **0.1% / $0.0016** (vs $1.60 if every message went to an LLM) |
| Latency p50 / p95 (excluding network) | **~3 ms / ~5 ms** |

Honest caveats, also in the report: the golden set was written by the same team as the rules, so it is
optimistic — the real-data sections are the ones to trust. The login model runs on synthetic data, and it
scores **0%** on malware running on the hotel's own PC (the login looks normal). That is the reason every
message is still checked on its own.

## Run it

```bash
pip install -r requirements.txt
bash scripts/fetch_data.sh            # only if data/raw is empty (the zip already includes it)
python -m eval.evaluate               # trains both models, writes eval/report.md + report.json (~2 min)
uvicorn stayguard.api:app --port 8000 # open http://localhost:8000
pytest -q                             # 20 tests
```

Or `docker compose up --build`, then open http://localhost:8000.

**Optional: real LLM judges.** Set `STAYGUARD_ANTHROPIC_API_KEY` (and optionally `STAYGUARD_LLM_MODEL`). Without
it a deterministic offline judge runs in their place, so everything works with no key and no network; the UI
says which one is active.

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
| `POST /v1/guest/verify` | Guest check by reservation number + PIN. |
| `POST /v1/properties/{id}/contain` | One-click containment; returns the case file. |
| `GET /v1/metrics` | Live counters, path share, p50/p95, cost per 1,000, dataset facts, evaluation. |
| `GET /v1/audit`, `GET /v1/audit/verify` | Tamper-evident audit trail. |
| `POST /v1/admin/llm-outage` | Simulate the LLM provider going down. |
| `POST /v1/demo/simulate-attack` | The scripted demo. |

Interactive docs at `/docs`. Set `STAYGUARD_API_KEY` to require an `X-API-Key` header.

## How a message is decided

```
message ──► guardrails ──► links ──► fast rules ──► small model ──► AI judges ──► login risk ──► decision
            mask PII       392k      payment terms   TF-IDF+LR      prosecutor     takeover score
            injection      blocklist card/bank asks  <0.10 deliver  vs defender,   makes it stricter,
            hidden chars   look-alike off-platform   >0.90 hold     quotes must    critical = nothing
            leetspeak      typosquat overpayment     else ─────────►exist in text  goes out
```

Cheap and explainable first; the judges only see what nothing else could settle (0.1% of normal traffic).
If they time out or the circuit breaker is open: normal login → deliver with a warning; risky login → hold.

## Layout

```
stayguard/      signals.py (lexicons, PII, injection, deobfuscation)  links.py  classifier.py
                session_risk.py  judges.py  engine.py (router)  service.py  db.py  api.py  static/
data/raw/       downloaded datasets          data/curated/  train seeds + golden eval set
eval/           evaluate.py, report.md, report.json
tests/          pytest suite
DECISIONS.md    why each choice was made
```
