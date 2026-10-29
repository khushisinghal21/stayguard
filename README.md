# StayGuard

**Stops reservation-hijack scams sent from compromised hotel accounts — before the guest sees them.**

Criminals phish hotel staff, steal their extranet session, read upcoming reservations, then message guests
*through the real booking platform*: "your card failed, re-confirm within 12 hours or we cancel". The message
comes from the real hotel, in the real app, about the real booking, so guests trust it. A blocklist can't help
when the link is new, and a spam filter can't help when the account is genuine.

StayGuard checks three things together:

1. **Is this login really the hotel?** Session-takeover rules and an anomaly score over signals the extranet must
   supply (cookie replayed from a new network, impossible travel, a new device bulk-reading reservations,
   payout-detail changes). Only tested on synthetic logins (see caveats).
2. **Does this message make sense for this booking?** The core rule: *on a booking whose terms say nothing is due
   before arrival, a message demanding payment before arrival is held, whatever the wording.* How common such
   bookings are depends on the platform: in the one public dataset we use (two Portuguese hotels, 2015-17, 82% sold
   through agents), 87.6% were "No Deposit". That is not the same as "paid at the hotel" on Booking.com, and the rule
   also holds some genuine payment requests (see limitations).
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
| [Hotel Booking Demand](https://github.com/rfordatascience/tidytuesday/tree/master/data/2020/2020-02-11) (Antonio, Almeida & Nunes, 2019) | Reservations in the database; `deposit_type` gives payment terms for the core rule | 119,390 bookings, 2 hotels, 177 guest countries (488 rows have none) |
| [UCI SMS Spam Collection](https://archive.ics.uci.edu/dataset/228/sms+spam+collection) | Trains the language model; held-out real messages measure false alarms | 5,574 messages |
| [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) (active domains) | Live phishing blocklist; 363 real Booking-themed hosts for testing | 392,178 domains |
| [OpenPhish public feed](https://github.com/openphish/public_feed) | Blocklist + generic phishing test | 300 URLs |
| [Top 1M domains](https://github.com/zer0h/top-1000000-domains) | Top 10k = popularity allowlist; ranks 10k–110k = dev and 110k–210k = held-out legit domains for false-positive tests | 1M domains |

Hand-written by us (and labelled as such): hotel message seeds for training (EN/HI/Hinglish/ES/PT/FR/DE/IT); a
115-message **dev** set written alongside the rules; a 124-message **held-out v1** set (`data/curated/HELDOUT_SOURCES.md`;
of its 66 scams, 10 reuse wording quoted in a cited report and the rest paraphrase reported patterns or were written
by us) committed before its first run and blind only for that first run; a
148-message **held-out v2** set written by a separate agent instructed not to read the code (it reports it did not;
same model family; brief in `docs/HELDOUT_V2_BRIEF.md`), from cited reports
(`data/curated/HELDOUT_V2_SOURCES.md`), committed before its only blind run; a red-team corpus
(`tests/adversarial/corpus.py`); and synthetic login telemetry (real account-takeover logs are private). Every live
feed is pinned by SHA-256 in `data/MANIFEST.json`, and reports refuse to compare across different feed snapshots.

## Results (rendered from `eval/report.json` by `scripts/render_docs.py`)

<!-- results:start -->
| | |
|---|---|
| **Held-out v2** (blind to its text; author instructed not to read the code; first run frozen): scams caught (74 scams, 95% CI) | **89.2%** (80.1%-94.4%) |
| Held-out v2: legitimate messages wrongly held (95% CI) / delivered with a warning (74 legit) | **13.5%** (7.5%-23.1%) / 13.5% |
| Held-out v2: legitimate payment messages (26) held / warned / delivered clean | 8 / 4 / 14 |
| Held-out v2: of those, the ones on pay-at-property bookings (the case the payment rule holds): held / total | 7 / 13 |
| Held-out v2, same messages, caught: StayGuard's classifier alone / generic spam filter / StayGuard with judges down | 89.2% / 39.2% / 87.8% |
| Held-out v2: StayGuard's classifier alone wrongly held / spam filter wrongly held | 24.3% / 8.1% |
| Held-out v2 legit messages held only by the full system / only by its classifier (paired McNemar p) | 2 / 10 (p = 0.039) |
| Held-out v2: scams caught only by the full system / only by its classifier (paired McNemar p) | 1 / 1 (p = 1) |
| Held-out v2 messages that crashed and failed closed (would count as caught) | 0 |
| Held-out v1 scams caught, first blind run (frozen before any v1 result was seen; 95% CI) | **66.7%** of 66 (54.7%-76.8%), wrongly held 1.7% |
| Held-out v1 first blind run vs its own classifier, same 66 scams (`eval/reconstruct_first_look.py`): full system caught / classifier alone would have caught (paired McNemar p) | 44 / 57 (p = 0.00024) |
| Held-out v1 scams caught now (NOT blind: later fixes targeted its first-run misses) | 87.9% of 66 |
| Held-out v1 legitimate messages wrongly held / delivered with a warning (now) | 1.7% / 3.4% |
| Held-out v1, same messages: StayGuard's classifier alone caught / wrongly held | 84.8% / 0% |
| Held-out v1, same messages: generic spam filter caught / wrongly held | 19.7% / 1.7% |
| Held-out v1: phishing blocklist alone caught (uninformative: 0 of its 35 URLs are in the feeds) | 0% |
| Held-out v1 scams caught with the AI judges down (not blind) | 72.7% |
| Held-out v1 scams caught after rewriting (no deadline + fresh domain + leetspeak), not blind: all / changed only | 65.2% / 65.2% |
| Dev set (written alongside the rules, near-duplicates of some training seeds, used in calibration): caught / wrongly held | 100% / 0% |
| Real everyday SMS wrongly held (1,130 messages, domain-shifted; used as a check during rule work, and two rules were narrowed because of it, DECISIONS #34; 95% CI) | 0% (0.00%-0.34%) |
| Unseen legit domains flagged (99,969 domains, ranks 110k-210k) | 0.007% |
| Unseen legit domains containing a travel-brand word flagged (49 domains) | 8.2% |
| Unseen Booking look-alike phishing hosts flagged, blocklist off (182 hosts) | 88.5% |
| Random phishing hosts from the whole feed flagged, blocklist off | 4.9% |
| Messages sent to the AI judges / estimated LLM cost per 1,000: hotel messages (held-out v1) | 14.5% / $0.0288 |
| Same on the SMS-heavy 1,000-message mix | 1.0% / $0.0020 (vs $0.1956 if every message went to the judges) |
| Legit held-out v1 messages with a common emoji added (❤️, 👍, 👨‍👩‍👧 …): warned / held | 3.4% / 1.7% |
| Evaluation checks that crashed and failed closed, across every run and rewrite (would count as caught) | 0 |
| Latency p50 / p95, in-process with the offline judge on the SMS-heavy mix (a hosted LLM would add an estimated 1-3 s to every judged message, so p95 on hotel messages would be seconds) | 2.7 ms / 4.5 ms |
<!-- results:end -->

### Honest caveats

1. **Quote blind runs only.** Dev numbers (100% caught, 0% false holds) are from a set written alongside the rules.
   Held-out v1 caught <!-- num:heldout_first_look_caught -->66.7%<!-- /num --> of scams on its first blind run. A later
   commit then fixed exactly its first-run misses with patterns that appear only in that set (review round 1, finding
   C1), so today's v1 figure of <!-- num:heldout_caught -->87.9%<!-- /num --> is a tuned number, not a blind one.
   Held-out v2 was written after that by an agent instructed not to read the code, and was run exactly once, after the
   last review round (`eval/heldout_v2_first_look.json`, commit `cb526dc`): <!-- num:v2_caught -->89.2%<!-- /num --> of
   scams caught, and **<!-- num:v2_false_holds -->13.5%<!-- /num --> of legitimate messages wrongly held**, far more than
   any earlier set showed. Most of those false holds are genuine payment and card-update messages (a declined card, a
   pre-authorisation, a refund, a group pro-forma) caught by the payment-terms and card rules (two of them by the pre-arrival
   timing rule added in round 3, one of those negated: "we will not charge it before you arrive"); <!-- num:v2_legit_payment_pap_held -->7<!-- /num --> of the
   <!-- num:v2_legit_payment_pap_n -->13<!-- /num --> legitimate payment messages on pay-at-property bookings were held.
   These are v2 results and are not tuned away; DECISIONS #37 lists them. Its text was never seen before that run, but
   its brief and language mix were known while later rules were written, so it is less blind than "never seen"
   suggests (DECISIONS #35).
2. **The classifier alone does most of the work on these sets.** On held-out v2 the full system and its classifier
   caught the same number of scams (paired p = <!-- num:v2_mcnemar_p -->1<!-- /num -->); where they differ is false holds:
   the classifier alone would have wrongly held <!-- num:v2_classifier_only_false_holds -->24.3%<!-- /num --> of legitimate
   messages against the full system's <!-- num:v2_false_holds -->13.5%<!-- /num --> (held only by the classifier
   <!-- num:v2_legit_only_classifier_held -->10<!-- /num -->, only by the full system
   <!-- num:v2_legit_only_full_held -->2<!-- /num -->, p = <!-- num:v2_legit_mcnemar_p -->0.039<!-- /num -->). On held-out v1 StayGuard's own classifier, with no
   rules, links or judges, caught <!-- num:heldout_classifier_only_caught -->84.8%<!-- /num --> (paired McNemar against the
   full system today: p = <!-- num:heldout_mcnemar_p -->0.73<!-- /num -->). On v1's only blind run it was worse than that:
   a reviewer's reconstruction found the full pipeline caught significantly fewer scams than its own classifier
   would have, because the "no payment ask" fast path delivered scams the model would have held (review round 2, C1).
   The rules matter for what a classifier cannot know (the booking's payment terms, the session, the link's owner) and
   for explaining a decision, but these sets do not show an accuracy gain over the model. Small sets: a 66-scam set has a 95%
   interval roughly 20 points wide, and at the low share of scams real hotel traffic has, even a 1.7% false-hold rate
   would mean most held messages are legitimate. We have no sourced figure for that share, so we give no precision.
3. **The SMS false-alarm test is domain-shifted, and not untouched.** Two rules were narrowed after they held texts
   in it (DECISIONS #34). Personal SMS rarely ask for money, so 0% held there shows StayGuard
   rarely interferes with ordinary chat. It does not measure false holds on real hotel traffic. Duplicate texts are
   removed before the SMS split (they leaked between train and test before round 1).
4. **The login model runs on synthetic data** whose attacks are generated from the same features the model scores,
   so its high detection is true by construction and is a plumbing check, not a result. It scores **0%** on malware
   running on the hotel's own PC (the login looks normal), which is why every message is still checked on its own.
5. **Cost is an estimate** from the published Claude Haiku 5.5 price and estimated token counts, not a bill.
6. **Thresholds** (`MODEL_LOW`/`MODEL_HIGH`) are chosen on a calibration split by a stated rule (`eval/calibrate.py`),
   never on held-out data, but the calibration is weak: it is mostly SMS, LOW is set by one or two generic SMS texts,
   and on hotel dev messages about 9% of legitimate ones score above HIGH, not the 1% the rule aims for (DECISIONS #14).
7. **The AI judges in every number are the offline deterministic stand-in.** No real LLM judge was run for these
   results; with `STAYGUARD_ANTHROPIC_API_KEY` set the judges change and the numbers would need re-measuring. The
   offline judge was itself edited after held-out v1 had been seen, so the v1 gap between "judges up" and "judges
   down" is not blind either.

### Known limitations (each pinned by a test that fails the day it is fixed)

- **Lexicon-free lures with a fresh, brand-free domain** ("Your stay needs one more step. Finish it at
  `<new domain>` before you travel.") are delivered *with a warning*, not held: red-team case A02, a strict xfail in
  `tests/adversarial/test_redteam.py`.
- **Languages outside the lexicons** rely on the model and judges; held-out misses are listed in `eval/report.md`.
- **Shorteners** are never followed (no network), so they get a warning, not a verdict.
- **Genuine pre-arrival payment requests on no-deposit bookings are held.** A hotel asking for a group pro-forma, a
  damage deposit or a city tax in advance looks exactly like the scam the core rule exists for. This is deliberate
  (CLAUDE.md invariant 2): the hotel is told to use the platform's own payment flow instead. Held-out v2's legitimate
  payment messages are mostly on prepaid or deposit bookings (its brief asked for that), so the pay-at-property subset
  that measures this cost is small; the results table shows it separately.
- **Travel-brand words in unfamiliar domains are flagged**: <!-- num:c3_heldout_brand_fp -->8.2%<!-- /num --> of unseen
  legitimate domains containing a travel-brand word, vs <!-- num:c3_heldout_fp -->0.007%<!-- /num --> of all unseen legitimate
  domains.
- **The guest-check PIN** is 4 digits: if the database leaked, the salted hashes fall to 10,000 guesses. The real
  protection is the attempt limits: 5 wrong PINs per client per booking, 20 per client, 50 per booking from all
  clients, all per 15 minutes; and 10 successful checks per booking per day, so the checker cannot be used as an
  unlimited oracle for testing scam wording.

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

## Pipeline changes waiting for their blind test (held-out v3)

Five changes built after held-out v2, all **off by default** and **not yet measured**: none of their numbers exist
until the one blind run on held-out v3 (`make eval-v3`), whatever it shows. Reasons and limits are in DECISIONS #38-#43.

| Change | Switch | DECISIONS |
|---|---|---|
| Multilingual encoder (multilingual-e5-small, ONNX) + booking context as the language model | `STAYGUARD_CLASSIFIER=encoder_ctx` | #38, #39 |
| TF-IDF + booking context (no download needed) | `STAYGUARD_CLASSIFIER=tfidf_ctx` | #39 |
| Model-only holds go to the prosecutor/defender judges (still held if they are down) | `STAYGUARD_ROUTE_MODEL_HIGH_TO_JUDGES=1` | #39 |
| Money mentions that only point to the platform's own app/reception are warned, not held | `STAYGUARD_PLATFORM_FLOW_WARN=1` | #40 |
| Shadow mode (decisions returned with `enforced: false`) and a labelled feedback queue | `STAYGUARD_ENFORCE=0`, `POST /v1/messages/{id}/label` | #41 |
| Network link checks: shortener destinations, domain age (RDAP), SSRF-safe | `STAYGUARD_NET_CHECKS=1` | #42 |

The blind run, on a machine that can reach huggingface.co (it downloads the encoder weights once):

```bash
make install-encoder         # dev toolchain + onnxruntime/tokenizers, hash-pinned (requirements-encoder.lock)
make encoder                 # fetch the encoder, train encoder_ctx, write eval/calibration_encoder_ctx.json
git add eval/calibration_encoder_ctx.json && git commit -m "Calibrate the encoder model for the v3 run"
make eval-v3                 # ONE blind run -> eval/heldout_v3_first_look.json (refuses a dirty tree)
# optional, same commit, real judges: STAYGUARD_ANTHROPIC_API_KEY=... python -m eval.evaluate_v3 --add-arm candidate_real_judges
```

The primary comparison is fixed in advance: the candidate (encoder + context + platform-flow warning + routing)
against today's system, on scams caught and legitimate messages held, paired exact McNemar, Holm-adjusted.
Held-out v3 was written by a separate agent that never saw the code (`docs/HELDOUT_V3_BRIEF.md`) and has not been
read by anyone working on StayGuard.

## The console (http://localhost:8000)

- **Live attack** — replays a hijack against real upcoming bookings: normal staff message delivered, attacker logs
  in with a stolen cookie at 03:12, six scams (English, Hindi, Hinglish + prompt injection, real phishing
  domains from the feed, a fresh look-alike) are stamped HELD/BLOCKED. "Log everyone out and warn guests" runs
  containment.
- **Check a message** — type anything; see the decision, highlighted evidence, each pipeline step with its
  timing, judge arguments, link verdicts. Toggle "AI judges down" to show the safe fallback.
- **Guest view** — the guest-facing check (reservation number + PIN; 5 wrong tries locks that client out of that booking).
- **Results** — the evaluation, live from `eval/report.json`.
- **Audit log** — hash-chained, append-only (SQLite triggers reject UPDATE/DELETE); "Verify the chain".

## API

| Endpoint | Purpose |
|---|---|
| `POST /v1/messages/check` | Decide on a message: `deliver` / `warn` / `hold` / `block`, with reason codes, quoted evidence, path, trace, versions. `message_id` makes it idempotent. |
| `POST /v1/messages/{id}/label` | A hotel, guest or analyst labels a stored message scam/legit (feedback queue, DECISIONS #41); never changes the decision. |
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
(<!-- num:hotel_judge_share -->14.5%<!-- /num --> of hotel messages in held-out v1, <!-- num:judge_share -->1.0%<!-- /num --> of an
SMS-heavy mix). The model thresholds (LOW <!-- num:model_low -->0.03<!-- /num -->,
HIGH <!-- num:model_high -->0.52<!-- /num -->) come from `eval/calibration.json`. If the judges time out or the circuit breaker is open: normal login → deliver with a
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
