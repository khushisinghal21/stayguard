# StayGuard

**Stops scams sent from hijacked hotel accounts, before the guest sees them.**

> Independent project, not affiliated with or endorsed by Booking.com or Booking Holdings. The attack it targets is
> documented in public reporting (Perception Point, Akamai, Secureworks, Microsoft). The demo's scam messages use real
> phishing domains from public feeds: treat every link in them as live and don't open them.

![The StayGuard console during a simulated account takeover: a normal message is delivered, the attacker's scams are blocked with reasons](docs/images/console-live-attack.png)

## The problem

Criminals infect hotel staff computers with infostealer malware, take over the hotel's booking-platform account, read
upcoming reservations, and then message real guests **from inside the platform's own chat**:

> "We couldn't verify your card. Confirm within 12 hours at <link> or your reservation will be cancelled."

The message comes from the real hotel, in the real app, about the real booking, so guests trust it. A spam filter
can't help because the sender is genuine, and a blocklist can't help because the link is brand new.

## What StayGuard does

Every message a hotel sends to a guest is checked before it is delivered, and gets one of four decisions:
**deliver**, **deliver with a warning**, **hold**, or **block**. Each decision comes with reason codes and quotes from
the message.

| Question | How StayGuard answers it |
|---|---|
| **Does this message make sense for this booking?** | Booking-aware rules. The core one: on a booking where nothing is due before arrival, any demand for payment before arrival is held, whatever the wording. Also card and bank-detail requests, payment outside the platform (bank transfer, UPI, Pix, crypto, gift cards and many local apps), moves to WhatsApp or phone, and hidden or disguised text. |
| **Is the link safe?** | Live phishing feeds, brand look-alikes, typosquats, free site builders, open redirectors and links hidden inside other links. |
| **Does it read like a scam?** | A small language model (TF-IDF + logistic regression) for wording the rules don't name. |
| **Unclear?** | Two AI agents argue the case: a **prosecutor** and a **defender**. Every claim must quote the message, invented quotes are thrown out, and they can never release a message a rule held. Text aimed at the AI ("ignore previous instructions") is treated as an attack. |
| **Is this login really the hotel?** | A takeover score for the extranet session (stolen cookie reused from a new network, impossible travel, a new device bulk-reading reservations, payout changes). A session that looks taken over can send nothing until it re-confirms with a passkey. |
| **Contain it** | One click logs out every session at the hotel, forces a passkey, freezes payout changes for 72 hours, rotates the PINs of every guest the attacker's session touched and warns them, and writes a case file mapped to MITRE ATT&CK. |

Guests get an **"Is this really from my hotel?"** check (booking number + PIN), and hotels are protected from the reverse
scam too: fake guests who "overpay" and ask for a refund by wire.

It **fails closed**: any internal error holds the message instead of delivering it. Personal data is masked before
anything is stored, logged or sent to an AI model, and every decision is written to a hash-chained, append-only audit log.

## How a message is decided

```mermaid
flowchart LR
  M([Message]) --> G[Guardrails<br/>mask personal data<br/>spot injection and hidden text]
  G --> L[Links<br/>phishing feeds, look-alikes,<br/>redirects]
  L --> R{Rules<br/>payment terms, card asks,<br/>off-platform moves}
  R -- a hard rule fires --> HOLD[Hold or block]
  R -- nothing decided --> C{Language model}
  C -- clearly normal --> OK[Deliver]
  C -- clearly a scam --> HOLD
  C -- unclear --> J[Two AI agents<br/>prosecutor vs defender<br/>quotes must exist]
  J --> RESULT[Deliver, warn or hold]
  HOLD --> S[Login risk<br/>can only make it stricter]
  OK --> S
  RESULT --> S
  S --> D([Decision + evidence])
```

Cheap, explainable checks run first. The AI agents only see what nothing else could settle
(<!-- num:hotel_judge_share -->14.5%<!-- /num --> of hotel messages in held-out v1, <!-- num:judge_share -->1.0%<!-- /num -->
of an SMS-heavy mix). The model's thresholds (LOW <!-- num:model_low -->0.03<!-- /num -->, HIGH
<!-- num:model_high -->0.52<!-- /num -->) come from `eval/calibration.json`. If the AI judges are down or time out, a normal
login's message is delivered with a warning and a risky login's is held. A step-by-step trace of one message is in
`docs/MESSAGE_TRACE.md`.

## How well it works

StayGuard is judged on **blind test sets**: messages written by an author who never saw the code, locked by their hash,
and run once. Numbers from sets it was built or tuned on are shown separately and should not be quoted as results.

| | Scams caught | Legitimate messages wrongly held |
|---|---|---|
| Dev set (written alongside the rules; not a result) | <!-- num:dev_caught -->100%<!-- /num --> | <!-- num:dev_false_holds -->0%<!-- /num --> |
| Held-out v1, first blind run | <!-- num:heldout_first_look_caught -->66.7%<!-- /num --> of 66 | <!-- num:heldout_first_look_false_holds -->1.7%<!-- /num --> |
| Held-out v2, its only blind run | <!-- num:v2_caught -->89.2%<!-- /num --> of 74 | <!-- num:v2_false_holds -->13.5%<!-- /num --> of 74 |

What these say, plainly:

- **The first blind test exposed a real flaw.** On held-out v1's only blind run, the full system caught
  <!-- num:first_look_full_caught_n -->44<!-- /num --> of 66 scams, while its own classifier alone would have caught
  <!-- num:first_look_classifier_caught_n -->57<!-- /num --> (paired McNemar p =
  <!-- num:first_look_mcnemar_p -->0.00024<!-- /num -->). The rules had been tuned to the dev set. That finding changed
  how StayGuard is tested.
- **On held-out v2 the rules earned their place on false holds, not catches.** The full system and its classifier
  caught the same scams (p = <!-- num:v2_mcnemar_p -->1<!-- /num -->), but the classifier alone would have wrongly held
  <!-- num:v2_classifier_only_false_holds -->24.3%<!-- /num --> of legitimate messages against the full system's
  <!-- num:v2_false_holds -->13.5%<!-- /num --> (p = <!-- num:v2_legit_mcnemar_p -->0.039<!-- /num -->).
- **Most remaining false holds are genuine payment messages** (a declined card, a pre-authorisation, a refund) held by
  the payment and card rules. They are listed in DECISIONS #37 and were not tuned away.
- **Every number uses written test messages and an offline stand-in for the AI judges.** Real platform traffic and real
  AI judges are not measured yet.

<details>
<summary><b>Full results table</b> (rendered from <code>eval/report.json</code> by <code>scripts/render_docs.py</code>)</summary>

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
| Latency p50 / p95, in-process with the offline judge on the SMS-heavy mix (a hosted LLM would add an estimated 1-3 s to every judged message, so p95 on hotel messages would be seconds) | 2.7 ms / 5.1 ms |
<!-- results:end -->

</details>

<details>
<summary><b>Caveats: read these before quoting any number</b></summary>

1. **Quote blind runs only.** The dev set was written alongside the rules. Held-out v1 caught
   <!-- num:heldout_first_look_caught -->66.7%<!-- /num --> of scams on its only blind run; later fixes targeted exactly
   its misses, so today's v1 figure of <!-- num:heldout_caught -->87.9%<!-- /num --> is a tuned number. Held-out v2 was
   written afterwards by an agent instructed not to read the code and run once (`eval/heldout_v2_first_look.json`,
   commit `cb526dc`). Its text was never seen before that run, but its brief and language mix were known while later
   rules were written (DECISIONS #35).
2. **The classifier does most of the catching.** On held-out v1, StayGuard's classifier alone caught
   <!-- num:heldout_classifier_only_caught -->84.8%<!-- /num --> (paired McNemar against the full system today: p =
   <!-- num:heldout_mcnemar_p -->0.73<!-- /num -->). On v2 the full system held fewer legitimate messages than the classifier
   alone (<!-- num:v2_legit_only_full_held -->2<!-- /num --> held only by the full system,
   <!-- num:v2_legit_only_classifier_held -->10<!-- /num --> only by the classifier). The rules matter for what a text
   model can't know (the booking's payment terms, the login, the link's owner) and for explaining decisions; these sets
   do not show them adding catches.
3. **Genuine payment messages are held.** <!-- num:v2_legit_payment_pap_held -->7<!-- /num --> of the
   <!-- num:v2_legit_payment_pap_n -->13<!-- /num --> legitimate payment messages on pay-at-property bookings in v2 were
   held. This is deliberate for real payment demands (CLAUDE.md invariant 2: the hotel is told to use the platform's
   payment flow), but it also catches declined-card and pre-authorisation notices.
4. **Small sets.** A 66-scam set has a 95% interval roughly 20 points wide. At the low share of scams in real hotel
   traffic, even a 1.7% false-hold rate would mean most held messages are legitimate; there is no sourced figure for
   that share, so no precision is claimed.
5. **The SMS false-alarm test is domain-shifted and not untouched.** Personal SMS rarely ask for money, so 0% held there
   shows StayGuard rarely interferes with ordinary chat, not how it does on hotel traffic. Two rules were narrowed
   because of it (DECISIONS #34).
6. **The login model runs on synthetic data** whose attacks are generated from the features it scores, so its detection
   is true by construction. It scores 0% on malware running on the hotel's own PC (the login looks normal), which is
   why every message is still checked on its own.
7. **The thresholds' calibration is weak**: mostly SMS, and about 9% of legitimate hotel dev messages score above HIGH,
   not the 1% the rule aims for (DECISIONS #14).
8. **Every number uses the offline stand-in judge**, not a real LLM, and costs are estimates from published prices.

</details>

<details>
<summary><b>Known limitations</b> (each pinned by a test that fails the day it is fixed)</summary>

- **Lexicon-free lures on a fresh, brand-free domain** ("Your stay needs one more step. Finish it at `<new domain>`
  before you travel.") are delivered with a warning, not held: red-team case A02, a strict xfail in
  `tests/adversarial/test_redteam.py`.
- **Languages outside the word lists** rely on the model and judges; held-out misses are listed in `eval/report.md`.
- **Link shorteners** aren't followed without network checks switched on, so they get a warning, not a verdict.
- **Travel-brand words in unfamiliar domains are flagged**: <!-- num:c3_heldout_brand_fp -->8.2%<!-- /num --> of unseen
  legitimate domains containing a travel-brand word, against <!-- num:c3_heldout_fp -->0.007%<!-- /num --> of all unseen
  legitimate domains.
- **The guest-check PIN has 4 digits**: if the database leaked, the salted hashes fall to 10,000 guesses. The real
  protection is the attempt limits (5 wrong PINs per client per booking, 20 per client, 50 per booking from all clients,
  per 15 minutes; 10 successful checks per booking per day).

</details>

## Run it

Needs Python 3.12 or newer (the lockfiles are built with 3.13).

```bash
pip install --require-hashes -r requirements.lock && pip install --no-deps -e .   # pinned, hash-checked
bash scripts/fetch_data.sh                    # real datasets into data/raw (+ data/MANIFEST.json)
python -m eval.evaluate                       # trains the models, writes eval/report.md + report.json (~3 min)
STAYGUARD_DEMO_MODE=1 uvicorn stayguard.api:app --port 8000   # console at http://localhost:8000
```

Or `docker compose up --build` (demo mode on), then open http://localhost:8000.

**Demo vs production mode.** Production mode is the default: the platform-facing endpoints need an `X-API-Key`
(`STAYGUARD_API_KEY`) and refuse to serve without one. Demo mode (`STAYGUARD_DEMO_MODE=1`) adds the console's demo
endpoints and, if no key is set, lets the console call everything. Never run demo mode on a public host.

**Real AI judges (optional).** Set `STAYGUARD_GEMINI_API_KEY` (Google AI Studio; free tier available; default model
`gemini-3.5-flash-lite`, change with `STAYGUARD_GEMINI_MODEL`) or `STAYGUARD_ANTHROPIC_API_KEY`. Without a key a
deterministic offline judge runs instead, so everything works with no key and no network. Google may use free-tier
requests to improve its products, so use a paid key for real guest messages (DECISIONS #44).

**Development:** `make lint types test` (see `CONTRIBUTING.md`). Tests run offline on a small fixture snapshot.

## The console

| Tab | What you see |
|---|---|
| **Live attack** | A hijack replayed against real upcoming bookings: a normal staff message is delivered, the attacker logs in with a stolen cookie at 03:12, and six scams (English, Hindi, Hinglish, a prompt injection, real phishing domains, a fresh look-alike) are blocked. "Log everyone out and warn guests" runs containment. |
| **Check a message** | Type anything and see the decision, highlighted evidence, every step with its timing, the judges' arguments and link verdicts. Toggle "AI judges down" to see the safe fallback. |
| **Guest view** | The guest-facing check (booking number + PIN; five wrong tries lock that client out of that booking). |
| **Results** | The evaluation, live from `eval/report.json`. |
| **Audit log** | The hash-chained, append-only log, with "Verify the chain". |

<p>
  <img src="docs/images/console-contained.png" alt="Containment: attacker logged out, guest PINs rotated, guests warned, MITRE ATT&CK case file" width="49%">
  <img src="docs/images/console-check-a-message.png" alt="Check a message: the decision, quoted evidence and each pipeline step with its timing" width="49%">
</p>

## Optional pipeline switches (not yet proven)

These were built after held-out v2 and are **off by default**. They were measured once on a third blind set,
held-out v3 (312 messages, 20 languages, written by an agent that never saw the code, `docs/HELDOUT_V3_BRIEF.md`); its
frozen result will be added here when it is committed. Until then, treat none of them as an improvement.

| Change | Switch | Why |
|---|---|---|
| Multilingual encoder (multilingual-e5-small, ONNX) + booking context as the language model | `STAYGUARD_CLASSIFIER=encoder_ctx` | DECISIONS #38, #39 |
| TF-IDF + booking context (no download needed) | `STAYGUARD_CLASSIFIER=tfidf_ctx` | #39 |
| Model-only holds go to the AI judges (still held if they're down) | `STAYGUARD_ROUTE_MODEL_HIGH_TO_JUDGES=1` | #39 |
| Money mentions that only point to the platform's own app or reception are warned, not held | `STAYGUARD_PLATFORM_FLOW_WARN=1` | #40 |
| Shadow mode (decisions returned with `enforced: false`) and a labelled feedback queue | `STAYGUARD_ENFORCE=0`, `POST /v1/messages/{id}/label` | #41 |
| Network link checks: shortener destinations and domain age, safe against server-side request forgery | `STAYGUARD_NET_CHECKS=1` | #42 |

<details>
<summary>Reproducing the held-out v3 run</summary>

Needs a machine that can reach huggingface.co (it downloads the encoder weights once).

```bash
make install-encoder         # dev toolchain + onnxruntime/tokenizers, hash-pinned (requirements-encoder.lock)
make encoder                 # fetch the encoder, train encoder_ctx, write eval/calibration_encoder_ctx.json
git add eval/calibration_encoder_ctx.json && git commit -m "Calibrate the encoder model for the v3 run"
make eval-v3                 # ONE blind run -> eval/heldout_v3_first_look.json (refuses a dirty tree)
# optional, same commit, real judges (Gemini free tier; pace to your AI Studio limit):
#   STAYGUARD_GEMINI_API_KEY=... python -m eval.evaluate_v3 --add-arm candidate_real_judges --judge-rpm 10
```

The primary comparison was fixed before the run: the candidate (encoder + context + platform-flow warning + routing)
against today's system, on scams caught and legitimate messages held, paired exact McNemar, Holm-adjusted.

</details>

## API

| Endpoint | Purpose |
|---|---|
| `POST /v1/messages/check` | Decide on a message: `deliver` / `warn` / `hold` / `block`, with reason codes, quoted evidence, path, trace and versions. `message_id` makes it idempotent. |
| `POST /v1/messages/{id}/label` | A hotel, guest or analyst labels a stored message scam or legit (feedback queue); never changes the decision. |
| `POST /v1/sessions/score` | Score an extranet login for takeover risk; returns `step_up_required`. |
| `POST /v1/sessions/{id}/reads` | The extranet reports which reservations a session opened (used by containment). |
| `POST /v1/guest/verify` | Guest check by booking number + PIN (public; rate-limited, locks after repeated wrong PINs). |
| `POST /v1/properties/{id}/contain` | One-click containment; returns the case file. |
| `GET /v1/metrics` | Live counters, path share, p50/p95, cost per 1,000, dataset facts, evaluation. |
| `GET /v1/audit`, `GET /v1/audit/verify` | Tamper-evident audit trail. |
| `POST /v1/admin/llm-outage` | Simulate the AI provider going down. |
| `POST /v1/demo/simulate-attack`, `POST /v1/reservations/{id}/demo-pin`, `GET /v1/samples` | Demo mode only (404 otherwise). |

Interactive docs at `/docs`. Everything except the console, `/healthz` and `/v1/guest/verify` needs `X-API-Key` in
production mode. A reused `message_id` with a different payload is rejected with 409.

## Data

| Dataset | Used for | Size |
|---|---|---|
| [Hotel Booking Demand](https://github.com/rfordatascience/tidytuesday/tree/master/data/2020/2020-02-11) (Antonio, Almeida & Nunes, 2019) | Reservations in the demo database; `deposit_type` gives the payment terms for the core rule | 119,390 bookings, 2 hotels |
| [UCI SMS Spam Collection](https://archive.ics.uci.edu/dataset/228/sms+spam+collection) | Trains the language model; held-out real messages measure false alarms | 5,574 messages |
| [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) (active domains) | Live phishing blocklist; real booking-themed hosts for testing | 392,178 domains |
| [OpenPhish public feed](https://github.com/openphish/public_feed) | Blocklist and a generic phishing test | 300 URLs |
| [Top 1M domains](https://github.com/zer0h/top-1000000-domains) | Popularity allowlist (top 10k) and unseen legitimate domains for false-positive tests | 1M domains |

Written for the project and labelled as such: hotel message seeds for training (eight languages and Hinglish); a
115-message dev set; held-out v1 (124 messages, `data/curated/HELDOUT_SOURCES.md`); held-out v2 (148, written by a
separate agent, `docs/HELDOUT_V2_BRIEF.md`); held-out v3 (312, `docs/HELDOUT_V3_BRIEF.md`); a red-team corpus
(`tests/adversarial/corpus.py`); and synthetic login telemetry, since real account-takeover logs are private. In the
booking dataset 87.6% of bookings are "No Deposit", which is not the same as "paid at the hotel" on a real platform.
Every live feed is pinned by SHA-256 in `data/MANIFEST.json`, and reports refuse to compare across different snapshots.

## Repository map

```
stayguard/      engine.py (the decision router), signals.py (word lists, PII masking, injection, deobfuscation),
                links.py, judges.py (prosecutor/defender), classifier.py, ctx_classifier.py, encoder.py,
                session_risk.py, netcheck.py, feedback.py, service.py, db.py, api.py, static/ (console)
data/curated/   training seeds, dev set, held-out v1/v2/v3 and their sources
eval/           evaluate.py, evaluate_v3.py, calibrate.py, report.md/json, frozen first-look results
tests/          unit, integration and adversarial tests; offline on tests/fixtures/raw
docs/           ADVERSARIAL_REVIEW.md (four review rounds), MESSAGE_TRACE.md, held-out briefs, images
DECISIONS.md    why each choice was made and what was rejected
CLAUDE.md       safety and honesty invariants every change must keep
```

**Where to read more:** `DECISIONS.md` explains every design choice, `docs/ADVERSARIAL_REVIEW.md` has the four rounds of
adversarial review and what was fixed or declined, and `eval/report.md` has the full evaluation.
