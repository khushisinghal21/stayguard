# Decisions

Short records of the choices that shape StayGuard, and what we'd change for production.

### 1. Booking payment terms are the strongest signal
87.6% of the 119,390 real bookings are "No Deposit" (paid at the hotel). For those, *nothing* is due before arrival,
so a payment demand is wrong regardless of language, link or wording. This one rule catches no-link scams, new
domains and languages the model has never seen, and it is fully explainable. The rule only fires on a real *ask*
(payment words + an instruction + a link/deadline/goal), never on mentions such as "parking is 15 EUR, payable
at the desk" or "you pay the driver directly".

### 2. Rules first, model second, LLM last
Rules settle almost all of a realistic mix in a few milliseconds (p50 <!-- num:p50_ms -->2.0 ms<!-- /num -->). The model
settles most of the rest. The judges see only what's left (<!-- num:judge_share -->0.7%<!-- /num --> of the mix), which keeps
the **estimated** LLM cost at <!-- num:est_cost_per_1000 -->$0.0014<!-- /num --> per 1,000 messages instead of
<!-- num:est_cost_per_1000_all_llm -->$0.1988<!-- /num --> if every message went to the judges (published Claude Haiku 5.5 price,
estimated token counts — an estimate, not a bill). An LLM-first design would also make an attacker's prompt
injection part of every decision.

### 3. The judges argue, and must quote
One LLM asked "is this a scam?" is easy to sway. Two roles (prosecutor, defender) must each give strict JSON
with quotes copied from the message; quotes that aren't in the message are dropped before the referee weighs
them. The message is wrapped as untrusted data and PII is masked first. Judges can make a decision stricter or
looser only where no hard rule fired — they can never release a message a rule held.

### 4. Fail safe, not fail open
LLM timeout 3 s, circuit breaker after 3 failures. While it's open: normal login → deliver with a guest warning;
risky login → hold. On the held-out set, StayGuard catches <!-- num:heldout_degraded_caught -->74.2%<!-- /num --> of scams with the
judges down, against <!-- num:heldout_caught -->86.4%<!-- /num --> with them up.

### 5. Login risk changes the decision, not just a dashboard
A critical session (stolen cookie replay, impossible travel, payout change from a new device) holds every outgoing
message until the hotel re-confirms with a passkey. Even "what time will you arrive?" is held, because attackers
build rapport before they send a link.

### 6. Every message is still checked on its own
In the synthetic data, malware running on the front-desk PC scores 0% at the login layer, because the login looks
normal. Message checks are the layer that still works when the account is fully compromised.

### 7. A classic model, not a large multilingual embedding
TF-IDF (word + character n-grams) + logistic regression: under a millisecond, works on Devanagari, Hinglish and
European languages through character n-grams, trains in seconds, and explains itself (top terms). URLs are
replaced with a token so the model learns language, not domains. Next step: a small multilingual encoder once we
have real labelled platform messages.

### 8. Link heuristics tuned on real data, including the false positives
The first version flagged airbnb.es, expedia.co.in, brookings.edu and Japanese IDN domains. Fixes, each measured on
99,967 real legit domains outside the top 10k: brand-owned country domains are allowed, fuzzy typosquat matches
need a second signal, a brand word counts only when it stands alone ("booking-checkin.com", not
"trybooking.com"), and punycode counts only when one label mixes Latin with Cyrillic/Greek. False positives
went from 0.15% to 0.01% on the ranges we tuned on; on 100k never-examined domains (ranks 110k–210k) the rate is
<!-- num:c3_heldout_fp -->0.006%<!-- /num -->. The heuristics are travel-specific (3% on generic phishing); the blocklist covers
everything else.

### 9. Honest evaluation over impressive numbers
The first zero-day test reported 100%, but it selected domains containing "booking", which is the heuristic's own
feature. We kept it, labelled it, and added a random feed sample, a 100k legit-domain false-positive test, and
mutation attacks (deadline removed, fresh brand-free domain, leetspeak, hidden characters, spaced letters). The
"fresh domain" attack exposed a fast-path gap (82% at first, 100% after the fix, both on the dev set), which is why it's in
the suite. That fix was itself tuned on dev, which is exactly why the held-out set (#13) exists.

### 10. Tamper-evident audit trail
Every decision, login score, guest check and containment is hash-chained (each row stores the previous row's hash).
SQLite triggers reject UPDATE and DELETE. Decisions store the PII-masked text plus engine/rules/model versions, so
any past decision can be explained later.

### 11. Guest check needs a PIN
Attackers already know names and dates, so a reservation number alone would let them test their own messages
against the checker. A PIN, with a lockout after 5 wrong tries per booking and 20 per client, prevents that, and
containment rotates the PIN of every guest whose booking the attacker's session opened or messaged (#21).

### 12. SQLite in the demo, Postgres in production
Same SQL. Production would add Kafka/Redis Streams between the message service and the checker, per-tenant rate
limits, a feedback loop from analyst verdicts into retraining, WHOIS/domain-age and redirect-following for links,
and a contextual bandit to tune thresholds per market.

### 13. A held-out set nobody tuned on, and a frozen first look
Chosen over: keep reporting the golden set. The golden set was written next to the rules and every miss on it was
fixed, so its 100% says little. The new held-out set (124 messages, `data/curated/HELDOUT_SOURCES.md`) is built from
cited public reports and hotel templates and was committed before StayGuard ever scored it. Its first blind result —
<!-- num:heldout_caught -->86.4%<!-- /num --> of scams caught — is frozen in `eval/heldout_first_look.json`. That is far below
dev, and it is the number to quote. Most misses went through the "no payment ask" fast path: lexicon gaps (French,
German, Polish, Russian card checks; "reply YES"; QR codes; spelled-out phone numbers) turned straight into deliveries.

### 14. Thresholds from a calibration split
Chosen over: hand-set 0.10 / 0.90. `eval/calibrate.py` picks MODEL_LOW/MODEL_HIGH on the SMS calibration split plus the
dev set by a rule fixed in advance (≤1% of calibration scams below LOW; ≤1% of calibration legit above HIGH). The
result (0.26 / 0.46) is much narrower than the hand-set band, so the model now settles more messages on its own and
fewer reach the judges.

### 15. PINs from `secrets`, stored as salted hashes
Chosen over: `random.Random(42)` PINs stored in plain text (and `random.Random(case_id)` on rotation). Replaying the
public seed predicted the first three PINs exactly (`docs/baselines/before/repro.txt`), which voided #11. Now
`secrets.randbelow`, a per-row salt, SHA-256, `hmac.compare_digest`. Because no PIN can be read back, the demo endpoint
*issues* a fresh PIN instead of showing the old one. Limit, stated: a 4-digit PIN falls to 10,000 guesses if the
database leaks; the attempt limits are the real protection.

### 16. Production mode is closed by default
Chosen over: one optional API key that, unset, left every endpoint open. Before: `/demo-pin` returned a PIN with no
key and `simulate-attack` could wipe sessions, messages and cases. Now production mode (default) answers 503 on
internal endpoints until a key is configured, and the demo endpoints are 404 unless `STAYGUARD_DEMO_MODE=1`.
Fail-closed beats convenient: a forgotten key now breaks the integration loudly instead of exposing it quietly.

### 17. Idempotency keys are bound to the payload
Chosen over: replaying the stored decision for any reused `message_id`. Reproduced: "Breakfast is from 7" delivered
under key `k1`, then a bank-transfer demand under `k1` also came back `deliver`. The key now carries a SHA-256 of
(text, reservation, session, direction); a different payload gets 409 and an audit row.

### 18. Only provider failures count as "judges unavailable"
Chosen over: `except Exception` around the judge call. A `KeyError` in judge code became `DEGRADED_WARN` (delivered)
and counted towards opening the breaker. Now timeouts, HTTP errors and malformed replies are provider failures
(degraded policy + breaker); anything else is a bug and holds the message (`SYSTEM_EXCEPTION_FAIL_CLOSED`). Half-open
admits exactly one probe (tested with 16 concurrent callers). `Engine.check` and `Service.check_message` both wrap
everything so no internal error can turn into a delivery.

### 19. Link extraction validated against the public-suffix list
Chosen over: a hand-written TLD alternation. It missed `.ro`, `.pl`, `.ws`, `.lat` and cut `.com.br` to `.com`, so
those links were never checked. Candidates are now validated with tldextract's bundled list; regressions cover
sentence boundaries ("today.So"), "e.g.", prices and `user@host` tricks.

### 20. Feeds pinned by a manifest
Chosen over: re-fetching live feeds and comparing reports across fetches. The phishing feeds change daily, so last
week's report could not be reproduced. `data/MANIFEST.json` records URL, fetch time, line count and SHA-256 per file;
reports store its hash and `--compare` refuses to diff across manifests without `--allow-drift`.

### 21. Containment warns exactly who was exposed
Chosen over: "the first N upcoming bookings by date", N = reads claimed by login telemetry — a guess presented as a
fact. The extranet now reports reads (`POST /v1/sessions/{id}/reads`); containment warns reads ∪ messaged guests and
reports any unattributed reads for manual review.

### 22. PII masked at rest; audit chain anchored
Chosen over: storing raw message text (a card number came back from `/v1/messages`). Stored text is masked; raw text
only with `STAYGUARD_RETAIN_RAW=1`, purged after the retention period. The audit head is appended to a separate anchor
file every N rows; a forger who rewrites the whole chain consistently is caught by the anchors (tested). Remaining
limit: someone who can rewrite both files can still forge; production needs a write-once external log.

### 23. Numbers in docs are rendered, never typed
Chosen over: hand-copied figures, which had drifted (README latency, "99.8% of normal traffic", the thresholds).
README and DECISIONS numbers are rendered from `eval/report.json`; a test fails if they differ.

### 24. A red-team corpus separate from both evaluation sets
Chosen over: fixing what the held-out set missed. After the frozen first look (<!-- num:heldout_first_look_caught -->66.7%<!-- /num -->
caught), fixes were driven by `tests/adversarial/corpus.py`, written independently. Honest caveat: the held-out misses
had been seen by then, so the current <!-- num:heldout_caught -->86.4%<!-- /num --> is less blind than the first look, and both
are always quoted together.

### 25. Judges vouch for links one by one
Chosen over: passing judges only the worst link score. Found by the new engine tests: "We confirm your reservation.
Directions: `<Google Maps link>`" was HELD, because the maps link scores 0.05 and "score > 0" meant unvouched. Judges
now get per-link verdicts and vouch only for official, brand-owned, maps and popular domains; a fresh brand-free
domain is still unvouched.

### 26. Known failures stay in the suite as strict xfails
Chosen over: weakening or deleting a red-team case the system fails. Red-team A02 (no money or deadline words, fresh
brand-free domain) is delivered with a warning, not held; the offline judge rules about 0.64 against a 0.65 hold line.
Moving the line to pass one case would be tuning on the test; the case stays as `xfail(strict=True)` so the suite
reports the day it passes.

### 27. Tests run offline on a fixture snapshot
Chosen over: tests that read `data/raw` or the network. `tests/fixtures/raw` is a small, fixed slice of the real
datasets; the suite (390 tests, 98% line coverage, ≥95% on engine/signals/links) runs in about 30 s with no key and
no network, and CI enforces the coverage gates.

## Known limits
- Both message sets have the same author as the rules. The held-out set cites outside wording and its first look is
  frozen, which reduces the bias but does not remove it. Real validation needs labelled platform traffic.
- Login data is synthetic, and separable by construction.
- Every reported number used the offline deterministic judge; real LLM judges are unmeasured.
- The link layer can't see where shorteners lead without network access (they get a warning, not a pass).
- Lexicon-free lures on fresh brand-free domains can be delivered with a warning (#26).
