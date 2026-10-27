# Decisions

Short records of the choices that shape StayGuard, and what we'd change for production.

### 1. Booking payment terms are the strongest signal
87.6% of the 119,390 real bookings are "No Deposit" (paid at the hotel). For those, *nothing* is due before arrival,
so a payment demand is wrong regardless of language, link or wording. This one rule catches no-link scams, new
domains and languages the model has never seen, and it is fully explainable. The rule only fires on a real *ask*
(payment words + an instruction + a link/deadline/goal), never on mentions such as "parking is 15 EUR, payable
at the desk" or "you pay the driver directly".

### 2. Rules first, model second, LLM last
Rules settle almost all of a realistic mix in a few milliseconds (p50 <!-- num:p50_ms -->3.0 ms<!-- /num -->). The model
settles most of the rest. The judges see only what's left (<!-- num:judge_share -->0.2%<!-- /num --> of the mix), which keeps
the **estimated** LLM cost at <!-- num:est_cost_per_1000 -->$0.0004<!-- /num --> per 1,000 messages instead of
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
risky login → hold. On the held-out set, StayGuard catches <!-- num:heldout_degraded_caught -->66.7%<!-- /num --> of scams with the
judges down, against <!-- num:heldout_caught -->66.7%<!-- /num --> with them up.

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
against the checker. A PIN, with a lockout after 5 wrong tries, prevents that, and containment rotates PINs for every
guest the attacker could see.

### 12. SQLite in the demo, Postgres in production
Same SQL. Production would add Kafka/Redis Streams between the message service and the checker, per-tenant rate
limits, a feedback loop from analyst verdicts into retraining, WHOIS/domain-age and redirect-following for links,
and a contextual bandit to tune thresholds per market.

### 13. A held-out set nobody tuned on, and a frozen first look
Chosen over: keep reporting the golden set. The golden set was written next to the rules and every miss on it was
fixed, so its 100% says little. The new held-out set (124 messages, `data/curated/HELDOUT_SOURCES.md`) is built from
cited public reports and hotel templates and was committed before StayGuard ever scored it. Its first blind result —
<!-- num:heldout_caught -->66.7%<!-- /num --> of scams caught — is frozen in `eval/heldout_first_look.json`. That is far below
dev, and it is the number to quote. Most misses went through the "no payment ask" fast path: lexicon gaps (French,
German, Polish, Russian card checks; "reply YES"; QR codes; spelled-out phone numbers) turned straight into deliveries.

### 14. Thresholds from a calibration split
Chosen over: hand-set 0.10 / 0.90. `eval/calibrate.py` picks MODEL_LOW/MODEL_HIGH on the SMS calibration split plus the
dev set by a rule fixed in advance (≤1% of calibration scams below LOW; ≤1% of calibration legit above HIGH). The
result (0.26 / 0.46) is much narrower than the hand-set band, so the model now settles more messages on its own and
fewer reach the judges.

## Known limits
- The golden set was written by the same team as the rules. Real validation needs labelled platform traffic.
- Login data is synthetic.
- The offline judge is a deterministic stand-in; plug in an API key for real LLM judges.
- The link layer can't see where shorteners lead without network access (they get a warning, not a pass).
