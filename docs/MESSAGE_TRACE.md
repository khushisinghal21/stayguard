# One message, end to end (baseline, commit 73b010d)

Request:

```
POST /v1/messages/check
{"text": "Dear guest, confirm your card within 12 hours at https://booking.com-hotela.eu/verify",
 "reservation_id": "R114326", "session_id": "S-…"}
```

1. **`api.check_message`** validates the body with Pydantic (`MessageIn`: 1–5,000 chars, direction and terms
   enums) and calls `Service.check_message(**body)`. `auth` passes because `STAYGUARD_API_KEY` is unset.
2. **`Service.check_message`**
   - If `message_id` was seen before, returns the cached response (no payload check — defect 1.3).
   - Loads the reservation → `payment_terms = pay_at_property` (from the dataset's `deposit_type = No Deposit`),
     the property → its own domains, and the session row → `{risk, level, reasons, status}`.
   - A revoked session short-circuits to `block / SESSION_REVOKED` and an audit row.
   - Builds `ctx = {payment_terms, direction, session, property_domains}` and calls `Engine.check(text, ctx)`.
3. **`Engine.check`** appends one `trace` entry per stage with its duration:
   1. `guardrails` — `mask_pii` (Luhn-checked cards, IBAN, UPI, e-mail, ID, phone) → `masked`; `extract(text)` →
      `TextSignals` (money ask strong/soft, card data, off-platform payment/contact, urgency, verification lure,
      impersonation, overpayment, injection, hidden characters, mixed scripts, deobfuscated leetspeak, URLs,
      evidence spans); `detect_language`.
   2. `links` — `LinkChecker.check` per URL: official → brand-owned → blocklist (392k hosts, parents too) →
      heuristics (brand token, domain-in-subdomain, typosquat, punycode, risky TLD, free hosting, shortener,
      lure words, popularity). Here: `booking.com-hotela.eu` is on the blocklist → `malicious`, score 1.0.
   3. `rules` — injection → hold; obfuscation → warn; `KNOWN_PHISHING_LINK` → block; look-alike → hold/block;
      `PAY_ASK_ON_PAY_AT_HOTEL`, `CARD_DATA_REQUEST`, `OFF_PLATFORM_PAYMENT`, `OFF_PLATFORM_CONTACT`
      (hotel→guest) or `OVERPAYMENT_REFUND_REQUEST` (guest→hotel). Computes `quiet`. Here: block.
   4. `model` — `ScamClassifier.score` (TF-IDF + logistic regression) always runs for the trace.
   5. `judges` — only if no rule decided and the message isn't quiet and the model is between 0.10 and 0.90.
      Circuit breaker → judge (offline or Anthropic) → referee `p_scam` → hold ≥ 0.65, warn ≥ 0.40, else deliver;
      on failure, the degraded policy. Skipped here.
   6. `session` — critical risk → at least hold (block if money/links), risky → one step stricter; suggests
      containment.
   Returns a `Decision` (decision, confidence, reasons, path, evidence, links, model_p, session, judges, language,
   masked text, banner, trace, latency, versions).
4. **Back in `Service.check_message`** — inserts the message row (raw text — defect 1.10) and the idempotency row,
   then `db.audit("message.decision", {…masked_text, versions…})`, which appends a row whose hash covers the
   previous row's hash.
5. **Response** — the decision JSON (`message_id`, decision, explanations, evidence, trace, versions, reservation
   summary) goes back to the platform, which delivers, adds the banner, or withholds the message.
