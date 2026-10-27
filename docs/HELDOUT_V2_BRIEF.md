# Held-out v2: the brief its author was given

This is the complete prompt given to the separate agent that wrote `data/curated/heldout_v2.jsonl` (commit `a0ef0f5`),
reproduced verbatim so the independence claim can be checked (review round 2, C14).

What it shows, stated plainly:

- The author was told not to open the repository or the round-1 scratch files, and its report says it did not.
- The brief was written by the same assistant that built StayGuard, after review round 1, and it asks for some of the
  hard cases round 1 had found (a reassuring phrase mixed with the ask, links on legitimate hosting, obfuscation) and
  for at least 20 legitimate payment messages. So v2 is aimed at known weak spots: it is harder than a random sample,
  and it is not a neutral estimate of real-traffic rates.
- The author is the same model family that wrote the seeds, the dev set and the rules, so its style may correlate
  with what the character n-gram model learned.

---

You are writing an INDEPENDENT evaluation set for a system that screens messages sent on a hotel booking platform (Booking.com-style). Criminals take over a hotel's partner/extranet account (usually with infostealer malware) and message real guests through the platform's own chat, asking for payment or card details, typically via a fake link, a bank transfer, or by moving the conversation to WhatsApp. Legitimate hotels also send lots of messages, including some that mention money (city tax, parking, deposits, card declined → update in the app, prepayment on a non-refundable rate, invoices for groups).

**Independence rules (strict):** Do NOT open, read, grep or list anything under `/home/claude/stayguard` or `/tmp/claude-0/-home-claude/d668c328-a1a5-51bd-b683-0485a90368c8/scratchpad/r1`. You must not see the detector's code, rules, lexicons, tests or existing datasets. Build everything from web sources (use WebSearch / WebFetch) and your own knowledge of how hotels write to guests.

**What to produce:** a JSON-lines file at `/tmp/claude-0/-home-claude/d668c328-a1a5-51bd-b683-0485a90368c8/scratchpad/heldout_v2/heldout_v2.jsonl` with **at least 140 rows: ~70 scams and ~70 legitimate**, plus `/tmp/claude-0/-home-claude/d668c328-a1a5-51bd-b683-0485a90368c8/scratchpad/heldout_v2/SOURCES.md` listing every source with URL and a short code (S1, S2, … for scam sources, L1, L2, … for legitimate templates). Each row is one JSON object:
`{"id": "v2-001", "split": "heldout_v2", "label": 1, "category": "...", "lang": "en", "terms": "pay_at_property", "direction": "hotel_to_guest", "source": "S3", "text": "..."}`
- `label`: 1 = scam, 0 = legitimate.
- `terms`: the booking's payment terms the message is about: `pay_at_property` (guest pays at the hotel; nothing due before arrival), `prepaid` (already paid through the platform), or `deposit` (platform collects a deposit, rest at the hotel). Choose realistically; scams overwhelmingly target pay_at_property bookings, but include some prepaid/deposit scams too. Legit money-related messages should mostly be on prepaid/deposit bookings or clearly say "pay at the hotel".
- `direction`: `hotel_to_guest` for almost all; include ~6 `guest_to_hotel` rows (e.g. fake-guest overpayment refund scams, malware "lost passport, see photos" lures, and normal guest questions).
- `category`: free text such as `reported_wording` (reuses a fragment quoted in a source), `reported_pattern` (paraphrases a described pattern), `legit_template`, `legit_payment`, `legit_logistics`, `multilingual`, `obfuscated`.
- `lang`: ISO code (en, es, pt, fr, de, it, nl, pl, hi, ar, zh, ja, ru, tr, ...). Use at least 8 languages across both labels, roughly 30% non-English.
- `source`: the source code the row is based on.

**Make it realistic and hard, both ways:**
- Scams: quote or closely paraphrase wording from real reports (security vendor write-ups — Akamai, Secureworks/Sophos, Perception Point, Microsoft "Storm-1865/ClickFix", KrebsOnSecurity, Bitdefender, Malwarebytes, BleepingComputer — news, consumer forums, Reddit/Tripadvisor threads, Booking.com's own scam warnings). Vary: with and without links; fresh-looking domains (invent new ones; do not use domains from blocklists); links on legit hosting (forms, docs, file-sharing); shortened links; QR codes; WhatsApp/Telegram moves; bank transfer/IBAN; "verify card within 24 hours or cancellation"; fake upgrade or tax payments; polite low-pressure versions; obfuscation (odd characters, spacing) in a handful; a few in which a reassuring phrase is mixed with the real ask.
- Legitimate: real hotel templates (check-in times, directions, parking, breakfast, late arrival, door codes, reviews), and crucially **legitimate payment-related messages**: city tax payable at the hotel, deposit charged by the platform, "your card was declined, please update it in the app", prepayment reminders on non-refundable rates via the platform, group invoices, hotels that genuinely use WhatsApp for logistics, optional paid extras. These are what make a detector hold real hotels by mistake, so include at least 20 of them.
- Do not try to guess or game any particular detector; write what real messages look like.

When done, verify the file parses (one JSON object per line, unique ids, both labels present) with a short Python check, and reply with: the row counts by label, language and category, the number of distinct sources, and the two file paths. Do not include the full file in your reply.