# Held-out v3: the brief its author was given

This is the complete prompt given to the separate agent that wrote `data/curated/heldout_v3.jsonl`, reproduced verbatim
so the independence claim can be checked. The file's SHA-256 is
`d260839140ddcb6239aef4057bfd6dc4448fada5fb7d794b3b29db99757ffd36` (also checked by `eval/evaluate_v3.py`).

What it shows, stated plainly:

- The author was told not to open anything under `/home/claude` or the session's scratch files except its own output
  folder: no code, rules, word lists, tests, earlier datasets or reviews.
- The file was copied into the repository and hashed by a script that printed only row counts. Nobody working on
  StayGuard has read its messages. It must not be read, tuned on, trained on or used for calibration until its one
  blind run (`make eval-v3`) has been frozen in `eval/heldout_v3_first_look.json`.
- The brief was written by the same assistant that builds StayGuard, after analysing held-out v2's misses. It asks for
  at least 60 legitimate money messages and 15 legitimate contact messages, which are the false holds v2 found. So, like
  v2, v3 is aimed at known weak spots: harder than a random sample, and not a neutral estimate of real-traffic rates.
- The pipeline changes measured on v3 (DECISIONS #38 to #42) were written while the author was writing v3. The author
  could not see them, and they were designed on held-out v2 and the dev set, never on v3.
- The author is the same model family that wrote the seeds, the dev set and held-out v1 and v2, so its style may
  correlate with what the models learned. A set written by people outside the project would be a stronger test.

Summary the author reported (counts only): 312 rows, 156 scam and 156 legitimate; 20 languages, 145 rows (46.5%) not in
English; 80 legit_payment and 25 legit_contact rows; 17 guest_to_hotel rows; 76 follow-ups; 60 distinct sources.

---

You are writing an INDEPENDENT evaluation set for a system that screens messages sent on a hotel booking platform (Booking.com-style). Criminals take over a hotel's partner/extranet account (usually with infostealer malware) and message real guests through the platform's own chat, asking for payment or card details, typically via a fake link, a bank transfer, or by moving the conversation to WhatsApp/Telegram/phone. Legitimate hotels also send many messages, and a large share of them mention money (city tax, parking, deposits, card declined → update it in the app, prepayment on a non-refundable rate, invoices for groups, paid extras, refunds).

**Independence rules (strict):** Do NOT open, read, grep or list anything under `/home/claude` or under `/tmp/claude-0/-home-claude/d668c328-a1a5-51bd-b683-0485a90368c8/scratchpad` except your own output folder `/tmp/claude-0/-home-claude/d668c328-a1a5-51bd-b683-0485a90368c8/scratchpad/heldout_v3/`. You must not see the detector's code, rules, word lists, tests, earlier datasets or reviews. Build everything from web sources (WebSearch / WebFetch) and your own knowledge of how hotels and guests write.

**What to produce:** a JSON-lines file at `/tmp/claude-0/-home-claude/d668c328-a1a5-51bd-b683-0485a90368c8/scratchpad/heldout_v3/heldout_v3.jsonl` with **at least 300 rows: ~150 scams and ~150 legitimate**, plus `/tmp/claude-0/-home-claude/d668c328-a1a5-51bd-b683-0485a90368c8/scratchpad/heldout_v3/SOURCES.md` listing every source with URL and a short code (S1, S2, … scam sources; L1, L2, … legitimate templates or guidance). Each row is one JSON object:
`{"id": "v3-001", "split": "heldout_v3", "label": 1, "category": "...", "lang": "en", "terms": "pay_at_property", "direction": "hotel_to_guest", "first_in_thread": true, "source": "S3", "text": "..."}`
- `label`: 1 = scam, 0 = legitimate.
- `terms`: the booking's payment terms: `pay_at_property` (guest pays at the hotel; nothing due before arrival), `prepaid` (already paid through the platform), or `deposit` (platform collects a deposit, rest at the hotel). Choose realistically: scams mostly target pay_at_property bookings, but include prepaid and deposit scams too (e.g. "your prepayment failed"). Legitimate money messages appear on all three; on pay_at_property they say the money is paid at the hotel.
- `direction`: `hotel_to_guest` for most; include ~15 `guest_to_hotel` rows (fake-guest overpayment/refund scams, malware lures such as "see photos of my lost item / complaint", and normal guest questions and requests).
- `first_in_thread`: true if this is the first message in the conversation, false if it replies to or follows earlier messages (write those so they read as a follow-up).
- `category`: one of `reported_wording` (reuses a fragment quoted in a source), `reported_pattern` (paraphrases a described pattern), `obfuscated`, `multilingual_scam`, `legit_payment`, `legit_logistics`, `legit_template`, `legit_contact` (real hotels giving a phone/WhatsApp/email for logistics), `multilingual_legit`, `guest_message`.
- `lang`: ISO code. Use **at least 12 languages** across both labels and make **about 45% of rows non-English**, with scams and legitimate messages in each non-English language you use (for example es, pt, fr, de, it, nl, pl, tr, ru, ar, hi, zh, ja, ko, id, th, vi, el, cs, ro). Write each in natural, native-sounding language for that market, not literal translations of English templates.
- `source`: the source code the row is based on.

**Make it realistic and hard, both ways, and do not aim it at any particular detector.**
- Scams (~150): ground them in real reports (security vendor write-ups, news, consumer forums, Reddit/Tripadvisor/Trustpilot threads, the booking platforms' own scam warnings, bank and police advisories). Vary: with and without links; fresh-looking domains (invent new ones; never use real blocklisted domains or real brands' look-alikes copied from reports); links on legitimate hosting (forms, docs, file sharing, site builders); shortened links; QR codes; WhatsApp/Telegram/phone moves; bank transfer with IBAN (some written with spaces, some without), local payment apps for each market (e.g. Pix, Bizum, BLIK, UPI, WeChat/Alipay, PayPal friends), crypto; "verify card within 24 hours or cancellation"; fake upgrade, tax, deposit-refund or "security deposit" payments; calm, polite, low-pressure versions; follow-ups that continue an earlier normal conversation; a handful obfuscated (odd characters, spacing, homoglyphs); a few that mix a reassuring sentence with the real ask.
- Legitimate (~150), including **at least 60 legitimate money-related messages**: city/tourist tax payable at the hotel, deposit collected by the platform, "your card was declined, please update it in the app/on the platform", prepayment reminders on non-refundable rates paid via the platform, pre-authorisations explained, refunds, group/company invoices and pro-formas, optional paid extras (parking, breakfast, airport transfer, late check-out), damage-deposit policies, "we will not charge before arrival" guarantees. Also ordinary logistics, check-in instructions, door codes, directions, reviews, and **at least 15 legitimate messages that give a phone number, WhatsApp, or email for logistics** (real hotels do this).
- Mix lengths: short one-liners to multi-paragraph messages.


This is an evaluation set for a fraud detector that protects travellers; the scam rows are realistic examples of known fraud wording for testing a defensive classifier, using invented domains, numbers and IBANs (never real accounts).

When done, verify the file parses (one JSON object per line, unique ids, all fields present, both labels present) with a short Python check, and reply with ONLY: the row counts by label, by language × label, and by category, the number of distinct sources, and the two file paths. Do not quote any message text in your reply.
