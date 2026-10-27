# Held-out set: sources and rules

`heldout_eval.jsonl` has 124 messages (66 scams, 58 legitimate). It was written on 2026-10-27 **after** the rules had
been tuned on `golden_eval.jsonl` (now `split: dev`). It was committed before StayGuard was ever run on it, and its
first results are frozen in `eval/heldout_first_look.json`.

Every row has a `source` code. "Reported wording" rows reuse fragments quoted in the source. "Reported pattern" rows
paraphrase a pattern the source describes (pretext, deadline, channel). Legitimate rows follow published hotel or
host message templates, or the self-service request types in Booking.com's messaging API.

It deliberately includes things the dev set and the lexicons don't cover: Dutch, Polish, Turkish, Arabic, Chinese and
Russian; QR-code and "reply YES" lures; spelled-out phone numbers; a hiragana `ん` used in place of `/`; guest-to-hotel
malware lures (stage 1 of the 2023 campaigns); and legitimate hotels using WhatsApp.

Honest limit: the same person who wrote the rules wrote this set. Citing outside wording and freezing the first look
reduces the bias but cannot remove it. Real validation needs labelled platform traffic.

| Code | Source |
|---|---|
| S1 | Camino de Santiago forum, "Beware of phishing scam targeting Booking dot com reservations" (verbatim email and in-app fragments): https://www.caminodesantiago.me/community/threads/beware-of-phishing-scam-targeting-booking-dot-com-reservations.83355/ |
| S2 | BleepingComputer, "Hotel hackers redirect guests to fake Booking.com to steal cards", 22 Sep 2023, incl. a reader's reproduced email: https://www.bleepingcomputer.com/news/security/hotel-hackers-redirect-guests-to-fake-bookingcom-to-steal-cards/ |
| S3 | TripProf, "Booking.com WhatsApp scam 2026": https://tripprof.com/en/blog/booking-com-whatsapp-scam-summer-2026/ |
| S4 | InboxGuard, "The Booking.com 'payment failed' message is a scam": https://inboxguard.app/blog/booking-com-payment-failed-message-scam |
| S5 | MalwareTips, "Hotel booking verification scam": https://malwaretips.com/blogs/hotel-booking-verification-scam/ |
| S6 | Euronews, "Fake listings and phishing emails", 23 Dec 2025: https://www.euronews.com/2025/12/23/fake-listings-and-phishing-emails-how-travellers-have-lost-hundreds-to-bookingcom-scams |
| S7 | Phixo, "Fake Booking.com email": https://phixo.app/fake-booking-confirmation-email |
| S8 | Akamai, "Unmasking a sophisticated phishing campaign that targets hotel guests", 21 Sep 2023: https://www.akamai.com/blog/security-research/sophisticated-phishing-campaign-targeting-hospitality |
| S9 | Bitdefender, "How hackers hijack hotel accounts on Booking.com" (the article in this project's history; no URL is recorded here, so these 10 rows are not independently checkable — review round 1, C13) |
| S10 | TechRadar, "Booking.com phishing scam uses secret characters", 15 Aug 2025: https://www.techradar.com/pro/security/booking-com-phishing-scam-uses-secret-characters-to-trick-victims-last-minute-holiday-hunters-beware |
| S11 | Malwarebytes, "Credit card thieves target Booking.com customers", Sep 2023 (Perception Point stage 1): https://www.malwarebytes.com/blog/news/2023/09/credit-card-thieves-target-bookingcom-customers |
| S12 | The Register, "That 'angry guest' email from Booking.com? It's a scam", 13 Mar 2025 (Microsoft, Storm-1865): https://www.theregister.com/2025/03/13/bookingdotcom_phishing_campaign/ |
| L1 | Amenitiz, ready-to-use guest message templates: https://support.amenitiz.com/en/articles/403621-ready-to-use-guest-message-templates-arrival-check-out-thank-you |
| L2 | Hospitable, pre-check-in message examples: https://hospitable.com/pre-check-in-message-examples |
| L3 | Booking.com Connectivity docs, "Understanding the Messaging API" (self-service request types): https://developers.booking.com/connectivity/docs/messaging-api/understanding-the-messaging-api |
