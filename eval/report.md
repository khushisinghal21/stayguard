# StayGuard evaluation report

Generated 2026-10-28 06:40 at commit `3756222`. Reproduce with `python -m eval.evaluate`.
Data manifest `c0cc5d1b1f71ce5d` (feeds fetched 2026-10-27T06:19:37+0000). Held-out set sha256 `9defc0ab5ab31ab4...`, committed in `04376a3`.
Model thresholds: MODEL_LOW 0.03, MODEL_HIGH 0.52 (eval/calibration.json).

**Dev** data was looked at while the rules were built, so dev numbers are optimistic. **Held-out v1** was blind only for its first run: later fixes were made after its misses were read (review round 1, finding C1), so only its frozen first look is a blind number. **Held-out v2** was written afterwards by an agent instructed not to read the code (self-reported; same model family) and committed before any run. It has NOT been run yet; no v2 number exists in this report. Its text was never seen, but its language mix and brief were known while later rules were written (DECISIONS #35).

## A. Messages: StayGuard vs baselines (dev and held-out v1)

Dev: 115 hand-written messages (60 scams). Held-out: 124 messages (66 scams; 10 reuse wording quoted in a cited report, the rest paraphrase reported patterns or were written by the rules' author; `data/curated/HELDOUT_SOURCES.md`). Not blind after its first run.

| System | Held-out v1 caught | Held-out v1 false holds | Dev caught | Dev false holds |
|---|---|---|---|---|
| baseline_blocklist_only | 0% | 0% | 17% | 0% |
| baseline_generic_spam_filter | 20% | 2% | 22% | 7% |
| baseline_stayguard_classifier_only | 85% | 0% | 98% | 9% |
| stayguard_full | 88% | 2% | 100% | 0% |
| stayguard_rules_only | 56% | 2% | 95% | 0% |
| stayguard_zero_day_links_blocklist_off | 88% | 2% | 100% | 0% |
| stayguard_degraded_llm_down | 73% | 2% | 100% | 0% |

The blocklist baseline is uninformative here: 0 of the 35 URLs in the held-out v1 set appear in the phishing feeds, so it could not catch anything. Section C measures links properly.

Held-out, StayGuard: caught 88% (78%-94%) of scams, falsely held 2% (0%-9%) of legitimate messages (95% Wilson intervals), and 3% of legitimate messages were delivered with a warning.

**First look** (frozen in `eval/heldout_first_look.json`, commit `fe4a82e`, 2026-10-27 08:07): caught 67%, falsely held 2%. Any later change that was motivated by held-out results makes the current held-out numbers less blind than the first look.

Held-out v1 by category:

| Category | n | Accuracy | Held | Warned | Delivered clean |
|---|---|---|---|---|---|
| guest_to_hotel_malware | 3 | 0% | 0 | 2 | 1 |
| injection | 2 | 100% | 2 | 0 | 0 |
| legit_guest | 6 | 100% | 0 | 0 | 6 |
| legit_logistics | 18 | 100% | 0 | 2 | 16 |
| legit_multilingual | 13 | 100% | 0 | 0 | 13 |
| legit_payment | 10 | 90% | 1 | 0 | 9 |
| legit_self_service | 5 | 100% | 0 | 0 | 5 |
| legit_template | 6 | 100% | 0 | 0 | 6 |
| obfuscated | 5 | 80% | 4 | 1 | 0 |
| overpayment | 3 | 67% | 2 | 1 | 0 |
| reported_pattern | 37 | 92% | 34 | 2 | 1 |
| reported_wording | 10 | 100% | 10 | 0 | 0 |
| unsupported_language | 6 | 100% | 6 | 0 | 0 |

Paired exact McNemar test, full system vs its classifier alone, on the same held-out v1 scams: full caught 5 the classifier missed, the classifier caught 3 the full system missed, p = 0.72656.


Held-out accuracy by language:

| Language | n | Accuracy |
|---|---|---|
| ar | 2 | 100% |
| de | 3 | 100% |
| en | 91 | 91% |
| es | 5 | 100% |
| fr | 3 | 100% |
| hi | 2 | 100% |
| hinglish | 3 | 67% |
| it | 2 | 100% |
| nl | 2 | 100% |
| pl | 2 | 100% |
| pt | 4 | 100% |
| ru | 1 | 100% |
| tr | 2 | 100% |
| zh | 2 | 100% |

Held-out misses, false holds and warned legit messages:

- `h025` (reported_pattern, en) label=1 -> **warn** via judges ['JUDGES_UNSURE']: Our records show the card on file expired. Update it on the link we texted you or the booking will be released
- `h042` (reported_pattern, hinglish) label=1 -> **warn** via judges ['JUDGES_UNSURE']: Sir hotel ka bank account site se connected nahi hai, aap 3500 rupaye Google Pay kar dijiye isi number pe, rec
- `h052` (obfuscated, en) label=1 -> **warn** via judges ['JUDGES_UNSURE']: Reply YES to keep your room, then follow the instructions we send to complete the guarantee.
- `h056` (guest_to_hotel_malware, en) label=1 -> **warn** via judges ['JUDGES_UNSURE']: Hello, I booked for next week and I have a medical condition. Could you please look at my doctor's documents b
- `h057` (guest_to_hotel_malware, en) label=1 -> **deliver** via rule ['NO_PAYMENT_ASK']: Hi, my wife needs a ground floor room because of her disability. I uploaded the certificate and a map of the a
- `h058` (guest_to_hotel_malware, en) label=1 -> **warn** via judges ['JUDGES_UNSURE']: I am extremely disappointed with my stay and will post a review unless you respond today. See the photos of th
- `h060` (overpayment, en) label=1 -> **warn** via judges ['JUDGES_UNSURE']: Hi, I sent the deposit three times because the page froze. Please keep one and send the other two back through
- `h066` (reported_pattern, en) label=1 -> **deliver** via rule ['NO_PAYMENT_ASK']: Enter the 6-digit code your bank just sent you so that we can finish the pre-authorisation for your stay.
- `h116` (legit_payment, en) label=0 -> **hold** via rule ['CARD_DATA_REQUEST']: We noticed your card details in the app may need updating. Please check them in the Booking.com app under your
- `h121` (legit_logistics, en) label=0 -> **warn** via judges ['OBFUSCATED_TEXT', 'JUDGES_LEGIT']: Here's how to find us from the train station: https://maps.app.goo.gl/2Yb8kQx . It's a 10 minute walk downhill
- `h132` (legit_logistics, en) label=0 -> **warn** via judges ['JUDGES_UNSURE']: Feel free to message us on WhatsApp too if that's easier for you while travelling: +351 21 555 0199.

Dev misses, false holds and warned legit messages:

- `g126` (legit_payment_talk, en) label=0 -> **warn** via judges ['JUDGES_LEGIT', 'REASSURANCE_NEXT_TO_PAYMENT']: We noticed Booking.com could not charge your card. Please update it in the Booking.com app under Payment detai
- `g148` (legit_guest, en) label=0 -> **warn** via judges ['JUDGES_LEGIT', 'REASSURANCE_NEXT_TO_PAYMENT']: Can I pay for parking with Apple Pay at the hotel?
- `g154` (legit_payment_talk, en) label=0 -> **warn** via judges ['JUDGES_UNSURE']: Our card machine is working again, so you can pay by card when you arrive, no need to bring cash.

## B. Real everyday messages (UCI SMS test split)

- 1130 real personal SMS through the full pipeline as hotel->guest on a pay-at-property booking: **0.00% held** (0.00%-0.34%), 0.18% delivered with a warning.
- 163 real spam SMS: 23.3% held (generic spam, not hotel scams).
- Caveat: these are personal SMS, not hotel conversations. They show the system rarely interferes with ordinary chat; they do not measure false holds on real hotel traffic, which needs platform data. This split was also used as a check while writing rules, and two rules were narrowed after they held texts in it (DECISIONS #34).

## C. Links nobody has reported yet (blocklist switched off)

| | Held-out | Dev (tuned on) |
|---|---|---|
| C1 Booking look-alike phishing hosts caught | 88.5% of 182 | 91.2% of 181 |
| C2 random hosts from the whole feed caught | 4.9% of 3,000 | 3.8% of 3,000 |
| C3 legit domains flagged | 0.007% of 99,969 (ranks 110,000-210,000) | 0.006% of 99,967 |
| C3 legit domains with a travel-brand word flagged | 8.2% of 49 | 6.6% of 61 |

C1 hosts were selected because they contain 'booking', which is itself a heuristic feature, so C1 measures look-alike coverage; C2 is the honest general zero-day number. Held-out flagged legit examples: booking4you.biz, fuck-a-girl-goday.com, q8booking.com, booking-wp-plugin.com, expedia.biz, accupassadmin.azurewebsites.net, la-chronique-agora.com. Held-out missed look-alikes: document1083921.aremusbooking.com, hire.easyinterviewbookingsp.com, hotelbookingguard.com, mail.vabookings.com, sanrafaelriveradventurebooking.com, shop.bookingyourrooms.com.
OpenPhish (300 live URLs, all brands): 3.0% by heuristics alone. Heuristics exist for links nobody has reported yet; in production the blocklist runs too. A flagged legit link is held only when the message also asks for money; otherwise the guest sees a warning.

## F. Robustness: scams rewritten to dodge filters

Held-out v1 (not blind). The changed-only rate excludes scams the rewrite left unchanged; zero-width characters are stripped before any rule and flag the message as obfuscated, so that row measures the obfuscation flag (it catches more than the unmutated set), not robustness to a new attack.

| Rewrite | Held-out v1 caught | Dev caught |
|---|---|---|
| no_urgency | 79% (changed only: 77%, n=30) | 100% |
| neutral_new_domain | 85% (changed only: 83%, n=30) | 100% |
| leetspeak | 80% (changed only: 79%, n=62) | 98% |
| zero_width | 92% (changed only: 92%, n=65) | 100% |
| spaced_letters | 76% (changed only: 73%, n=60) | 98% |
| combined | 65% (changed only: 65%, n=66) | 98% |

Legit held-out messages with zero-width characters inserted: 2% held, 98% warned.

## D. Session takeover model (synthetic logins)

ROC AUC 0.971; false alarms at the 'risky' threshold 0.22%.

| Attack | Caught at risky | Caught at critical |
|---|---|---|
| cookie_replay | 100% | 100% |
| phished_password | 100% | 57% |
| stealthy_proxy | 100% | 15% |
| on_device_malware | 0% | 0% |

Synthetic data is separable by construction, so this is a plumbing check, not evidence of field performance. The useful finding is `on_device_malware`: malware on the hotel's own PC produces a normal-looking login, which is why every message is still checked on its own.

## E. Cost and latency (970 SMS test-split messages + 30 held-out scams)

- Paths: {'rule': 985, 'model': 5, 'judges': 10}; share sent to the AI judges: **1.0%** on this SMS-heavy mix, **14.5%** on the held-out v1 hotel messages (estimated $0.0288 per 1,000 at that share).
- Latency p50 2.39 ms, p95 4.12 ms, p99 6.64 ms
- **Estimated** LLM cost: $0.001991 per 1,000 messages, vs $0.19564 if every message went to the judges ($0.000199 per judged message). Price: Claude Haiku 5.5 $0.1/MTok in, $0.5/MTok out (platform.claude.com/docs/en/about-claude/pricing, checked 2026-10-27).
- ESTIMATE, not a bill: input tokens = prompt characters / 4, output = 150 tokens per judge, 2 judges. Latency is in-process, excludes network and DB, and the judge path ran offline-deterministic; a hosted LLM adds an estimated 1-3 s to judged messages only.

## Classifier and calibration

SMS test split: ROC AUC 0.987, precision 100.0%, recall 84.0%. Thresholds chosen on the calibration split by the rule in `eval/calibrate.py`; reliability diagram in `eval/reliability.png`.
