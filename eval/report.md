# StayGuard evaluation report

Generated 2026-10-27 08:07 at commit `fe4a82e`. Reproduce with `python -m eval.evaluate`.
Data manifest `c0cc5d1b1f71ce5d` (feeds fetched 2026-10-27T06:19:37+0000). Held-out set sha256 `9defc0ab5ab31ab4...`, committed in `04376a3`.
Model thresholds: MODEL_LOW 0.26, MODEL_HIGH 0.46 (eval/calibration.json).

**Dev** data was looked at while the rules were built, so dev numbers are optimistic. **Held-out** data was not. Read held-out first.

## A. Messages: StayGuard vs baselines

Dev: 115 hand-written messages (60 scams). Held-out: 124 messages (66 scams) built from cited public scam reports and hotel templates (`data/curated/HELDOUT_SOURCES.md`).

| System | Held-out caught | Held-out false holds | Dev caught | Dev false holds |
|---|---|---|---|---|
| baseline_blocklist_only | 0% | 0% | 17% | 0% |
| baseline_generic_spam_filter | 27% | 3% | 35% | 13% |
| stayguard_full | 67% | 2% | 100% | 0% |
| stayguard_rules_only | 44% | 2% | 93% | 0% |
| stayguard_zero_day_links_blocklist_off | 67% | 2% | 100% | 0% |
| stayguard_degraded_llm_down | 67% | 2% | 100% | 0% |

Held-out, StayGuard: caught 67% (55%-77%) of scams, falsely held 2% (0%-9%) of legitimate messages (95% Wilson intervals), and 2% of legitimate messages were delivered with a warning.

**First look** (frozen in `eval/heldout_first_look.json`, commit `fe4a82e`, 2026-10-27 08:07): caught 67%, falsely held 2%. Any later change that was motivated by held-out results makes the current held-out numbers less blind than the first look.

Held-out accuracy by category:

| Category | n | Accuracy |
|---|---|---|
| guest_to_hotel_malware | 3 | 0% |
| injection | 2 | 100% |
| legit_guest | 6 | 100% |
| legit_logistics | 18 | 100% |
| legit_multilingual | 13 | 100% |
| legit_payment | 10 | 90% |
| legit_self_service | 5 | 100% |
| legit_template | 6 | 100% |
| obfuscated | 5 | 40% |
| overpayment | 3 | 67% |
| reported_pattern | 37 | 70% |
| reported_wording | 10 | 90% |
| unsupported_language | 6 | 50% |

Held-out accuracy by language:

| Language | n | Accuracy |
|---|---|---|
| ar | 2 | 100% |
| de | 3 | 67% |
| en | 91 | 81% |
| es | 5 | 100% |
| fr | 3 | 67% |
| hi | 2 | 100% |
| hinglish | 3 | 67% |
| it | 2 | 100% |
| nl | 2 | 100% |
| pl | 2 | 50% |
| pt | 4 | 100% |
| ru | 1 | 0% |
| tr | 2 | 50% |
| zh | 2 | 100% |

Held-out misses, false holds and warned legit messages:

- `h006` (reported_wording, en) label=1 -> **deliver** via rule ['NO_PAYMENT_ASK']: Good morning, this is the reception. Payments for your stay are handled by our third-party payment processor. 
- `h015` (reported_pattern, en) label=1 -> **deliver** via rule ['NO_PAYMENT_ASK']: As this is a verification test, you will see 1 EUR on your statement which is returned straight away. Please d
- `h019` (reported_pattern, en) label=1 -> **warn** via judges ['JUDGES_LEGIT', 'UNVERIFIED_LINK']: To finish the booking process please fill in the guest form here https://guest-registration-hotel.net/form/552
- `h020` (reported_pattern, en) label=1 -> **warn** via judges ['JUDGES_LEGIT', 'UNVERIFIED_LINK']: Complete your online check-in here: https://lisbon-checkin-portal.com/r/2291 . Without online check-in we cann
- `h025` (reported_pattern, en) label=1 -> **deliver** via rule ['NO_PAYMENT_ASK']: Our records show the card on file expired. Update it on the link we texted you or the booking will be released
- `h028` (reported_pattern, en) label=1 -> **deliver** via rule ['NO_PAYMENT_ASK']: We are required by law to verify foreign cards before arrival. Please do so in the next 6 hours using the link
- `h029` (reported_pattern, en) label=1 -> **deliver** via rule ['NO_PAYMENT_ASK']: URGENT: your booking will be auto-cancelled. Call our booking office on +44 20 3769 4410 now and have your car
- `h035` (reported_pattern, fr) label=1 -> **deliver** via rule ['NO_PAYMENT_ASK']: Nous avons le regret de vous informer que votre carte n'a pas passé le contrôle de sécurité. Merci de la confi
- `h037` (reported_pattern, de) label=1 -> **deliver** via rule ['NO_PAYMENT_ASK']: Leider hat Ihre Kreditkarte die Sicherheitsprüfung nicht bestanden. Bitte schließen Sie die Kartenverifizierun
- `h042` (reported_pattern, hinglish) label=1 -> **deliver** via rule ['NO_PAYMENT_ASK']: Sir hotel ka bank account site se connected nahi hai, aap 3500 rupaye Google Pay kar dijiye isi number pe, rec
- `h044` (unsupported_language, pl) label=1 -> **deliver** via rule ['NO_PAYMENT_ASK']: Niestety Pana karta nie przeszła weryfikacji. Prosimy potwierdzić kartę w ciągu 12 godzin, w przeciwnym razie 
- `h045` (unsupported_language, tr) label=1 -> **deliver** via rule ['NO_PAYMENT_ASK']: Merhaba, rezervasyonunuz iptal edilme riski altında. Lütfen 24 saat içinde kartınızı bu bağlantıdan doğrulayın
- `h048` (unsupported_language, ru) label=1 -> **deliver** via rule ['NO_PAYMENT_ASK']: К сожалению, ваша карта не прошла проверку безопасности. Подтвердите карту в течение 12 часов, иначе бронирова
- `h051` (obfuscated, en) label=1 -> **deliver** via rule ['NO_PAYMENT_ASK']: Your booking needs a quick confirmation. Scan the QR code in the attached image with your banking app to finis
- `h052` (obfuscated, en) label=1 -> **deliver** via rule ['NO_PAYMENT_ASK']: Reply YES to keep your room, then follow the instructions we send to complete the guarantee.
- `h053` (obfuscated, en) label=1 -> **deliver** via rule ['NO_PAYMENT_ASK']: Kindly call us back on plus four four, two zero, three seven six nine, four four one zero with your card in ha
- `h056` (guest_to_hotel_malware, en) label=1 -> **deliver** via rule ['NO_PAYMENT_ASK']: Hello, I booked for next week and I have a medical condition. Could you please look at my doctor's documents b
- `h057` (guest_to_hotel_malware, en) label=1 -> **deliver** via rule ['NO_PAYMENT_ASK']: Hi, my wife needs a ground floor room because of her disability. I uploaded the certificate and a map of the a
- `h058` (guest_to_hotel_malware, en) label=1 -> **warn** via judges ['JUDGES_LEGIT', 'UNVERIFIED_LINK']: I am extremely disappointed with my stay and will post a review unless you respond today. See the photos of th
- `h060` (overpayment, en) label=1 -> **warn** via judges ['JUDGES_UNSURE']: Hi, I sent the deposit three times because the page froze. Please keep one and send the other two back through
- `h064` (reported_pattern, en) label=1 -> **deliver** via rule ['NO_PAYMENT_ASK']: Hi, we upgraded you for free! Just confirm the upgrade with your card on our partner site within 12 hours, oth
- `h066` (reported_pattern, en) label=1 -> **deliver** via rule ['NO_PAYMENT_ASK']: Enter the 6-digit code your bank just sent you so that we can finish the pre-authorisation for your stay.
- `h116` (legit_payment, en) label=0 -> **hold** via rule ['CARD_DATA_REQUEST']: We noticed your card details in the app may need updating. Please check them in the Booking.com app under your
- `h132` (legit_logistics, en) label=0 -> **warn** via judges ['JUDGES_UNSURE']: Feel free to message us on WhatsApp too if that's easier for you while travelling: +351 21 555 0199.

Dev misses, false holds and warned legit messages:

- none

## B. Real everyday messages (UCI SMS test split)

- 1207 real personal SMS through the full pipeline as hotel->guest on a pay-at-property booking: **0.00% held** (0%-0%), 0.00% delivered with a warning.
- 187 real spam SMS: 8.0% held (generic spam, not hotel scams).
- Caveat: these are personal SMS, not hotel conversations. They show the system rarely interferes with ordinary chat; they do not measure false holds on real hotel traffic, which needs platform data.

## C. Links nobody has reported yet (blocklist switched off)

| | Held-out | Dev (tuned on) |
|---|---|---|
| C1 Booking look-alike phishing hosts caught | 88.5% of 182 | 91.2% of 181 |
| C2 random hosts from the whole feed caught | 3.7% of 3,000 | 3.0% of 3,000 |
| C3 legit domains flagged | 0.006% of 99,969 (ranks 110,000-210,000) | 0.006% of 99,967 |
| C3 legit domains with a travel-brand word flagged | 8.2% of 49 | 6.6% of 61 |

C1 hosts were selected because they contain 'booking', which is itself a heuristic feature, so C1 measures look-alike coverage; C2 is the honest general zero-day number. Held-out flagged legit examples: booking4you.biz, fuck-a-girl-goday.com, q8booking.com, booking-wp-plugin.com, expedia.biz, la-chronique-agora.com. Held-out missed look-alikes: document1083921.aremusbooking.com, hire.easyinterviewbookingsp.com, hotelbookingguard.com, mail.vabookings.com, sanrafaelriveradventurebooking.com, shop.bookingyourrooms.com.
OpenPhish (300 live URLs, all brands): 3.0% by heuristics alone. Heuristics exist for links nobody has reported yet; in production the blocklist runs too. A flagged legit link is held only when the message also asks for money; otherwise the guest sees a warning.

## F. Robustness: scams rewritten to dodge filters

| Rewrite | Held-out caught | Dev caught |
|---|---|---|
| no_urgency | 64% | 100% |
| neutral_new_domain | 55% | 100% |
| leetspeak | 65% | 98% |
| zero_width | 86% | 100% |
| spaced_letters | 65% | 98% |
| combined | 44% | 97% |

Legit held-out messages with zero-width characters inserted: 3% held, 97% warned.

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

- Paths: {'rule': 992, 'model': 6, 'judges': 2}; share sent to the AI judges: **0.2%**
- Latency p50 2.99 ms, p95 5.18 ms, p99 6.94 ms
- **Estimated** LLM cost: $0.0004 per 1,000 messages, vs $0.1988 if every message went to the judges ($0.000196 per judged message). Price: Claude Haiku 5.5 $0.1/MTok in, $0.5/MTok out (platform.claude.com/docs/en/about-claude/pricing, checked 2026-10-27).
- ESTIMATE, not a bill: input tokens = prompt characters / 4, output = 150 tokens per judge, 2 judges. Latency is in-process, excludes network and DB, and the judge path ran the offline judge; a hosted LLM adds roughly 1-3 s to judged messages only.

## Classifier and calibration

SMS test split: ROC AUC 0.992, precision 99.4%, recall 92.5%. Thresholds chosen on the calibration split by the rule in `eval/calibrate.py`; reliability diagram in `eval/reliability.png`.
