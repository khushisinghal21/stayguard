# StayGuard evaluation report

Generated 2026-10-27 07:47. Reproduce with `python -m eval.evaluate`.

## A. Golden + red-team set

115 hand-written messages (60 scams, 55 legitimate) in English, Hindi, Hinglish, Spanish, Portuguese, French, German and Italian. Never used for training. **Caveat:** written by the same team that wrote the rules, so these numbers are optimistic; B and C below use real, independent data.

| System | Catch rate | False alarms | Legit warned | Precision | F1 |
|---|---|---|---|---|---|
| baseline_blocklist_only | 17% | 0% |  | 100% | 0.2857 |
| baseline_generic_spam_filter | 62% | 24% |  | 74% | 0.6727 |
| stayguard_full | 100% | 0% | 0% | 100% | 1.0 |
| stayguard_rules_only | 93% | 0% |  | 100% | 0.9655 |
| stayguard_zero_day_links_blocklist_off | 100% | 0% | 0% | 100% | 1.0 |
| stayguard_degraded_llm_down | 97% | 0% | 0% | 100% | 0.9831 |

Accuracy by category:

| Category | n | Accuracy |
|---|---|---|
| hijack_link | 6 | 100% |
| hijack_link_novel | 12 | 100% |
| hijack_multilingual | 17 | 100% |
| hijack_nolink | 11 | 100% |
| injection | 5 | 100% |
| legit_guest | 5 | 100% |
| legit_logistics | 22 | 100% |
| legit_multilingual | 11 | 100% |
| legit_payment_talk | 17 | 100% |
| obfuscation | 4 | 100% |
| overpayment | 5 | 100% |

Accuracy by language:

| Language | n | Accuracy |
|---|---|---|
| de | 3 | 100% |
| en | 84 | 100% |
| es | 4 | 100% |
| fr | 3 | 100% |
| hi | 5 | 100% |
| hinglish | 10 | 100% |
| it | 3 | 100% |
| pt | 3 | 100% |

Misses, false alarms and warnings on legit messages:

- none

## B. Real messages (UCI SMS Spam Collection, held-out split)

- 1207 real everyday messages sent through the full pipeline as hotel->guest on a pay-at-property booking: **0.00% held**, 0.00% delivered with a warning.
- 187 real spam messages: 8.0% held/blocked, 0.0% warned (generic spam, not hotel scams).

Real messages that were held:

- none

## C. Links nobody has reported yet (blocklist switched off)

- C1 travel-brand look-alikes: 181 of the 363 real Booking-themed phishing hosts withheld -> **91.2%** flagged. (Selected by containing 'booking', which is itself a heuristic feature - so read this as look-alike coverage.)
- C2 random sample of 3,000 hosts from the whole 392k feed (every brand and lure): **3.0%** flagged by heuristics alone.
- C3 false positives on 99,967 real legit domains ranked 10,001-110,000 (not in the popularity allowlist): **0.01%**; among the 61 legit domains containing a travel brand token: 6.6% (e.g. secure-hotel-booking.com, reservation-booking-system.com, expedia-aarp.com, hotel4booking.com).
- Examples of flagged legit domains: secure-hotel-booking.com, laoda.info, reservation-booking-system.com, plugin-update.support, expedia-aarp.com, hotel4booking.com
- OpenPhish (300 live URLs): 3.0% by heuristics alone.
- In production the blocklist and heuristics run together; heuristics exist for links nobody has reported yet. A flagged legit link is 'held' only when the message also asks for money; otherwise the guest sees a warning.

## F. Robustness: scams rewritten to dodge filters

| Mutation | Catch rate | Missed |
|---|---|---|
| no_urgency | 100% | - |
| neutral_new_domain | 100% | - |
| leetspeak | 98% | g058 |
| zero_width | 100% | - |
| spaced_letters | 98% | g058 |
| combined | 95% | g006, g014, g058 |

Legit messages with zero-width characters inserted: 4% held, 96% warned.

`neutral_new_domain` swaps every link for a fresh, brand-free domain (the hardest case for link checks); `combined` also strips deadlines and applies leetspeak.

## D. Session takeover model (synthetic logins)

ROC AUC 0.971; false alarms at the 'risky' threshold 0.22%.

| Attack | Caught at risky | Caught at critical |
|---|---|---|
| cookie_replay | 100% | 100% |
| phished_password | 100% | 57% |
| stealthy_proxy | 100% | 15% |
| on_device_malware | 0% | 0% |

Synthetic data is separable by construction, so treat these as a plumbing check. The useful finding is `on_device_malware`: when malware runs on the hotel's own PC the login looks normal, which is why every message is still checked on its own.

## E. Cost and latency (1,000-message realistic mix: 97% normal, 3% scams)

- Paths: {'rule': 998, 'model': 1, 'judges': 1}
- Judge (LLM) share: **0.1%**
- Latency p50 2.96 ms, p95 4.96 ms, p99 7.28 ms
- LLM cost per 1,000 messages: **$0.0016** vs $1.6 if every message went to an LLM (at $0.0016 per judged message).
- Latency excludes network; judge path measured with the offline judge. With a hosted LLM add ~1-3 s to judge-path messages only.

## Classifier sanity check (SMS held-out)

ROC AUC 0.992, precision 100.0%, recall 93.0%.
