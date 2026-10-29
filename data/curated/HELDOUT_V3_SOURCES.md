# heldout_v3 sources

All message texts are newly written for this set. Scam rows reuse short fragments (`reported_wording`) or paraphrase described patterns (`reported_pattern`, `multilingual_scam`, `obfuscated`, scam `guest_message`) from the sources below. Every domain, phone number, IBAN, account number, wallet, handle and name is invented; none are copied from reports.
Legitimate rows follow the hotel-messaging templates and payment guidance below, plus ordinary hotel practice.

## Scam sources (S)

| Code | Source | URL | Used for |
|---|---|---|---|
| S1 | Graham Cluley: "Fraudsters target Booking.com customers claiming hotel stay could be cancelled" | https://grahamcluley.com/fraudsters-target-booking-com-customers-claiming-hotel-stay-could-be-cancelled | Verbatim: card "not automatically verified", 12-hour deadline, "funds temporarily reserved… refunded within 10 minutes", "use a Mastercard" |
| S2 | Which?: "A scammer messaged me through Booking.com's app" | https://www.which.co.uk/news/article/a-scammer-messaged-me-through-booking.coms-app-aE4XI5J2w1hd | "unable to register you at our hotel", "do it all over again", "enter your booking fee" |
| S3 | Rick Steves Travel Forum: "Almost fell for a scam on booking site" | https://community.ricksteves.com/travel-forum/tourist-scams/almost-fell-for-a-scam-on-booking-site-be-smarter-than-me | "update my credit card before my stay to maintain my reservation"; "cancelled within 12 hours… verification of my credit card"; 3-D Secure approval |
| S4 | Akamai Security Research: sophisticated phishing campaign targeting hospitality | https://www.akamai.com/es/blog/security-research/sophisticated-phishing-campaign-targeting-hospitality | "vuelva a confirmar su tarjeta de crédito", 24-hour cancellation threat, fake page with support chat |
| S5 | Help Net Security (Secureworks findings): Booking.com customers targeted in hotel booking scam | https://www.helpnetsecurity.com/2023/12/04/booking-com-hotel-booking-scam/ | Guest-to-hotel "left my passport" lure, then a link to a malware download; "confirmation of payment details" |
| S6 | Hackread (Sekoia research): "I Paid Twice" attack | https://hackread.com/i-paid-twice-scam-booking-com-purerat-clickfix/ | "security problem with their payment", "procedure… to stop cancellations", WhatsApp, guests paying twice |
| S7 | Kaspersky blog: Booking.com scam (via WP JSON) | https://www.kaspersky.com/blog/wp-json/wp/v2/posts/50109 | "error in verifying… payment card information", "otherwise the reservation will be canceled", links with reservation/approve/confirmation words |
| S8 | VPNCentral: Hackers hijack hotel booking workflows to send fake payment requests | https://vpncentral.com/?p=247876 | "verify or complete payment before arrival", PDF invoices, 24-48 h deadlines, WhatsApp/SMS/email |
| S9 | IdentityIQ: Booking.com WhatsApp scam 2026 | https://www.identityiq.com/articles/booking-com-whatsapp-scam-2026 | Payment processing error, security verification before check-in, updated payment policy, bank transfer, WhatsApp |
| S10 | Singapore Police Force advisory on hotel-related phishing scams (27 Feb 2023) | https://police.gov.sg/Media-Room/News/20230227_police_advisory_on_hotel-related_phishing_scams | Phone/WhatsApp contact posing as hotel, confirmation link, OTP requests |
| S11 | bluewin.ch: "Beware of this perfidious scam on Booking" | https://www.bluewin.ch/en/news/beware-of-this-perfidious-scam-on-booking-2735965.html | "credit card check", "Respond within a few hours!" |
| S12 | Ynetnews: Travelers report growing scam attempts on Booking.com listings | https://www.ynetnews.com/travel/article/s1rwr6asll | Card info "through a link", extra €2,000 deposit request, payment outside the platform |
| S13 | Verbraucherzentrale Niedersachsen: Phishing-Versuch über Chat in Booking.com-App | https://www.verbraucherzentrale-niedersachsen.de/wissen/digitale-welt/datenschutz/phishingversuch-ueber-chat-in-booking-comapp-120337 | "Standard-Check Ihrer Kreditkarte", "Daten über den beigefügten Link erneut eingeben" |
| S14 | Genbeta: "Cuidado si recurres a Booking… esta estafa roba tus datos bancarios" | https://www.genbeta.com/seguridad/cuidado-recurres-a-booking-para-irte-vacaciones-esta-estafa-roba-tus-datos-bancarios | "problema con su reserva… actualizar sus datos bancarios", 24 h; fake guests citing "motivos técnicos" |
| S15 | Spidersweb: hotel message about a card payment problem (PL) | https://spidersweb.pl/2024/01/hotel-wiadomosc-problem-platnosci-karta-oszustwo.html | Payment failed, so the guest must repay; fake complaint with large photo file leads to Vidar infostealer |
| S16 | Journal de l'économie: faux messages après une réservation Booking | https://www.journaldeleconomie.fr/booking-faux-messages-reservation/ | Update card, pay deposit, transfer within 24 h or cancellation |
| S17 | J-CAST News: Japan Hotel Association warning about Booking.com messages | https://www.j-cast.com/2026/06/15515598.html?p=all | Real booking number and dates shown, link to card-phishing site |
| S18 | Welingelichte Kringen: Booking.com WhatsApp fraud reports up 560% | https://www.welingelichtekringen.nl/tips/pas-op-met-bookingcom-meldingen-van-fraude-via-whatsapp-stegen-dit-jaar-met-560-zo-herken-je-de-nep-berichten | Reservation "paused", failed payment, reconfirm details, WhatsApp |
| S19 | QuiFinanza: Truffa su Booking, messaggi ingannevoli (June 2026) | https://quifinanza.it/info-utili/truffa-booking-messaggi-giungno-2026/998182/ | "problemi con il pagamento", fake payment page, bank transfer requests |
| S20 | Which?: "Scam alert: why you can't trust that Booking.com message" | https://www.which.co.uk/news/article/why-you-cant-trust-that-booking.com-message-aNQwx7T2ltWs | "secure her spot", "confirm your identity", repeated messages, "the hostel took full responsibility" |
| S21 | ScanNetSecurity: Hotel Sunroute Asakusa warning about suspicious messages | https://scan.netsecurity.ne.jp/article/2026/06/02/55401.html | Booking confirmation via WhatsApp and other messaging apps |
| S22 | Euronews Türkçe: Booking.com dolandırıcılığı | https://tr.euronews.com/2025/12/23/sahte-ilanlar-oltalama-e-postalar-yolcular-bookingcom-dolandiriciliginda-yuzlerce-avro-kay | Verify payment method via link, "no charge will be taken", time limit, WhatsApp staff profile |
| S23 | Cyprus Mail: Police warn of new online fraud linked to hotel bookings | https://cyprus-mail.com/2023/10/27/police-warn-of-new-online-fraud-linked-to-hotel-bookings | "not fulfilling their payment conditions", pay through link |
| S24 | Which? Scamwatch: "Fraudsters posed as my hotel to get my bank details" | https://www.which.co.uk/news/article/scamwatch-fraudsters-posed-as-my-hotel-to-get-my-bank-details-aWoVa0i12Pog | "new security regulations… no longer legal to hold credit card information without consent"; pay in full before arrival |
| S25 | awd.is: "Мошенники пишут через Букинг.ком" | https://awd.is/moshenniki-pishut-cherez-buking-kom/ | Stealer-based extranet takeover, link with deadline, newly registered domains |
| S26 | Bangkok Post: Japanese hotels fall prey to phishing scams | https://www.bangkokpost.com/business/general/2775646/japanese-hotels-fall-prey-to-phishing-scams | Child food-allergy list lure to hotel; "cancelled unless payment is made in advance" |
| S27 | The Hacker News: Microsoft warns of ClickFix phishing (Storm-1865) | https://thehackernews.com/2025/03/microsoft-warns-of-clickfix-phishing.html | Fake guest reviews, account verification, ClickFix "I am not a robot" lure to hotel staff |
| S28 | WA ScamNet: Overpayment scams – holiday bookings | https://scamnet.wa.gov.au/scamnet/Scam_types-Buying_or_selling-Overpayment_scams-Holiday_bookings.htm | Fake-guest overpayment with refund of the difference; payment mix-up cover stories (used also for off-platform direct-payment offers) |
| S29 | Vrbo Help: Most common booking request scams | https://help.vrbo.com/articles/What-are-the-most-common-booking-request-scams | Overpayment and refund requests to owners; payer is a travel agent or third party |
| S30 | Orain.eus: Ertzaintza detects increase in hotel booking fraud (Oct 2026) | https://orain.eus/en/current-events/society-and-social-news-now/2026/10/06/the-ertzaintza-detects-an-increase-in-cases-of-fraud-related-to-hotel-bookings/ | WhatsApp message posing as the hotel: "confirm their stay before they arrive" link, real booking data, full payment by transfer |
| S31 | ESET Greece: common Booking.com scams | https://www.eset.com/gr/about/newsroom/press-releases-gr-1/den-yparchei-choros-gia-lathi-min-parasyrtheite-apo-aytes-tis-koines-apates/ | In-app chat from taken-over hotel accounts: "earlier payment failed, pay again", card or passport details to verify the booking |
| S32 | Booking.com: Safety tips for travellers | https://www.booking.com/trust-and-safety/travellers.en-us.html | Platform statement on payment/card requests; scams that pretend to follow this advice |
| S33 | The Statesman: Online hotel booking scam on the rise in Odisha | https://www.thestatesman.com/india/online-hotel-booking-scam-on-the-rise-in-odisha-1503449569.html | Indian market: fake hotel staff/sites demanding payment via UPI, wallets or bank transfer |
| S34 | Tourdom.ru: tourists booking on Booking.com attacked by fraudsters | https://www.tourdom.ru/news/turistov-broniruyuschikh-oteli-na-booking-com-atakuyut-moshenniki.html | Booking-change notices, cancellation plus 59 EUR fine within 6 hours, card-verification link, 100 EUR pre-authorisation even on prepaid bookings |
| S35 | The Caterer: Warning issued over Booking.com fraud | https://www.thecaterer.com/news/warning-issued-booking-dot-com-fraud | Hotel-account takeover; in-app, email and WhatsApp requests for payments the guest did not need to make, card or bank details, cancellation urgency |

## Legitimate templates and guidance (L)

| Code | Source | URL | Used for |
|---|---|---|---|
| L1 | Booking.com Connectivity docs: Understanding the Credit Card Status API | https://developers.booking.com/connectivity/docs/credit-card-status-api/understanding-the-credit-card-status-api | Invalid or declined card flow: guest updates card on the platform, 24 h window |
| L2 | Hostaway: Booking.com – Report an Invalid Credit Card | https://support.hostaway.com/hc/en-us/articles/360038214214-Booking-com-Report-an-Invalid-Credit-Card | Invalid card flow on non-refundable bookings |
| L3 | RoomRaccoon: What happens when I mark a card as invalid to Booking.com | https://contact.roomraccoon.com/en/support/solutions/articles/150000012260-what-happens-when-i-mark-a-card-as-invalid-to-booking-com | Guest-side outcome after card update |
| L4 | SetupMyHotel: Pre-arrival letter format | https://setupmyhotel.com/hotel-formats/front-office-formats/pre-arrival-letter-pre-stay-letter-format-send-to-hotel-guests/ | Pre-arrival letters, group and company invoices |
| L5 | RoomRaccoon: Email Template Guide | https://static.roomraccoon.com/buyersguides/Email-Template-Guide-ENG.pdf | Upsell (breakfast, parking, extras), pre-arrival templates |
| L6 | Amenitiz: Ready-to-use guest message templates | https://support.amenitiz.com/en/articles/403621-ready-to-use-guest-message-templates-arrival-check-out-thank-you | Arrival, check-out and thank-you templates |
| L7 | Cloudbeds: Four common email templates | https://www.cloudbeds.com/articles/four-common-email-templates-build-better-relationships-guests | Confirmation and service notices |
| L8 | Hostaway: Airbnb guest messaging templates | https://www.hostaway.com/blog/airbnb-guest-messaging-templates/ | Check-in, review request and service messages |
| L9 | Your.Rentals: 6 check-in instruction message templates | https://your.rentals/blog/6-check-in-instruction-message-templates-for-hosts/ | Door codes, lockboxes, house rules |
| L10 | Hospitable: Pre-check-in message examples | https://hospitable.com/pre-check-in-message-examples | Early check-in, arrival-time and online check-in messages |
| L11 | Little Hotelier: How to process a pre-authorisation | https://helpcentre.littlehotelier.com/en/articles/11997556-how-to-process-a-pre-authorisation | Pre-authorisation explained |
| L12 | Credit.com: Why hotels put a hold on your credit card | https://credit.com/blog/why-hotels-put-a-hold-on-your-credit-card-104134 | Holds and release timelines |
| L13 | Guestline Distribution Hub: Booking.com deposits overview | https://help-guestline.theaccessgroup.com/en/articles/13117014-guestline-distribution-hub-booking-com-deposits-overview | Deposits collected by Booking.com, balance at property |
| L14 | BookingSync: Synchronization of the damage deposit | https://manual.bookingsync.com/hc/en-us/articles/360006824178-Synchronization-of-the-damage-deposit | Damage deposit collected by platform, instalments |
| L15 | Holidu: How to claim damages on Booking.com | https://www.holidu.co.uk/magazine/how-to-claim-damages-on-booking | Damage deposit policies for holiday rentals |
| L16 | TravelNest: Tourist tax | https://help.travelnest.com/tourist-tax | City or tourist tax payable at the property |
| L17 | Monde du Voyage: Tourist taxes in Europe | https://monde-du-voyage.com/en/blog/accommodation/tourist-taxes-in-europe-how-to-calculate-the-real-cost-before-booking-accommodation/ | Per-city tourist-tax levels (Amsterdam, etc.) |
| L18 | StayGenerator FAQ: Do I have to pay city tax? | https://staygenerator.com/faq/booking-information/pricing-and-payment/do-i-have-to-pay-city-tax | City tax not included in prepaid amount |
| L19 | respond.io: WhatsApp for hotels | https://respond.io/blog/whatsapp-hotel | Real hotels using WhatsApp for logistics and concierge |
| L20 | HiJiffy: WhatsApp Business for hotels | https://www.hijiffy.com/resources/articles/whatsapp-business-for-hotels | Phone/WhatsApp contact for arrivals and services |
| L21 | Booking.com Customer FAQ | https://booking.com/faq.html | Payment at property, refunds, cancellations, prepaid stays |
| L22 | Hospitality Net: Booking.com new prepayment policies | https://www.hospitalitynet.org/viewpoint/125000220.html | Non-refundable and prepayment charge timing |
| L23 | Paraty Tech: Changes in Booking.com, pre-paid rates | https://www.paratytech.com/en/news/changes-in-booking.com-goodbye-to-pre-paid-rates.html | Virtual cards and Payments by Booking.com |
| L24 | SmartOrder: How to write a confirmation email for a hotel booking | https://www.smartorder.ai/blog/how-to-write-a-confirmation-email-for-a-hotel-booking/ | Confirmation content, price inclusions, directions |
| L25 | Minoan: 7 must-have Airbnb message templates | https://minoan.com/blog/airbnb-message-templates | Short-stay notices (roadworks, local info) |
