# Test fixtures

`raw/` is a small, fixed snapshot of the real datasets so tests and CI run offline and deterministically:

- `hotels.csv` — 2,782 real rows of the Hotel Booking Demand dataset: June–August 2017 rows sampled up to 700 per
  hotel × deposit type, 600 earlier rows and 20 extra `Refundable` rows, seed-fixed.
- `sms.tsv`, `openphish-feed.txt`, `top-10000-domains.txt` — the full files as fetched on 2026-10-27.
- `phishing-domains-ACTIVE.txt` — every Booking-themed host plus 5,000 random others from the 2026-10-27 feed.
- `top-1m.txt` — the first 30,000 lines of the top-1M list (fast-mode evaluation uses ranks 10k–30k).

Numbers computed on fixtures are for CI regression only; the reported numbers use `data/raw` (see `data/MANIFEST.json`).
