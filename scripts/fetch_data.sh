#!/usr/bin/env bash
# Downloads the real datasets into data/raw. Safe to re-run.
set -euo pipefail
cd "$(dirname "$0")/../data/raw" 2>/dev/null || { mkdir -p "$(dirname "$0")/../data/raw"; cd "$(dirname "$0")/../data/raw"; }
get() { echo "-> $2"; curl -sSfL -o "$2" "$1"; }
get https://raw.githubusercontent.com/rfordatascience/tidytuesday/master/data/2020/2020-02-11/hotels.csv hotels.csv
get https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv sms.tsv
get https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt phishing-domains-ACTIVE.txt
get https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt openphish-feed.txt
get https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-10000-domains top-10000-domains.txt
get https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-1000000-domains top-1m.txt
wc -l *
cd ../..
python3 scripts/make_manifest.py data/raw
