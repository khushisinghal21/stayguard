#!/usr/bin/env bash
# Pack data/raw + MANIFEST.json into data/snapshots/<date>-<hash>.tar.gz, to attach to a GitHub release so the
# submitted numbers can be reproduced after the live feeds have moved on.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/make_manifest.py data/raw >/dev/null
HASH=$(python3 -c "import json,sys; sys.path.insert(0,'scripts'); from make_manifest import manifest_hash; print(manifest_hash(json.load(open('data/MANIFEST.json'))))")
mkdir -p data/snapshots
OUT="data/snapshots/$(date +%Y-%m-%d)-${HASH}.tar.gz"
tar -czf "$OUT" data/raw data/MANIFEST.json
echo "$OUT"
