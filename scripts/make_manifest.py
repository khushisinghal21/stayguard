"""Write data/MANIFEST.json: what each raw file is, where it came from, when, and its SHA-256.

The phishing feeds are live and change daily, so evaluation numbers only mean something next to the exact
files they were computed on. eval/evaluate.py stores this manifest's hash in report.json.
Usage: python scripts/make_manifest.py [data_dir]
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

SOURCES = {
    "hotels.csv": "https://raw.githubusercontent.com/rfordatascience/tidytuesday/master/data/2020/2020-02-11/hotels.csv",
    "sms.tsv": "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv",
    "phishing-domains-ACTIVE.txt": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
    "openphish-feed.txt": "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
    "top-10000-domains.txt": "https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-10000-domains",
    "top-1m.txt": "https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-1000000-domains",
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build(data_dir: Path, fetched_at: str | None = None) -> dict:
    files = []
    for name, url in SOURCES.items():
        p = data_dir / name
        if not p.exists():
            continue
        with open(p, "rb") as f:
            lines = sum(1 for _ in f)
        files.append({"file": name, "url": url, "lines": lines, "bytes": p.stat().st_size, "sha256": sha256(p)})
    if fetched_at is None:  # the files' modification time is when fetch_data.sh downloaded them
        mtimes = [(data_dir / f["file"]).stat().st_mtime for f in files]
        fetched_at = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(min(mtimes))) if mtimes else "unknown"
    return {"fetched_at": fetched_at, "files": files}


def manifest_hash(manifest: dict) -> str:
    """Hash of the file contents only (not the fetch time), so identical data gives an identical hash."""
    body = json.dumps(sorted((f["file"], f["sha256"]) for f in manifest["files"]))
    return hashlib.sha256(body.encode()).hexdigest()[:16]


if __name__ == "__main__":
    d = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "data" / "raw"
    m = build(d)
    out = d.parent / "MANIFEST.json"
    out.write_text(json.dumps(m, indent=2) + "\n")
    print(f"wrote {out} ({len(m['files'])} files, data hash {manifest_hash(m)})")
