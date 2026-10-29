"""Download the multilingual encoder used by STAYGUARD_CLASSIFIER=encoder_ctx (DECISIONS #38).

Fetches the int8 ONNX export of intfloat/multilingual-e5-small published as Xenova/multilingual-e5-small, at the
revision pinned in stayguard/encoder.py, into models/encoder/, and writes models/encoder/MANIFEST.json with the SHA-256
of every file. stayguard/encoder.py refuses to load files that do not match the manifest.

Needs network access to huggingface.co and the encoder extra:
    pip install --require-hashes -r requirements-encoder.lock
Usage: python scripts/fetch_encoder.py [--dir models/encoder]
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from stayguard import config  # noqa: E402
from stayguard.encoder import MODEL_FILE, REPO, REVISION, TOKENIZER_FILE, sha256_file  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", type=Path, default=config.ENCODER_DIR)
    args = ap.parse_args(argv)
    try:
        from huggingface_hub import hf_hub_download
    except ImportError:
        print("huggingface_hub is missing: pip install --require-hashes -r requirements-encoder.lock", file=sys.stderr)
        return 1
    out: Path = args.dir
    out.mkdir(parents=True, exist_ok=True)
    files = {}
    for rel in (MODEL_FILE, TOKENIZER_FILE):
        cached = Path(hf_hub_download(REPO, rel, revision=REVISION))
        dest = out / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(cached, dest)
        files[rel] = sha256_file(dest)
        print(f"{rel}: {dest.stat().st_size / 1e6:.1f} MB sha256 {files[rel][:16]}...")
    manifest = {"repo": REPO, "revision": REVISION, "model": MODEL_FILE, "tokenizer": TOKENIZER_FILE, "files": files}
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {out / 'MANIFEST.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
