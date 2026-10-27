"""Model files are pickles (joblib), and loading a pickle runs code. So every model we write gets a SHA-256
sidecar, and we only load a file whose hash matches; anything else is treated as missing and rebuilt."""
from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

import joblib

log = logging.getLogger("stayguard.artifacts")


def _sidecar(path: Path) -> Path:
    return path.with_name(path.name + ".sha256")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def save_model(obj: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(obj, path)
    _sidecar(path).write_text(sha256_file(path) + "\n")


def load_model(path: Path) -> Any | None:
    """Return the unpickled object, or None if the file is missing or its hash does not match the sidecar."""
    side = _sidecar(path)
    if not path.exists() or not side.exists():
        return None
    if sha256_file(path) != side.read_text().strip():
        log.warning("refusing to load %s: checksum mismatch", path)
        return None
    return joblib.load(path)  # hash verified: this is a file we wrote
