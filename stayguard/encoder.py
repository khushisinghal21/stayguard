"""Multilingual sentence encoder for the scam-language model (DECISIONS #38).

Why: the TF-IDF model only sees surface overlap with its training words, so a paraphrase or a language it has few
examples of slips past it. A small multilingual encoder maps "please settle the deposit" and "bitte überweisen Sie die
Anzahlung" close together, so a classifier trained mostly on English can still read other languages.

What: intfloat's multilingual-e5-small (100 languages, 384 dimensions), as the ONNX export published by Xenova on
Hugging Face, run with onnxruntime and the `tokenizers` library. No torch. Weights are not installed by pip:
`python scripts/fetch_encoder.py` downloads them at a pinned revision and writes models/encoder/MANIFEST.json with the
SHA-256 of every file. This module refuses to load files whose hashes do not match the manifest.

The runtime libraries are an optional extra (`pip install -r requirements-encoder.lock`); CI and the default
classifier never import them. If the engine is configured for the encoder and it cannot load, start-up fails instead
of silently falling back to another model.
"""

from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path
from typing import Any

import numpy as np

from .signals import normalise, sub_links

REPO = "Xenova/multilingual-e5-small"
REVISION = "761b726dd34fb83930e26aab4e9ac3899aa1fa78"  # main on 2026-10-29, read from the model page
MODEL_FILE = "onnx/model_quantized.onnx"  # int8 weights: smaller and faster on a laptop CPU than the fp32 export
TOKENIZER_FILE = "tokenizer.json"
PREFIX = "query: "  # e5 models are trained with a role prefix; "query: " is the documented one for classification
MAX_TOKENS = 256  # hotel messages are short; the cap bounds latency on a pasted essay


class EncoderUnavailable(RuntimeError):
    """The encoder's files or runtime libraries are missing or do not match the manifest."""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def prep(text: str) -> str:
    """Same view of the text as the TF-IDF model: normalised, links replaced (judging links is the link checker's job)."""
    return PREFIX + sub_links(normalise(text), " link ").strip()


def _import(name: str) -> Any:
    try:
        return importlib.import_module(name)
    except ImportError as e:
        raise EncoderUnavailable(f"{name} is not installed: pip install --require-hashes -r requirements-encoder.lock") from e


class Encoder:
    """Text -> L2-normalised mean-pooled embedding."""

    def __init__(self, directory: Path, threads: int = 1) -> None:
        manifest_path = directory / "MANIFEST.json"
        if not manifest_path.exists():
            raise EncoderUnavailable(f"{manifest_path} not found: run python scripts/fetch_encoder.py")
        manifest = json.loads(manifest_path.read_text())
        for rel, want in manifest["files"].items():
            p = directory / rel
            if not p.exists() or sha256_file(p) != want:
                raise EncoderUnavailable(f"{p} is missing or does not match MANIFEST.json")
        ort, tokenizers = _import("onnxruntime"), _import("tokenizers")
        self.tok = tokenizers.Tokenizer.from_file(str(directory / manifest.get("tokenizer", TOKENIZER_FILE)))
        self.tok.enable_truncation(max_length=MAX_TOKENS)
        pad_id = self.tok.token_to_id("<pad>")
        self.tok.enable_padding(pad_id=1 if pad_id is None else pad_id, pad_token="<pad>")  # noqa: S106 - a token, not a secret
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = threads  # one message at a time on the request path; batching is for training
        self.sess = ort.InferenceSession(
            str(directory / manifest.get("model", MODEL_FILE)), sess_options=opts, providers=["CPUExecutionProvider"]
        )
        self.inputs = {i.name for i in self.sess.get_inputs()}
        self.version = f"{manifest.get('repo', REPO)}@{str(manifest.get('revision', REVISION))[:7]}"
        self.manifest = manifest

    def embed(self, texts: list[str], batch: int = 32) -> np.ndarray:
        out = []
        for i in range(0, len(texts), batch):
            enc = self.tok.encode_batch([prep(t) for t in texts[i : i + batch]])
            ids = np.array([e.ids for e in enc], dtype=np.int64)
            mask = np.array([e.attention_mask for e in enc], dtype=np.int64)
            feed = {"input_ids": ids, "attention_mask": mask}
            if "token_type_ids" in self.inputs:
                feed["token_type_ids"] = np.zeros_like(ids)
            hidden = np.asarray(self.sess.run(None, {k: v for k, v in feed.items() if k in self.inputs})[0])
            if hidden.ndim == 3:  # token states -> mean over real tokens (the pooling e5 was trained with)
                m = mask[..., None].astype(hidden.dtype)
                pooled = (hidden * m).sum(axis=1) / np.clip(m.sum(axis=1), 1e-9, None)
            else:  # an export that already pools
                pooled = hidden
            norms = np.linalg.norm(pooled, axis=1, keepdims=True)
            out.append(pooled / np.clip(norms, 1e-12, None))
        dim = out[0].shape[1] if out else 0
        return np.vstack(out) if out else np.zeros((0, dim), dtype=np.float32)
