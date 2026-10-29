"""Build the tiny encoder test fixture (tests/fixtures/encoder): an 8-dimensional ONNX "encoder" (an embedding lookup
with the same inputs and output layout as the real multilingual-e5 export) and a word-level tokenizer.json.

It lets tests/test_encoder.py exercise stayguard/encoder.py (tokenise, pad, run onnxruntime, mean-pool, normalise,
manifest checks) without downloading the 118 MB model. Needs the `onnx` package, which is not in any lockfile: the
fixture is built once and committed. Usage: python scripts/make_encoder_fixture.py
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper
from tokenizers import Tokenizer, models, pre_tokenizers

OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "encoder"
WORDS = [
    "<s>",
    "<pad>",
    "</s>",
    "<unk>",
    "query:",
    "pay",
    "deposit",
    "card",
    "now",
    "link",
    "welcome",
    "breakfast",
    "check-in",
    "is",
    "from",
    "3",
    "pm",
    "please",
    "the",
    "your",
]


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    vocab = {w: i for i, w in enumerate(WORDS)}
    tok = Tokenizer(models.WordLevel(vocab=vocab, unk_token="<unk>"))  # noqa: S106 - a token, not a password
    tok.pre_tokenizer = pre_tokenizers.Whitespace()
    tok.save(str(OUT / "tokenizer.json"))

    rng = np.random.default_rng(7)
    table = rng.normal(size=(len(WORDS), 8)).astype(np.float32)
    table[vocab["<pad>"]] = 100.0  # pad tokens must not leak into the mean: a test checks padding does not change it
    graph = helper.make_graph(
        [helper.make_node("Gather", ["table", "input_ids"], ["last_hidden_state"], axis=0)],
        "tiny_encoder",
        [
            helper.make_tensor_value_info("input_ids", TensorProto.INT64, ["batch", "seq"]),
            helper.make_tensor_value_info("attention_mask", TensorProto.INT64, ["batch", "seq"]),
        ],
        [helper.make_tensor_value_info("last_hidden_state", TensorProto.FLOAT, ["batch", "seq", 8])],
        [numpy_helper.from_array(table, "table")],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)], ir_version=8)
    onnx.checker.check_model(model)
    (OUT / "onnx").mkdir(exist_ok=True)
    onnx.save(model, str(OUT / "onnx" / "model_quantized.onnx"))

    files = {rel: hashlib.sha256((OUT / rel).read_bytes()).hexdigest() for rel in ("onnx/model_quantized.onnx", "tokenizer.json")}
    manifest = {
        "repo": "test/tiny-encoder",
        "revision": "fixture0",
        "model": "onnx/model_quantized.onnx",
        "tokenizer": "tokenizer.json",
        "files": files,
    }
    (OUT / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
