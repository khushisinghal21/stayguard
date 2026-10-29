"""Scam-language models that also see the booking context (DECISIONS #38, #39).

The original model (classifier.py, "tfidf") reads only the text. These read the text plus the booking around it:
payment terms, who is writing, whether the message opens the conversation, and whether it carries a link or a phone
number. The same words mean different things in different bookings: "please pay the balance" is normal on a deposit
booking and a red flag on a pay-at-property one.

Two kinds, chosen with STAYGUARD_CLASSIFIER:
- "tfidf_ctx": the original word + character TF-IDF features, plus the context features.
- "encoder_ctx": a multilingual sentence embedding (encoder.py) plus the context features.
Both end in a logistic regression whose regularisation is picked by grouped cross-validation on the training rows
only (all augmented copies of one seed stay in one fold, so copies cannot leak across folds). The CV score is log loss,
not a ranking metric: the engine compares the output to MODEL_LOW / MODEL_HIGH as a probability, and choosing C by
average precision picked the weakest regularisation, whose overconfident scores pushed the calibrated thresholds to
their 0.02 / 0.98 clamps (found on first training, before any held-out v3 run).

Training data (never the dev, held-out v2 or held-out v3 sets; tests enforce it):
- the SMS train split and the augmented hotel seeds, as for the original model (their booking context is unknown);
- held-out v1 (data/curated/heldout_eval.jsonl), retired as an evaluation set: it was tuned on after its first run
  (DECISIONS #28) and it is the only labelled set with booking context that is not used for calibration;
- the feedback queue (data/feedback/labelled_queue.jsonl), when it exists (DECISIONS #41).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import log_loss
from sklearn.model_selection import GroupKFold

from . import config
from .artifacts import load_model, save_model
from .classifier import build_pipeline, hotel_training_rows, prep, sms_splits
from .signals import PHONE_RX, TextSignals, extract

CTX_FEATURES = [
    "terms_pay_at_property",
    "terms_prepaid",
    "terms_deposit",
    "terms_unknown",
    "guest_to_hotel",
    "first_in_thread",
    "follow_up",
    "has_link",
    "has_phone",
    "platform_flow_only",
]
# The rule signals themselves (money_ask, card_data, off-platform moves and their products with the payment terms) were
# tried as features and dropped before any held-out v3 run: they are near-perfect scam markers in the training rows, so
# the model learned to trust them absolutely and scored 10.8% of v2's legitimate messages above 0.98 (5.4% without them,
# 1.4% for the original model). The rules already act on those signals; the model double-counting them only adds false
# holds. Compared on the calibration rows (dev + retired v2), recorded in DECISIONS #39.
VERSIONS = {"tfidf_ctx": "tfidf-ctx-1", "encoder_ctx": "e5s-ctx-1"}
HOTEL_WEIGHT = 3.0  # same weight the original model gives the target domain
FEEDBACK_QUEUE = config.ROOT / "data" / "feedback" / "labelled_queue.jsonl"


def model_path(kind: str) -> Path:
    return config.MODELS / f"scam_classifier_{kind}.joblib"


def ctx_vector(text: str, ctx: dict[str, Any] | None, sig: TextSignals | None = None) -> np.ndarray:
    """Context features for one message. Missing context is 'unknown', never guessed."""
    ctx = ctx or {}
    sig = sig if sig is not None else extract(text)
    terms = ctx.get("payment_terms") or "unknown"
    first = ctx.get("first_in_thread")
    f = {
        "terms_pay_at_property": terms == "pay_at_property",
        "terms_prepaid": terms == "prepaid",
        "terms_deposit": terms == "deposit",
        "terms_unknown": terms not in ("pay_at_property", "prepaid", "deposit"),
        "guest_to_hotel": ctx.get("direction") == "guest_to_hotel",
        "first_in_thread": first is True,
        "follow_up": first is False,
        "has_link": bool(sig.urls),
        "has_phone": bool(PHONE_RX.search(text)),
        "platform_flow_only": sig.platform_flow_only,
    }
    return np.array([float(f[k]) for k in CTX_FEATURES], dtype=np.float64)


def _ctx_of(row: dict[str, Any]) -> dict[str, Any]:
    first = row.get("first_in_thread")
    return {
        "payment_terms": row.get("terms") or "unknown",
        "direction": row.get("direction") or "hotel_to_guest",
        "first_in_thread": first if isinstance(first, bool) else None,
    }


def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def training_rows() -> pd.DataFrame:
    """Every row the context models are fitted on, with its context, weight and CV group."""
    sms_tr, _, _ = sms_splits()
    sms = pd.DataFrame(
        {"text": sms_tr["text"], "label": sms_tr["label"], "terms": None, "direction": None, "first_in_thread": None}
    )
    sms["source"], sms["weight"] = "sms", 1.0
    sms["group"] = [f"sms-{i}" for i in range(len(sms))]
    seeds = hotel_training_rows()
    seeds = seeds.assign(terms=None, first_in_thread=None, source="hotel_seed", weight=HOTEL_WEIGHT)
    if "direction" not in seeds:
        seeds["direction"] = None
    seeds["group"] = [f"seed-{i // 8}" for i in range(len(seeds))]  # 8 augmented copies per seed (hotel_training_rows)
    frames = [sms, seeds[["text", "label", "terms", "direction", "first_in_thread", "source", "weight", "group"]]]
    for name, path in (("heldout_v1_retired", config.DATA_CURATED / "heldout_eval.jsonl"), ("feedback", FEEDBACK_QUEUE)):
        rows = _jsonl(path)
        if rows:
            df = pd.DataFrame(rows)
            for col in ("terms", "direction", "first_in_thread"):
                if col not in df:
                    df[col] = None
            df = df[["text", "label", "terms", "direction", "first_in_thread"]].assign(source=name, weight=HOTEL_WEIGHT)
            df["group"] = [f"{name}-{i}" for i in range(len(df))]
            frames.append(df)
    out = pd.concat(frames, ignore_index=True)
    out["label"] = out["label"].astype(int)
    return out


def _records(df: pd.DataFrame) -> list[dict[str, Any]]:
    return cast(list[dict[str, Any]], df.to_dict("records"))


class ContextClassifier:
    """Text features (TF-IDF or encoder) + context features -> logistic regression."""

    def __init__(self, kind: str, encoder: Any | None = None) -> None:
        if kind not in VERSIONS:
            raise ValueError(f"unknown context classifier {kind!r}")
        self.kind, self.version, self.encoder = kind, VERSIONS[kind], encoder
        self.text_feats: Any = None
        self.lr: LogisticRegression | None = None
        self.report: dict[str, Any] = {}

    # -- features ------------------------------------------------------------------------------------------------
    def _text_matrix(self, texts: list[str], fit: bool = False) -> Any:
        if self.kind == "tfidf_ctx":
            if fit:
                self.text_feats = build_pipeline().named_steps["feats"]
                return self.text_feats.fit_transform([prep(t) for t in texts])
            return self.text_feats.transform([prep(t) for t in texts])
        if self.encoder is None:
            raise RuntimeError("encoder_ctx needs an encoder")
        return self.encoder.embed(texts)

    def _matrix(self, texts: list[str], ctxs: list[dict[str, Any]], sigs: list[TextSignals | None], fit: bool = False) -> Any:
        tx = self._text_matrix(texts, fit=fit)
        cx = np.vstack([ctx_vector(t, c, s) for t, c, s in zip(texts, ctxs, sigs, strict=True)])
        if sparse.issparse(tx):
            return sparse.hstack([tx, sparse.csr_matrix(cx)]).tocsr()
        return np.hstack([np.asarray(tx), cx])

    # -- training ------------------------------------------------------------------------------------------------
    def fit(self, rows: pd.DataFrame) -> ContextClassifier:
        texts = [str(t) for t in rows["text"]]
        ctxs = [_ctx_of(r) for r in _records(rows)]
        x = self._matrix(texts, ctxs, [None] * len(texts), fit=True)
        y = rows["label"].to_numpy()
        w = rows["weight"].to_numpy(dtype=float)
        groups = rows["group"].to_numpy()
        # C by grouped 5-fold CV on the training rows (weighted log loss, lower is better), from a fixed grid
        grid = [0.25, 1.0, 4.0, 16.0, 64.0]
        folds = list(GroupKFold(n_splits=5).split(x, y, groups))
        cv: dict[float, float] = {}
        for c in grid:
            scores = []
            for tr, te in folds:
                m = LogisticRegression(C=c, max_iter=4000, class_weight="balanced")
                m.fit(x[tr], y[tr], sample_weight=w[tr])
                p = m.predict_proba(x[te])[:, 1]
                scores.append(float(log_loss(y[te], p, sample_weight=w[te], labels=[0, 1])))
            cv[c] = float(np.mean(scores))
        best = min(grid, key=lambda c: (cv[c], c))  # ties go to the stronger regularisation
        self.lr = LogisticRegression(C=best, max_iter=4000, class_weight="balanced")
        self.lr.fit(x, y, sample_weight=w)
        self.report = {
            "kind": self.kind,
            "version": self.version,
            "C": best,
            "cv_log_loss": {str(k): round(v, 4) for k, v in cv.items()},
            "n_train": int(len(rows)),
            "by_source": {str(k): int(v) for k, v in rows["source"].value_counts().items()},
            "encoder": getattr(self.encoder, "version", None),
        }
        return self

    # -- scoring -------------------------------------------------------------------------------------------------
    def score(self, text: str, ctx: dict[str, Any] | None = None) -> float:
        if self.lr is None:
            raise RuntimeError("model not trained")
        sig = (ctx or {}).get("signals")
        x = self._matrix([text], [ctx or {}], [sig if isinstance(sig, TextSignals) else None])
        return float(self.lr.predict_proba(x)[0, 1])

    def top_terms(self, text: str, k: int = 5) -> list[str]:
        """Word n-grams pushing towards scam (TF-IDF kind only; an embedding has no words to show)."""
        if self.kind != "tfidf_ctx" or self.lr is None:
            return []
        word_vec = self.text_feats.transformer_list[0][1]
        coefs = self.lr.coef_[0][: len(word_vec.vocabulary_)]
        xw = word_vec.transform([prep(text)])
        contrib = xw.multiply(coefs).tocoo()
        pairs = sorted(zip(contrib.col, contrib.data, strict=True), key=lambda t: -t[1])
        inv = {i: w for w, i in word_vec.vocabulary_.items()}
        return [inv[i] for i, v in pairs[:k] if v > 0 and inv[i] != "urltoken"]

    # -- persistence ---------------------------------------------------------------------------------------------
    def state(self) -> dict[str, Any]:
        return {"kind": self.kind, "version": self.version, "text_feats": self.text_feats, "lr": self.lr, "report": self.report}

    @classmethod
    def from_state(cls, blob: dict[str, Any], encoder: Any | None = None) -> ContextClassifier:
        m = cls(blob["kind"], encoder=encoder)
        m.text_feats, m.lr, m.report = blob["text_feats"], blob["lr"], blob.get("report", {})
        if blob.get("version") != m.version:
            raise RuntimeError(f"model file is {blob.get('version')}, code expects {m.version}: retrain")
        return m


def load_encoder() -> Any:
    from .encoder import Encoder

    return Encoder(config.ENCODER_DIR)


def train(kind: str, encoder: Any | None = None, save: bool = True) -> ContextClassifier:
    if kind == "encoder_ctx" and encoder is None:
        encoder = load_encoder()
    m = ContextClassifier(kind, encoder=encoder).fit(training_rows())
    if save:
        save_model(m.state(), model_path(kind))
    return m


def load(kind: str, encoder: Any | None = None) -> ContextClassifier:
    """Load a trained context model. A missing model is trained (tfidf_ctx); a missing encoder raises."""
    if kind == "encoder_ctx" and encoder is None:
        encoder = load_encoder()
    blob = load_model(model_path(kind))
    if blob is None:
        return train(kind, encoder=encoder)
    m = ContextClassifier.from_state(blob, encoder=encoder)
    if kind == "encoder_ctx" and m.report.get("encoder") != getattr(encoder, "version", None):
        raise RuntimeError("model was trained with a different encoder version: retrain")
    return m


def make_classifier(kind: str) -> Any:
    """The classifier the engine uses for STAYGUARD_CLASSIFIER=kind. Fails loudly rather than switching model."""
    if kind == "tfidf":
        from .classifier import ScamClassifier

        return ScamClassifier()
    return load(kind)


if __name__ == "__main__":
    import sys

    k = sys.argv[1] if len(sys.argv) > 1 else "tfidf_ctx"
    print(json.dumps(train(k).report, indent=2))
