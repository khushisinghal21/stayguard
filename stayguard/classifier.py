"""Small, fast scam-language model.

TF-IDF over words (1-2 grams) and characters (2-5 grams) + logistic regression. Character n-grams keep it
useful for Hindi (Devanagari), Hinglish and European languages without a heavy multilingual model, and it
scores a message in well under a millisecond.

Training data
- UCI SMS Spam Collection (5,574 real labelled SMS) - teaches generic scam/urgency language. Split 60/15/25
  into train / calibration / test (`sms_splits`); only the train part is fitted on.
- data/curated/train_seeds.jsonl - hand-written hotel messages (EN/HI/Hinglish/ES/PT/FR/DE/IT), expanded
  with random names, amounts, deadlines and links. Weighted higher because it is the target domain.
The golden evaluation set (data/curated/golden_eval.jsonl) is never used here.

URLs are replaced by a token before training: judging links is the link checker's job, and we don't want
the model memorising domains.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

from . import config
from .artifacts import load_model, save_model
from .signals import normalise, sub_links

MODEL_PATH = config.MODELS / "scam_classifier.joblib"
SEED = 7

NAMES = ["Sarah", "Ahmed", "Priya", "Lukas", "Maria", "Tom", "Aisha", "Joao", "Chen", "Elena", "Rahul", "Sophie", "Omar", "Anna"]
HOTELS = ["Lisbon City Hotel", "Algarve Resort Hotel", "our hotel", "the property"]
AMOUNTS = ["EUR 120", "150 EUR", "€85", "€240", "$199", "₹4,500", "Rs 3000", "300 euros", "95 EUR"]
HOURS = ["6", "12", "24", "48", "2"]
DATES = ["14 June", "Friday", "3 August", "next Monday", "the 21st"]
SCAM_LINKS = [
    "https://guest-verify-{n}.xyz/pay",
    "https://booking-{n}-confirm.com",
    "http://secure-roompay.top/{n}",
    "https://bit.ly/{n}Kx",
    "https://card-check-guest.online/r/{n}",
    "https://reserv-{n}.live/verify",
    "https://stay-guarantee.vercel.app/{n}",
    "hxxps://pay-hotel-{n}.shop",
]
LEGIT_LINKS = [
    "https://maps.app.goo.gl/{n}a",
    "https://www.booking.com/mybooking",
    "https://instagram.com/hotel{n}",
    "https://www.lisboncityhotel.pt/menu",
    "https://www.visitportugal.com",
]


def prep(text: str) -> str:
    t = normalise(text)
    t = sub_links(t, " URLTOKEN ")
    return t.lower()


def _fill(tpl: str, rng: random.Random) -> str:
    n = str(rng.randint(1000, 99999))
    return tpl.format(
        name=rng.choice(NAMES),
        hotel=rng.choice(HOTELS),
        amount=rng.choice(AMOUNTS),
        hours=rng.choice(HOURS),
        date=rng.choice(DATES),
        res=f"{rng.randint(1000, 9999)}-{rng.randint(1000, 9999)}",
        link=rng.choice(SCAM_LINKS).format(n=n),
    )


def hotel_training_rows(copies: int = 8) -> pd.DataFrame:
    rng = random.Random(SEED)  # noqa: S311 - seeded augmentation for reproducible training, not security
    rows = []
    with open(config.DATA_CURATED / "train_seeds.jsonl", encoding="utf-8") as f:
        seeds = [json.loads(line) for line in f if line.strip()]
    for s in seeds:
        for _ in range(copies):
            txt = _fill(s["text"], rng)
            if s["label"] == 0 and rng.random() < 0.5:
                txt += " More info: " + rng.choice(LEGIT_LINKS).format(n=rng.randint(10, 99))
            rows.append({"text": txt, "label": s["label"], "source": "hotel_seed", "lang": s["lang"]})
    return pd.DataFrame(rows)


def sms_rows() -> pd.DataFrame:
    df = pd.read_csv(config.SMS_TSV, sep="\t", header=None, names=["label", "text"], quoting=3)
    df["label"] = (df["label"] == "spam").astype(int)
    df["source"] = "sms"
    df["lang"] = "en"
    return df


def sms_splits() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Seeded, stratified 60 / 15 / 25 split of the SMS corpus into train / calibration / test.
    Calibration rows choose the model thresholds (eval/calibrate.py); test rows are only ever reported on."""
    sms = sms_rows()
    rest, sms_te = train_test_split(sms, test_size=0.25, random_state=SEED, stratify=sms["label"])
    sms_tr, sms_cal = train_test_split(rest, test_size=0.20, random_state=SEED, stratify=rest["label"])
    return sms_tr, sms_cal, sms_te


def build_pipeline() -> Pipeline:
    feats = FeatureUnion(
        [
            (
                "word",
                TfidfVectorizer(
                    analyzer="word",
                    ngram_range=(1, 2),
                    min_df=1,
                    sublinear_tf=True,
                    max_features=40000,
                    token_pattern=r"(?u)\b\w+\b",  # noqa: S106 - a regex, not a password
                ),
            ),
            ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=2, sublinear_tf=True, max_features=80000)),
        ]
    )
    return Pipeline([("feats", feats), ("lr", LogisticRegression(C=6.0, max_iter=3000, class_weight="balanced"))])


@dataclass
class TrainReport:
    sms_test: dict[str, Any]
    n_train: int
    n_sms_train: int
    n_hotel_train: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "sms_test": self.sms_test,
            "n_train": self.n_train,
            "n_sms_train": self.n_sms_train,
            "n_hotel_train": self.n_hotel_train,
        }


def train(save: bool = True) -> tuple[Pipeline, TrainReport, pd.DataFrame]:
    sms_tr, sms_cal, sms_te = sms_splits()
    hotel = hotel_training_rows()
    tr = pd.concat([sms_tr, hotel], ignore_index=True)
    weights = np.where(tr["source"] == "hotel_seed", 3.0, 1.0)
    pipe = build_pipeline()
    pipe.fit(tr["text"].map(prep), tr["label"], lr__sample_weight=weights)

    p = pipe.predict_proba(sms_te["text"].map(prep))[:, 1]
    y = sms_te["label"].to_numpy()
    yhat = (p >= 0.5).astype(int)
    rep = TrainReport(
        sms_test={
            "n": int(len(y)),
            "roc_auc": float(roc_auc_score(y, p)),
            "pr_auc": float(average_precision_score(y, p)),
            "precision": float(precision_score(y, yhat)),
            "recall": float(recall_score(y, yhat)),
            "f1": float(f1_score(y, yhat)),
        },
        n_train=int(len(tr)),
        n_sms_train=int(len(sms_tr)),
        n_hotel_train=int(len(hotel)),
    )
    if save:
        config.MODELS.mkdir(parents=True, exist_ok=True)
        save_model({"pipeline": pipe, "report": rep.as_dict(), "version": "tfidf-lr-1"}, MODEL_PATH)
        sms_te.to_csv(config.MODELS / "sms_holdout.csv", index=False)
        sms_cal.to_csv(config.MODELS / "sms_calibration.csv", index=False)
    return pipe, rep, sms_te


class ScamClassifier:
    version = "tfidf-lr-1"

    def __init__(self) -> None:
        blob = load_model(MODEL_PATH)
        if blob is None:  # missing, or not the file we wrote
            train(save=True)
            blob = load_model(MODEL_PATH)
        if blob is None:
            raise RuntimeError(f"could not build or load {MODEL_PATH}")
        self.pipe: Pipeline = blob["pipeline"]
        self.report = blob.get("report", {})

    def score(self, text: str) -> float:
        return float(self.pipe.predict_proba([prep(text)])[0, 1])

    def top_terms(self, text: str, k: int = 5) -> list[str]:
        """Word n-grams in this message that push the score towards scam (for explanations)."""
        word_vec: TfidfVectorizer = self.pipe.named_steps["feats"].transformer_list[0][1]
        coefs = self.pipe.named_steps["lr"].coef_[0][: len(word_vec.vocabulary_)]
        x = word_vec.transform([prep(text)])
        contrib = x.multiply(coefs).tocoo()
        pairs = sorted(zip(contrib.col, contrib.data, strict=True), key=lambda t: -t[1])
        inv = {i: w for w, i in word_vec.vocabulary_.items()}
        return [inv[i] for i, v in pairs[:k] if v > 0 and inv[i] != "urltoken"]


if __name__ == "__main__":
    _, r, _ = train()
    print(json.dumps(r.as_dict(), indent=2))
