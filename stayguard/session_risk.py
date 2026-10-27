"""Session risk for hotel extranet logins: was this session taken over?

Real account-takeover telemetry is private, so the login data is SYNTHETIC (clearly labelled as such).
The generator models the attack chains seen in the 2023-2025 Booking.com partner campaigns:
  - infostealer cookie replay: the session token is reused from a new IP / ASN / user agent (MFA bypassed)
  - phished password: new device, far-away location, odd hours, failed attempts
  - stealthy: residential proxy in the hotel's own country, business hours, but a new device that bulk-reads
    reservations and messages many guests
An Isolation Forest is trained on normal sessions only (no attack labels needed, which is what you'd have on
day one), then combined with a few hard rules that should never be overridden by a model.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score

from . import config
from .artifacts import load_model, save_model

MODEL_PATH = config.MODELS / "session_iforest.joblib"
FEATURES = ["hour_offset", "is_new_device", "log_km_from_usual", "log_speed_kmh", "new_asn", "hosting_asn",
            "log_reservations_viewed", "log_messages_sent", "guest_fanout", "token_replay", "failed_logins_1h",
            "payout_change"]
ATTACK_KINDS = ["cookie_replay", "phished_password", "stealthy_proxy", "on_device_malware"]
PROPERTY_GEO = {"H1": (37.0194, -7.9304), "H2": (38.7223, -9.1393)}  # Algarve resort (Faro), Lisbon city hotel


def haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    la1, lo1, la2, lo2 = map(math.radians, (*a, *b))
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 2 * 6371 * math.asin(math.sqrt(h))


def _shift_offset(hour: int) -> float:
    """Hours outside a 07:00-23:00 working window (0 inside it)."""
    if 7 <= hour <= 23:
        return 0.0
    return float(min(abs(hour - 7), abs(hour + 24 - 23)) if hour < 7 else 0)


def featurise(ev: dict) -> dict:
    hour = int(ev.get("hour", 12))
    viewed = float(ev.get("reservations_viewed", 0))
    sent = float(ev.get("messages_sent", 0))
    guests = float(ev.get("distinct_guests_messaged", min(sent, viewed)))
    return {
        "hour_offset": _shift_offset(hour),
        "is_new_device": float(bool(ev.get("is_new_device", False))),
        "log_km_from_usual": math.log1p(float(ev.get("km_from_usual", 0))),
        "log_speed_kmh": math.log1p(float(ev.get("speed_kmh", 0))),
        "new_asn": float(bool(ev.get("new_asn", False))),
        "hosting_asn": float(bool(ev.get("hosting_asn", False))),
        "log_reservations_viewed": math.log1p(viewed),
        "log_messages_sent": math.log1p(sent),
        "guest_fanout": guests / (1.0 + viewed) if viewed else 0.0,
        "token_replay": float(bool(ev.get("token_replay", False))),
        "failed_logins_1h": float(ev.get("failed_logins_1h", 0)),
        "payout_change": float(bool(ev.get("payout_change", False))),
    }


# ----------------------------------------------------------------------------------------------
# Synthetic data
# ----------------------------------------------------------------------------------------------
def gen_normal(n: int, rng: np.random.Generator) -> pd.DataFrame:
    travelling = rng.random(n) < 0.02
    km = np.where(travelling, rng.uniform(200, 2500, n), rng.exponential(6, n))
    return pd.DataFrame({
        "hour": rng.choice(np.arange(24), n, p=_hour_profile()),
        "is_new_device": rng.random(n) < 0.03,
        "km_from_usual": km,
        "speed_kmh": np.where(travelling, rng.uniform(0, 600, n), rng.exponential(3, n)),
        "new_asn": rng.random(n) < np.where(travelling, 0.8, 0.04),
        "hosting_asn": rng.random(n) < 0.01,
        "reservations_viewed": rng.poisson(9, n),
        "messages_sent": rng.poisson(3, n),
        "token_replay": rng.random(n) < 0.002,
        "failed_logins_1h": rng.poisson(0.15, n),
        "payout_change": rng.random(n) < 0.002,
    }).assign(distinct_guests_messaged=lambda d: np.minimum(d.messages_sent, d.reservations_viewed), label=0, attack="none")


def _hour_profile() -> np.ndarray:
    w = np.array([0.3, 0.2, 0.1, 0.1, 0.1, 0.2, 0.8, 3, 5, 6, 6, 6, 5, 5, 6, 6, 6, 5, 4, 3, 3, 2, 1.5, 0.8])
    return w / w.sum()


def gen_attacks(n: int, rng: np.random.Generator) -> pd.DataFrame:
    kinds = rng.choice(["cookie_replay", "phished_password", "stealthy_proxy", "on_device_malware"], n,
                       p=[0.35, 0.3, 0.2, 0.15])
    rows = []
    for k in kinds:
        if k == "cookie_replay":
            rows.append({"hour": int(rng.integers(0, 24)), "is_new_device": rng.random() < 0.7,
                         "km_from_usual": rng.uniform(800, 9000), "speed_kmh": rng.uniform(900, 20000),
                         "new_asn": True, "hosting_asn": rng.random() < 0.7, "reservations_viewed": int(rng.integers(40, 600)),
                         "messages_sent": int(rng.integers(5, 200)), "token_replay": True, "failed_logins_1h": 0,
                         "payout_change": rng.random() < 0.3})
        elif k == "phished_password":
            rows.append({"hour": int(rng.choice([0, 1, 2, 3, 4, 5, 22, 23, 14])), "is_new_device": True,
                         "km_from_usual": rng.uniform(500, 9000), "speed_kmh": rng.uniform(500, 15000),
                         "new_asn": True, "hosting_asn": rng.random() < 0.5, "reservations_viewed": int(rng.integers(25, 400)),
                         "messages_sent": int(rng.integers(3, 150)), "token_replay": False,
                         "failed_logins_1h": int(rng.integers(0, 6)), "payout_change": rng.random() < 0.25})
        elif k == "on_device_malware":
            # remote-access malware on the front-desk PC: same device, same place, same hours. Session telemetry
            # barely moves - this is exactly why message checking (layer 2) has to exist.
            rows.append({"hour": int(rng.integers(8, 22)), "is_new_device": False, "km_from_usual": rng.exponential(5),
                         "speed_kmh": rng.exponential(3), "new_asn": False, "hosting_asn": False,
                         "reservations_viewed": int(rng.integers(12, 45)), "messages_sent": int(rng.integers(4, 25)),
                         "token_replay": False, "failed_logins_1h": 0, "payout_change": rng.random() < 0.05})
        else:
            rows.append({"hour": int(rng.integers(9, 19)), "is_new_device": True, "km_from_usual": rng.uniform(5, 300),
                         "speed_kmh": rng.uniform(0, 120), "new_asn": rng.random() < 0.6, "hosting_asn": False,
                         "reservations_viewed": int(rng.integers(30, 150)), "messages_sent": int(rng.integers(10, 60)),
                         "token_replay": False, "failed_logins_1h": int(rng.integers(0, 2)), "payout_change": rng.random() < 0.15})
    df = pd.DataFrame(rows)
    df["distinct_guests_messaged"] = np.minimum(df.messages_sent, df.reservations_viewed)
    df["label"] = 1
    df["attack"] = kinds
    return df


def _matrix(df: pd.DataFrame) -> np.ndarray:
    return np.array([[featurise(r)[f] for f in FEATURES] for r in df.to_dict("records")])


# ----------------------------------------------------------------------------------------------
# Model
# ----------------------------------------------------------------------------------------------
@dataclass
class SessionScore:
    risk: float
    level: str
    reasons: list[str]
    model_risk: float
    rule_floor: float

    def as_dict(self) -> dict:
        return {"risk": round(self.risk, 3), "level": self.level, "reasons": self.reasons,
                "model_risk": round(self.model_risk, 3), "rule_floor": round(self.rule_floor, 3)}


def train(seed: int = 11, save: bool = True) -> tuple[dict, dict]:
    rng = np.random.default_rng(seed)
    normal = gen_normal(20000, rng)
    tr, te_norm = normal.iloc[:15000], normal.iloc[15000:]
    attacks = gen_attacks(900, rng)
    X = _matrix(tr)
    forest = IsolationForest(n_estimators=300, contamination="auto", random_state=seed).fit(X)
    s_tr = forest.score_samples(X)
    blob = {"forest": forest, "median": float(np.median(s_tr)), "low": float(np.percentile(s_tr, 0.5)),
            "feat_median": np.median(X, axis=0), "feat_std": X.std(axis=0) + 1e-6}
    scorer = SessionRiskModel(blob)
    te = pd.concat([te_norm, attacks], ignore_index=True)
    risks = np.array([r.risk for r in scorer.score_many(te.to_dict("records"))])
    y = te["label"].to_numpy()
    norm_r = risks[y == 0]
    report = {
        "synthetic": True,
        "n_train_normal": int(len(tr)), "n_test_normal": int(len(te_norm)), "n_test_attacks": int(len(attacks)),
        "roc_auc": float(roc_auc_score(y, risks)),
        "fpr_at_risky": float((norm_r >= config.SESSION_RISKY).mean()),
        "fpr_at_critical": float((norm_r >= config.SESSION_CRITICAL).mean()),
        "recall_at_risky": {k: float((risks[(te.attack == k).to_numpy()] >= config.SESSION_RISKY).mean())
                            for k in ATTACK_KINDS},
        "recall_at_critical": {k: float((risks[(te.attack == k).to_numpy()] >= config.SESSION_CRITICAL).mean())
                               for k in ATTACK_KINDS},
    }
    if save:
        config.MODELS.mkdir(parents=True, exist_ok=True)
        save_model({**blob, "report": report}, MODEL_PATH)
    return blob, report


class SessionRiskModel:
    version = "iforest-1"

    def __init__(self, blob: dict | None = None) -> None:
        if blob is None:
            blob = load_model(MODEL_PATH)
            if blob is None:  # missing, or not the file we wrote
                train(save=True)
                blob = load_model(MODEL_PATH)
        self.blob = blob
        self.report = blob.get("report", {})

    def score(self, ev: dict) -> SessionScore:
        return self.score_many([ev])[0]

    def score_many(self, evs: list[dict]) -> list[SessionScore]:
        feats = [featurise(ev) for ev in evs]
        X = np.array([[f[k] for k in FEATURES] for f in feats])
        scores = self.blob["forest"].score_samples(X)
        return [self._explain(f, X[i], float(scores[i])) for i, f in enumerate(feats)]

    def _explain(self, f: dict, xrow: np.ndarray, s: float) -> SessionScore:
        x = xrow[None, :]
        med, low = self.blob["median"], self.blob["low"]
        model_risk = float(np.clip((med - s) / (med - low) * 0.6, 0, 1))  # 0.5th percentile of normal -> 0.6

        reasons, floor = [], 0.0
        if f["token_replay"] and (f["new_asn"] or f["hosting_asn"]):
            floor = max(floor, 0.95); reasons.append("SESSION_TOKEN_REPLAYED_FROM_NEW_NETWORK")
        if f["log_speed_kmh"] > math.log1p(1000):
            floor = max(floor, 0.8); reasons.append("IMPOSSIBLE_TRAVEL")
        if f["payout_change"] and f["is_new_device"]:
            floor = max(floor, 0.9); reasons.append("PAYOUT_CHANGE_FROM_NEW_DEVICE")
        if f["is_new_device"] and f["log_reservations_viewed"] > math.log1p(30):
            floor = max(floor, 0.75); reasons.append("NEW_DEVICE_BULK_RESERVATION_READ")
        if f["is_new_device"] and f["log_km_from_usual"] > math.log1p(500):
            floor = max(floor, 0.7); reasons.append("NEW_DEVICE_NEW_COUNTRY")

        z = (x[0] - self.blob["feat_median"]) / self.blob["feat_std"]
        for i in np.argsort(-z)[:3]:
            if z[i] > 2.5:
                name = FEATURES[i].replace("log_", "").upper()
                code = f"UNUSUAL_{name}"
                if code not in reasons:
                    reasons.append(code)
        risk = max(model_risk, floor)
        level = "critical" if risk >= config.SESSION_CRITICAL else "risky" if risk >= config.SESSION_RISKY else (
            "elevated" if risk >= 0.4 else "normal")
        return SessionScore(risk, level, reasons, model_risk, floor)


if __name__ == "__main__":
    import json
    _, rep = train()
    print(json.dumps(rep, indent=2))
