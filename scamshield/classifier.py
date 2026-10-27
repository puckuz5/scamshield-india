"""TF-IDF (word + character n-grams) + logistic regression.

Character n-grams matter here: they cope with Hinglish spelling variation
("giraftar"/"giraftaar"), Devanagari and the typos scammers use on purpose.

Two models:
  * binary  — scam vs legit (probability used in the risk score)
  * type    — which scam type, trained on scam rows only
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "messages.csv"
MODEL_DIR = ROOT / "models"


def _features() -> FeatureUnion:
    return FeatureUnion(
        [
            ("word", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=1, sublinear_tf=True, lowercase=True)),
            ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=1, sublinear_tf=True, lowercase=True)),
        ]
    )


def build_binary() -> Pipeline:
    return Pipeline([("feats", _features()), ("clf", LogisticRegression(C=4.0, max_iter=2000, class_weight="balanced"))])


def build_type() -> Pipeline:
    return Pipeline([("feats", _features()), ("clf", LogisticRegression(C=4.0, max_iter=2000, class_weight="balanced"))])


def load_data(path: Path = DATA) -> pd.DataFrame:
    return pd.read_csv(path)


def train(df: pd.DataFrame | None = None, save: bool = True) -> tuple[Pipeline, Pipeline]:
    df = load_data() if df is None else df
    binary = build_binary().fit(df["text"], (df["label"] == "scam").astype(int))
    scams = df[df["label"] == "scam"]
    typer = build_type().fit(scams["text"], scams["scam_type"])
    if save:
        MODEL_DIR.mkdir(exist_ok=True)
        joblib.dump(binary, MODEL_DIR / "binary.joblib")
        joblib.dump(typer, MODEL_DIR / "type.joblib")
    return binary, typer


@dataclass
class Prediction:
    scam_prob: float
    type_key: str
    type_prob: float


class Classifier:
    def __init__(self) -> None:
        b, t = MODEL_DIR / "binary.joblib", MODEL_DIR / "type.joblib"
        if b.exists() and t.exists():
            self.binary, self.typer = joblib.load(b), joblib.load(t)
        else:
            self.binary, self.typer = train()

    def predict(self, text: str) -> Prediction:
        p = float(self.binary.predict_proba([text])[0][1])
        probs = self.typer.predict_proba([text])[0]
        i = int(probs.argmax())
        return Prediction(p, str(self.typer.classes_[i]), float(probs[i]))


if __name__ == "__main__":
    train()
    print(f"Saved models to {MODEL_DIR}")
