"""Evaluate ScamShield on the held-out set (never used for training).

Reports three systems side by side so the value of each layer is visible:
  rules only  |  model only  |  fused (what the app uses)

"Flagged" = verdict SCAM or SUSPICIOUS. A legit message flagged SUSPICIOUS
counts as a false positive — we hold the system to the strict standard.

Run:  python -m eval.evaluate
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
from sklearn.model_selection import StratifiedKFold, cross_val_predict

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scamshield import engine  # noqa: E402
from scamshield.classifier import build_binary, load_data, train  # noqa: E402


def metrics(y_true: list[int], y_flag: list[int]) -> dict:
    tp = sum(1 for t, f in zip(y_true, y_flag) if t and f)
    fn = sum(1 for t, f in zip(y_true, y_flag) if t and not f)
    fp = sum(1 for t, f in zip(y_true, y_flag) if not t and f)
    tn = sum(1 for t, f in zip(y_true, y_flag) if not t and not f)
    recall = tp / (tp + fn) if tp + fn else 0
    precision = tp / (tp + fp) if tp + fp else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
    acc = (tp + tn) / len(y_true)
    return dict(recall=recall, precision=precision, f1=f1, fpr=fpr, accuracy=acc, tp=tp, fn=fn, fp=fp, tn=tn)


def run(split: str = "test") -> str:
    train_df = load_data()
    train(train_df)  # refresh saved models from the training data only
    engine._classifier.cache_clear()

    hold = pd.read_csv(ROOT / "eval" / f"{split}.csv")
    y = (hold["label"] == "scam").astype(int).tolist()

    rows = {"rules only": [], "model only": [], "fused (app)": []}
    type_correct = type_total = 0
    misses = []
    for text, label, st in zip(hold["text"], hold["label"], hold["scam_type"]):
        r_rules = engine.analyze(text, use_model=False)
        r_full = engine.analyze(text, use_model=True)
        rows["rules only"].append(int(r_rules.verdict != engine.LOW))
        rows["model only"].append(int(r_full.model_prob >= 0.5))
        flagged = int(r_full.verdict != engine.LOW)
        rows["fused (app)"].append(flagged)
        if label == "scam" and flagged:
            type_total += 1
            type_correct += int(r_full.scam_type == st)
        if (label == "scam") != bool(flagged):
            misses.append((label, r_full.verdict, round(r_full.risk, 2), text))

    # 5-fold CV of the classifier alone on the training set (sanity check)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    yt = (train_df["label"] == "scam").astype(int)
    cv_pred = cross_val_predict(build_binary(), train_df["text"], yt, cv=cv)
    cv_m = metrics(yt.tolist(), cv_pred.tolist())

    lines = [
        f"# ScamShield India — evaluation report ({split} set)",
        "",
        f"Training set: {len(train_df)} messages ({int(yt.sum())} scam / {int((1 - yt).sum())} legit).  ",
        f"Held-out set: {len(hold)} messages ({sum(y)} scam / {len(y) - sum(y)} legit), written separately with different phrasing "
        "and deliberately tricky genuine messages (real OTP SMS, bank alerts, recruiter messages, police awareness tips).",
        "",
        "Flagged = verdict SCAM or SUSPICIOUS. False-positive rate = genuine messages wrongly flagged.",
        "",
        "## Results" + (" (BLIND: written after all tuning, evaluated once)" if split == "test" else " (dev set: used for error analysis and tuning, so optimistic)"),
        "",
        "| System | Scam recall | Precision | F1 | False-positive rate | Accuracy |",
        "|---|---|---|---|---|---|",
    ]
    for name, flags in rows.items():
        m = metrics(y, flags)
        lines.append(
            f"| {name} | {m['recall']:.1%} ({m['tp']}/{m['tp'] + m['fn']}) | {m['precision']:.1%} | {m['f1']:.3f} | "
            f"{m['fpr']:.1%} ({m['fp']}/{m['fp'] + m['tn']}) | {m['accuracy']:.1%} |"
        )
    lines += [
        "",
        f"Scam-type accuracy on correctly flagged scams: **{type_correct}/{type_total}** "
        f"({type_correct / type_total:.1%})" if type_total else "",
        "",
        "## Classifier alone, 5-fold cross-validation on the training set",
        "",
        f"Recall {cv_m['recall']:.1%} · Precision {cv_m['precision']:.1%} · F1 {cv_m['f1']:.3f} · FPR {cv_m['fpr']:.1%}",
        "",
        "## Errors on the held-out set",
        "",
    ]
    if misses:
        lines += ["| True label | Verdict | Risk | Message |", "|---|---|---|---|"]
        for label, verdict, risk, text in misses:
            lines.append(f"| {label} | {verdict} | {risk} | {text.replace('|', '/')} |")
    else:
        lines.append("None.")
    lines += [
        "",
        "## Honest limitations",
        "",
        "- All messages are written by the author, modelled on patterns in official advisories (I4C, RBI, TRAI, NPCI). "
        "They are not real victim data, so real-world accuracy will be lower. The next step is a held-out set of real, "
        "consented and redacted messages.",
        "- Small dataset: numbers above have wide error bars. Treat them as a regression test, not a benchmark.",
    ]
    report = "\n".join(lines) + "\n"
    (ROOT / "eval" / f"report_{split}.md").write_text(report, encoding="utf-8")
    return report


if __name__ == "__main__":
    print(run(sys.argv[1] if len(sys.argv) > 1 else "test"))
