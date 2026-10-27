# ScamShield India — evaluation report (dev set)

Training set: 210 messages (104 scam / 106 legit).  
Held-out set: 52 messages (28 scam / 24 legit), written separately with different phrasing and deliberately tricky genuine messages (real OTP SMS, bank alerts, recruiter messages, police awareness tips).

Flagged = verdict SCAM or SUSPICIOUS. False-positive rate = genuine messages wrongly flagged.

## Results (dev set: used for error analysis and tuning, so optimistic)

| System | Scam recall | Precision | F1 | False-positive rate | Accuracy |
|---|---|---|---|---|---|
| rules only | 67.9% (19/28) | 100.0% | 0.809 | 0.0% (0/24) | 82.7% |
| model only | 96.4% (27/28) | 96.4% | 0.964 | 4.2% (1/24) | 96.2% |
| fused (app) | 100.0% (28/28) | 100.0% | 1.000 | 0.0% (0/24) | 100.0% |

Scam-type accuracy on correctly flagged scams: **24/28** (85.7%)

## Classifier alone, 5-fold cross-validation on the training set

Recall 92.3% · Precision 81.4% · F1 0.865 · FPR 20.8%

## Errors on the held-out set

None.

## Honest limitations

- All messages are written by the author, modelled on patterns in official advisories (I4C, RBI, TRAI, NPCI). They are not real victim data, so real-world accuracy will be lower. The next step is a held-out set of real, consented and redacted messages.
- Small dataset: numbers above have wide error bars. Treat them as a regression test, not a benchmark.
