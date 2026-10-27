# ScamShield India — evaluation report (test set)

Training set: 210 messages (104 scam / 106 legit).  
Held-out set: 60 messages (30 scam / 30 legit), written separately with different phrasing and deliberately tricky genuine messages (real OTP SMS, bank alerts, recruiter messages, police awareness tips).

Flagged = verdict SCAM or SUSPICIOUS. False-positive rate = genuine messages wrongly flagged.

## Results (BLIND: written after all tuning, evaluated once)

| System | Scam recall | Precision | F1 | False-positive rate | Accuracy |
|---|---|---|---|---|---|
| rules only | 53.3% (16/30) | 94.1% | 0.681 | 3.3% (1/30) | 75.0% |
| model only | 100.0% (30/30) | 88.2% | 0.938 | 13.3% (4/30) | 93.3% |
| fused (app) | 93.3% (28/30) | 96.6% | 0.949 | 3.3% (1/30) | 95.0% |

Scam-type accuracy on correctly flagged scams: **21/28** (75.0%)

## Classifier alone, 5-fold cross-validation on the training set

Recall 92.3% · Precision 81.4% · F1 0.865 · FPR 20.8%

## Errors on the held-out set

| True label | Verdict | Risk | Message |
|---|---|---|---|
| scam | NO_KNOWN_PATTERN | 0.37 | Hello, ED headquarters. We found illegal transactions in your account. You will remain under observation on video till the inquiry ends. |
| scam | NO_KNOWN_PATTERN | 0.4 | Hi, our company Global Media is hiring. Watch short videos and give ratings, Rs 200 per task. Earn 4-6k daily. Reply to start. |
| legit | SUSPICIOUS | 0.62 | Delhi Police: Cyber thugs pose as officers on video calls. There is no digital arrest. Report such calls on 1930. |

## Honest limitations

- All messages are written by the author, modelled on patterns in official advisories (I4C, RBI, TRAI, NPCI). They are not real victim data, so real-world accuracy will be lower. The next step is a held-out set of real, consented and redacted messages.
- Small dataset: numbers above have wide error bars. Treat them as a regression test, not a benchmark.
