"""Combine rules, link analysis and the classifier into one verdict.

Design choices (these are the interesting part — see README):
  * Noisy-OR fusion: each independent red flag raises risk; no single weak
    signal can push a message to SCAM on its own.
  * The tool never says "safe". The lowest verdict is "no known scam pattern
    found", because a false "safe" is the most harmful mistake it can make.
  * Advice and helpline numbers come from taxonomy.py, never from the LLM.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from functools import lru_cache

from . import links as linkmod
from . import signals, taxonomy
from .classifier import Classifier

SCAM, SUSPICIOUS, LOW = "SCAM", "SUSPICIOUS", "NO_KNOWN_PATTERN"
SEVERITY = {LOW: 0, SUSPICIOUS: 1, SCAM: 2}
SCAM_T, SUSPICIOUS_T = 0.70, 0.40

# Some rules are decisive on their own: there is no legitimate reason for them.
DECISIVE = {"pin_to_receive", "apk", "da_safe_account", "credential_request", "remote_access"}


@dataclass
class Analysis:
    text: str
    verdict: str
    risk: float
    scam_type: str
    scam_type_name_en: str
    scam_type_name_hi: str
    hits: list[dict] = field(default_factory=list)
    links: list[dict] = field(default_factory=list)
    upi_ids: list[str] = field(default_factory=list)
    phones: list[dict] = field(default_factory=list)
    model_prob: float = 0.0
    rule_risk: float = 0.0
    advice_en: list[str] = field(default_factory=list)
    advice_hi: list[str] = field(default_factory=list)
    kb_id: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def noisy_or(ws: list[float]) -> float:
    p = 1.0
    for w in ws:
        p *= 1.0 - max(0.0, min(1.0, w))
    return 1.0 - p


@lru_cache(maxsize=1)
def _classifier() -> Classifier:
    return Classifier()


def verdict_for(risk: float) -> str:
    if risk >= SCAM_T:
        return SCAM
    if risk >= SUSPICIOUS_T:
        return SUSPICIOUS
    return LOW


def analyze(text: str, use_model: bool = True) -> Analysis:
    text = (text or "").strip()
    hits = signals.find_hits(text)
    link_reports = linkmod.analyze_links(text)
    phones = linkmod.extract_phones(text)
    upis = linkmod.extract_upi_ids(text)

    for p in phones:
        if p["foreign"]:
            hits.append(
                signals.Hit(
                    "foreign_number", None, 0.2, p["number"], text.find(p["number"]), text.find(p["number"]) + len(p["number"]),
                    "International number — Indian police, banks and companies don't contact you from foreign numbers",
                    "विदेशी नंबर — भारतीय पुलिस, बैंक या कंपनियां विदेशी नंबर से संपर्क नहीं करतीं",
                )
            )
            break

    weights = [h.weight for h in hits]
    weights += [lr.risk * 0.8 for lr in link_reports if lr.risk > 0.2]
    rule_risk = noisy_or(weights)

    benign = signals.benign_score(text) and not any(h.weight >= 0.5 for h in hits) and not any(
        lr.risk >= 0.5 for lr in link_reports
    )
    if benign:
        rule_risk *= 0.35

    model_prob = 0.0
    pred = None
    if use_model and text:
        pred = _classifier().predict(text)
        model_prob = pred.scam_prob

    # Rules carry the evidence; the model generalises to phrasings the rules miss.
    # The model can push a message all the way to SCAM only when the rules found
    # real evidence. With context-only mentions ("Delhi Police", "TRAI") or no
    # rule hits, the model alone can reach SUSPICIOUS at most.
    strong = signals.has_strong_evidence(hits) or any(lr.risk >= 0.3 for lr in link_reports) or any(
        p["foreign"] for p in phones
    )
    if not use_model:
        risk = rule_risk
    elif strong:
        risk = max(0.65 * rule_risk + 0.35 * model_prob, rule_risk * 0.9, model_prob * 0.85)
    else:
        risk = min(max(0.5 * rule_risk + 0.5 * model_prob, model_prob * 0.6), SCAM_T - 0.01)
    if benign:
        risk = min(risk, SUSPICIOUS_T - 0.01) if not strong else risk * 0.6
    if any(h.rule_id in DECISIVE for h in hits) or any(lr.risk >= 0.9 for lr in link_reports):
        risk = max(risk, SCAM_T + 0.05)
    risk = round(min(risk, 0.99), 3)

    # Scam type: rules vote by weight, model breaks ties / fills in.
    votes: dict[str, float] = defaultdict(float)
    for h in hits:
        if h.scam_type:
            votes[h.scam_type] += h.weight
    if any("apk" in r for lr in link_reports for r in lr.reasons):
        votes["malicious_app"] += 0.5
    elif any(lr.risk >= 0.5 for lr in link_reports) and not votes:
        votes["kyc_phishing"] += 0.3
    if pred and pred.type_prob > 0.3:
        votes[pred.type_key] += 0.4 * pred.type_prob
    v = verdict_for(risk)
    type_key = max(votes, key=votes.get) if votes and v != LOW else taxonomy.NONE_KEY
    st = taxonomy.get(type_key)

    advice_en = list(st.advice_en) if st else []
    advice_hi = list(st.advice_hi) if st else []
    if v != LOW:
        advice_en += [taxonomy.LOST_MONEY_EN, taxonomy.REPORT_EN]
        advice_hi += [taxonomy.LOST_MONEY_HI, taxonomy.REPORT_HI]
    else:
        advice_en = ["No common scam pattern found — but that is not a guarantee. If anyone asks for money, OTP or PIN, stop and verify on an official number."]
        advice_hi = ["कोई जाना-पहचाना स्कैम पैटर्न नहीं मिला — पर यह गारंटी नहीं है। कोई पैसे, OTP या पिन मांगे तो रुकें और ऑफिशियल नंबर पर जांचें।"]

    return Analysis(
        text=text,
        verdict=v,
        risk=risk,
        scam_type=type_key,
        scam_type_name_en=st.name_en if st else "",
        scam_type_name_hi=st.name_hi if st else "",
        hits=[asdict(h) for h in hits],
        links=[asdict(lr) for lr in link_reports],
        upi_ids=upis,
        phones=phones,
        model_prob=round(model_prob, 3),
        rule_risk=round(rule_risk, 3),
        advice_en=advice_en,
        advice_hi=advice_hi,
        kb_id=st.kb_id if st else None,
    )
