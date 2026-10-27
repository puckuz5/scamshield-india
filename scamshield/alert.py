"""A short, forwardable warning for the family WhatsApp group.

Template-based on purpose: this text gets shared widely, so it must never
contain anything an LLM made up.
"""

from __future__ import annotations

from urllib.parse import quote

from . import engine


def family_alert(analysis: engine.Analysis, top_flag: str | None = None) -> str:
    if analysis.verdict == engine.LOW:
        return ""
    name_en = analysis.scam_type_name_en or "scam"
    name_hi = analysis.scam_type_name_hi or "स्कैम"
    first_advice_en = analysis.advice_en[0] if analysis.advice_en else ""
    first_advice_hi = analysis.advice_hi[0] if analysis.advice_hi else ""
    lines = [
        f"⚠️ Scam alert: {name_en}",
        f"⚠️ सावधान: {name_hi}",
        "",
    ]
    if top_flag:
        lines.append(f"Watch out for messages like: “{top_flag[:90]}”")
    lines += [
        f"✅ {first_advice_en}",
        f"✅ {first_advice_hi}",
        "",
        "Lost money? Call 1930 / cybercrime.gov.in",
        "पैसे गए? तुरंत 1930 पर कॉल करें",
        "",
        "Checked with ScamShield India",
    ]
    return "\n".join(lines)


def whatsapp_link(text: str) -> str:
    return "https://wa.me/?text=" + quote(text)
