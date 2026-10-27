"""Grounded explanation: retrieve official guidance, ask the LLM, then guard it.

The hallucination guard (all checks are deterministic code, not prompts):
  1. Every red flag the LLM lists must quote text that is actually in the
     message. Quotes that aren't found are dropped.
  2. Citations must point to knowledge-base chunks that were retrieved for this
     message. Anything else is dropped.
  3. The LLM may raise the verdict by one level (only with a verified quote),
     but can never lower the verdict the rule+ML engine reached.
  4. Phone numbers and links the LLM writes that are not in the message are
     removed. Helplines and advice come from taxonomy.py only.

Without a GROQ_API_KEY everything still works: the explanation is built from
the engine's own evidence instead.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

from . import engine, taxonomy
from .kb import Chunk, get_kb

DEFAULT_MODEL = os.environ.get("SCAMSHIELD_MODEL", "llama-3.3-70b-versatile")

SYSTEM = """You are ScamShield, an assistant that explains whether a message received in India is a scam.
You are given: the message, findings from a rule-based + ML detector, and excerpts from official advisories (each with an id).

Return ONLY a JSON object with these keys:
- "verdict": one of "SCAM", "SUSPICIOUS", "NO_KNOWN_PATTERN"
- "scam_type": one of {types}
- "summary_en": 1-2 short, calm sentences in simple English for a non-technical person (e.g. a parent).
- "summary_hi": the same in simple Hindi (Devanagari).
- "red_flags": list of up to 4 objects {{"quote": <copy an EXACT short phrase from the message>, "explanation_en": <why it is a red flag>, "explanation_hi": <same in Hindi>}}
- "citations": list of advisory ids you relied on (only ids from the excerpts provided)

Rules:
- Quote only text that appears word-for-word in the message.
- Base claims about what police/banks/TRAI/NPCI do ONLY on the excerpts provided.
- Never write phone numbers, links or helpline numbers; the app adds official ones itself.
- Never call a message "safe" or "genuine"; if nothing is wrong say no known scam pattern was found.
- If the message is not a scam, return an empty red_flags list."""


@dataclass
class Explanation:
    verdict: str
    scam_type: str
    summary_en: str
    summary_hi: str
    red_flags: list[dict] = field(default_factory=list)
    citations: list[dict] = field(default_factory=list)
    used_llm: bool = False
    guard_log: list[str] = field(default_factory=list)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def _cite(c: Chunk) -> dict:
    return {"id": c.id, "title": c.title, "heading": c.heading, "sources": list(c.sources)}


PHONE_OR_URL = re.compile(r"(\+?\d[\d\s-]{7,}\d)|(https?://\S+)|(\b[\w-]+\.(com|in|org|net|xyz|online|site|info)\b\S*)", re.I)


def _scrub(text: str, message: str, log: list[str]) -> str:
    def repl(m: re.Match) -> str:
        frag = m.group(0)
        if frag.strip().lower() in message.lower():
            return frag
        log.append(f"removed unverified number/link from summary: {frag}")
        return ""

    return re.sub(r"\s{2,}", " ", PHONE_OR_URL.sub(repl, text or "")).strip()


def retrieve(analysis: engine.Analysis, k: int = 4) -> list[Chunk]:
    reasons = " ".join(h["why_en"] for h in analysis.hits)
    q = f"{analysis.text} {analysis.scam_type_name_en} {reasons}"
    return get_kb().search(q, k=k, prefer_doc=analysis.kb_id)


def offline_explanation(analysis: engine.Analysis, chunks: list[Chunk]) -> Explanation:
    flags = [
        {"quote": h["evidence"], "explanation_en": h["why_en"], "explanation_hi": h["why_hi"]}
        for h in sorted(analysis.hits, key=lambda h: -h["weight"])[:4]
    ]
    for lr in analysis.links:
        if lr["risk"] >= 0.3 and len(flags) < 5:
            flags.append(
                {
                    "quote": lr["url"],
                    "explanation_en": "Risky link: " + "; ".join(lr["reasons"]),
                    "explanation_hi": "खतरनाक लिंक: " + "; ".join(lr["reasons"]),
                }
            )
    if analysis.verdict == engine.SCAM:
        en = f"This looks like a {analysis.scam_type_name_en} scam. Do not reply, pay or share any details."
        hi = f"यह {analysis.scam_type_name_hi} वाला स्कैम लगता है। जवाब न दें, पैसे न भेजें, कोई जानकारी न दें।"
    elif analysis.verdict == engine.SUSPICIOUS:
        name = analysis.scam_type_name_en or "known scam"
        en = f"This has warning signs of a {name} pattern. Verify through an official number before doing anything."
        hi = "इसमें स्कैम के संकेत हैं। कुछ भी करने से पहले ऑफिशियल नंबर पर जांच करें।"
    else:
        en = "No common scam pattern was found. That is not a guarantee — stay careful if money, OTP or PIN is involved."
        hi = "कोई जाना-पहचाना स्कैम पैटर्न नहीं मिला। फिर भी पैसे, OTP या पिन की बात हो तो सावधान रहें।"
    cites = [_cite(c) for c in chunks if c.doc_id == analysis.kb_id or c.doc_id == "KB-REPORT"][:3]
    return Explanation(analysis.verdict, analysis.scam_type, en, hi, flags, cites, used_llm=False)


def _llm_call(analysis: engine.Analysis, chunks: list[Chunk], model: str) -> dict:
    from groq import Groq

    client = Groq(api_key=os.environ["GROQ_API_KEY"])
    excerpts = "\n\n".join(f"[{c.id}] {c.title} — {c.heading}\n{c.text}" for c in chunks)
    findings = {
        "engine_verdict": analysis.verdict,
        "risk": analysis.risk,
        "likely_type": analysis.scam_type,
        "rule_hits": [{"rule": h["rule_id"], "evidence": h["evidence"]} for h in analysis.hits],
        "links": [{"url": lr["url"], "risk": lr["risk"], "reasons": lr["reasons"]} for lr in analysis.links],
    }
    user = f"MESSAGE:\n\"\"\"{analysis.text}\"\"\"\n\nDETECTOR FINDINGS:\n{json.dumps(findings, ensure_ascii=False)}\n\nADVISORY EXCERPTS:\n{excerpts}"
    resp = client.chat.completions.create(
        model=model,
        temperature=0.1,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": SYSTEM.format(types=", ".join(taxonomy.all_keys() + [taxonomy.NONE_KEY]))},
            {"role": "user", "content": user},
        ],
    )
    return json.loads(resp.choices[0].message.content)


def guard(raw: dict, analysis: engine.Analysis, chunks: list[Chunk]) -> Explanation:
    log: list[str] = []
    msg_norm = _norm(analysis.text)

    flags = []
    for f in raw.get("red_flags") or []:
        q = str(f.get("quote", "")).strip().strip("\"'")
        if q and _norm(q) in msg_norm:
            flags.append(
                {
                    "quote": q,
                    "explanation_en": _scrub(str(f.get("explanation_en", "")), analysis.text, log),
                    "explanation_hi": _scrub(str(f.get("explanation_hi", "")), analysis.text, log),
                }
            )
        else:
            log.append(f"dropped red flag with a quote not found in the message: {q!r}")

    allowed = {c.id: c for c in chunks}
    cites = []
    for cid in raw.get("citations") or []:
        cid = str(cid).strip()
        if cid in allowed:
            cites.append(_cite(allowed[cid]))
        else:
            log.append(f"dropped citation that was not retrieved: {cid!r}")

    llm_v = str(raw.get("verdict", "")).upper()
    llm_v = llm_v if llm_v in engine.SEVERITY else analysis.verdict
    final_v = analysis.verdict
    if engine.SEVERITY[llm_v] > engine.SEVERITY[analysis.verdict]:
        if flags:
            final_v = [k for k, v in engine.SEVERITY.items() if v == engine.SEVERITY[analysis.verdict] + 1][0]
            log.append(f"LLM raised verdict {analysis.verdict} -> {final_v} with verified evidence")
        else:
            log.append("LLM tried to raise the verdict without verified evidence; kept engine verdict")
    elif engine.SEVERITY[llm_v] < engine.SEVERITY[analysis.verdict]:
        log.append(f"LLM suggested {llm_v}; kept stricter engine verdict {analysis.verdict}")

    st = analysis.scam_type
    if st == taxonomy.NONE_KEY and final_v != engine.LOW and raw.get("scam_type") in taxonomy.TYPES:
        st = raw["scam_type"]

    offline = offline_explanation(analysis, chunks)
    if final_v != engine.LOW and not flags:
        # fall back to the engine's own, already-verified evidence
        flags = offline.red_flags

    n_before = len(log)
    summary_en = _scrub(str(raw.get("summary_en", "")), analysis.text, log)
    summary_hi = _scrub(str(raw.get("summary_hi", "")), analysis.text, log)
    # A summary written for a softer verdict, or one we had to censor, can't be
    # shown next to a stricter verdict — it would contradict it.
    if engine.SEVERITY[llm_v] < engine.SEVERITY[final_v] or len(log) > n_before or not summary_en:
        if summary_en:
            log.append("replaced LLM summary with engine summary (contradicted verdict or contained unverified details)")
        summary_en, summary_hi = offline.summary_en, offline.summary_hi

    return Explanation(
        verdict=final_v,
        scam_type=st,
        summary_en=summary_en,
        summary_hi=summary_hi or offline.summary_hi,
        red_flags=flags,
        citations=cites or offline.citations,
        used_llm=True,
        guard_log=log,
    )


def explain(analysis: engine.Analysis, use_llm: bool | None = None, model: str = DEFAULT_MODEL) -> Explanation:
    chunks = retrieve(analysis)
    if use_llm is None:
        use_llm = bool(os.environ.get("GROQ_API_KEY"))
    if not use_llm or not analysis.text:
        return offline_explanation(analysis, chunks)
    try:
        raw = _llm_call(analysis, chunks, model)
    except Exception as e:  # network, quota, bad JSON — never fail the user
        exp = offline_explanation(analysis, chunks)
        exp.guard_log.append(f"LLM unavailable ({type(e).__name__}); used offline explanation")
        return exp
    return guard(raw, analysis, chunks)
