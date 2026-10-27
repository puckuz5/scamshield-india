"""ScamShield India — Streamlit app.

Run locally:  streamlit run app.py
"""

from __future__ import annotations

import html
import io
import os

import streamlit as st
from PIL import Image

st.set_page_config(page_title="ScamShield India", page_icon="🛡️", layout="centered")

# Streamlit Cloud secrets -> env (the package reads env vars)
try:
    if "GROQ_API_KEY" in st.secrets and not os.environ.get("GROQ_API_KEY"):
        os.environ["GROQ_API_KEY"] = st.secrets["GROQ_API_KEY"]
except Exception:
    pass

from scamshield import engine, explain  # noqa: E402
from scamshield.alert import family_alert, whatsapp_link  # noqa: E402

EXAMPLES = {
    "📦 Parcel + police": "This is Inspector Sharma, Mumbai Crime Branch. A FedEx parcel in your name with drugs and 5 fake passports was seized. Join the video call now for your statement. Do not tell anyone or an arrest warrant will be issued.",
    "💸 UPI 'refund'": "Hi I am posted in army, want to buy your sofa from OLX. I have sent Rs 5,000 advance, just scan the QR and enter your UPI PIN to receive the payment.",
    "⚡ Bijli bill": "Dear consumer, your electricity power will be disconnected tonight at 9.30 pm because your previous month bill was not updated. Contact electricity officer 9876501234 immediately.",
    "📈 Stock tips": "Join our VIP stock market WhatsApp group. Guaranteed 30% monthly returns. Download our trading app: bit.ly/vip-trade",
    "🏦 Real bank OTP": "483920 is your one time password for HDFC Bank NetBanking. Valid for 5 mins. Do not share this OTP with anyone.",
}

CSS = """
<style>
:root { --scam:#c62828; --sus:#b26a00; --low:#455a64; }
.block-container { max-width: 760px; padding-top: 2rem; }
.verdict { border-radius: 14px; padding: 18px 20px; color: #fff; margin: 8px 0 14px; }
.verdict h2 { margin: 0; font-size: 1.5rem; color:#fff; }
.verdict p { margin: 6px 0 0; opacity: .95; }
.v-SCAM { background: var(--scam); }
.v-SUSPICIOUS { background: var(--sus); }
.v-NO_KNOWN_PATTERN { background: var(--low); }
.msg { border: 1px solid rgba(128,128,128,.35); border-radius: 12px; padding: 14px 16px; line-height: 1.7; white-space: pre-wrap; }
.msg mark { background: #ffcdd2; color: #7f0000; padding: 1px 3px; border-radius: 4px; }
.flag { border-left: 4px solid var(--scam); padding: 6px 12px; margin: 8px 0; }
.flag b { display:block; }
.small { font-size: .85rem; opacity: .75; }
.meta { display:flex; flex-wrap:wrap; gap:10px; margin: 0 0 6px; }
.meta span { border:1px solid rgba(128,128,128,.35); border-radius: 999px; padding: 6px 14px; font-size: .95rem; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

T = {
    "en": {
        "title": "🛡️ ScamShield India",
        "tag": "Got a suspicious WhatsApp, SMS or call? Check it in seconds. Works with English, Hindi and Hinglish.",
        "tab_text": "Message", "tab_img": "Screenshot", "tab_audio": "Call recording",
        "paste": "Paste the message here", "check": "Check for scam",
        "img_help": "Upload a screenshot of the message", "audio_help": "Upload or record the call / voice note",
        "read": "Text we read (you can fix mistakes before checking):",
        "verdicts": {"SCAM": "🚨 This is very likely a SCAM", "SUSPICIOUS": "⚠️ Suspicious — be careful", "NO_KNOWN_PATTERN": "ℹ️ No known scam pattern found"},
        "type": "Type", "risk": "Risk score", "flags": "Why we think so", "todo": "What to do now",
        "links": "Links, UPI IDs and numbers found", "sources": "Official sources", "share": "Warn your family",
        "share_btn": "Share on WhatsApp", "how": "How this was decided",
        "highlight": "Red flags highlighted in the message",
    },
    "hi": {
        "title": "🛡️ स्कैमशील्ड इंडिया",
        "tag": "शक वाला व्हाट्सऐप, SMS या कॉल? सेकंडों में जांचें। हिंदी, अंग्रेज़ी और हिंग्लिश में काम करता है।",
        "tab_text": "मैसेज", "tab_img": "स्क्रीनशॉट", "tab_audio": "कॉल रिकॉर्डिंग",
        "paste": "मैसेज यहां पेस्ट करें", "check": "स्कैम जांचें",
        "img_help": "मैसेज का स्क्रीनशॉट अपलोड करें", "audio_help": "कॉल / वॉइस नोट अपलोड या रिकॉर्ड करें",
        "read": "हमने यह टेक्स्ट पढ़ा (जांच से पहले गलती ठीक कर सकते हैं):",
        "verdicts": {"SCAM": "🚨 यह लगभग पक्का स्कैम है", "SUSPICIOUS": "⚠️ संदिग्ध — सावधान रहें", "NO_KNOWN_PATTERN": "ℹ️ कोई जाना-पहचाना स्कैम पैटर्न नहीं मिला"},
        "type": "प्रकार", "risk": "जोखिम स्कोर", "flags": "हमें शक क्यों है", "todo": "अब क्या करें",
        "links": "मिले हुए लिंक, UPI ID और नंबर", "sources": "आधिकारिक स्रोत", "share": "परिवार को सावधान करें",
        "share_btn": "व्हाट्सऐप पर शेयर करें", "how": "फैसला कैसे हुआ",
        "highlight": "मैसेज में खतरे के संकेत",
    },
}

with st.sidebar:
    lang = "hi" if st.radio("Language / भाषा", ["English", "हिंदी"], horizontal=True) == "हिंदी" else "en"
    st.markdown("---")
    has_key = bool(os.environ.get("GROQ_API_KEY"))
    st.markdown(
        f"**AI explanations:** {'on (LLaMA 3.3 via Groq)' if has_key else 'off — rule + ML engine only'}  \n"
        "**Privacy:** messages are not stored. "
        + ("With AI explanations on, the message text is sent to Groq to generate the explanation." if has_key else "")
    )
    st.markdown("---")
    st.markdown(
        "<span class='small'>Not a substitute for official help. Lost money? Call **1930** or visit "
        "[cybercrime.gov.in](https://cybercrime.gov.in).</span>",
        unsafe_allow_html=True,
    )

L = T[lang]
st.title(L["title"])
st.caption(L["tag"])

if "text" not in st.session_state:
    st.session_state.text = ""

# The tabs only *fill* the single message box below them. They run before the
# box is created, so writing to st.session_state.text here is allowed.
tab_text, tab_img, tab_audio = st.tabs([L["tab_text"], L["tab_img"], L["tab_audio"]])

with tab_text:
    st.caption("Try an example:" if lang == "en" else "उदाहरण आज़माएं:")
    cols = st.columns(len(EXAMPLES))
    for col, (label, ex) in zip(cols, EXAMPLES.items()):
        if col.button(label, use_container_width=True):
            st.session_state.text = ex

with tab_img:
    up = st.file_uploader(L["img_help"], type=["png", "jpg", "jpeg", "webp"])
    if up is not None:
        img = Image.open(up)
        st.image(img, width=280)
        if st.session_state.get("ocr_for") != up.file_id:
            from scamshield.ocr import image_to_text

            with st.spinner("Reading the screenshot…"):
                try:
                    st.session_state.text = image_to_text(img)
                except Exception as e:
                    st.error(f"Couldn't read the image: {e}")
            st.session_state.ocr_for = up.file_id
        st.caption(L["read"])

with tab_audio:
    if not os.environ.get("GROQ_API_KEY"):
        st.info("Call transcription needs a free Groq API key (set GROQ_API_KEY).")
    else:
        audio = st.audio_input(L["audio_help"]) if hasattr(st, "audio_input") else None
        audio_file = st.file_uploader(L["audio_help"], type=["mp3", "m4a", "wav", "ogg", "opus", "webm"], key="audio_up")
        src = audio_file or audio
        src_id = getattr(src, "file_id", None) if src is not None else None
        if src is not None and st.session_state.get("asr_for") != src_id:
            from scamshield.audio import transcribe

            with st.spinner("Transcribing the call…"):
                try:
                    st.session_state.text = transcribe(src.getvalue(), getattr(src, "name", "call.wav"))
                except Exception as e:
                    st.error(f"Couldn't transcribe: {e}")
            st.session_state.asr_for = src_id
        if src is not None:
            st.caption(L["read"])

st.text_area(L["paste"], key="text", height=150)


def highlight(text: str, quotes: list[str]) -> str:
    spans = []
    low = text.lower()
    for q in quotes:
        i = low.find(q.lower())
        if i >= 0 and q.strip():
            spans.append((i, i + len(q)))
    spans.sort()
    merged = []
    for s, e in spans:
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    out, pos = [], 0
    for s, e in merged:
        out.append(html.escape(text[pos:s]))
        out.append(f"<mark>{html.escape(text[s:e])}</mark>")
        pos = e
    out.append(html.escape(text[pos:]))
    return "".join(out)


if st.button(L["check"], type="primary", use_container_width=True, disabled=not st.session_state.text.strip()):
    text = st.session_state.text.strip()
    with st.spinner("Checking…"):
        a = engine.analyze(text)
        ex = explain.explain(a)

    verdict = ex.verdict
    type_name = (a.scam_type_name_hi if lang == "hi" else a.scam_type_name_en) if verdict != engine.LOW else ""
    if ex.scam_type != a.scam_type:  # LLM filled in a type the engine left blank
        from scamshield import taxonomy

        stype = taxonomy.get(ex.scam_type)
        type_name = (stype.name_hi if lang == "hi" else stype.name_en) if stype else type_name
    summary = ex.summary_hi if lang == "hi" else ex.summary_en

    st.markdown(
        f"<div class='verdict v-{verdict}'><h2>{L['verdicts'][verdict]}</h2>"
        f"<p>{html.escape(summary)}</p></div>",
        unsafe_allow_html=True,
    )
    st.markdown(
        f"<div class='meta'><span><b>{L['risk']}:</b> {int(round(a.risk * 100))}/100</span>"
        + (f"<span class='type'><b>{L['type']}:</b> {html.escape(type_name)}</span>" if type_name else "")
        + "</div>",
        unsafe_allow_html=True,
    )

    quotes = [f["quote"] for f in ex.red_flags]
    if quotes:
        st.subheader(L["highlight"])
        st.markdown(f"<div class='msg'>{highlight(text, quotes)}</div>", unsafe_allow_html=True)

        st.subheader(L["flags"])
        for f in ex.red_flags:
            why = f.get("explanation_hi") if lang == "hi" and f.get("explanation_hi") else f.get("explanation_en", "")
            st.markdown(
                f"<div class='flag'><b>“{html.escape(f['quote'][:140])}”</b>{html.escape(why)}</div>",
                unsafe_allow_html=True,
            )

    st.subheader(L["todo"])
    for tip in (a.advice_hi if lang == "hi" else a.advice_en):
        st.markdown(f"- {tip}")

    if a.links or a.upi_ids or a.phones:
        with st.expander(L["links"]):
            for lr in a.links:
                badge = "🔴" if lr["risk"] >= 0.6 else "🟠" if lr["risk"] >= 0.3 else "⚪"
                st.markdown(f"{badge} `{lr['url']}` — {'; '.join(lr['reasons']) or 'no obvious issues'}")
            for u in a.upi_ids:
                st.markdown(f"💳 UPI ID: `{u}` — don't pay or approve requests from IDs in unsolicited messages")
            for p in a.phones:
                st.markdown(f"📞 `{p['number']}`" + (" — international number" if p["foreign"] else ""))

    if ex.citations:
        with st.expander(L["sources"]):
            for c in ex.citations:
                srcs = " · ".join(f"[{i + 1}]({u})" for i, u in enumerate(c["sources"]))
                st.markdown(f"**{c['title']}** — {c['heading']}  \n{srcs}")

    alert = family_alert(a, quotes[0] if quotes else None)
    if alert:
        st.subheader(L["share"])
        st.code(alert, language=None, wrap_lines=True)
        st.link_button(L["share_btn"], whatsapp_link(alert))

    with st.expander(L["how"]):
        st.markdown(
            f"- Rule engine risk: **{a.rule_risk:.2f}** ({len(a.hits)} red-flag rules matched)\n"
            f"- ML classifier scam probability: **{a.model_prob:.2f}**\n"
            f"- Final risk: **{a.risk:.2f}** → {verdict}\n"
            f"- AI explanation: {'LLaMA 3.3 via Groq, checked by the hallucination guard' if ex.used_llm else 'off (explanation built from the rule engine)'}"
        )
        for g in ex.guard_log:
            st.markdown(f"  - 🛡️ guard: {g}")
