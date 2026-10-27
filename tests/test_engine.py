import pytest

from scamshield import engine, explain, links, signals
from scamshield.alert import family_alert


@pytest.mark.parametrize(
    "text,expected_type",
    [
        ("CBI officer here. Your Aadhaar is linked to money laundering. Stay on the video call and do not tell anyone.", "digital_arrest"),
        ("Your mobile number will be disconnected in 2 hours by TRAI. Press 9 to speak to an officer.", "trai_telecom"),
        ("I sent you Rs 5000, please enter your UPI PIN to receive it.", "upi_collect_qr"),
        ("Join our VIP stock group, guaranteed 20% monthly returns.", "investment"),
        ("Part time job: like YouTube videos and earn Rs 3000 daily. Contact HR on WhatsApp.", "task_job"),
        ("Pay your traffic challan here: rto-challan.apk", "malicious_app"),
        ("Your electricity will be disconnected tonight at 9:30, previous month bill not updated. Call officer.", "utility_bill"),
        ("You have won Rs 25 lakh in KBC lottery, pay processing fee to claim.", "lottery_prize"),
        ("Hi Mummy this is my new number, phone is broken. Send Rs 10,000 urgently.", "impersonation"),
    ],
)
def test_detects_scam_types(text, expected_type):
    a = engine.analyze(text)
    assert a.verdict in (engine.SCAM, engine.SUSPICIOUS), a.to_dict()
    assert a.scam_type == expected_type


@pytest.mark.parametrize(
    "text",
    [
        "Your OTP for login is 482913. Do not share this OTP with anyone. -HDFC Bank",
        "Rs 450.00 debited from a/c XX9921 for UPI txn to ZOMATO. Not you? Call 1800 1080. -SBI",
        "Congratulations, you won the college coding hackathon! Collect your certificate on Monday.",
        "Delhi Police: lock your car and keep valuables out of sight during festivals.",
        "Kal college band hai, exam postpone ho gaya.",
    ],
)
def test_genuine_messages_not_flagged(text):
    assert engine.analyze(text).verdict == engine.LOW


def test_never_says_safe():
    a = engine.analyze("Happy birthday bhai!")
    assert a.verdict == engine.LOW
    assert "not a guarantee" in a.advice_en[0]


def test_negation_is_respected():
    hits = {h.rule_id for h in signals.find_hits("Never share your OTP with anyone.")}
    assert "credential_request" not in hits
    hits = {h.rule_id for h in signals.find_hits("Please share the OTP you received.")}
    assert "credential_request" in hits


def test_hindi_devanagari():
    a = engine.analyze("आपके आधार का इस्तेमाल मनी लॉन्ड्रिंग में हुआ है। वीडियो कॉल पर रहें, किसी को मत बताना।")
    assert a.verdict == engine.SCAM
    assert a.scam_type == "digital_arrest"


def test_link_analysis():
    assert links.analyze_url("https://sbi-kyc-update.xyz/login").risk >= 0.9
    assert links.analyze_url("https://www.onlinesbi.sbi/").risk == 0
    assert links.analyze_url("https://www.hdfc.bank.in/").risk <= 0.1
    assert links.analyze_url("hdfcbnk.com/verify").risk >= 0.5
    assert links.analyze_url("http://10.0.0.5/app.apk").risk >= 0.9
    assert links.extract_upi_ids("pay rahul@ybl or mail a@gmail.com") == ["rahul@ybl"]
    assert "gmail.com" not in links.extract_urls("mail me at a@gmail.com")


def test_foreign_number_is_evidence():
    a = engine.analyze("Call me on WhatsApp +92 301 2345678 for the job")
    assert any(h["rule_id"] == "foreign_number" for h in a.hits)


def test_guard_blocks_hallucinations():
    a = engine.analyze("I sent Rs 5000, enter your UPI PIN to receive.")
    chunks = explain.retrieve(a)
    fake = {
        "verdict": "NO_KNOWN_PATTERN",
        "summary_en": "Looks fine. Call 1800-111-222.",
        "red_flags": [
            {"quote": "enter your UPI PIN to receive", "explanation_en": "PIN is for sending"},
            {"quote": "this text is not in the message", "explanation_en": "made up"},
        ],
        "citations": [chunks[0].id, "KB-NOPE#1"],
    }
    g = explain.guard(fake, a, chunks)
    assert g.verdict == engine.SCAM                       # can't be downgraded
    assert [f["quote"] for f in g.red_flags] == ["enter your UPI PIN to receive"]
    assert all(c["id"] != "KB-NOPE#1" for c in g.citations)
    assert "1800-111-222" not in g.summary_en and "fine" not in g.summary_en.lower()


def test_guard_cannot_escalate_without_evidence():
    a = engine.analyze("Meeting moved to 4 pm tomorrow.")
    chunks = explain.retrieve(a)
    g = explain.guard({"verdict": "SCAM", "red_flags": [{"quote": "invented"}]}, a, chunks)
    assert g.verdict == engine.LOW


def test_offline_explanation_works_without_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    a = engine.analyze("Your account will be blocked today. Update KYC at sbi-kyc.xyz")
    e = explain.explain(a)
    assert not e.used_llm and e.red_flags and e.citations


def test_family_alert_contains_only_fixed_helplines():
    a = engine.analyze("I sent Rs 5000, enter your UPI PIN to receive. Call 9876543210")
    msg = family_alert(a, "enter your UPI PIN to receive")
    assert "1930" in msg and "9876543210" not in msg
