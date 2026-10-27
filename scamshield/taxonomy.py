"""Scam types, human-readable names and the fixed safety advice for each.

Advice and helpline numbers live here, in code, on purpose: the LLM is never
allowed to write phone numbers or reporting steps, so they can't be hallucinated.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScamType:
    key: str
    name_en: str
    name_hi: str
    kb_id: str
    advice_en: tuple[str, ...]
    advice_hi: tuple[str, ...] = field(default_factory=tuple)


LOST_MONEY_EN = "Already paid or shared details? Call 1930 right now and file at cybercrime.gov.in. Every minute counts for freezing the money."
LOST_MONEY_HI = "पैसे भेज दिए या जानकारी दे दी? तुरंत 1930 पर कॉल करें और cybercrime.gov.in पर शिकायत करें। जितनी जल्दी, पैसे रुकने की उतनी संभावना।"
REPORT_EN = "Didn't lose money? Report the number/message on Chakshu (Sanchar Saathi portal) so it can be blocked."
REPORT_HI = "पैसे नहीं गए? इस नंबर/मैसेज को संचार साथी पोर्टल पर 'चक्षु' में रिपोर्ट करें।"


TYPES: dict[str, ScamType] = {
    "digital_arrest": ScamType(
        "digital_arrest",
        "Digital arrest / fake police or CBI",
        "डिजिटल अरेस्ट / नकली पुलिस या CBI",
        "KB-DA",
        (
            "Hang up. Police, CBI, ED, customs and courts never arrest anyone over a video call.",
            "Do not transfer any money to 'verify' or 'clear' your name.",
            "Tell a family member right away — scammers depend on keeping you isolated.",
        ),
        (
            "कॉल काट दें। पुलिस, CBI, ED, कस्टम या कोर्ट कभी वीडियो कॉल पर गिरफ्तार नहीं करते।",
            "'वेरिफिकेशन' के नाम पर कोई पैसा न भेजें।",
            "तुरंत परिवार को बताएं — ठग आपको अकेला रखना चाहते हैं।",
        ),
    ),
    "trai_telecom": ScamType(
        "trai_telecom",
        "Fake TRAI / SIM disconnection",
        "नकली TRAI / सिम बंद होने की धमकी",
        "KB-TRAI",
        (
            "Disconnect. TRAI never calls to disconnect numbers or asks for Aadhaar/OTP.",
            "Don't press any key or talk to the 'officer' they transfer you to.",
        ),
        (
            "कॉल काट दें। TRAI कभी नंबर बंद करने के लिए कॉल नहीं करता और न ही आधार/OTP मांगता है।",
            "कोई बटन न दबाएं, और 'ऑफिसर' से बात न करें।",
        ),
    ),
    "upi_collect_qr": ScamType(
        "upi_collect_qr",
        "UPI PIN / QR code / collect-request trick",
        "UPI पिन / QR कोड / कलेक्ट रिक्वेस्ट धोखा",
        "KB-UPI",
        (
            "Your UPI PIN is only for SENDING money. You never need it to receive money.",
            "Never scan a QR code or approve a request to 'receive' a payment.",
            "Got money 'by mistake'? Check your bank app yourself — don't return it via a link or request.",
        ),
        (
            "UPI पिन सिर्फ पैसे भेजने के लिए है। पैसे लेने के लिए कभी पिन नहीं लगता।",
            "पैसे 'पाने' के लिए कभी QR कोड स्कैन न करें, न रिक्वेस्ट अप्रूव करें।",
            "'गलती से' पैसे आए? खुद बैंक ऐप में देखें — लिंक या रिक्वेस्ट से वापस न भेजें।",
        ),
    ),
    "investment": ScamType(
        "investment",
        "Fake stock tips / trading app",
        "नकली शेयर टिप्स / ट्रेडिंग ऐप",
        "KB-INV",
        (
            "No one can guarantee stock returns. Leave the group.",
            "Only use trading apps from the official app store with a registered broker.",
            "If they ask for 'tax' or 'fees' before withdrawal, the money is already gone — stop paying.",
        ),
        (
            "शेयर बाजार में गारंटीड मुनाफा कोई नहीं दे सकता। ग्रुप छोड़ दें।",
            "सिर्फ ऑफिशियल ऐप स्टोर के रजिस्टर्ड ब्रोकर ऐप इस्तेमाल करें।",
            "पैसे निकालने से पहले 'टैक्स' या 'फीस' मांगें तो और पैसा न दें।",
        ),
    ),
    "task_job": ScamType(
        "task_job",
        "Part-time task / fake job",
        "पार्ट-टाइम टास्क / नकली नौकरी",
        "KB-JOB",
        (
            "Real employers never ask you to pay to work.",
            "Don't make 'prepaid task' deposits — and don't pay more to recover losses.",
        ),
        (
            "असली कंपनी काम देने के लिए पैसे नहीं मांगती।",
            "'प्रीपेड टास्क' के लिए पैसे न डालें — नुकसान वापस पाने के लिए और पैसा न दें।",
        ),
    ),
    "malicious_app": ScamType(
        "malicious_app",
        "Malicious app (.apk) / screen sharing",
        "खतरनाक ऐप (.apk) / स्क्रीन शेयरिंग",
        "KB-APK",
        (
            "Don't open or install the file/link. Apps only from the official app store.",
            "Never install AnyDesk/TeamViewer or share your screen for a stranger.",
            "Already installed? Turn on airplane mode, uninstall it, and call your bank.",
        ),
        (
            "फाइल/लिंक न खोलें। ऐप सिर्फ ऑफिशियल ऐप स्टोर से।",
            "किसी अनजान के कहने पर AnyDesk/TeamViewer न डालें, स्क्रीन शेयर न करें।",
            "इंस्टॉल कर लिया? एयरप्लेन मोड चालू करें, ऐप हटाएं, बैंक को कॉल करें।",
        ),
    ),
    "kyc_phishing": ScamType(
        "kyc_phishing",
        "KYC / account block / OTP phishing",
        "KYC / अकाउंट ब्लॉक / OTP ठगी",
        "KB-KYC",
        (
            "Banks never ask for OTP, PIN, CVV or passwords.",
            "Don't click the link — open your bank's official app or website yourself.",
        ),
        (
            "बैंक कभी OTP, पिन, CVV या पासवर्ड नहीं मांगता।",
            "लिंक न खोलें — खुद अपने बैंक का ऑफिशियल ऐप या वेबसाइट खोलें।",
        ),
    ),
    "utility_bill": ScamType(
        "utility_bill",
        "Electricity bill disconnection",
        "बिजली बिल / कनेक्शन कटने की धमकी",
        "KB-ELEC",
        (
            "Check your bill only on your electricity company's official app, website or toll-free number.",
            "Don't call or WhatsApp the 'officer' number in the message.",
        ),
        (
            "बिल सिर्फ बिजली कंपनी के ऑफिशियल ऐप, वेबसाइट या टोल-फ्री नंबर पर चेक करें।",
            "मैसेज में दिए 'ऑफिसर' के नंबर पर कॉल/व्हाट्सऐप न करें।",
        ),
    ),
    "lottery_prize": ScamType(
        "lottery_prize",
        "Lottery / prize / KBC",
        "लॉटरी / इनाम / KBC",
        "KB-MISC",
        ("You can't win a lottery you never entered. Never pay a fee or tax to receive a prize.",),
        ("जिस लॉटरी में हिस्सा नहीं लिया, वो नहीं जीत सकते। इनाम के लिए कभी फीस या टैक्स न भरें।",),
    ),
    "loan_app": ScamType(
        "loan_app",
        "Instant loan / fake lender",
        "इंस्टेंट लोन / नकली लोन ऐप",
        "KB-MISC",
        (
            "Never pay a processing fee upfront to an unknown lender.",
            "Borrow only from RBI-regulated banks/NBFCs and their official apps.",
        ),
        (
            "अनजान लोन देने वाले को पहले कोई प्रोसेसिंग फीस न दें।",
            "सिर्फ RBI-रेगुलेटेड बैंक/NBFC और उनके ऑफिशियल ऐप से लोन लें।",
        ),
    ),
    "impersonation": ScamType(
        "impersonation",
        "Friend / family impersonation",
        "दोस्त / रिश्तेदार बनकर ठगी",
        "KB-MISC",
        (
            "Call the person back on their OLD saved number before sending anything.",
            "Voices can be cloned with AI — a familiar voice is not proof.",
        ),
        (
            "पैसे भेजने से पहले उनके पुराने सेव नंबर पर कॉल करके पक्का करें।",
            "AI से आवाज़ की नकल हो सकती है — जानी-पहचानी आवाज़ सबूत नहीं है।",
        ),
    ),
}

NONE_KEY = "none"


def get(key: str) -> ScamType | None:
    return TYPES.get(key)


def all_keys() -> list[str]:
    return list(TYPES.keys())
