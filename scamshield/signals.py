"""Rule-based red-flag detection in English, Hinglish and Hindi (Devanagari).

Each rule returns the exact text that triggered it, so the UI can highlight it
and the user can see *why* something was flagged. Rules encode the red flags
listed in official advisories (see knowledge_base/).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

F = re.IGNORECASE | re.UNICODE


@dataclass(frozen=True)
class Rule:
    id: str
    scam_type: str | None  # None = generic manipulation tactic
    weight: float          # contribution to risk (0..1), combined with noisy-OR
    pattern: re.Pattern
    why_en: str
    why_hi: str


@dataclass
class Hit:
    rule_id: str
    scam_type: str | None
    weight: float
    evidence: str
    start: int
    end: int
    why_en: str
    why_hi: str


def _r(id, scam_type, weight, pattern, why_en, why_hi):
    return Rule(id, scam_type, weight, re.compile(pattern, F), why_en, why_hi)


RULES: list[Rule] = [
    # ---------- generic pressure tactics ----------
    _r("urgency", None, 0.15,
       r"\b(immediately|urgent(ly)?|within \d+ ?(hours?|hrs?|minutes?|mins?)|today itself|last (chance|warning|reminder)|"
       r"turant|jaldi( se)?|abhi ke abhi|before (tonight|midnight|9:?30))\b|तुरंत|अभी|जल्दी",
       "Creates panic with a deadline so you act before thinking",
       "जल्दबाज़ी का दबाव — ताकि आप सोचे बिना कदम उठाएं"),
    _r("secrecy", None, 0.35,
       r"(don'?t|do not|never) (tell|inform|share this with) (anyone|anybody|your family|family)|keep (this|it) (confidential|secret)|"
       r"kisi ko (bhi )?(mat|na) batana|किसी को (भी )?(मत|न) बताना|गोपनीय रखें",
       "Asks you to keep it secret — scammers isolate victims from family",
       "राज़ रखने को कहा — ठग आपको परिवार से अलग रखते हैं"),
    _r("credential_request", None, 0.6,
       r"\b(share|send|tell|give|provide|forward|read out|batao|bata do|bhejo)\b[^.\n]{0,30}\b(otp|cvv|upi ?pin|atm ?pin|m-?pin|password|card (number|details))\b|"
       r"\b(otp|cvv|upi ?pin|atm ?pin|password)\b[^.\n]{0,25}\b(share|send|tell|batao|bata do|bhejo|bhej do)\b|"
       r"(ओटीपी|OTP|पिन)[^।\n]{0,20}(बताएं|बताओ|भेजें|भेजो|शेयर)",
       "Asks for OTP / PIN / CVV / password — no bank or official ever needs these",
       "OTP / पिन / CVV / पासवर्ड मांगा — कोई बैंक या अधिकारी कभी नहीं मांगता"),
    _r("threat", None, 0.25,
       r"\b(arrest(ed)?|warrant|fir (has been|will be|is) (registered|filed|lodged)|legal action|case (has been |is )?(registered|filed)|"
       r"jail|police complaint|giraftar|giraftaar)\b|गिरफ्तार|गिरफ़्तार|कानूनी कार्रवाई|जेल",
       "Threatens arrest or legal action to scare you",
       "गिरफ्तारी या कानूनी कार्रवाई की धमकी"),
    _r("pay_to_unlock", None, 0.3,
       r"\b(processing|registration|joining|clearance|verification|security|activation|refundable|withdrawal|release)\s+(fee|fees|charges?|deposit|amount|tax)\b|"
       r"\b(pay|deposit|transfer)\b[^.\n]{0,40}\b(to (receive|claim|withdraw|release|unlock|activate|get))\b|"
       r"फीस|शुल्क",
       "Asks you to pay first to receive money / a prize / a job",
       "पहले पैसे देने को कहा ताकि कुछ 'मिल' सके"),
    _r("channel_switch", None, 0.15,
       r"\b(contact|message|join|ping|dm)\b[^.\n]{0,20}\b(on )?(telegram|whats ?app)\b|t\.me/|wa\.me/|chat\.whatsapp\.com",
       "Moves you to Telegram/WhatsApp, away from official channels",
       "आपको टेलीग्राम/व्हाट्सऐप पर ले जा रहा है"),

    # ---------- digital arrest / fake law enforcement ----------
    _r("da_agency", "digital_arrest", 0.25,
       r"\b(cbi|ncb|enforcement directorate|narcotics|customs (department|officer)|cyber ?(cell|crime) (officer|department|branch)|"
       r"crime branch|(mumbai|delhi|bangalore|bengaluru|hyderabad) police|police station|ips officer|supreme court|high court judge|rbi officer)\b|"
       r"सीबीआई|पुलिस|नारकोटिक्स|कस्टम",
       "Claims to be police / CBI / customs / court",
       "खुद को पुलिस / CBI / कस्टम / कोर्ट बताया"),
    _r("da_crime", "digital_arrest", 0.45,
       r"\bdigital(ly)? arrest|money laundering|drug(s)? (trafficking|found|seized)|parcel[^.\n]{0,60}(drugs|seized|illegal|passports?|mdma|contraband)|"
       r"(aadhaar|aadhar|sim)[^.\n]{0,40}(misused|used in|linked to (a )?(crime|case|money laundering))|human trafficking|"
       r"डिजिटल अरेस्ट|मनी लॉन्ड्रिंग|ड्रग्स",
       "Says you or your parcel/Aadhaar is linked to a crime — the classic 'digital arrest' opener",
       "कहा कि आपका पार्सल/आधार किसी अपराध से जुड़ा है — 'डिजिटल अरेस्ट' की शुरुआत"),
    _r("da_videocall", "digital_arrest", 0.4,
       r"\b(stay|remain|be) on (the )?(video )?call|keep (your )?camera on|skype|video (call )?(statement|interrogation|verification)|"
       r"(join|come on) (a )?video call|वीडियो कॉल",
       "Asks you to stay on video call / Skype — real agencies never do this",
       "वीडियो कॉल पर बने रहने को कहा — असली एजेंसियां ऐसा नहीं करतीं"),
    _r("da_safe_account", "digital_arrest", 0.5,
       r"(safe|secure|verification|rbi|supervisory|escrow) account|transfer[^.\n]{0,40}for (verification|investigation)|"
       r"(verify|clear|check) your (funds|money|savings)",
       "Asks you to move money to a 'safe/verification account'",
       "पैसे 'सेफ/वेरिफिकेशन अकाउंट' में भेजने को कहा"),

    # ---------- TRAI / telecom ----------
    _r("trai", "trai_telecom", 0.35,
       r"\b(trai|telecom regulatory|department of telecom(munications)?|dot officer)\b|ट्राई|दूरसंचार",
       "Claims to be from TRAI / Department of Telecom",
       "खुद को TRAI / दूरसंचार विभाग बताया"),
    _r("sim_block", "trai_telecom", 0.4,
       r"\b(sim|mobile number|your number|phone number|sim card)\b[^.\n]{0,30}\b(will be|is being|has been|shall be)\b[^.\n]{0,15}"
       r"\b(blocked|disconnected|suspended|deactivated|barred|band)\b|press \d to (speak|talk|connect)|"
       r"(नंबर|सिम)[^।\n]{0,25}(बंद|ब्लॉक)",
       "Says your SIM/number will be blocked — TRAI never calls about this",
       "कहा कि आपका सिम/नंबर बंद होगा — TRAI ऐसा कॉल नहीं करता"),
    _r("tower", "trai_telecom", 0.35,
       r"mobile tower (installation|lagwaye|lagwane)|tower (rent|installation)[^.\n]{0,40}(fee|charges|registration)",
       "Mobile-tower installation offer with a fee",
       "मोबाइल टावर लगवाने का ऑफर, फीस के साथ"),

    # ---------- UPI / QR ----------
    _r("pin_to_receive", "upi_collect_qr", 0.75,
       r"(enter|put|type|daalo|dalo|dal do)[^.\n]{0,20}(upi )?pin[^.\n]{0,30}(receive|get|credit|accept|refund|milenge|aa jayenge)|"
       r"(receive|get|accept)[^.\n]{0,30}(enter|put)[^.\n]{0,10}(your )?(upi )?pin|पिन (डालें|डालो)[^।\n]{0,20}(पैसे|रिफंड)",
       "Says you must enter your UPI PIN to RECEIVE money — PIN is only for sending",
       "पैसे 'पाने' के लिए पिन डालने को कहा — पिन सिर्फ भेजने के लिए है"),
    _r("qr_to_receive", "upi_collect_qr", 0.6,
       r"scan[^.\n]{0,30}(qr|code)[^.\n]{0,40}(receive|get|refund|credited|payment will)|"
       r"(qr|code)[^.\n]{0,20}scan karo[^.\n]{0,20}(paise|payment|refund)",
       "Asks you to scan a QR code to receive money — QR codes are only for paying",
       "पैसे पाने के लिए QR स्कैन करने को कहा — QR सिर्फ भुगतान के लिए है"),
    _r("collect_request", "upi_collect_qr", 0.45,
       r"\b(collect|payment|money) request\b[^.\n]{0,40}\b(accept|approve|confirm|receive)\b|\b(accept|approve)\b[^.\n]{0,30}\b(collect|payment) request\b",
       "Asks you to approve a UPI request — person-to-person collect requests were discontinued by NPCI in Oct 2025",
       "UPI रिक्वेस्ट अप्रूव करने को कहा — NPCI ने अक्टूबर 2025 से व्यक्ति-से-व्यक्ति कलेक्ट रिक्वेस्ट बंद कर दी है"),
    _r("mistake_credit", "upi_collect_qr", 0.45,
       r"(sent|transferred|credited|paid)[^.\n]{0,40}(by mistake|wrongly|galti se)|(wrong(ly)?|mistaken) (transfer|payment|transaction)|"
       r"(return|refund|send back|wapas)[^.\n]{0,25}(extra|the money|amount|paise)|गलती से",
       "Claims money was sent 'by mistake' and asks you to return it",
       "'गलती से' पैसे भेजने का दावा और वापस मांगना"),
    _r("army_buyer", "upi_collect_qr", 0.35,
       r"\b(army|defen[cs]e|crpf|bsf|cisf|military)\b[^\n]{0,80}\b(buy|purchase|sell|rent|olx|furniture|bike|sofa|car|scooter|flat)\b|"
       r"\b(buy|purchase|sell|rent|olx|furniture|bike|sofa|scooter)\b[^\n]{0,80}\b(army|defen[cs]e|crpf|bsf|cisf|military)\b",
       "Buyer/seller claiming to be army/defence — a known marketplace scam script",
       "खुद को फौजी बताने वाला खरीदार/विक्रेता — जाना-पहचाना ठगी तरीका"),

    # ---------- investment ----------
    _r("guaranteed_returns", "investment", 0.55,
       r"guarantee(d)? (returns?|profits?|income)|\b\d{1,3}\s?% (daily|per day|weekly|monthly|in \d+ days)|double your money|"
       r"(daily|assured|fixed) (profit|returns)|risk[- ]free (returns|profit|investment)|पक्का मुनाफा|गारंटी",
       "Promises guaranteed / unrealistic returns",
       "पक्के / बहुत ज़्यादा मुनाफे का वादा"),
    _r("stock_group", "investment", 0.4,
       r"\b(vip|premium|exclusive)\b[^.\n]{0,20}\b(group|tips|stock|calls|signals)\b|stock (market )?tips|ipo (allotment|quota)|institutional (account|quota)|"
       r"(trading|investment) (app|platform)[^.\n]{0,40}(download|link|install|register)|block trade|insider (tips|info)",
       "Stock-tip group / unofficial trading app",
       "शेयर टिप्स ग्रुप / अनऑफिशियल ट्रेडिंग ऐप"),
    _r("crypto", "investment", 0.3,
       r"\b(crypto|usdt|bitcoin|btc|forex)\b[^.\n]{0,40}\b(profit|returns|earn|invest|trading)\b",
       "Crypto / forex profit pitch",
       "क्रिप्टो / फॉरेक्स मुनाफे का लालच"),

    # ---------- task / job ----------
    _r("task_job", "task_job", 0.45,
       r"part[- ]?time (job|work|income)|work from home[^.\n]{0,40}(earn|income|₹|rs)|like (youtube )?videos|"
       r"(rate|review) (hotels?|products?|restaurants?)|prepaid task|merchant task|simple (online )?tasks?|"
       r"earn[^.\n]{0,15}(₹|rs\.?|inr)\s?\d[\d,]*[^.\n]{0,20}(per day|daily|a day|/day|per task)|ghar baithe|घर बैठे",
       "Easy online task / part-time job paying daily — the 'task scam' pattern",
       "आसान ऑनलाइन टास्क / पार्ट-टाइम जॉब — 'टास्क स्कैम' का तरीका"),
    _r("hr_contact", "task_job", 0.2,
       r"\b(hr|hiring) (manager|team|department)\b[^.\n]{0,40}(whats ?app|telegram|contact)|"
       r"(you have been|you are) (selected|shortlisted)[^.\n]{0,40}(part[- ]time|online|whatsapp|telegram)",
       "Unsolicited 'HR' offer over WhatsApp/Telegram",
       "व्हाट्सऐप/टेलीग्राम पर बिन मांगा 'HR' ऑफर"),

    # ---------- malicious apps / remote access ----------
    _r("apk", "malicious_app", 0.7,
       r"\.apk\b|install[^.\n]{0,30}(this|the|our|below) (app|application)|download[^.\n]{0,25}app[^.\n]{0,20}(link|below|from here)",
       "Asks you to install an app or .apk file from a link",
       "लिंक से ऐप या .apk फाइल इंस्टॉल करने को कहा"),
    _r("remote_access", "malicious_app", 0.6,
       r"\b(any ?desk|team ?viewer|quick ?support|rust ?desk|airdroid|screen ?shar(e|ing)|share (your )?screen)\b",
       "Asks you to install a screen-sharing / remote-access app",
       "स्क्रीन शेयरिंग / रिमोट ऐक्सेस ऐप डालने को कहा"),
    _r("challan_scheme", "malicious_app", 0.3,
       r"(rto|traffic|e-?challan|challan)[^.\n]{0,50}(pay|download|link|apk|click)|pm[- ]?kisan[^.\n]{0,40}(app|apk|link|update)|"
       r"wedding (invitation|card)[^.\n]{0,30}(download|apk|open)",
       "Traffic-challan / scheme / invitation message with a link — common app-malware bait",
       "चालान / सरकारी योजना / शादी कार्ड के नाम पर लिंक — मालवेयर का चारा"),

    # ---------- KYC / phishing ----------
    _r("account_block", "kyc_phishing", 0.4,
       r"\b(account|a/c|card|net ?banking|wallet|yono|pan)\b[^.\n]{0,30}\b(will be|has been|is|shall be|gets?)\b[^.\n]{0,15}"
       r"\b(blocked|suspended|frozen|freezed|deactivated|closed|disabled|band)\b|(खाता|अकाउंट)[^।\n]{0,25}(बंद|ब्लॉक)",
       "Threatens to block your account / card",
       "अकाउंट / कार्ड बंद करने की धमकी"),
    _r("kyc_update", "kyc_phishing", 0.35,
       r"\b(update|complete|verify|link)\b[^.\n]{0,20}\b(kyc|e-?kyc|pan|aadhaar|aadhar)\b|\bkyc\b[^.\n]{0,30}(pending|expired|incomplete|update)|"
       r"reward points?[^.\n]{0,40}(expir|redeem)",
       "Asks you to update KYC / PAN / redeem points via a message",
       "मैसेज से KYC / PAN अपडेट करने या पॉइंट्स रिडीम करने को कहा"),
    _r("customer_care", "kyc_phishing", 0.2,
       r"(customer care|helpline|support) (number|executive|agent)[^.\n]{0,30}(call|contact|whatsapp)|refund (agent|department|process)",
       "Unofficial 'customer care' / refund agent",
       "अनऑफिशियल 'कस्टमर केयर' / रिफंड एजेंट"),

    # ---------- electricity ----------
    _r("power_cut", "utility_bill", 0.6,
       r"(electricity|power|light|bijli|connection)[^.\n]{0,40}(will be |shall be )?(disconnect|cut|kat jayegi|band)|"
       r"(previous|last) month('?s)? bill[^.\n]{0,30}(not|was not) (updated|paid)|electricity (officer|department)|बिजली[^।\n]{0,30}(कट|बंद)",
       "Electricity disconnection threat asking you to contact an 'officer'",
       "बिजली कटने की धमकी और 'ऑफिसर' से संपर्क करने को कहा"),

    # ---------- lottery ----------
    _r("lottery", "lottery_prize", 0.55,
       r"\b(lottery|lucky draw|jackpot|kbc|kaun banega crorepati|prize money|bumper prize)\b|"
       r"(you('ve| have)?|your (number|mobile|email|sim)( has)?) won\b[^.\n]{0,40}(rs\.?|₹|inr|lakh|crore|usd|\$|cash|car|iphone|bike|prize|reward|draw|gift)|"
       r"(claim|collect) your (prize|reward|gift)|लॉटरी|इनाम|आपने जीता",
       "Says you won a lottery / prize",
       "लॉटरी / इनाम जीतने का दावा"),

    # ---------- loan ----------
    _r("instant_loan", "loan_app", 0.45,
       r"(instant|pre-?approved|guaranteed) (personal )?loan|loan[^.\n]{0,20}(approved|sanctioned)[^.\n]{0,40}(fee|charges|pay|link|app)|"
       r"(without|no|low) cibil|loan[^.\n]{0,30}processing (fee|charges)|बिना सिबिल",
       "Instant / no-CIBIL loan with upfront fees",
       "बिना सिबिल / इंस्टेंट लोन, पहले फीस"),

    # ---------- impersonation ----------
    _r("new_number", "impersonation", 0.45,
       r"(this is my new number|my (old )?(number|phone) (is )?(lost|changed|broken|not working)|naya number|new number[^.\n]{0,20}save)|"
       r"\b(hi|hello) (mum|mom|mummy|dad|papa|mama|beta|didi|bhaiya)\b[^.\n]{0,60}(new|naya) number",
       "Claims to be a known person on a 'new number'",
       "'नए नंबर' से जान-पहचान वाला बनने का दावा"),
    _r("emergency_money", "impersonation", 0.4,
       r"(in (the )?hospital|accident|stuck at|stranded|in trouble|emergency)[^.\n]{0,60}(send|transfer|need|bhej)[^.\n]{0,20}(money|₹|rs|paise|amount)|"
       r"(urgently|asap) need (money|₹|rs)|paise bhej(o|do)[^.\n]{0,30}(urgent|jaldi|abhi)",
       "Emergency story with an urgent money request",
       "इमरजेंसी की कहानी और तुरंत पैसे की मांग"),
]

# Patterns that look like a genuine bank/app-generated message. They lower risk
# only when no high-risk rule fired (a scammer quoting an OTP SMS still gets caught).
BENIGN = [
    re.compile(r"\bis (your|the) (otp|one time password|verification code)\b[^.\n]{0,80}(do not|don'?t|never) share", F),
    re.compile(r"(do not|don'?t|never) share (this |your )?(otp|code|pin)[^.\n]{0,40}(with anyone|bank never)", F),
    re.compile(r"\b(debited|credited) (from|to|with)?[^.\n]{0,40}(a/c|account|ac)\s?(no\.?)?\s?[x*]+\d{3,4}", F),
    re.compile(r"\bnot you\?[^.\n]{0,40}(call|sms|report)", F),
    # public-awareness messages from banks / police / regulators
    re.compile(r"(\btip\b|be aware|beware of|stay (safe|alert)|awareness|cyber dost)[^\n]{0,120}", F),
    re.compile(r"(report (fraud|it|cyber ?crime)[^.\n]{0,30}(1930|cybercrime\.gov\.in))|(never|don'?t|do not) (ask|asks) for (your )?(otp|pin|password)", F),
]


# A match preceded by one of these is advice, not a request ("never share your OTP").
NEGATION = re.compile(
    r"(\bnever|\bdo not|\bdon'?t|\bnot|\bno one|\bnobody|\bmat|\bna|\bnahi|\bnahin|\bkabhi|कभी|मत|नहीं)\W*(\w+\W+){0,3}$", F
)
NEGATABLE = {"credential_request", "remote_access", "apk", "pin_to_receive", "qr_to_receive", "secrecy"}

# "Context" rules only say who/what is being talked about. On their own they
# are not evidence of a scam (a real police awareness SMS mentions the police).
CONTEXT_ONLY = {"da_agency", "trai", "urgency", "channel_switch", "hr_contact", "customer_care", "threat"}


def _negated(text: str, start: int) -> bool:
    return bool(NEGATION.search(text[max(0, start - 30):start]))


def find_hits(text: str) -> list[Hit]:
    hits: list[Hit] = []
    for rule in RULES:
        for m in rule.pattern.finditer(text):
            if rule.id in NEGATABLE and _negated(text, m.start()):
                continue
            hits.append(
                Hit(rule.id, rule.scam_type, rule.weight, m.group(0).strip(), m.start(), m.end(), rule.why_en, rule.why_hi)
            )
            break
    return hits


def benign_score(text: str) -> int:
    return sum(1 for p in BENIGN if p.search(text))


def has_strong_evidence(hits: list[Hit]) -> bool:
    return any(h.rule_id not in CONTEXT_ONLY for h in hits)
