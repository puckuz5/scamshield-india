"""Extract URLs, UPI IDs and phone numbers, and score how risky each link looks.

No network calls: everything here is static analysis, so it works offline and
never "clicks" a scammer's link.
"""

from __future__ import annotations

import difflib
import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

URL_RE = re.compile(
    r"""(?xi)
    \b(
      (?:https?://|www\.)[^\s<>"'()]+            # explicit scheme or www.
      |
      (?:[a-z0-9-]+\.)+(?:[a-z]{2,24})(?:/[^\s<>"'()]*)  # bare domain followed by a path
      |
      (?:[a-z0-9-]+\.)+(?:com|in|net|org|xyz|top|info|link|live|online|site|shop|click|icu|vip|cc|me|io|co)\b
    )
    """
)
UPI_RE = re.compile(r"(?<![\w.@-])([a-zA-Z0-9][\w.\-]{1,255}@[a-zA-Z]{2,64})(?![\w.@])")
PHONE_RE = re.compile(r"(?<!\d)(\+?\d[\d\s\-]{8,15}\d)(?!\d)")

SHORTENERS = {
    "bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "rb.gy", "t.ly", "shorturl.at", "rebrand.ly",
    "tiny.cc", "s.id", "goo.su", "ow.ly", "t.co", "shorturl.asia", "u.to", "v.gd", "qr.ae",
    "surl.li", "clck.ru", "linktr.ee", "wa.link",
}
RISKY_TLDS = {
    "xyz", "top", "click", "icu", "buzz", "shop", "live", "online", "site", "info", "cc", "vip",
    "work", "life", "cfd", "sbs", "rest", "lol", "monster", "quest", "cyou", "bond", "pw", "tk",
    "ml", "ga", "cf", "gq", "zip", "mov", "support", "help",
}
# Restricted Indian registries: only government bodies / banks can register these.
TRUSTED_SUFFIXES = ("gov.in", "nic.in", "bank.in")
TWO_LEVEL_SUFFIXES = {
    "co.in", "gov.in", "nic.in", "org.in", "net.in", "ac.in", "bank.in", "res.in", "edu.in",
    "firm.in", "gen.in", "ind.in", "co.uk", "org.uk", "com.au",
}

# brand keyword -> official registered domains
BRANDS: dict[str, set[str]] = {
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "sbicard.com", "sbi"},
    "hdfc": {"hdfcbank.com", "hdfc.bank.in", "hdfc.com", "hdfclife.com"},
    "icici": {"icicibank.com", "icici.bank.in", "icicidirect.com"},
    "axis": {"axisbank.com", "axis.bank.in"},
    "kotak": {"kotak.com", "kotak.bank.in"},
    "paytm": {"paytm.com", "paytm.in"},
    "phonepe": {"phonepe.com"},
    "googlepay": {"google.com"},
    "npci": {"npci.org.in"},
    "bhim": {"bhimupi.org.in", "npci.org.in"},
    "indiapost": {"indiapost.gov.in"},
    "fedex": {"fedex.com"},
    "dhl": {"dhl.com", "dhl.co.in"},
    "bluedart": {"bluedart.com"},
    "delhivery": {"delhivery.com"},
    "amazon": {"amazon.in", "amazon.com", "amazonpay.in"},
    "flipkart": {"flipkart.com"},
    "airtel": {"airtel.in", "airtel.com"},
    "jio": {"jio.com"},
    "uidai": {"uidai.gov.in"},
    "aadhaar": {"uidai.gov.in"},
    "incometax": {"incometax.gov.in"},
    "epfo": {"epfindia.gov.in"},
    "parivahan": {"parivahan.gov.in"},
    "echallan": {"parivahan.gov.in"},
    "pmkisan": {"pmkisan.gov.in"},
    "irctc": {"irctc.co.in"},
    "tatapower": {"tatapower.com", "tatapower-ddl.com"},
    "bses": {"bsesdelhi.com"},
    "trai": {"trai.gov.in"},
    "cybercrime": {"cybercrime.gov.in"},
}


@dataclass
class LinkReport:
    url: str
    domain: str
    risk: float  # 0..1
    reasons: list[str] = field(default_factory=list)


def _registered_domain(host: str) -> str:
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _label(registered: str) -> str:
    """The brand-ish part of a registered domain: 'hdfcbank' from 'hdfcbank.com'."""
    return registered.split(".")[0]


def _is_trusted(host: str) -> bool:
    return any(host == s or host.endswith("." + s) for s in TRUSTED_SUFFIXES)


def _official_for(registered: str) -> set[str]:
    hits = set()
    for brand, domains in BRANDS.items():
        if registered in domains:
            hits.add(brand)
    return hits


def analyze_url(raw: str) -> LinkReport:
    url = raw.rstrip(".,;:!?)]}")
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = (parsed.hostname or "").lower()
    path = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
    reasons: list[str] = []
    risk = 0.0

    if not host:
        return LinkReport(url, "", 0.0, [])

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
        risk += 0.6
        reasons.append("link goes to a raw IP address instead of a website name")
    except ValueError:
        pass

    registered = host if is_ip else _registered_domain(host)
    tld = "" if is_ip else host.rsplit(".", 1)[-1]

    if path.lower().split("?")[0].endswith(".apk") or ".apk" in path.lower():
        risk += 0.9
        reasons.append("link downloads an Android app file (.apk) from outside the app store")

    if registered in SHORTENERS or host in SHORTENERS:
        risk += 0.4
        reasons.append(f"shortened link ({registered}) hides the real destination")

    if host.startswith("xn--") or ".xn--" in host:
        risk += 0.5
        reasons.append("domain uses look-alike (punycode) characters")

    if tld in RISKY_TLDS:
        risk += 0.35
        reasons.append(f"cheap top-level domain often used in scams (.{tld})")

    trusted = _is_trusted(host)
    if not is_ip and not trusted and not _official_for(registered):
        hay = re.sub(r"[^a-z0-9]", "", host)
        label = _label(registered)
        for brand, domains in BRANDS.items():
            if brand in hay:
                risk += 0.6
                reasons.append(
                    f"mentions '{brand}' but is not its official site ({', '.join(sorted(domains)[:2])})"
                )
                break
            official_labels = {_label(d) for d in domains}
            for ol in official_labels:
                if len(ol) >= 5 and label != ol and difflib.SequenceMatcher(None, label, ol).ratio() >= 0.85:
                    risk += 0.6
                    reasons.append(f"'{registered}' looks like a misspelling of {ol}")
                    break

    if host.count("-") >= 2 or sum(c.isdigit() for c in _label(registered)) >= 3:
        risk += 0.15
        reasons.append("unusual domain name (many hyphens/digits)")

    if parsed.scheme == "http" and "://" in url:
        risk += 0.1
        reasons.append("not using HTTPS")

    if trusted:
        risk = min(risk, 0.1)
        reasons = [r for r in reasons if "apk" in r] or ["official Indian government/bank domain"]

    return LinkReport(url, registered, min(risk, 1.0), reasons)


def extract_urls(text: str) -> list[str]:
    found = []
    for m in URL_RE.finditer(text):
        u = m.group(1)
        start = m.start(1)
        if "@" in u or (start > 0 and text[start - 1] in "@."):  # part of an email or UPI ID
            continue
        if u not in found:
            found.append(u)
    return found


def extract_upi_ids(text: str) -> list[str]:
    out = []
    for m in UPI_RE.finditer(text):
        handle = m.group(1)
        if "." in handle.split("@", 1)[1]:  # an email address, not a UPI ID
            continue
        if handle not in out:
            out.append(handle)
    return out


def extract_phones(text: str) -> list[dict]:
    out = []
    for m in PHONE_RE.finditer(text):
        raw = m.group(1)
        digits = re.sub(r"\D", "", raw)
        if len(digits) < 10 or len(digits) > 13:
            continue
        foreign = raw.strip().startswith("+") and not digits.startswith("91")
        out.append({"number": raw.strip(), "foreign": foreign})
    return out


def analyze_links(text: str) -> list[LinkReport]:
    return [analyze_url(u) for u in extract_urls(text)]
