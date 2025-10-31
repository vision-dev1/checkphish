import re
import math
from typing import List, Dict, Tuple

import requests
from bs4 import BeautifulSoup
import tldextract

# Small, illustrative blacklist of known phishing domains. Extend as needed.
KNOWN_PHISHING_DOMAINS = {
    "login-secure-account.com",
    "paypal-security-alert.net",
    "microsoftverify-support.com",
    "apple-id-recovery.net",
    "secure-verify-billing.xyz",
}

# Commonly abused or inexpensive TLDs. This is a heuristic, not a judgment.
UNCOMMON_SUSPICIOUS_TLDS = {
    "zip", "xyz", "top", "club", "gq", "tk", "ml", "cf", "casa", "rest", "click", "work",
}

# Very small set of popular brands for typo-heuristics. Not exhaustive.
BRANDS = [
    "google", "apple", "microsoft", "paypal", "facebook", "amazon", "bank", "outlook", "office",
]

PHISHING_KEYWORDS = [
    "verify your account", "password expired", "unusual activity", "update payment", "urgent",
    "security alert", "confirm your identity", "suspended", "click the link", "limited time",
]

USER_AGENT = {
    "User-Agent": "PhishingAwarenessTool/1.0 (+https://example.com)"
}


def _extract_domain_parts(url: str) -> Tuple[str, str, str]:
    """Return (subdomain, domain, suffix) using tldextract."""
    extracted = tldextract.extract(url)
    return extracted.subdomain, extracted.domain, extracted.suffix


def _is_https(url: str) -> bool:
    return url.strip().lower().startswith("https://")


def _is_uncommon_tld(suffix: str) -> bool:
    return suffix.lower() in UNCOMMON_SUSPICIOUS_TLDS


def _looks_random_label(label: str) -> bool:
    """Heuristic: very long, lots of digits, low vowel ratio suggest randomness."""
    s = re.sub(r"[^a-z0-9]", "", label.lower())
    if len(s) >= 24:
        return True
    digits = sum(c.isdigit() for c in s)
    if len(s) >= 12 and digits / max(1, len(s)) > 0.35:
        return True
    vowels = sum(c in "aeiou" for c in s)
    if len(s) >= 10 and vowels / max(1, len(s)) < 0.2:
        return True
    if "xn--" in label:  # punycode
        return True
    return False


def _has_brand_typos(domain: str) -> bool:
    """Naive heuristic: domain contains brand name with extra/prefix/suffix tokens."""
    d = domain.lower()
    for b in BRANDS:
        if b in d and not d.startswith(b) and not d.endswith(b):
            return True
        if d.startswith(b) and len(d) > len(b) + 3:
            return True
        if d.endswith(b) and len(d) > len(b) + 3:
            return True
    return False


def _domain_label(domain: str) -> str:
    return domain.split(".")[0]


def _path_looks_suspicious(url: str) -> bool:
    path_q = re.sub(r"^[a-z]+://[^/]+", "", url, flags=re.I)
    if len(path_q) > 60:
        return True
    if re.search(r"(login|verify|secure|update|invoice|payment)", path_q, flags=re.I):
        return True
    return False


def _check_blacklist(domain_full: str) -> bool:
    return domain_full.lower() in KNOWN_PHISHING_DOMAINS


def _try_head(url: str) -> Tuple[bool, str]:
    """Try a HEAD request to see if reachable. Return (ok, reason)."""
    try:
        r = requests.head(url, timeout=4, allow_redirects=True, headers=USER_AGENT)
        if 200 <= r.status_code < 400:
            return True, f"reachable (status {r.status_code})"
        return False, f"unusual status {r.status_code}"
    except requests.RequestException as e:
        return False, f"request error: {type(e).__name__}"


def analyze_url(url: str) -> Dict:
    """Analyze a URL and return a dict with verdict and reasons."""
    reasons: List[str] = []
    verdict = "Safe"

    sub, dom, suf = _extract_domain_parts(url)
    registrable = f"{dom}.{suf}" if suf else dom
    full_host = registrable if not sub else f"{sub}.{registrable}"

    if not _is_https(url):
        reasons.append("URL does not use HTTPS")
    else:
        reasons.append("HTTPS detected")

    if _is_uncommon_tld(suf):
        reasons.append(f"Uncommon/abused TLD: .{suf}")

    if _looks_random_label(dom) or (sub and _looks_random_label(sub.split(".")[-1])):
        reasons.append("Domain label looks random or punycoded")

    if _has_brand_typos(dom):
        reasons.append("Brand-like domain with extra tokens (possible typosquatting)")

    if _path_looks_suspicious(url):
        reasons.append("Suspicious path or query indicates login/verify/payment")

    if _check_blacklist(full_host):
        reasons.append("Domain found in known phishing list")

    ok, network_note = _try_head(url)
    reasons.append(f"Network check: {network_note}")

    danger_signals = [
        any(r.startswith("Domain found in known phishing") for r in reasons),
    ]
    suspicious_signals = [
        any(r.startswith("Uncommon/abused TLD") for r in reasons),
        any("random" in r for r in reasons),
        any("typosquatting" in r for r in reasons),
        any(r.startswith("URL does not use HTTPS") for r in reasons),
        any(r.startswith("Suspicious path") for r in reasons),
    ]

    if any(danger_signals):
        verdict = "Dangerous"
    elif sum(1 for s in suspicious_signals if s) >= 1:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return {
        "input": url,
        "host": full_host,
        "registrable_domain": registrable,
        "tld": suf,
        "verdict": verdict,
        "reasons": reasons,
    }


URL_REGEX = re.compile(r"https?://[\w\-.:@%/?#=+&]+", re.I)
EMAIL_REGEX = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)


def _extract_links_from_html(email_text: str) -> List[str]:
    try:
        soup = BeautifulSoup(email_text, "lxml")
    except Exception:
        soup = BeautifulSoup(email_text, "html.parser")
    return [a.get("href") for a in soup.find_all("a", href=True)]


def _extract_links(email_text: str) -> List[str]:
    links = set()
    # From HTML
    links.update(_extract_links_from_html(email_text))
    # From plain text
    links.update(URL_REGEX.findall(email_text))
    return [l for l in links if l]


def _extract_sender(email_text: str) -> str:
    # Look for a From: header first
    m = re.search(r"^From:\s*(.+)$", email_text, flags=re.I | re.M)
    if m:
        sender_field = m.group(1)
        m2 = EMAIL_REGEX.search(sender_field)
        if m2:
            return m2.group(0)
    # Otherwise first email in the text
    m3 = EMAIL_REGEX.search(email_text)
    return m3.group(0) if m3 else ""


def _sender_domain(sender: str) -> str:
    if not sender:
        return ""
    parts = sender.split("@")
    if len(parts) == 2:
        sub, dom, suf = tldextract.extract(parts[1])
        return f"{dom}.{suf}" if suf else dom
    return ""


def _contains_phishing_keywords(text: str) -> List[str]:
    found = []
    lower = text.lower()
    for kw in PHISHING_KEYWORDS:
        if kw in lower:
            found.append(kw)
    return found


def analyze_email(email_text: str) -> Dict:
    reasons: List[str] = []
    verdict = "Safe"

    sender = _extract_sender(email_text)
    sender_dom = _sender_domain(sender)

    links = _extract_links(email_text)
    link_domains = []
    for l in links:
        _, d, s = _extract_domain_parts(l)
        link_domains.append(f"{d}.{s}" if s else d)

    keywords = _contains_phishing_keywords(email_text)
    if keywords:
        reasons.append(f"Phishing keywords present: {', '.join(keywords[:5])}")

    if links:
        reasons.append(f"Found {len(links)} link(s) in email body")

    # Mismatch sender vs link domains
    mismatches = []
    for ld in set(link_domains):
        if sender_dom and ld and ld != sender_dom:
            mismatches.append((sender_dom, ld))
    if mismatches:
        reasons.append(
            "Sender domain differs from link domain(s): "
            + ", ".join(f"{a} -> {b}" for a, b in mismatches[:5])
        )

    # Check link domains against blacklist and suspicious heuristics
    blacklist_hits = []
    suspicious_link_signals = 0
    for l in links:
        res = analyze_url(l)
        if res["verdict"] == "Dangerous":
            blacklist_hits.append(res["host"])
        if res["verdict"] in {"Suspicious", "Dangerous"}:
            suspicious_link_signals += 1
    if blacklist_hits:
        reasons.append("Links include known phishing domain(s): " + ", ".join(set(blacklist_hits)))

    # Decide verdict
    if blacklist_hits:
        verdict = "Dangerous"
    elif mismatches or keywords or suspicious_link_signals >= 1:
        verdict = "Suspicious"

    return {
        "sender": sender,
        "sender_domain": sender_dom,
        "links": links,
        "verdict": verdict,
        "reasons": reasons,
    }
