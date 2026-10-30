
import re
from urllib.parse import urlparse


URGENT_PHRASES = [
    "act immediately",
    "urgent action required",
    "your account will be suspended",
    "account suspended",
    "verify your account",
    "within 24 hours",
    "immediately",
]

SENSITIVE_REQUESTS = [
    "send your password",
    "confirm your password",
    "enter your password",
    "share your password",
    "bank details",
    "credit card details",
    "one-time password",
    "otp code",
]

REWARD_PHRASES = [
    "you have won",
    "claim your prize",
    "free gift",
    "you are the winner",
    "claim your reward",
]


def extract_urls(text):
    """Extract URL-like strings from email text."""
    pattern = r"""https?://[^\s<>"']+|www\.[^\s<>"']+"""
    return re.findall(pattern, text, flags=re.IGNORECASE)


def inspect_url(url):
    """Return warning signs found in a URL."""
    findings = []

    cleaned_url = url.rstrip(".,!?;:)")

    if cleaned_url.lower().startswith("www."):
        cleaned_url = "http://" + cleaned_url

    try:
        parsed = urlparse(cleaned_url)
        host = parsed.hostname or ""

        if parsed.scheme != "https":
            findings.append("Link does not use HTTPS")

        if host and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            findings.append("Link uses an IP address instead of a domain name")

        if "@" in parsed.netloc:
            findings.append("Link contains an @ symbol that may mislead users")

        if host.startswith("xn--") or ".xn--" in host:
            findings.append("Domain uses an internationalised encoding worth checking")

        if len(host) > 50:
            findings.append("Domain name is unusually long")

    except ValueError:
        findings.append("Link could not be parsed reliably")

    return findings


def analyse_email(sender, subject, body):
    """Analyse an email using simple, explainable rules."""
    findings = []
    score = 0

    combined_text = f"{sender}\n{subject}\n{body}".lower()

    for phrase in URGENT_PHRASES:
        if phrase in combined_text:
            findings.append({
                "type": "Urgency",
                "evidence": f"Contains the phrase: '{phrase}'",
                "points": 2,
            })
            score += 2

    for phrase in SENSITIVE_REQUESTS:
        if phrase in combined_text:
            findings.append({
                "type": "Sensitive information",
                "evidence": f"Contains the phrase: '{phrase}'",
                "points": 3,
            })
            score += 3

    for phrase in REWARD_PHRASES:
        if phrase in combined_text:
            findings.append({
                "type": "Unexpected reward",
                "evidence": f"Contains the phrase: '{phrase}'",
                "points": 2,
            })
            score += 2

    urls = extract_urls(body)

    for url in urls:
        for warning in inspect_url(url):
            findings.append({
                "type": "Link warning",
                "evidence": f"{url}: {warning}",
                "points": 2,
            })
            score += 2

    # Cap the final score after all checks.
    score = min(score, 10)

    if not findings:
        verdict = "No obvious warning signs found"
        advice = (
            "The rules did not find known warning patterns. "
            "This does not prove that the email is safe."
        )
    elif score >= 5:
        verdict = "High risk indicators"
        advice = (
            "Do not click links or share sensitive information. "
            "Verify the sender through an independent, trusted channel."
        )
    else:
        verdict = "Suspicious indicators"
        advice = (
            "Be cautious. Verify unexpected requests before taking action."
        )

    return {
        "sender": sender,
        "subject": subject,
        "score": score,
        "verdict": verdict,
        "findings": findings,
        "urls": urls,
        "advice": advice,
    }
