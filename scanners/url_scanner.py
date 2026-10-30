
import ipaddress
import re
from urllib.parse import urlparse


def analyse_url(url):
    """Check a URL for basic warning signs without visiting it."""

    url = url.strip()
    findings = []

    if not url:
        return {
            "url": url,
            "valid": False,
            "score": 0,
            "verdict": "Invalid URL",
            "findings": ["Please enter a URL."],
            "advice": "Enter a web address to analyse.",
        }

    # Add a scheme if the user entered a bare domain.
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        host = parsed.hostname

        if parsed.scheme not in ("http", "https"):
            raise ValueError("Unsupported URL scheme")

        if not host or "." not in host and host != "localhost":
            raise ValueError("Missing or invalid hostname")

        # Accessing .port also detects malformed port numbers.
        _ = parsed.port

    except ValueError:
        return {
            "url": url,
            "valid": False,
            "score": 0,
            "verdict": "Invalid URL",
            "findings": ["The address is malformed or uses an unsupported scheme."],
            "advice": "Check the address and enter a valid HTTP or HTTPS URL.",
        }

    host = host.lower()

    if parsed.scheme == "http":
        findings.append("The link uses HTTP rather than encrypted HTTPS.")

    if "@" in parsed.netloc:
        findings.append(
            "The address contains an @ symbol, which can disguise the actual destination."
        )

    if host.startswith("xn--") or ".xn--" in host:
        findings.append(
            "The domain uses internationalised encoding. Verify its spelling carefully."
        )

    try:
        ipaddress.ip_address(host)
        findings.append(
            "The destination is an IP address rather than a conventional domain name."
        )
    except ValueError:
        pass

    if len(host) > 50:
        findings.append("The domain name is unusually long.")

    if host.count(".") >= 4:
        findings.append("The domain has many subdomain levels. Check the registered domain.")

    if len(url) > 200:
        findings.append("The full URL is unusually long.")

    score = min(len(findings) * 2, 10)

    if score >= 6:
        verdict = "Multiple warning signs"
        advice = (
            "Avoid opening this link until you verify its destination "
            "using a trusted source."
        )
    elif findings:
        verdict = "Potential warning signs"
        advice = (
            "Review the findings and verify the destination before proceeding."
        )
    else:
        verdict = "No obvious warning signs found"
        advice = (
            "These basic checks found no obvious warning signs. "
            "This does not prove that the website is safe."
        )

    return {
        "url": url,
        "valid": True,
        "score": score,
        "verdict": verdict,
        "findings": findings,
        "advice": advice,
    }
