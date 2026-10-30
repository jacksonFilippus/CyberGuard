
import os
import requests


SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)


def _unavailable(message):
    return {
        "status": "unavailable",
        "message": message,
        "matches": [],
    }


def lookup_safe_browsing(url):
    """Check a URL against Google's Safe Browsing threat lists."""

    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

    if not api_key:
        return _unavailable(
            "Google Safe Browsing API key is not configured."
        )

    payload = {
        "client": {
            "clientId": "cyberguard",
            "clientVersion": "1.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": [
                "ANY_PLATFORM",
            ],
            "threatEntryTypes": [
                "URL",
            ],
            "threatEntries": [
                {"url": url},
            ],
        },
    }

    try:
        response = requests.post(
            SAFE_BROWSING_URL,
            params={"key": api_key},
            json=payload,
            timeout=15,
        )

        if response.status_code == 429:
            return _unavailable(
                "Google Safe Browsing request limit reached."
            )

        if response.status_code in (400, 401, 403):
            return _unavailable(
                "Google Safe Browsing rejected the request. "
                "Check the API key and API configuration."
            )

        response.raise_for_status()
        data = response.json()

        raw_matches = data.get("matches", [])
        matches = []

        for item in raw_matches:
            matches.append({
                "threat_type": item.get(
                    "threatType", "Unknown threat"
                ),
                "platform": item.get(
                    "platformType", "Unknown platform"
                ),
                "entry_type": item.get(
                    "threatEntryType", "URL"
                ),
            })

        if matches:
            return {
                "status": "flagged",
                "message": (
                    "Google Safe Browsing found "
                    f"{len(matches)} threat-list match(es). "
                    "Avoid opening this URL."
                ),
                "matches": matches,
            }

        return {
            "status": "no_known_detection",
            "message": (
                "No matches were returned by Google Safe Browsing. "
                "This does not prove that the URL is safe."
            ),
            "matches": [],
        }

    except requests.Timeout:
        return _unavailable(
            "Google Safe Browsing timed out. Try again later."
        )

    except requests.RequestException:
        return _unavailable(
            "Could not contact Google Safe Browsing."
        )

    except (ValueError, TypeError, AttributeError):
        return _unavailable(
            "The Google Safe Browsing response could not be interpreted."
        )
