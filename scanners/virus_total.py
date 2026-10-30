
import os
import base64
import requests


FILES_API_URL = "https://www.virustotal.com/api/v3/files/{}"
URLS_API_URL = "https://www.virustotal.com/api/v3/urls/{}"


def _get_api_key():
    return os.getenv("VIRUSTOTAL_API_KEY")


def _unavailable(message):
    return {
        "status": "unavailable",
        "message": message,
    }


def _interpret_stats(stats, resource_name):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    if malicious > 0:
        status = "flagged"
        message = (
            f"VirusTotal reports {malicious} malicious detection(s) "
            f"for this {resource_name}."
        )
    elif suspicious > 0:
        status = "suspicious"
        message = (
            f"VirusTotal reports {suspicious} suspicious detection(s) "
            f"for this {resource_name}."
        )
    else:
        status = "no_known_detection"
        message = (
            "No malicious or suspicious detections were reported "
            "in this result. This does not prove it is safe."
        )

    return {
        "status": status,
        "message": message,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total": sum(stats.values()),
    }


def lookup_file_hash(sha256):
    api_key = _get_api_key()

    if not api_key:
        return _unavailable(
            "VirusTotal API key is not configured."
        )

    try:
        response = requests.get(
            FILES_API_URL.format(sha256),
            headers={"x-apikey": api_key},
            timeout=15,
        )

        if response.status_code == 404:
            return {
                "status": "not_found",
                "message": "No existing report was found for this hash.",
            }

        if response.status_code == 429:
            return _unavailable(
                "The VirusTotal API request limit may have been reached."
            )

        response.raise_for_status()
        data = response.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats", {})

        return _interpret_stats(stats, "file")

    except requests.RequestException:
        return _unavailable(
            "Could not contact VirusTotal. Please try again later."
        )
    except (KeyError, TypeError, ValueError):
        return _unavailable(
            "The returned file report could not be interpreted."
        )


def lookup_url(url):
    """Look up an existing VirusTotal URL report without visiting the URL."""

    api_key = _get_api_key()

    if not api_key:
        return _unavailable(
            "VirusTotal API key is not configured."
        )

    # VirusTotal identifies URLs using URL-safe Base64 without padding.
    url_id = base64.urlsafe_b64encode(
        url.encode("utf-8")
    ).decode("ascii").rstrip("=")

    try:
        response = requests.get(
            URLS_API_URL.format(url_id),
            headers={"x-apikey": api_key},
            timeout=15,
        )

        if response.status_code == 404:
            return {
                "status": "not_found",
                "message": (
                    "No existing VirusTotal URL report was found. "
                    "This does not mean the URL is safe."
                ),
            }

        if response.status_code == 429:
            return _unavailable(
                "The VirusTotal API request limit may have been reached."
            )

        response.raise_for_status()
        data = response.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats", {})

        return _interpret_stats(stats, "URL")

    except requests.RequestException:
        return _unavailable(
            "Could not contact VirusTotal. Please try again later."
        )
    except (KeyError, TypeError, ValueError):
        return _unavailable(
            "The returned URL report could not be interpreted."
        )
