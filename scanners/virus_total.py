
import os
import base64
from datetime import datetime, timezone

import requests


FILES_API_URL = "https://www.virustotal.com/api/v3/files/{}"
URLS_API_URL = "https://www.virustotal.com/api/v3/urls/{}"

VIRUSTOTAL_GUI_URL = "https://www.virustotal.com/gui/url/{}"


def _get_api_key():
    return os.getenv("VIRUSTOTAL_API_KEY")


def _unavailable(message):
    return {
        "status": "unavailable",
        "severity": "unknown",
        "message": message,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "total": 0,
        "engine_detections": [],
        "analysis_date": None,
        "report_url": None,
    }


def _interpret_stats(
    stats,
    resource_name,
    analysis_results=None,
    analysis_date=None,
    report_url=None,
):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    total = sum(
        value for value in stats.values()
        if isinstance(value, (int, float))
    )

    # Keep the detection status separate from its severity.
    if malicious > 0:
        status = "flagged"

        if malicious == 1:
            severity = "single_engine_warning"
            message = (
                f"One security engine reported this {resource_name} "
                "as malicious. This requires further investigation "
                "and may be a false positive."
            )

        elif malicious <= 4:
            severity = "multiple_engine_warning"
            message = (
                f"{malicious} security engines reported this "
                f"{resource_name} as malicious."
            )

        else:
            severity = "strong_threat_signal"
            message = (
                f"{malicious} security engines reported this "
                f"{resource_name} as malicious."
            )

    elif suspicious > 0:
        status = "suspicious"
        severity = "suspicious"
        message = (
            f"VirusTotal reports {suspicious} suspicious "
            f"detection(s) for this {resource_name}."
        )

    else:
        status = "no_known_detection"
        severity = "no_known_detection"
        message = (
            "No malicious or suspicious detections were reported "
            "in this result. This does not prove it is safe."
        )

    # Extract individual malicious and suspicious engine results.
    engine_detections = []

    if isinstance(analysis_results, dict):
        for engine_name, engine_data in analysis_results.items():
            if not isinstance(engine_data, dict):
                continue

            category = engine_data.get("category")

            if category in ("malicious", "suspicious"):
                engine_detections.append({
                    "engine": str(engine_name)[:100],
                    "category": category,
                    "result": str(
                        engine_data.get("result") or "Detection reported"
                    )[:200],
                })

    # Format the Unix timestamp returned by VirusTotal.
    formatted_date = None

    if isinstance(analysis_date, (int, float)):
        try:
            formatted_date = datetime.fromtimestamp(
                analysis_date,
                tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M UTC")
        except (ValueError, OverflowError, OSError):
            formatted_date = None

    return {
        "status": status,
        "severity": severity,
        "message": message,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total": total,
        "engine_detections": engine_detections,
        "analysis_date": formatted_date,
        "report_url": report_url,
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
                "severity": "unknown",
                "message": "No existing report was found for this hash.",
            }

        if response.status_code == 429:
            return _unavailable(
                "The VirusTotal API request limit may have been reached."
            )

        response.raise_for_status()

        data = response.json()["data"]["attributes"]

        return _interpret_stats(
            data.get("last_analysis_stats", {}),
            "file",
            analysis_results=data.get("last_analysis_results", {}),
            analysis_date=data.get("last_analysis_date"),
        )

    except requests.RequestException:
        return _unavailable(
            "Could not contact VirusTotal. Please try again later."
        )

    except (KeyError, TypeError, ValueError):
        return _unavailable(
            "The returned file report could not be interpreted."
        )


def lookup_url(url):
    """Look up an existing VirusTotal URL report without visiting it."""

    api_key = _get_api_key()

    if not api_key:
        return _unavailable(
            "VirusTotal API key is not configured."
        )

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
                "severity": "unknown",
                "message": (
                    "No existing VirusTotal URL report was found. "
                    "This does not mean the URL is safe."
                ),
                "engine_detections": [],
                "analysis_date": None,
                "report_url": (
                    VIRUSTOTAL_GUI_URL.format(url_id)
                ),
            }

        if response.status_code == 429:
            return _unavailable(
                "The VirusTotal API request limit may have been reached."
            )

        response.raise_for_status()

        data = response.json()["data"]["attributes"]

        return _interpret_stats(
            data.get("last_analysis_stats", {}),
            "URL",
            analysis_results=data.get("last_analysis_results", {}),
            analysis_date=data.get("last_analysis_date"),
            report_url=VIRUSTOTAL_GUI_URL.format(url_id),
        )

    except requests.RequestException:
        return _unavailable(
            "Could not contact VirusTotal. Please try again later."
        )

    except (KeyError, TypeError, ValueError):
        return _unavailable(
            "The returned URL report could not be interpreted."
        )
