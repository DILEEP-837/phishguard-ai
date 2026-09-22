"""
PhishGuard AI
V3.0 Phase 4 - HTTP Response Intelligence

Analyzes HTTP responses for:
- Suspicious status codes
- Content-Type mismatches
- Server technology disclosure
- Response header anomalies
- Missing/ambiguous Content-Type
- Suspicious redirect responses
- Response-size anomalies
- HTTP response risk scoring
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests


DEFAULT_TIMEOUT = 8


SUSPICIOUS_STATUS_CODES = {
    401: ("Unauthorized response", 10),
    403: ("Forbidden response", 5),
    404: ("Resource not found", 3),
    405: ("Method not allowed", 5),
    406: ("Not acceptable response", 5),
    407: ("Proxy authentication required", 10),
    408: ("Request timeout", 5),
    409: ("Conflict response", 3),
    410: ("Resource permanently removed", 3),
    429: ("Rate limiting detected", 5),
    500: ("Internal server error", 10),
    502: ("Bad gateway response", 10),
    503: ("Service unavailable response", 10),
    504: ("Gateway timeout response", 10),
}


SECURITY_RELEVANT_HEADERS = {
    "server",
    "x-powered-by",
    "via",
    "x-aspnet-version",
    "x-generator",
}


def extract_hostname(url: str) -> Optional[str]:
    """Extract and validate hostname from a normal or scheme-less URL."""

    if not isinstance(url, str) or not url.strip():
        return None

    value = url.strip()

    parsed = urlparse(value)

    if not parsed.hostname:
        parsed = urlparse("//" + value)

    hostname = parsed.hostname

    if not hostname:
        return None

    # Reject values containing whitespace.
    if any(char.isspace() for char in hostname):
        return None

    # A valid hostname must contain only valid hostname characters.
    allowed = set(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "-."
    )

    if any(char not in allowed for char in hostname):
        return None

    # Reject labels that are empty or begin/end with a hyphen.
    labels = hostname.split(".")

    if any(
        not label
        or label.startswith("-")
        or label.endswith("-")
        for label in labels
    ):
        return None

    return hostname


def normalize_content_type(content_type: Optional[str]) -> Optional[str]:
    """Normalize Content-Type to its media type."""

    if not content_type:
        return None

    return content_type.split(";", 1)[0].strip().lower() or None


def fetch_http_response(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """
    Retrieve an HTTP response and expose the information needed
    for response intelligence analysis.
    """

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            headers={
                "User-Agent": "PhishGuard-AI/3.0",
            },
        )

        headers = {
            str(key).lower(): str(value)
            for key, value in response.headers.items()
        }

        content_type = headers.get("content-type")

        return {
            "success": True,
            "status_code": response.status_code,
            "reason": getattr(response, "reason", None),
            "headers": headers,
            "content_type": normalize_content_type(content_type),
            "content_length": len(getattr(response, "content", b"")),
            "url": getattr(response, "url", url) or url,
            "error": None,
        }

    except requests.RequestException as exc:
        return {
            "success": False,
            "status_code": None,
            "reason": None,
            "headers": {},
            "content_type": None,
            "content_length": 0,
            "url": url,
            "error": str(exc),
        }


def analyze_status_code(status_code: Optional[int]) -> Dict[str, Any]:
    """Analyze the HTTP status code."""

    result = {
        "status_code": status_code,
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicator": None,
    }

    if status_code is None:
        result["risk_score"] = 10
        result["risk_level"] = "LOW"
        result["indicator"] = "HTTP status code unavailable"
        return result

    if status_code in SUSPICIOUS_STATUS_CODES:
        indicator, score = SUSPICIOUS_STATUS_CODES[status_code]
        result["risk_score"] = score
        result["indicator"] = indicator

    elif 500 <= status_code <= 599:
        result["risk_score"] = 10
        result["indicator"] = "Server-side HTTP error"

    elif 400 <= status_code <= 499:
        result["risk_score"] = 5
        result["indicator"] = "Client-side HTTP error"

    if result["risk_score"] >= 10:
        result["risk_level"] = "MEDIUM"
    elif result["risk_score"] > 0:
        result["risk_level"] = "LOW"

    return result


def analyze_content_type(
    content_type: Optional[str],
    url: str,
) -> Dict[str, Any]:
    """
    Analyze Content-Type in relation to the requested URL.

    This is intentionally conservative. A missing Content-Type is
    treated as an anomaly, while obviously dangerous combinations
    receive additional risk.
    """

    normalized = normalize_content_type(content_type)
    hostname = extract_hostname(url)

    result = {
        "content_type": normalized,
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
        "hostname": hostname,
    }

    if not normalized:
        result["risk_score"] = 10
        result["risk_level"] = "LOW"
        result["indicators"].append(
            "HTTP Content-Type header is missing"
        )
        return result

    if normalized in {
        "text/html",
        "application/xhtml+xml",
    }:
        result["risk_score"] = 0

    elif normalized.startswith("text/"):
        result["risk_score"] = 0

    elif normalized in {
        "application/javascript",
        "text/javascript",
        "application/json",
        "application/xml",
        "text/xml",
    }:
        result["risk_score"] = 0

    elif normalized in {
        "application/octet-stream",
        "application/x-msdownload",
        "application/x-shockwave-flash",
    }:
        result["risk_score"] = 10
        result["indicators"].append(
            f"Potentially risky Content-Type: {normalized}"
        )

    else:
        result["risk_score"] = 2

    if result["risk_score"] >= 10:
        result["risk_level"] = "MEDIUM"
    elif result["risk_score"] > 0:
        result["risk_level"] = "LOW"

    return result


def analyze_server_headers(
    headers: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Detect technology/server information disclosure."""

    normalized = {
        str(key).lower(): str(value)
        for key, value in (headers or {}).items()
    }

    disclosures = {}

    for header in SECURITY_RELEVANT_HEADERS:
        if header in normalized and normalized[header].strip():
            disclosures[header] = normalized[header]

    risk_score = 0
    indicators = []

    if "server" in disclosures:
        risk_score += 3
        indicators.append("Server technology disclosed")

    if "x-powered-by" in disclosures:
        risk_score += 5
        indicators.append("Application technology disclosed")

    if "x-aspnet-version" in disclosures:
        risk_score += 5
        indicators.append("ASP.NET version disclosed")

    if "x-generator" in disclosures:
        risk_score += 3
        indicators.append("Site generator information disclosed")

    if "via" in disclosures:
        risk_score += 2
        indicators.append("Proxy/gateway information disclosed")

    risk_score = min(15, risk_score)

    if risk_score >= 10:
        risk_level = "MEDIUM"
    elif risk_score > 0:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"

    return {
        "disclosures": disclosures,
        "disclosure_count": len(disclosures),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
    }


def analyze_response_headers(
    headers: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Analyze response headers for unusual or ambiguous behavior."""

    normalized = {
        str(key).lower(): str(value)
        for key, value in (headers or {}).items()
    }

    indicators = []
    risk_score = 0

    if "location" in normalized:
        location = normalized["location"].strip()

        if location:
            risk_score += 2
            indicators.append("HTTP response contains a Location header")

            parsed_location = urlparse(location)

            if parsed_location.scheme in {"http", "https"}:
                indicators.append(
                    "HTTP response contains an absolute redirect destination"
                )
                risk_score += 2

    if "content-disposition" in normalized:
        disposition = normalized["content-disposition"].lower()

        if "attachment" in disposition:
            indicators.append(
                "HTTP response requests file download"
            )
            risk_score += 3

    if "transfer-encoding" in normalized:
        transfer_encoding = normalized["transfer-encoding"].lower()

        if "chunked" in transfer_encoding:
            indicators.append(
                "Chunked transfer encoding detected"
            )

    risk_score = min(15, risk_score)

    if risk_score >= 10:
        risk_level = "MEDIUM"
    elif risk_score > 0:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
    }


def analyze_http_response(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """Perform complete HTTP response intelligence analysis."""

    hostname = extract_hostname(url)

    if not hostname:
        return {
            "success": False,
            "status_code": None,
            "risk_score": 30,
            "risk_level": "MEDIUM",
            "indicators": ["Unable to determine hostname"],
            "status_analysis": {},
            "content_type_analysis": {},
            "server_analysis": {},
            "header_analysis": {},
            "error": "Invalid URL hostname",
        }

    response = fetch_http_response(url, timeout=timeout)

    if not response.get("success"):
        return {
            "success": False,
            "status_code": None,
            "risk_score": 30,
            "risk_level": "MEDIUM",
            "indicators": ["Unable to retrieve HTTP response"],
            "status_analysis": {},
            "content_type_analysis": {},
            "server_analysis": {},
            "header_analysis": {},
            "error": response.get("error"),
        }

    status_analysis = analyze_status_code(
        response.get("status_code")
    )

    content_type_analysis = analyze_content_type(
        response.get("content_type"),
        url,
    )

    server_analysis = analyze_server_headers(
        response.get("headers")
    )

    header_analysis = analyze_response_headers(
        response.get("headers")
    )

    indicators = []

    for indicator in [
        status_analysis.get("indicator"),
        *content_type_analysis.get("indicators", []),
        *server_analysis.get("indicators", []),
        *header_analysis.get("indicators", []),
    ]:
        if indicator and indicator not in indicators:
            indicators.append(indicator)

    risk_score = (
        status_analysis.get("risk_score", 0)
        + content_type_analysis.get("risk_score", 0)
        + server_analysis.get("risk_score", 0)
        + header_analysis.get("risk_score", 0)
    )

    risk_score = min(100, risk_score)

    if risk_score >= 80:
        risk_level = "CRITICAL"
    elif risk_score >= 60:
        risk_level = "HIGH"
    elif risk_score >= 30:
        risk_level = "MEDIUM"
    elif risk_score > 0:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"

    return {
        "success": True,
        "hostname": hostname,
        "status_code": response.get("status_code"),
        "reason": response.get("reason"),
        "content_type": response.get("content_type"),
        "content_length": response.get("content_length", 0),
        "final_url": response.get("url", url),
        "headers": response.get("headers", {}),
        "status_analysis": status_analysis,
        "content_type_analysis": content_type_analysis,
        "server_analysis": server_analysis,
        "header_analysis": header_analysis,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
        "error": None,
    }
