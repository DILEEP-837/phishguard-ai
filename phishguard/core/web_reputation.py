"""
PhishGuard AI
V3.0 Phase 5 - Web Reputation & Infrastructure Intelligence

Analyzes domain and infrastructure reputation signals without
depending on a commercial reputation API.

Signals:
- Suspicious TLDs
- Free-hosting/subdomain patterns
- Excessive subdomain depth
- Numeric-heavy domains
- Punycode/IDN domains
- Suspicious domain labels
- IP-address URLs
- Domain/IP mismatch indicators
- Infrastructure risk scoring
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, Optional
from urllib.parse import urlparse


SUSPICIOUS_TLDS = {
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "top",
    "xyz",
    "click",
    "download",
    "zip",
    "review",
    "country",
    "stream",
    "work",
}

FREE_HOSTING_DOMAINS = {
    "000webhostapp.com",
    "blogspot.com",
    "blogspot.in",
    "github.io",
    "gitlab.io",
    "pages.dev",
    "web.app",
    "firebaseapp.com",
    "netlify.app",
    "vercel.app",
    "herokuapp.com",
    "wordpress.com",
    "wixsite.com",
    "weebly.com",
}

SUSPICIOUS_LABELS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "banking",
    "wallet",
    "support",
    "password",
    "authenticate",
    "authentication",
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

    # Reject whitespace and malformed hostname characters.
    if any(char.isspace() for char in hostname):
        return None

    allowed = set(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "-."
    )

    if any(char not in allowed for char in hostname):
        return None

    labels = hostname.split(".")

    if any(
        not label
        or label.startswith("-")
        or label.endswith("-")
        for label in labels
    ):
        return None

    return hostname.lower()


def is_ip_address(hostname: Optional[str]) -> bool:
    """Return True when hostname is a valid IPv4 or IPv6 address."""

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def get_registered_domain(hostname: Optional[str]) -> Optional[str]:
    """
    Extract a simple registrable-domain approximation.

    This intentionally avoids an external Public Suffix List dependency.
    """

    if not hostname or is_ip_address(hostname):
        return hostname

    labels = hostname.split(".")

    if len(labels) < 2:
        return hostname

    return ".".join(labels[-2:])


def get_tld(hostname: Optional[str]) -> Optional[str]:
    """Return the final hostname label."""

    if not hostname:
        return None

    if is_ip_address(hostname):
        return None

    return hostname.rstrip(".").split(".")[-1].lower()


def calculate_numeric_ratio(value: str) -> float:
    """Calculate the proportion of numeric characters."""

    if not value:
        return 0.0

    alphanumeric = [
        char for char in value
        if char.isalnum()
    ]

    if not alphanumeric:
        return 0.0

    digits = sum(
        char.isdigit()
        for char in alphanumeric
    )

    return digits / len(alphanumeric)


def analyze_domain_reputation(
    hostname: Optional[str],
) -> Dict[str, Any]:
    """Analyze domain-level reputation signals."""

    result = {
        "hostname": hostname,
        "registered_domain": None,
        "tld": None,
        "is_ip": False,
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
    }

    if not hostname:
        result["risk_score"] = 30
        result["risk_level"] = "MEDIUM"
        result["indicators"].append(
            "Hostname unavailable for reputation analysis"
        )
        return result

    hostname = hostname.lower().rstrip(".")
    result["hostname"] = hostname
    result["is_ip"] = is_ip_address(hostname)

    if result["is_ip"]:
        result["risk_score"] += 15
        result["indicators"].append(
            "URL uses an IP address instead of a domain name"
        )

        # IP addresses should not receive domain-specific heuristics.
        result["risk_level"] = "LOW"
        return result

    registered_domain = get_registered_domain(hostname)
    result["registered_domain"] = registered_domain

    tld = get_tld(hostname)
    result["tld"] = tld

    if tld in SUSPICIOUS_TLDS:
        result["risk_score"] += 10
        result["indicators"].append(
            f"Domain uses a commonly abused or higher-risk TLD: .{tld}"
        )

    if "xn--" in hostname:
        result["risk_score"] += 15
        result["indicators"].append(
            "Punycode/IDN hostname detected"
        )

    labels = hostname.split(".")

    if len(labels) >= 4:
        result["risk_score"] += 5
        result["indicators"].append(
            "Deep subdomain structure detected"
        )

    if len(hostname) > 60:
        result["risk_score"] += 5
        result["indicators"].append(
            "Unusually long hostname detected"
        )

    numeric_ratio = calculate_numeric_ratio(hostname)

    if numeric_ratio >= 0.30:
        result["risk_score"] += 10
        result["indicators"].append(
            "Hostname contains a high proportion of numeric characters"
        )

    if hostname.count("-") >= 3:
        result["risk_score"] += 5
        result["indicators"].append(
            "Hostname contains excessive hyphens"
        )

    suspicious_labels = []

    for label in labels:
        normalized_label = label.lower()

        if normalized_label in SUSPICIOUS_LABELS:
            suspicious_labels.append(normalized_label)

    if suspicious_labels:
        result["risk_score"] += min(
            15,
            5 * len(set(suspicious_labels)),
        )

        result["indicators"].append(
            "Sensitive authentication-related domain label detected"
        )

    result["risk_score"] = min(
        100,
        result["risk_score"],
    )

    if result["risk_score"] >= 60:
        result["risk_level"] = "HIGH"
    elif result["risk_score"] >= 30:
        result["risk_level"] = "MEDIUM"
    elif result["risk_score"] > 0:
        result["risk_level"] = "LOW"

    return result


def analyze_hosting_reputation(
    hostname: Optional[str],
) -> Dict[str, Any]:
    """Analyze known free-hosting and platform-hosting patterns."""

    result = {
        "hostname": hostname,
        "hosting_platform": None,
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
    }

    if not hostname:
        return result

    hostname = hostname.lower().rstrip(".")

    for domain in FREE_HOSTING_DOMAINS:
        if hostname == domain or hostname.endswith("." + domain):
            result["hosting_platform"] = domain
            result["risk_score"] = 5
            result["risk_level"] = "LOW"
            result["indicators"].append(
                f"Hostname uses a shared/free hosting platform: {domain}"
            )
            break

    return result


def analyze_domain_labels(
    hostname: Optional[str],
) -> Dict[str, Any]:
    """Analyze individual hostname labels for suspicious patterns."""

    result = {
        "labels": [],
        "suspicious_labels": [],
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
    }

    if not hostname:
        return result

    hostname = hostname.lower().rstrip(".")
    labels = hostname.split(".")

    result["labels"] = labels

    suspicious = [
        label
        for label in labels
        if label in SUSPICIOUS_LABELS
    ]

    result["suspicious_labels"] = suspicious

    if suspicious:
        result["risk_score"] = min(
            15,
            len(set(suspicious)) * 5,
        )
        result["risk_level"] = "LOW"
        result["indicators"].append(
            "Suspicious authentication-related hostname label"
        )

    for label in labels:
        if len(label) > 40:
            result["risk_score"] += 5
            result["indicators"].append(
                "Unusually long hostname label detected"
            )
            break

    result["risk_score"] = min(
        30,
        result["risk_score"],
    )

    if result["risk_score"] >= 30:
        result["risk_level"] = "MEDIUM"
    elif result["risk_score"] > 0:
        result["risk_level"] = "LOW"

    return result


def analyze_infrastructure(
    url: str,
) -> Dict[str, Any]:
    """
    Perform combined Web Reputation & Infrastructure Intelligence.
    """

    hostname = extract_hostname(url)

    if not hostname:
        return {
            "success": False,
            "hostname": None,
            "risk_score": 30,
            "risk_level": "MEDIUM",
            "indicators": [
                "Unable to determine hostname"
            ],
            "domain_analysis": {},
            "hosting_analysis": {},
            "label_analysis": {},
            "error": "Invalid URL hostname",
        }

    domain_analysis = analyze_domain_reputation(hostname)
    hosting_analysis = analyze_hosting_reputation(hostname)
    label_analysis = analyze_domain_labels(hostname)

    indicators = []

    for indicator in [
        *domain_analysis.get("indicators", []),
        *hosting_analysis.get("indicators", []),
        *label_analysis.get("indicators", []),
    ]:
        if indicator not in indicators:
            indicators.append(indicator)

    risk_score = (
        domain_analysis.get("risk_score", 0)
        + hosting_analysis.get("risk_score", 0)
        + label_analysis.get("risk_score", 0)
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
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
        "domain_analysis": domain_analysis,
        "hosting_analysis": hosting_analysis,
        "label_analysis": label_analysis,
        "error": None,
    }
