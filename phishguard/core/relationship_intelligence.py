"""
PhishGuard AI
V3.0 Phase 6 - Advanced URL & Domain Relationship Intelligence

Correlates results from existing intelligence modules:
- URL hostname
- DNS/domain intelligence
- TLS certificate identity
- Redirect destinations
- HTTPS usage
- Cross-domain relationships

This module does not perform network requests itself.
It consumes already collected analysis results.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urlparse


def extract_hostname(url: Optional[str]) -> Optional[str]:
    """Extract a normalized hostname from a URL."""

    if not isinstance(url, str) or not url.strip():
        return None

    value = url.strip()

    parsed = urlparse(value)

    if not parsed.hostname:
        parsed = urlparse("//" + value)

    hostname = parsed.hostname

    if not hostname:
        return None

    if any(char.isspace() for char in hostname):
        return None

    return hostname.lower().rstrip(".")


def is_https_url(url: Optional[str]) -> bool:
    """Return True when the URL explicitly uses HTTPS."""

    if not isinstance(url, str):
        return False

    value = url.strip()

    parsed = urlparse(value)

    return parsed.scheme.lower() == "https"


def hostnames_match(
    hostname_a: Optional[str],
    hostname_b: Optional[str],
) -> bool:
    """Compare two hostnames case-insensitively."""

    if not hostname_a or not hostname_b:
        return False

    return (
        hostname_a.lower().rstrip(".")
        == hostname_b.lower().rstrip(".")
    )


def is_subdomain(
    hostname: Optional[str],
    parent: Optional[str],
) -> bool:
    """Determine whether hostname is a subdomain of parent."""

    if not hostname or not parent:
        return False

    hostname = hostname.lower().rstrip(".")
    parent = parent.lower().rstrip(".")

    if hostname == parent:
        return False

    return hostname.endswith("." + parent)


def analyze_hostname_redirect_relationship(
    original_url: Optional[str],
    final_url: Optional[str],
) -> Dict[str, Any]:
    """Analyze the relationship between original and final URL hosts."""

    original_hostname = extract_hostname(original_url)
    final_hostname = extract_hostname(final_url)

    result = {
        "original_hostname": original_hostname,
        "final_hostname": final_hostname,
        "same_domain": False,
        "cross_domain": False,
        "subdomain_redirect": False,
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
    }

    if not original_hostname or not final_hostname:
        result["risk_score"] = 10
        result["risk_level"] = "LOW"
        result["indicators"].append(
            "Unable to compare original and final redirect hostnames"
        )
        return result

    if hostnames_match(original_hostname, final_hostname):
        result["same_domain"] = True
        return result

    result["cross_domain"] = True
    result["risk_score"] += 10
    result["indicators"].append(
        "Redirect destination uses a different hostname"
    )

    if (
        is_subdomain(final_hostname, original_hostname)
        or is_subdomain(original_hostname, final_hostname)
    ):
        result["subdomain_redirect"] = True
        result["risk_score"] = 5
        result["indicators"].append(
            "Redirect remains within a related subdomain hierarchy"
        )

    result["risk_level"] = "LOW"

    return result


def analyze_tls_hostname_relationship(
    url: Optional[str],
    tls_result: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compare URL hostname with TLS certificate hostname matching."""

    hostname = extract_hostname(url)

    result = {
        "hostname": hostname,
        "certificate_present": False,
        "hostname_match": None,
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
    }

    tls_result = tls_result or {}

    result["certificate_present"] = bool(
        tls_result.get("certificate_present")
    )

    hostname_match = tls_result.get("hostname_match")

    if hostname_match is not None:
        result["hostname_match"] = bool(hostname_match)

    if not is_https_url(url):
        return result

    if not result["certificate_present"]:
        result["risk_score"] = 10
        result["risk_level"] = "LOW"
        result["indicators"].append(
            "HTTPS URL has no certificate information available"
        )
        return result

    if hostname_match is False:
        result["risk_score"] = 30
        result["risk_level"] = "MEDIUM"
        result["indicators"].append(
            "HTTPS hostname does not match the TLS certificate"
        )

    return result


def analyze_dns_hostname_relationship(
    url: Optional[str],
    dns_result: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compare URL hostname with DNS analysis information."""

    hostname = extract_hostname(url)

    result = {
        "hostname": hostname,
        "dns_available": False,
        "resolved_addresses": [],
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
    }

    dns_result = dns_result or {}

    addresses = []

    for key in ("a_records", "aaaa_records", "addresses"):
        value = dns_result.get(key)

        if isinstance(value, list):
            addresses.extend(value)

    result["resolved_addresses"] = list(dict.fromkeys(addresses))
    result["dns_available"] = bool(result["resolved_addresses"])

    if not hostname:
        result["risk_score"] = 10
        result["risk_level"] = "LOW"
        result["indicators"].append(
            "Unable to compare URL hostname with DNS information"
        )
        return result

    if not result["dns_available"]:
        result["risk_score"] = 5
        result["risk_level"] = "LOW"
        result["indicators"].append(
            "No DNS address information available for correlation"
        )

    return result


def analyze_https_consistency(
    url: Optional[str],
    tls_result: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Analyze consistency between HTTPS usage and TLS information."""

    result = {
        "https": is_https_url(url),
        "tls_available": False,
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
    }

    tls_result = tls_result or {}

    if not result["https"]:
        return result

    result["tls_available"] = bool(
        tls_result.get("certificate_present")
        or tls_result.get("success")
        or tls_result.get("tls_version")
    )

    if not result["tls_available"]:
        result["risk_score"] = 10
        result["risk_level"] = "LOW"
        result["indicators"].append(
            "HTTPS URL has no correlated TLS information"
        )

    return result


def analyze_relationships(
    url: Optional[str],
    redirect_result: Optional[Dict[str, Any]] = None,
    dns_result: Optional[Dict[str, Any]] = None,
    tls_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Perform combined relationship intelligence.

    The function consumes existing analysis results and produces
    correlation indicators and a bounded risk contribution.
    """

    hostname = extract_hostname(url)

    if not hostname:
        return {
            "success": False,
            "hostname": None,
            "risk_score": 30,
            "risk_level": "MEDIUM",
            "indicators": [
                "Unable to determine hostname for relationship analysis"
            ],
            "redirect_relationship": {},
            "tls_relationship": {},
            "dns_relationship": {},
            "https_consistency": {},
            "error": "Invalid URL hostname",
        }

    redirect_result = redirect_result or {}
    dns_result = dns_result or {}
    tls_result = tls_result or {}

    final_url = (
        redirect_result.get("final_url")
        or redirect_result.get("destination")
        or redirect_result.get("redirect_target")
        or url
    )

    redirect_relationship = analyze_hostname_redirect_relationship(
        url,
        final_url,
    )

    tls_relationship = analyze_tls_hostname_relationship(
        url,
        tls_result,
    )

    dns_relationship = analyze_dns_hostname_relationship(
        url,
        dns_result,
    )

    https_consistency = analyze_https_consistency(
        url,
        tls_result,
    )

    indicators = []

    for indicator in [
        *redirect_relationship.get("indicators", []),
        *tls_relationship.get("indicators", []),
        *dns_relationship.get("indicators", []),
        *https_consistency.get("indicators", []),
    ]:
        if indicator not in indicators:
            indicators.append(indicator)

    risk_score = (
        redirect_relationship.get("risk_score", 0)
        + tls_relationship.get("risk_score", 0)
        + dns_relationship.get("risk_score", 0)
        + https_consistency.get("risk_score", 0)
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
        "redirect_relationship": redirect_relationship,
        "tls_relationship": tls_relationship,
        "dns_relationship": dns_relationship,
        "https_consistency": https_consistency,
        "error": None,
    }
