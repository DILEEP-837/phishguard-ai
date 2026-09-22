"""
PhishGuard AI
V3.0 Phase 7 - IP & Network Intelligence
"""

import ipaddress
import socket
from urllib.parse import urlparse


DEFAULT_TIMEOUT = 5


# =========================================================
# URL / HOSTNAME UTILITIES
# =========================================================

def extract_hostname(url):
    """Extract and normalize hostname from a URL."""

    if not isinstance(url, str):
        return None

    url = url.strip()

    if not url or any(char.isspace() for char in url):
        return None

    try:
        # Handle raw IPv6 URLs before urlparse().
        # Example:
        # https://2001:db8::1
        if "://" in url:
            possible_host = url.split("://", 1)[1].split("/", 1)[0]

            if is_ipv6(possible_host):
                return possible_host.lower().rstrip(".")

        parsed = urlparse(url)

        if not parsed.hostname:
            parsed = urlparse(f"//{url}")

        hostname = parsed.hostname

        if not hostname:
            return None

        hostname = hostname.lower().rstrip(".")

        if not hostname:
            return None

        return hostname

    except (ValueError, TypeError):
        return None


def is_ip_address(value):
    """Return True when value is a valid IPv4 or IPv6 address."""

    if not isinstance(value, str) or not value:
        return False

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_ip(value):
    """Return an ipaddress object or None."""

    if not isinstance(value, str) or not value:
        return None

    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def is_ipv4(value):
    """Return True when value is a valid IPv4 address."""

    parsed = parse_ip(value)
    return parsed is not None and parsed.version == 4


def is_ipv6(value):
    """Return True when value is a valid IPv6 address."""

    parsed = parse_ip(value)
    return parsed is not None and parsed.version == 6


# =========================================================
# IP CLASSIFICATION
# =========================================================

def classify_ip(value):
    """
    Classify an IP address.

    Returns:
        {
            "ip": str,
            "version": 4 or 6,
            "private": bool,
            "loopback": bool,
            "reserved": bool,
            "link_local": bool,
            "multicast": bool,
            "unspecified": bool,
            "global": bool,
            "classification": str
        }
    """

    parsed = parse_ip(value)

    if parsed is None:
        return {
            "ip": value,
            "version": None,
            "private": False,
            "loopback": False,
            "reserved": False,
            "link_local": False,
            "multicast": False,
            "unspecified": False,
            "global": False,
            "classification": "invalid",
        }

    if parsed.is_loopback:
        classification = "loopback"
    elif parsed.is_private:
        classification = "private"
    elif parsed.is_reserved:
        classification = "reserved"
    elif parsed.is_link_local:
        classification = "link_local"
    elif parsed.is_multicast:
        classification = "multicast"
    elif parsed.is_unspecified:
        classification = "unspecified"
    elif parsed.is_global:
        classification = "global"
    else:
        classification = "special"

    return {
        "ip": str(parsed),
        "version": parsed.version,
        "private": parsed.is_private,
        "loopback": parsed.is_loopback,
        "reserved": parsed.is_reserved,
        "link_local": parsed.is_link_local,
        "multicast": parsed.is_multicast,
        "unspecified": parsed.is_unspecified,
        "global": parsed.is_global,
        "classification": classification,
    }


# =========================================================
# DNS RESOLUTION
# =========================================================

def resolve_hostname(hostname, timeout=DEFAULT_TIMEOUT):
    """
    Resolve a hostname to IPv4/IPv6 addresses.

    Returns a dictionary containing unique resolved addresses.
    """

    result = {
        "success": False,
        "hostname": hostname,
        "addresses": [],
        "ipv4_addresses": [],
        "ipv6_addresses": [],
        "error": None,
    }

    if not hostname:
        result["error"] = "Hostname is missing"
        return result

    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)

        try:
            records = socket.getaddrinfo(
                hostname,
                None,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
            )
        finally:
            socket.setdefaulttimeout(old_timeout)

        addresses = []

        for record in records:
            sockaddr = record[4]

            if not sockaddr:
                continue

            address = sockaddr[0]

            if address not in addresses:
                addresses.append(address)

        result["addresses"] = addresses
        result["ipv4_addresses"] = [
            address for address in addresses if is_ipv4(address)
        ]
        result["ipv6_addresses"] = [
            address for address in addresses if is_ipv6(address)
        ]
        result["success"] = bool(addresses)

        if not addresses:
            result["error"] = "No IP addresses resolved"

        return result

    except (socket.gaierror, socket.timeout, OSError) as exc:
        result["error"] = str(exc)
        return result


# =========================================================
# IP / NETWORK ANALYSIS
# =========================================================

def analyze_ip_addresses(addresses):
    """Analyze a collection of IP addresses."""

    if not isinstance(addresses, (list, tuple, set)):
        addresses = []

    unique_addresses = []

    for address in addresses:
        if address not in unique_addresses:
            unique_addresses.append(address)

    classifications = [
        classify_ip(address)
        for address in unique_addresses
    ]

    private_addresses = [
        item["ip"]
        for item in classifications
        if item["private"]
    ]

    loopback_addresses = [
        item["ip"]
        for item in classifications
        if item["loopback"]
    ]

    reserved_addresses = [
        item["ip"]
        for item in classifications
        if item["reserved"]
    ]

    link_local_addresses = [
        item["ip"]
        for item in classifications
        if item["link_local"]
    ]

    multicast_addresses = [
        item["ip"]
        for item in classifications
        if item["multicast"]
    ]

    unspecified_addresses = [
        item["ip"]
        for item in classifications
        if item["unspecified"]
    ]

    ipv4_addresses = [
        item["ip"]
        for item in classifications
        if item["version"] == 4
    ]

    ipv6_addresses = [
        item["ip"]
        for item in classifications
        if item["version"] == 6
    ]

    risk_score = 0
    indicators = []

    if loopback_addresses:
        risk_score += 25
        indicators.append("Loopback IP address detected")
    elif private_addresses:
        risk_score += 15
        indicators.append("Private IP address detected")
    elif reserved_addresses:
        risk_score += 15
        indicators.append("Reserved IP address detected")
    elif link_local_addresses:
        risk_score += 10
        indicators.append("Link-local IP address detected")
    elif multicast_addresses:
        risk_score += 10
        indicators.append("Multicast IP address detected")
    elif unspecified_addresses:
        risk_score += 15
        indicators.append("Unspecified IP address detected")

    if len(unique_addresses) >= 5:
        risk_score += 10
        indicators.append("Multiple IP addresses detected")

    if len(unique_addresses) >= 10:
        risk_score += 10
        indicators.append("Excessive IP address count detected")

    risk_score = min(100, risk_score)

    if risk_score >= 60:
        risk_level = "HIGH"
    elif risk_score >= 30:
        risk_level = "MEDIUM"
    elif risk_score > 0:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"

    return {
        "addresses": unique_addresses,
        "address_count": len(unique_addresses),
        "ipv4_addresses": ipv4_addresses,
        "ipv6_addresses": ipv6_addresses,
        "private_addresses": private_addresses,
        "loopback_addresses": loopback_addresses,
        "reserved_addresses": reserved_addresses,
        "link_local_addresses": link_local_addresses,
        "multicast_addresses": multicast_addresses,
        "unspecified_addresses": unspecified_addresses,
        "classifications": classifications,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
    }


# =========================================================
# DIRECT IP / HOSTNAME RELATIONSHIP
# =========================================================

def analyze_ip_hostname_relationship(url, resolved_addresses=None):
    """
    Analyze whether a URL directly uses an IP address and,
    when applicable, compare it with resolved addresses.
    """

    hostname = extract_hostname(url)

    result = {
        "hostname": hostname,
        "direct_ip": False,
        "ip_version": None,
        "resolved_match": None,
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
    }

    if not hostname:
        result["risk_score"] = 30
        result["risk_level"] = "MEDIUM"
        result["indicators"].append(
            "Unable to determine hostname for IP relationship analysis"
        )
        return result

    parsed_ip = parse_ip(hostname)

    if parsed_ip is not None:
        result["direct_ip"] = True
        result["ip_version"] = parsed_ip.version
        result["risk_score"] += 20
        result["indicators"].append(
            "URL uses a direct IP address instead of a hostname"
        )

        classification = classify_ip(hostname)

        if classification["loopback"]:
            result["risk_score"] += 25
            result["indicators"].append(
                "Direct URL uses a loopback IP address"
            )
        elif classification["private"]:
            result["risk_score"] += 15
            result["indicators"].append(
                "Direct URL uses a private IP address"
            )
        elif classification["reserved"]:
            result["risk_score"] += 15
            result["indicators"].append(
                "Direct URL uses a reserved IP address"
            )

        result["risk_score"] = min(100, result["risk_score"])

    if resolved_addresses:
        result["resolved_match"] = hostname in resolved_addresses

    if result["risk_score"] >= 60:
        result["risk_level"] = "HIGH"
    elif result["risk_score"] >= 30:
        result["risk_level"] = "MEDIUM"
    elif result["risk_score"] > 0:
        result["risk_level"] = "LOW"

    return result


# =========================================================
# COMPLETE IP & NETWORK ANALYSIS
# =========================================================

def analyze_ip_network(url, timeout=DEFAULT_TIMEOUT):
    """
    Perform complete V3.0 Phase 7 IP & Network Intelligence.
    """

    hostname = extract_hostname(url)

    if not hostname:
        return {
            "success": False,
            "hostname": None,
            "direct_ip": False,
            "resolution": {},
            "ip_analysis": analyze_ip_addresses([]),
            "relationship": analyze_ip_hostname_relationship(url),
            "risk_score": 30,
            "risk_level": "MEDIUM",
            "indicators": [
                "Unable to determine hostname for IP and network analysis"
            ],
            "error": "Invalid or missing hostname",
        }

    direct_ip = is_ip_address(hostname)

    if direct_ip:
        resolution = {
            "success": True,
            "hostname": hostname,
            "addresses": [hostname],
            "ipv4_addresses": (
                [hostname] if is_ipv4(hostname) else []
            ),
            "ipv6_addresses": (
                [hostname] if is_ipv6(hostname) else []
            ),
            "error": None,
        }
    else:
        resolution = resolve_hostname(hostname, timeout=timeout)

    ip_analysis = analyze_ip_addresses(
        resolution.get("addresses", [])
    )

    relationship = analyze_ip_hostname_relationship(
        url,
        resolution.get("addresses", []),
    )

    risk_score = 0
    indicators = []

    # Direct IP / hostname relationship
    risk_score += relationship.get("risk_score", 0)

    # DNS / network infrastructure
    if not direct_ip and not resolution.get("success"):
        risk_score += 10
        indicators.append("Hostname did not resolve to an IP address")

    risk_score += ip_analysis.get("risk_score", 0)

    indicators.extend(relationship.get("indicators", []))
    indicators.extend(ip_analysis.get("indicators", []))

    if not direct_ip and resolution.get("success"):
        indicators.append("Hostname successfully resolved to IP address")

    # Remove duplicate indicators
    unique_indicators = []

    for indicator in indicators:
        if indicator not in unique_indicators:
            unique_indicators.append(indicator)

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
        "success": resolution.get("success", False),
        "hostname": hostname,
        "direct_ip": direct_ip,
        "resolution": resolution,
        "ip_analysis": ip_analysis,
        "relationship": relationship,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": unique_indicators,
        "error": resolution.get("error"),
    }
