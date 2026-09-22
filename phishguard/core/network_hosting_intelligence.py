"""
PhishGuard AI
V3.0 Phase 8 - Advanced Network & Hosting Intelligence
"""

import ipaddress
from urllib.parse import urlparse


# =========================================================
# KNOWN INFRASTRUCTURE PATTERNS
# =========================================================

CLOUD_PROVIDER_DOMAINS = {
    "amazonaws.com": "AWS",
    "cloudfront.net": "AWS CloudFront",
    "googleusercontent.com": "Google Cloud",
    "appspot.com": "Google App Engine",
    "azurewebsites.net": "Microsoft Azure",
    "cloudapp.azure.com": "Microsoft Azure",
    "azurefd.net": "Microsoft Azure",
    "digitaloceanspaces.com": "DigitalOcean",
    "digitalocean.com": "DigitalOcean",
    "linode.com": "Linode",
    "vultr.com": "Vultr",
}

HOSTING_PROVIDER_DOMAINS = {
    "herokuapp.com": "Heroku",
    "netlify.app": "Netlify",
    "vercel.app": "Vercel",
    "pages.dev": "Cloudflare Pages",
    "web.app": "Firebase Hosting",
    "firebaseapp.com": "Firebase Hosting",
    "github.io": "GitHub Pages",
    "gitlab.io": "GitLab Pages",
    "wordpress.com": "WordPress",
    "wixsite.com": "Wix",
    "weebly.com": "Weebly",
}

DATACENTER_KEYWORDS = {
    "server",
    "srv",
    "node",
    "host",
    "hosting",
    "vps",
    "dedicated",
    "cloud",
    "compute",
    "instance",
    "datacenter",
    "dc",
}

RESIDENTIAL_KEYWORDS = {
    "dynamic",
    "dhcp",
    "broadband",
    "dsl",
    "fiber",
    "ftth",
    "cable",
    "pppoe",
    "residential",
}

KNOWN_CLOUD_ASNS = {
    16509: "Amazon",
    14618: "Amazon",
    15169: "Google",
    8075: "Microsoft",
    14061: "DigitalOcean",
    63949: "Linode",
    20473: "Vultr",
    13335: "Cloudflare",
}

# =========================================================
# GENERAL HELPERS
# =========================================================

def extract_hostname(url):
    """Extract and normalize a hostname from a URL."""

    if not isinstance(url, str):
        return None

    url = url.strip()

    if not url or any(char.isspace() for char in url):
        return None

    try:
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


def get_registered_domain(hostname):
    """Return a simple registered-domain approximation."""

    if not hostname:
        return None

    hostname = hostname.lower().rstrip(".")
    labels = hostname.split(".")

    if len(labels) < 2:
        return hostname

    return ".".join(labels[-2:])


def is_ip_address(value):
    """Return True if value is an IPv4 or IPv6 address."""

    if not isinstance(value, str) or not value:
        return False

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_asn(asn):
    """Normalize ASN values such as AS13335 or 13335."""

    if asn is None:
        return None

    if isinstance(asn, int):
        return asn

    if isinstance(asn, str):
        value = asn.strip().upper()

        if value.startswith("AS"):
            value = value[2:]

        try:
            return int(value)
        except ValueError:
            return None

    return None


# =========================================================
# PROVIDER DETECTION
# =========================================================

def detect_provider_from_hostname(hostname):
    """
    Detect known cloud/hosting providers from hostname suffixes.
    """

    if not hostname:
        return {
            "provider": None,
            "provider_type": None,
            "matched_domain": None,
        }

    hostname = hostname.lower().rstrip(".")

    for domain, provider in CLOUD_PROVIDER_DOMAINS.items():
        if hostname == domain or hostname.endswith("." + domain):
            return {
                "provider": provider,
                "provider_type": "cloud",
                "matched_domain": domain,
            }

    for domain, provider in HOSTING_PROVIDER_DOMAINS.items():
        if hostname == domain or hostname.endswith("." + domain):
            return {
                "provider": provider,
                "provider_type": "hosting",
                "matched_domain": domain,
            }

    return {
        "provider": None,
        "provider_type": None,
        "matched_domain": None,
    }


def analyze_hostname_infrastructure(hostname):
    """
    Analyze hostname patterns for hosting/datacenter clues.
    """

    if not hostname:
        return {
            "hostname": None,
            "provider": None,
            "provider_type": None,
            "datacenter_keyword_matches": [],
            "residential_keyword_matches": [],
            "risk_score": 30,
            "risk_level": "MEDIUM",
            "indicators": [
                "Unable to determine hostname for infrastructure analysis"
            ],
        }

    hostname = hostname.lower()

    provider_info = detect_provider_from_hostname(hostname)

    labels = hostname.replace("-", ".").split(".")

    datacenter_matches = [
        keyword
        for keyword in DATACENTER_KEYWORDS
        if keyword in hostname
    ]

    residential_matches = [
        keyword
        for keyword in RESIDENTIAL_KEYWORDS
        if keyword in hostname
    ]

    risk_score = 0
    indicators = []

    if provider_info["provider"]:
        if provider_info["provider_type"] == "cloud":
            risk_score += 5
            indicators.append(
                f"Known cloud infrastructure provider detected: "
                f"{provider_info['provider']}"
            )
        elif provider_info["provider_type"] == "hosting":
            risk_score += 5
            indicators.append(
                f"Known hosting provider detected: "
                f"{provider_info['provider']}"
            )

    if datacenter_matches:
        risk_score += 5
        indicators.append(
            "Hostname contains datacenter/hosting infrastructure keywords"
        )

    if residential_matches:
        risk_score = max(0, risk_score - 3)

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
        "hostname": hostname,
        "provider": provider_info["provider"],
        "provider_type": provider_info["provider_type"],
        "matched_domain": provider_info["matched_domain"],
        "datacenter_keyword_matches": datacenter_matches,
        "residential_keyword_matches": residential_matches,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
    }


# =========================================================
# ASN / ISP INTELLIGENCE
# =========================================================

def analyze_asn(asn=None, organization=None, isp=None):
    """
    Analyze supplied ASN / organization / ISP information.

    This function does not perform an external lookup.
    Information must be supplied by the caller.
    """

    normalized_asn = normalize_asn(asn)

    organization_text = (
        str(organization).strip()
        if organization is not None
        else None
    )

    isp_text = (
        str(isp).strip()
        if isp is not None
        else None
    )

    known_provider = None

    if normalized_asn in KNOWN_CLOUD_ASNS:
        known_provider = KNOWN_CLOUD_ASNS[normalized_asn]

    combined_text = " ".join(
        value.lower()
        for value in [organization_text, isp_text]
        if value
    )

    datacenter_matches = [
        keyword
        for keyword in DATACENTER_KEYWORDS
        if keyword in combined_text
    ]

    residential_matches = [
        keyword
        for keyword in RESIDENTIAL_KEYWORDS
        if keyword in combined_text
    ]

    risk_score = 0
    indicators = []

    if known_provider:
        risk_score += 5
        indicators.append(
            f"Known cloud/network provider ASN detected: {known_provider}"
        )

    if datacenter_matches:
        risk_score += 5
        indicators.append(
            "ASN/ISP information contains hosting or datacenter indicators"
        )

    if residential_matches:
        risk_score = max(0, risk_score - 3)

    if not normalized_asn and not organization_text and not isp_text:
        indicators.append(
            "ASN and network ownership information unavailable"
        )

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
        "asn": normalized_asn,
        "organization": organization_text,
        "isp": isp_text,
        "known_provider": known_provider,
        "datacenter_matches": datacenter_matches,
        "residential_matches": residential_matches,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
    }


# =========================================================
# IP / HOSTING RELATIONSHIP
# =========================================================

def analyze_ip_hosting_relationship(
    hostname,
    ip_addresses=None,
    asn=None,
    organization=None,
    isp=None,
):
    """
    Correlate hostname, resolved IPs and supplied network ownership.
    """

    if not hostname:
        return {
            "hostname": None,
            "ip_count": 0,
            "asn": None,
            "organization": None,
            "isp": None,
            "risk_score": 30,
            "risk_level": "MEDIUM",
            "indicators": [
                "Unable to determine hostname for hosting relationship"
            ],
        }

    if not isinstance(ip_addresses, (list, tuple, set)):
        ip_addresses = []

    unique_ips = []

    for address in ip_addresses:
        if address not in unique_ips:
            unique_ips.append(address)

    asn_result = analyze_asn(
        asn=asn,
        organization=organization,
        isp=isp,
    )

    hostname_result = analyze_hostname_infrastructure(hostname)

    risk_score = (
        hostname_result.get("risk_score", 0)
        + asn_result.get("risk_score", 0)
    )

    indicators = []

    indicators.extend(hostname_result.get("indicators", []))
    indicators.extend(asn_result.get("indicators", []))

    if len(unique_ips) >= 5:
        risk_score += 5
        indicators.append(
            "Hostname resolves to multiple network addresses"
        )

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
        "hostname": hostname,
        "ip_addresses": unique_ips,
        "ip_count": len(unique_ips),
        "asn": asn_result.get("asn"),
        "organization": asn_result.get("organization"),
        "isp": asn_result.get("isp"),
        "provider": hostname_result.get("provider"),
        "provider_type": hostname_result.get("provider_type"),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": unique_indicators,
    }


# =========================================================
# COMPLETE PHASE 8 ANALYSIS
# =========================================================

def analyze_network_hosting(
    url,
    ip_addresses=None,
    asn=None,
    organization=None,
    isp=None,
):
    """
    Complete V3.0 Phase 8 Network & Hosting Intelligence.
    """

    hostname = extract_hostname(url)

    if not hostname:
        return {
            "success": False,
            "hostname": None,
            "hostname_infrastructure": {},
            "asn_intelligence": {},
            "relationship": {},
            "risk_score": 30,
            "risk_level": "MEDIUM",
            "indicators": [
                "Unable to determine hostname for network and hosting analysis"
            ],
            "error": "Invalid or missing hostname",
        }

    hostname_result = analyze_hostname_infrastructure(hostname)

    asn_result = analyze_asn(
        asn=asn,
        organization=organization,
        isp=isp,
    )

    relationship_result = analyze_ip_hosting_relationship(
        hostname=hostname,
        ip_addresses=ip_addresses,
        asn=asn,
        organization=organization,
        isp=isp,
    )

    risk_score = relationship_result.get("risk_score", 0)

    indicators = []

    indicators.extend(hostname_result.get("indicators", []))
    indicators.extend(asn_result.get("indicators", []))
    indicators.extend(relationship_result.get("indicators", []))

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
        "success": True,
        "hostname": hostname,
        "hostname_infrastructure": hostname_result,
        "asn_intelligence": asn_result,
        "relationship": relationship_result,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": unique_indicators,
        "error": None,
    }
