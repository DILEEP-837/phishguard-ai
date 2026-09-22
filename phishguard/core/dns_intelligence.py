import socket

import dns.resolver


DNS_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "CNAME")


def extract_hostname(url):
    """Extract hostname from a URL or hostname string."""
    if not url:
        return ""

    value = url.strip()

    if "://" in value:
        value = value.split("://", 1)[1]

    value = value.split("/", 1)[0]
    value = value.split("?", 1)[0]
    value = value.split("#", 1)[0]
    value = value.split(":", 1)[0]

    return value.lower().strip(".")


def resolve_a_records(hostname):
    """Resolve IPv4 addresses."""
    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_INET,
            socket.SOCK_STREAM,
        )

        return sorted({
            result[4][0]
            for result in results
        })

    except (socket.gaierror, OSError):
        return []


def resolve_aaaa_records(hostname):
    """Resolve IPv6 addresses."""
    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_INET6,
            socket.SOCK_STREAM,
        )

        return sorted({
            result[4][0]
            for result in results
        })

    except (socket.gaierror, OSError):
        return []


def resolve_cname(hostname):
    """Resolve CNAME aliases."""
    try:
        _, aliases, _ = socket.gethostbyname_ex(hostname)

        return sorted({
            alias.lower()
            for alias in aliases
            if alias.lower() != hostname.lower()
        })

    except (socket.gaierror, OSError):
        return []


def resolve_mx_records(hostname):
    """Resolve MX mail exchanger records."""
    try:
        answers = dns.resolver.resolve(
            hostname,
            "MX",
            lifetime=5,
        )

        records = []

        for answer in answers:
            exchange = str(answer.exchange).rstrip(".").lower()
            preference = int(answer.preference)

            records.append({
                "priority": preference,
                "exchange": exchange,
            })

        return sorted(
            records,
            key=lambda item: (item["priority"], item["exchange"]),
        )

    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.resolver.LifetimeTimeout,
    ):
        return []


def resolve_ns_records(hostname):
    """Resolve authoritative nameserver records."""
    try:
        answers = dns.resolver.resolve(
            hostname,
            "NS",
            lifetime=5,
        )

        return sorted({
            str(answer.target).rstrip(".").lower()
            for answer in answers
        })

    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.resolver.LifetimeTimeout,
    ):
        return []


def analyze_dns(url):
    """
    Perform complete DNS and domain intelligence.

    Includes:
    - A records
    - AAAA records
    - CNAME records
    - MX records
    - NS records
    - DNS infrastructure analysis
    - Domain structure analysis
    """
    hostname = extract_hostname(url)

    if not hostname:
        return {
            "hostname": "",
            "a_records": [],
            "aaaa_records": [],
            "cname_records": [],
            "mx_records": [],
            "ns_records": [],
            "resolved": False,
            "risk_score": 20,
            "risk_level": "MEDIUM",
            "indicators": ["Unable to extract hostname"],
            "infrastructure": {
                "risk_score": 0,
                "risk_level": "SAFE",
                "indicators": [],
            },
            "domain_structure": {
                "risk_score": 0,
                "risk_level": "SAFE",
                "indicators": [],
            },
        }

    a_records = resolve_a_records(hostname)
    aaaa_records = resolve_aaaa_records(hostname)
    cname_records = resolve_cname(hostname)
    mx_records = resolve_mx_records(hostname)
    ns_records = resolve_ns_records(hostname)

    resolved = bool(
        a_records
        or aaaa_records
        or cname_records
        or mx_records
        or ns_records
    )

    indicators = []
    risk_score = 0

    if not resolved:
        indicators.append("DNS resolution failed")
        risk_score += 30

    if len(a_records) > 5:
        indicators.append("Multiple IPv4 addresses detected")
        risk_score += 10

    if len(aaaa_records) > 5:
        indicators.append("Multiple IPv6 addresses detected")
        risk_score += 10

    if cname_records:
        indicators.append("CNAME alias detected")

    if not mx_records:
        indicators.append("No MX records detected")

    if not ns_records:
        indicators.append("No NS records detected")

    infrastructure = analyze_dns_infrastructure(
        hostname,
        a_records=a_records,
        aaaa_records=aaaa_records,
        cname_records=cname_records,
        mx_records=mx_records,
        ns_records=ns_records,
    )

    domain_structure = analyze_domain_structure(hostname)

    indicators.extend(infrastructure["indicators"])
    indicators.extend(domain_structure["indicators"])

    risk_score += infrastructure["risk_score"]
    risk_score += domain_structure["risk_score"]

    risk_score = min(risk_score, 100)

    if risk_score >= 40:
        risk_level = "HIGH"
    elif risk_score >= 20:
        risk_level = "MEDIUM"
    elif risk_score > 0:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"

    return {
        "hostname": hostname,
        "a_records": a_records,
        "aaaa_records": aaaa_records,
        "cname_records": cname_records,
        "mx_records": mx_records,
        "ns_records": ns_records,
        "resolved": resolved,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": list(dict.fromkeys(indicators)),
        "infrastructure": infrastructure,
        "domain_structure": domain_structure,
    }

def analyze_dns_infrastructure(
    hostname,
    a_records=None,
    aaaa_records=None,
    cname_records=None,
    mx_records=None,
    ns_records=None,
):
    """
    Analyze DNS infrastructure for suspicious structural indicators.
    """

    a_records = a_records or []
    aaaa_records = aaaa_records or []
    cname_records = cname_records or []
    mx_records = mx_records or []
    ns_records = ns_records or []

    indicators = []
    risk_score = 0

    hostname = hostname.lower().strip(".")

    # IP-address-like hostname
    try:
        socket.inet_aton(hostname)
        indicators.append("Hostname appears to be an IPv4 address")
        risk_score += 25
    except OSError:
        pass

    # Excessive A records
    if len(a_records) > 10:
        indicators.append("Excessive IPv4 addresses detected")
        risk_score += 15

    # Excessive nameservers
    if len(ns_records) > 6:
        indicators.append("Large number of nameservers detected")
        risk_score += 10

    # Numeric-heavy hostname
    hostname_without_tld = hostname.rsplit(".", 1)[0]

    if hostname_without_tld:
        digit_count = sum(
            character.isdigit()
            for character in hostname_without_tld
        )

        if digit_count >= 4:
            indicators.append("Hostname contains many numeric characters")
            risk_score += 10

    # Very long hostname
    if len(hostname) > 50:
        indicators.append("Unusually long hostname detected")
        risk_score += 10

    # Many subdomain levels
    if hostname.count(".") >= 4:
        indicators.append("Deep subdomain structure detected")
        risk_score += 10

    if risk_score >= 40:
        risk_level = "HIGH"
    elif risk_score >= 20:
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


def analyze_domain_structure(hostname):
    """
    Analyze domain structure for suspicious characteristics.

    This is heuristic analysis only. These indicators do not
    independently prove that a domain is malicious.
    """
    hostname = hostname.lower().strip(".")

    indicators = []
    risk_score = 0

    if not hostname:
        return {
            "risk_score": 0,
            "risk_level": "SAFE",
            "indicators": [],
        }

    # Punycode / internationalized domain indicator
    if "xn--" in hostname:
        indicators.append("Punycode/IDN domain detected")
        risk_score += 15

    # Very long hostname
    if len(hostname) > 60:
        indicators.append("Very long domain structure detected")
        risk_score += 10

    # Excessive hyphens
    hyphen_count = hostname.count("-")

    if hyphen_count >= 4:
        indicators.append("Excessive hyphens detected")
        risk_score += 10

    # Numeric-heavy hostname
    alphanumeric = [
        character
        for character in hostname
        if character.isalnum()
    ]

    if alphanumeric:
        digit_count = sum(
            character.isdigit()
            for character in alphanumeric
        )

        digit_ratio = digit_count / len(alphanumeric)

        if digit_ratio >= 0.30:
            indicators.append("High numeric character ratio detected")
            risk_score += 10

    # Deep subdomain structure
    if hostname.count(".") >= 4:
        indicators.append("Deep subdomain structure detected")
        risk_score += 10

    # Very long individual label
    labels = hostname.split(".")

    if any(len(label) > 30 for label in labels):
        indicators.append("Very long domain label detected")
        risk_score += 10

    if risk_score >= 40:
        risk_level = "HIGH"
    elif risk_score >= 20:
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
