"""
PHISHGUARD AI
Domain Reputation Intelligence
Version 2.6
"""

HIGH_RISK_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click",
    "work", "zip", "review", "country", "stream", "download",
}

SUSPICIOUS_DNS_PROVIDERS = {
    "duckdns.org", "no-ip.com", "ddns.net", "dynu.net",
    "freedns.afraid.org",
}

SUSPICIOUS_DOMAIN_KEYWORDS = {
    "login", "verify", "verification", "secure", "account",
    "update", "confirm", "support", "wallet", "payment",
    "signin", "bank",
}


def looks_random(domain):
    domain = domain.lower()

    if len(domain) < 8:
        return False

    letters = sum(character.isalpha() for character in domain)
    digits = sum(character.isdigit() for character in domain)

    if letters == 0:
        return False

    if digits / len(domain) >= 0.35:
        return True

    vowels = sum(character in "aeiou" for character in domain)

    return len(domain) >= 14 and vowels <= 2


def analyze_domain_structure(domain):
    indicators = []
    score = 0

    hyphen_count = domain.count("-")
    digit_count = sum(character.isdigit() for character in domain)

    if hyphen_count >= 2:
        score += 5
        indicators.append("Multiple hyphens detected in domain")

    if digit_count >= 3:
        score += 5
        indicators.append("Multiple numeric characters detected in domain")

    return score, indicators


def analyze_domain_keywords(domain):
    domain_lower = domain.lower()
    return [
        keyword
        for keyword in SUSPICIOUS_DOMAIN_KEYWORDS
        if keyword in domain_lower
    ]


def detect_suspicious_dns_provider(hostname):
    hostname = hostname.lower()

    for provider in SUSPICIOUS_DNS_PROVIDERS:
        if hostname == provider or hostname.endswith("." + provider):
            return provider

    return None


def analyze_reputation(hostname, domain, tld):
    hostname = hostname or ""
    domain = domain or ""
    tld = tld or ""

    score = 0
    indicators = []

    if tld.lower() in HIGH_RISK_TLDS:
        score += 15
        indicators.append(f"High-risk TLD detected: .{tld.lower()}")

    dns_provider = detect_suspicious_dns_provider(hostname)

    if dns_provider:
        score += 10
        indicators.append(
            f"Free/dynamic DNS provider detected: {dns_provider}"
        )

    keywords = analyze_domain_keywords(domain)

    if keywords:
        score += min(len(keywords) * 5, 15)
        indicators.append(
            "Security-sensitive keywords detected in domain: "
            + ", ".join(sorted(keywords))
        )

    structure_score, structure_indicators = analyze_domain_structure(domain)
    score += structure_score
    indicators.extend(structure_indicators)

    if looks_random(domain):
        score += 10
        indicators.append("Domain appears randomly generated or unusual")

    if len(domain) >= 25:
        score += 5
        indicators.append("Unusually long domain name detected")

    score = min(score, 40)

    return {
        "score": score,
        "indicators": indicators,
    }
