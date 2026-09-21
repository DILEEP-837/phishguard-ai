import ipaddress
import re
from urllib.parse import urlparse

from phishguard.core.domain_intelligence import analyze_hostname
from phishguard.core.brand_intelligence import analyze_brand_similarity
from phishguard.core.phishing_patterns import detect_phishing_patterns

def calculate_risk(analysis):
    """
    PHISHGUARD AI Risk Engine V2.3

    Returns:
        score
        level
        reasons
        indicators
    """

    url = analysis.get("url", "")
    hostname = analysis.get("hostname", "") or ""

    score = 0
    reasons = []

    parsed = urlparse(url)
    path = parsed.path or ""

    # =========================================================
    # 1. DOMAIN INTELLIGENCE
    # =========================================================

    domain_analysis = analyze_hostname(
        hostname,
        analysis.get("tld", "")
    )

    score += domain_analysis.get("score", 0)

    for indicator in domain_analysis.get("indicators", []):
        reasons.append(indicator)

    # =========================================================
    # 2. BRAND / TYPOSQUATTING INTELLIGENCE
    # =========================================================

    brand_analysis = analyze_brand_similarity(hostname)

    score += brand_analysis.get("score", 0)

    for indicator in brand_analysis.get("indicators", []):
        reasons.append(indicator)
    # =========================================================
    # 3. PHISHING PATTERN INTELLIGENCE V2.4
    # =========================================================

    pattern_analysis = detect_phishing_patterns(
        hostname,
        parsed.path
    )

    score += pattern_analysis.get("score", 0)

    for indicator in pattern_analysis.get("indicators", []):
        reasons.append(indicator)

    # =========================================================
    # 3. IP ADDRESS INTELLIGENCE
    # =========================================================

    if analysis.get("is_ip"):

        try:
            ip = ipaddress.ip_address(hostname)

            if ip.is_loopback:
                score += 3
                reasons.append(
                    "Loopback IP address detected"
                )

            elif ip.is_private:
                score += 5
                reasons.append(
                    "Private IP address used instead of a domain"
                )

            elif ip.is_link_local:
                score += 5
                reasons.append(
                    "Link-local IP address detected"
                )

            else:
                score += 15
                reasons.append(
                    "Public IP address used instead of a domain"
                )

        except ValueError:
            score += 15
            reasons.append(
                "IP address could not be classified"
            )

    # =========================================================
    # 4. HTTPS
    # =========================================================

    if not analysis.get("https"):
        score += 10
        reasons.append(
            "Connection does not use HTTPS"
        )

    # =========================================================
    # 5. @ SYMBOL
    # =========================================================

    if "@" in url:
        score += 20
        reasons.append(
            "URL contains '@' which can obscure the destination"
        )

    # =========================================================
    # 6. URL LENGTH
    # =========================================================

    if len(url) > 150:
        score += 10
        reasons.append(
            "URL is unusually long"
        )

    # =========================================================
    # 7. SUBDOMAIN ANALYSIS
    # =========================================================

    labels = [
        part
        for part in hostname.split(".")
        if part
    ]

    if len(labels) >= 4:
        score += 10
        reasons.append(
            "Multiple subdomain levels detected"
        )

    if len(labels) >= 6:
        score += 10
        reasons.append(
            "Excessive subdomain levels detected"
        )

    # =========================================================
    # 8. SENSITIVE KEYWORDS
    # =========================================================

    sensitive_keywords = [
        "login",
        "signin",
        "verify",
        "verification",
        "password",
        "credential",
        "account",
        "secure",
        "update",
        "confirm",
        "payment",
        "banking",
        "wallet",
        "recover",
        "unlock",
        "suspended",
    ]

    found_keywords = []

    url_lower = url.lower()

    for keyword in sensitive_keywords:
        if keyword in url_lower:
            found_keywords.append(keyword)

    if found_keywords:

        keyword_score = min(
            15,
            len(found_keywords) * 5
        )

        score += keyword_score

        reasons.append(
            "Sensitive keywords detected: "
            + ", ".join(found_keywords)
        )

    # =========================================================
    # 9. SUSPICIOUS PORT
    # =========================================================

    suspicious_ports = {
        21,
        22,
        23,
        25,
        445,
        3389,
        8080,
        8443,
    }

    try:

        port = parsed.port

        if port in suspicious_ports:
            score += 10
            reasons.append(
                f"Potentially unusual port detected: {port}"
            )

    except ValueError:

        score += 10
        reasons.append(
            "Invalid port specification detected"
        )

    # =========================================================
    # 10. ENCODED CHARACTERS
    # =========================================================

    encoded_count = len(
        re.findall(
            r"%[0-9A-Fa-f]{2}",
            url
        )
    )

    if encoded_count >= 3:
        score += 10
        reasons.append(
            "Multiple encoded characters detected"
        )

    # =========================================================
    # 11. DOUBLE SLASH IN PATH
    # =========================================================

    if "//" in path:
        score += 5
        reasons.append(
            "Unusual double slash detected in URL path"
        )

    # =========================================================
    # 12. DANGEROUS FILE EXTENSIONS
    # =========================================================

    dangerous_extensions = [
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".msi",
        ".js",
        ".vbs",
        ".ps1",
    ]

    for extension in dangerous_extensions:

        if path.lower().endswith(extension):

            score += 15

            reasons.append(
                f"Potentially dangerous file type: {extension}"
            )

            break

    # =========================================================
    # 13. SCORE LIMIT
    # =========================================================

    score = min(score, 100)

    # =========================================================
    # 14. RISK LEVEL
    # =========================================================

    if score == 0:
        level = "SAFE"

    elif score < 25:
        level = "LOW"

    elif score < 50:
        level = "MEDIUM"

    elif score < 75:
        level = "HIGH"

    else:
        level = "CRITICAL"

    # =========================================================
    # 15. REMOVE DUPLICATES
    # =========================================================

    unique_reasons = []

    for reason in reasons:

        if reason not in unique_reasons:
            unique_reasons.append(reason)

    # =========================================================
    # 16. FINAL RESULT
    # =========================================================

    return {
        "score": score,
        "level": level,
        "reasons": unique_reasons,
        "indicators": unique_reasons,
    }
