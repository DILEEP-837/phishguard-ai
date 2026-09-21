from urllib.parse import urlparse
import ipaddress
import re
import tldextract

from phishguard.core.risk_engine import calculate_risk


def clean_input_url(url: str) -> str:
    """
    Clean common Markdown-formatted URLs.

    Example:
        [https://example.com](https://example.com)

    becomes:
        https://example.com
    """

    url = (url or "").strip()

    markdown_match = re.fullmatch(
        r"\[.*?\]\((https?://[^)]+)\)",
        url
    )

    if markdown_match:
        url = markdown_match.group(1)

    return url


def analyze_url(url: str):
    """
    PHISHGUARD AI URL Analyzer V2.3

    Pipeline:

        Input
          ↓
        Clean URL
          ↓
        Parse URL
          ↓
        Domain/IP analysis
          ↓
        Risk Engine
          ↓
        Final result
    """

    # =========================================================
    # 1. CLEAN INPUT
    # =========================================================

    url = clean_input_url(url)

    result = {
        "url": url,
        "https": False,
        "hostname": None,
        "domain": None,
        "tld": None,
        "is_ip": False,
        "suspicious": False,
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
    }

    # =========================================================
    # 2. ADD SCHEME IF MISSING
    # =========================================================

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    result["url"] = url

    # =========================================================
    # 3. HTTPS
    # =========================================================

    result["https"] = parsed.scheme == "https"

    # =========================================================
    # 4. HOSTNAME
    # =========================================================

    result["hostname"] = parsed.hostname

    if not parsed.hostname:

        result["suspicious"] = True
        result["risk_score"] = 100
        result["risk_level"] = "CRITICAL"

        result["indicators"].append(
            "Invalid hostname"
        )

        return result

    hostname = parsed.hostname.lower()

    # =========================================================
    # 5. DOMAIN / TLD
    # =========================================================

    extracted = tldextract.extract(hostname)

    result["domain"] = extracted.domain
    result["tld"] = extracted.suffix

    # =========================================================
    # 6. IP ADDRESS DETECTION
    # =========================================================

    try:

        ipaddress.ip_address(hostname)

        result["is_ip"] = True

    except ValueError:

        result["is_ip"] = False

    # =========================================================
    # 7. RISK ENGINE
    # =========================================================

    risk_analysis = calculate_risk(result)

    result["risk_score"] = risk_analysis["score"]
    result["risk_level"] = risk_analysis["level"]
    result["indicators"] = risk_analysis["indicators"]

    # =========================================================
    # 8. FINAL SUSPICIOUS DECISION
    # =========================================================

    result["suspicious"] = (
        risk_analysis["score"] > 0
    )

    return result
