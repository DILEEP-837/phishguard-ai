import re
from urllib.parse import urljoin, urlparse


JAVASCRIPT_REDIRECT_PATTERNS = [
    r"window\.location\s*=",
    r"window\.location\.",
    r"location\.href\s*=",
    r"location\.replace\s*\(",
    r"location\.assign\s*\(",
]

COOKIE_PATTERNS = [
    r"document\.cookie",
]

OBFUSCATION_PATTERNS = [
    r"\beval\s*\(",
    r"\batob\s*\(",
    r"fromcharcode\s*\(",
]

JAVASCRIPT_LINK_PATTERN = re.compile(
    r"""(?:href|src)\s*=\s*["']\s*javascript:""",
    re.IGNORECASE,
)

META_REFRESH_PATTERN = re.compile(
    r"""<meta[^>]+http-equiv\s*=\s*["']?refresh["']?""",
    re.IGNORECASE,
)


def _safe_html(html):
    return html if isinstance(html, str) else ""


def detect_javascript_redirect(html):
    html = _safe_html(html)
    return any(
        re.search(pattern, html, re.IGNORECASE)
        for pattern in JAVASCRIPT_REDIRECT_PATTERNS
    )


def detect_meta_refresh(html):
    html = _safe_html(html)
    return bool(META_REFRESH_PATTERN.search(html))


def detect_javascript_links(html):
    html = _safe_html(html)
    return bool(JAVASCRIPT_LINK_PATTERN.search(html))


def detect_cookie_access(html):
    html = _safe_html(html)
    return any(
        re.search(pattern, html, re.IGNORECASE)
        for pattern in COOKIE_PATTERNS
    )


def detect_obfuscated_javascript(html):
    html = _safe_html(html)

    matches = 0

    for pattern in OBFUSCATION_PATTERNS:
        if re.search(pattern, html, re.IGNORECASE):
            matches += 1

    return matches >= 2


def detect_suspicious_combinations(html):
    html = _safe_html(html)

    javascript_redirect = detect_javascript_redirect(html)
    meta_refresh = detect_meta_refresh(html)
    javascript_link = detect_javascript_links(html)
    cookie_access = detect_cookie_access(html)
    obfuscated_javascript = detect_obfuscated_javascript(html)

    hidden_iframe = bool(
        re.search(
            r"<iframe[^>]+(?:display\s*:\s*none|visibility\s*:\s*hidden|"
            r'width\s*=\s*["\']?0["\']?|height\s*=\s*["\']?0["\']?)',
            html,
            re.IGNORECASE,
        )
    )

    suspicious = False
    score = 0
    indicators = []

    if javascript_redirect:
        score += 20
        indicators.append(
            "JavaScript redirect behavior detected"
        )

    if meta_refresh:
        score += 15
        indicators.append(
            "Meta refresh redirect detected"
        )

    if javascript_link:
        score += 15
        indicators.append(
            "JavaScript URL detected"
        )

    if cookie_access:
        score += 15
        indicators.append(
            "JavaScript accesses document cookies"
        )

    if obfuscated_javascript:
        score += 25
        indicators.append(
            "Obfuscated JavaScript behavior detected"
        )

    if hidden_iframe:
        score += 20
        indicators.append(
            "Hidden iframe behavior detected"
        )

    if (
        obfuscated_javascript
        and javascript_redirect
    ):
        score += 20
        indicators.append(
            "Obfuscated JavaScript combined with redirect behavior"
        )

    if (
        cookie_access
        and javascript_redirect
    ):
        score += 20
        indicators.append(
            "Cookie access combined with redirect behavior"
        )

    if (
        hidden_iframe
        and (
            javascript_redirect
            or obfuscated_javascript
        )
    ):
        score += 20
        indicators.append(
            "Hidden iframe combined with suspicious JavaScript"
        )

    if indicators:
        suspicious = True

    score = min(100, score)

    if score >= 70:
        classification = "MALICIOUS"
        risk_level = "HIGH"
    elif score >= 30:
        classification = "SUSPICIOUS"
        risk_level = "MEDIUM"
    elif score > 0:
        classification = "SUSPICIOUS"
        risk_level = "LOW"
    else:
        classification = "SAFE"
        risk_level = "SAFE"

    return {
        "suspicious": suspicious,
        "javascript_redirect": javascript_redirect,
        "meta_refresh": meta_refresh,
        "javascript_links": javascript_link,
        "cookie_access": cookie_access,
        "obfuscated_javascript": obfuscated_javascript,
        "hidden_iframe": hidden_iframe,
        "risk_score": score,
        "risk_level": risk_level,
        "classification": classification,
        "indicators": indicators,
        "evidence": list(indicators),
    }


def analyze_web_behavior(html, page_url=None):
    result = detect_suspicious_combinations(html)

    result["url"] = page_url
    result["hostname"] = None

    if isinstance(page_url, str):
        try:
            parsed = urlparse(page_url)

            if not parsed.netloc:
                parsed = urlparse(
                    "https://" + page_url
                )

            result["hostname"] = (
                parsed.hostname.lower()
                if parsed.hostname
                else None
            )
        except ValueError:
            result["hostname"] = None

    return result
