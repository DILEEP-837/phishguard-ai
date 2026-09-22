import requests
from urllib.parse import urlparse


DEFAULT_TIMEOUT = 8


SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security",
        "risk": 15,
    },
    "content-security-policy": {
        "name": "Content-Security-Policy",
        "risk": 15,
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "risk": 10,
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "risk": 10,
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "risk": 5,
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "risk": 5,
    },
}


def extract_hostname(url):
    """
    Extract hostname from a URL.
    """
    if not url:
        return ""

    try:
        parsed = urlparse(url)

        if parsed.hostname:
            return parsed.hostname.lower()

        parsed = urlparse("//" + url)

        if parsed.hostname:
            return parsed.hostname.lower()

    except Exception:
        pass

    return ""


def is_https_url(url):
    """
    Return True when the URL uses HTTPS.
    """
    if not url:
        return False

    try:
        return urlparse(url).scheme.lower() == "https"
    except Exception:
        return False


def fetch_http_response(url, timeout=DEFAULT_TIMEOUT):
    """
    Fetch an HTTP response for security-header analysis.
    """

    result = {
        "success": False,
        "status_code": None,
        "headers": {},
        "cookies": [],
        "url": url,
        "error": None,
    }

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={
                "User-Agent": "PhishGuard-AI/3.0"
            },
        )

        result["success"] = True
        result["status_code"] = response.status_code
        result["headers"] = dict(response.headers)
        result["url"] = response.url

        for cookie in response.cookies:
            result["cookies"].append({
                "name": cookie.name,
                "secure": bool(cookie.secure),
                "httponly": False,
                "samesite": None,
            })

        return result

    except Exception as exc:
        result["error"] = str(exc)
        return result


def analyze_security_headers(headers, https=True):
    """
    Analyze HTTP security headers.
    """

    normalized = {
        str(key).lower(): str(value)
        for key, value in (headers or {}).items()
    }

    result = {
        "headers_present": [],
        "headers_missing": [],
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
    }

    for key, metadata in SECURITY_HEADERS.items():

        if key in normalized and normalized[key].strip():

            result["headers_present"].append(
                metadata["name"]
            )

        else:

            result["headers_missing"].append(
                metadata["name"]
            )

            # HSTS is relevant specifically to HTTPS.
            if key == "strict-transport-security" and not https:
                continue

            result["risk_score"] += metadata["risk"]

            result["indicators"].append(
                f"Missing security header: {metadata['name']}"
            )

    result["risk_score"] = min(
        result["risk_score"],
        60,
    )

    if result["risk_score"] >= 40:
        result["risk_level"] = "HIGH"
    elif result["risk_score"] >= 20:
        result["risk_level"] = "MEDIUM"
    elif result["risk_score"] > 0:
        result["risk_level"] = "LOW"
    else:
        result["risk_level"] = "SAFE"

    return result


def analyze_cookies(cookies, https=True):
    """
    Analyze cookie security attributes.
    """

    result = {
        "cookie_count": len(cookies or []),
        "secure_cookies": 0,
        "insecure_cookies": 0,
        "httponly_cookies": 0,
        "missing_httponly": 0,
        "samesite_cookies": 0,
        "missing_samesite": 0,
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
    }

    for cookie in cookies or []:

        name = cookie.get("name", "unknown")
        secure = bool(cookie.get("secure", False))
        httponly = bool(cookie.get("httponly", False))
        samesite = cookie.get("samesite")

        if secure:
            result["secure_cookies"] += 1
        else:
            result["insecure_cookies"] += 1

            if https:
                result["risk_score"] += 10

                result["indicators"].append(
                    f"Cookie missing Secure flag: {name}"
                )

        if httponly:
            result["httponly_cookies"] += 1
        else:
            result["missing_httponly"] += 1

            result["risk_score"] += 5

            result["indicators"].append(
                f"Cookie missing HttpOnly flag: {name}"
            )

        if samesite:
            result["samesite_cookies"] += 1
        else:
            result["missing_samesite"] += 1

            result["risk_score"] += 5

            result["indicators"].append(
                f"Cookie missing SameSite attribute: {name}"
            )

    result["risk_score"] = min(
        result["risk_score"],
        40,
    )

    if result["risk_score"] >= 30:
        result["risk_level"] = "HIGH"
    elif result["risk_score"] >= 15:
        result["risk_level"] = "MEDIUM"
    elif result["risk_score"] > 0:
        result["risk_level"] = "LOW"
    else:
        result["risk_level"] = "SAFE"

    return result


def analyze_http_security(url, timeout=DEFAULT_TIMEOUT):
    """
    Complete V3.0 Phase 3 HTTP Security Intelligence analysis.
    """

    hostname = extract_hostname(url)
    https = is_https_url(url)

    result = {
        "url": url,
        "hostname": hostname,
        "https": https,
        "connection": None,
        "status_code": None,
        "final_url": url,
        "security_headers": None,
        "cookies": None,
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
    }

    if not hostname:
        result["risk_score"] = 20
        result["risk_level"] = "MEDIUM"
        result["indicators"].append(
            "Unable to determine hostname"
        )
        return result

    response_result = fetch_http_response(
        url,
        timeout=timeout,
    )

    result["connection"] = response_result
    result["status_code"] = response_result.get(
        "status_code"
    )
    result["final_url"] = response_result.get(
        "url",
        url,
    )

    if not response_result.get("success"):

        result["risk_score"] = 30
        result["risk_level"] = "MEDIUM"

        result["indicators"].append(
            "Unable to retrieve HTTP response"
        )

        if response_result.get("error"):
            result["error"] = response_result["error"]

        return result

    security_headers = analyze_security_headers(
        response_result.get("headers", {}),
        https=https,
    )

    cookies = analyze_cookies(
        response_result.get("cookies", []),
        https=https,
    )

    result["security_headers"] = security_headers
    result["cookies"] = cookies

    indicators = []

    for indicator in (
        security_headers.get("indicators", [])
        + cookies.get("indicators", [])
    ):
        if indicator not in indicators:
            indicators.append(indicator)

    result["indicators"] = indicators

    result["risk_score"] = min(
        100,
        security_headers.get("risk_score", 0)
        + cookies.get("risk_score", 0),
    )

    if result["risk_score"] >= 80:
        result["risk_level"] = "CRITICAL"
    elif result["risk_score"] >= 60:
        result["risk_level"] = "HIGH"
    elif result["risk_score"] >= 30:
        result["risk_level"] = "MEDIUM"
    elif result["risk_score"] > 0:
        result["risk_level"] = "LOW"
    else:
        result["risk_level"] = "SAFE"

    return result
