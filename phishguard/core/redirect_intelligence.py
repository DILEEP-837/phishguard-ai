"""
PhishGuard AI - V2.7 Redirect Intelligence
"""

from urllib.parse import urlparse, parse_qs, unquote, urljoin
import base64
import re
import requests


# =========================================================
# PHASE 1
# URL-BASED REDIRECT INTELLIGENCE
# =========================================================

REDIRECT_PARAMETERS = {
    "url",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "redir",
    "next",
    "target",
    "destination",
    "dest",
    "return",
    "return_url",
    "continue",
    "goto",
    "link",
}


def extract_redirect_targets(url):
    """
    Extract possible redirect destinations from URL parameters.
    """

    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    targets = []

    for key, values in query.items():

        if key.lower() not in REDIRECT_PARAMETERS:
            continue

        for value in values:

            decoded = unquote(value)

            if decoded.startswith(("http://", "https://")):
                targets.append(decoded)

    return targets


def detect_redirect_parameters(url):
    """
    Detect URL parameters commonly used for redirects.
    """

    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    found = []

    for key in query:

        if key.lower() in REDIRECT_PARAMETERS:
            found.append(key)

    return found


def detect_encoded_redirect(url):
    """
    Detect Base64-like encoded redirect destinations.
    """

    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    for key, values in query.items():

        if key.lower() not in REDIRECT_PARAMETERS:
            continue

        for value in values:

            decoded = unquote(value)

            if len(decoded) >= 12 and re.fullmatch(
                r"[A-Za-z0-9+/=_-]+",
                decoded
            ):

                try:

                    padded = decoded + "=" * (
                        -len(decoded) % 4
                    )

                    decoded_bytes = base64.urlsafe_b64decode(
                        padded
                    )

                    decoded_text = decoded_bytes.decode(
                        "utf-8",
                        errors="ignore"
                    )

                    if decoded_text.startswith(
                        ("http://", "https://")
                    ):
                        return True

                except Exception:
                    pass

    return False


def analyze_redirect(url):
    """
    Analyze a URL for redirect-related indicators.
    """

    redirect_parameters = detect_redirect_parameters(url)

    redirect_targets = extract_redirect_targets(url)

    encoded_redirect = detect_encoded_redirect(url)

    risk_score = 0
    indicators = []

    if redirect_parameters:

        risk_score += 20

        indicators.append(
            f"Suspicious redirect parameter(s): "
            f"{', '.join(redirect_parameters)}"
        )

    if redirect_targets:

        source_domain = urlparse(url).netloc

        for target in redirect_targets:

            target_domain = urlparse(target).netloc

            if (
                target_domain
                and target_domain != source_domain
            ):

                risk_score += 30

                indicators.append(
                    f"External redirect target detected: "
                    f"{target_domain}"
                )

    if encoded_redirect:

        risk_score += 30

        indicators.append(
            "Encoded redirect destination detected"
        )

    if risk_score >= 60:
        risk_level = "HIGH"

    elif risk_score >= 30:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return {
        "url": url,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "redirect_parameters": redirect_parameters,
        "redirect_targets": redirect_targets,
        "encoded_redirect": encoded_redirect,
        "indicators": indicators,
    }


# =========================================================
# PHASE 2
# HTTP REDIRECT CHAIN INTELLIGENCE
# =========================================================

REDIRECT_STATUS_CODES = {
    301,
    302,
    303,
    307,
    308,
}


def analyze_redirect_chain(
    url,
    max_redirects=10,
    timeout=5
):
    """
    Follow HTTP redirects manually and analyze the
    complete redirect chain.
    """

    chain = []
    visited = set()

    current_url = url

    risk_score = 0
    indicators = []

    cross_domain_redirect = False
    http_to_https = False
    https_to_http = False
    redirect_loop = False

    try:

        session = requests.Session()

        for _ in range(max_redirects + 1):

            # ---------------------------------------------
            # Redirect loop detection
            # ---------------------------------------------

            if current_url in visited:

                redirect_loop = True

                risk_score += 50

                indicators.append(
                    "Redirect loop detected"
                )

                break

            visited.add(current_url)

            # ---------------------------------------------
            # Request without automatic redirects
            # ---------------------------------------------

            response = session.get(
                current_url,
                allow_redirects=False,
                timeout=timeout,
                headers={
                    "User-Agent": "PhishGuard-AI/2.7"
                }
            )

            status_code = response.status_code

            entry = {
                "url": current_url,
                "status_code": status_code,
            }

            # ---------------------------------------------
            # Normal response
            # ---------------------------------------------

            if status_code not in REDIRECT_STATUS_CODES:

                chain.append(entry)

                break

            # ---------------------------------------------
            # Missing Location header
            # ---------------------------------------------

            location = response.headers.get(
                "Location"
            )

            if not location:

                chain.append(entry)

                break

            entry["location"] = location

            chain.append(entry)

            # ---------------------------------------------
            # Resolve relative redirects
            # ---------------------------------------------

            next_url = urljoin(
                current_url,
                location
            )

            # ---------------------------------------------
            # Domain comparison
            # ---------------------------------------------

            current_domain = urlparse(
                current_url
            ).netloc.lower()

            next_domain = urlparse(
                next_url
            ).netloc.lower()

            if current_domain != next_domain:

                cross_domain_redirect = True

                risk_score += 25

                indicators.append(
                    f"Cross-domain redirect: "
                    f"{current_domain} → {next_domain}"
                )

            # ---------------------------------------------
            # Protocol comparison
            # ---------------------------------------------

            current_scheme = urlparse(
                current_url
            ).scheme.lower()

            next_scheme = urlparse(
                next_url
            ).scheme.lower()

            # HTTP → HTTPS
            if (
                current_scheme == "http"
                and next_scheme == "https"
            ):

                http_to_https = True

            # HTTPS → HTTP
            if (
                current_scheme == "https"
                and next_scheme == "http"
            ):

                https_to_http = True

                risk_score += 30

                indicators.append(
                    "HTTPS to HTTP downgrade detected"
                )

            current_url = next_url

        # ---------------------------------------------
        # Redirect count
        # ---------------------------------------------

        redirect_count = sum(
            1
            for item in chain
            if item["status_code"]
            in REDIRECT_STATUS_CODES
        )

        # ---------------------------------------------
        # Excessive redirects
        # ---------------------------------------------

        excessive_redirects = (
            redirect_count >= 5
        )

        if excessive_redirects:

            risk_score += 25

            indicators.append(
                f"Excessive redirect chain: "
                f"{redirect_count} redirects"
            )

        # ---------------------------------------------
        # Risk classification
        # ---------------------------------------------

        if risk_score >= 60:

            risk_level = "HIGH"

        elif risk_score >= 30:

            risk_level = "MEDIUM"

        else:

            risk_level = "LOW"

        return {
            "original_url": url,
            "final_url": current_url,
            "chain": chain,
            "redirect_count": redirect_count,
            "cross_domain_redirect": cross_domain_redirect,
            "http_to_https": http_to_https,
            "https_to_http": https_to_http,
            "redirect_loop": redirect_loop,
            "excessive_redirects": excessive_redirects,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "indicators": indicators,
            "error": None,
        }

    except requests.RequestException as exc:

        return {
            "original_url": url,
            "final_url": None,
            "chain": chain,
            "redirect_count": len(chain),
            "cross_domain_redirect": cross_domain_redirect,
            "http_to_https": http_to_https,
            "https_to_http": https_to_http,
            "redirect_loop": redirect_loop,
            "excessive_redirects": False,
            "risk_score": risk_score,
            "risk_level": "UNKNOWN",
            "indicators": indicators,
            "error": str(exc),
        }
