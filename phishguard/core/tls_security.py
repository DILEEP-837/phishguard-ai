import socket
import ssl
from urllib.parse import urlparse


DEFAULT_TIMEOUT = 8


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

        # urlparse treats a hostname without a scheme as a path.
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


def fetch_tls_configuration(
    hostname,
    port=443,
    timeout=DEFAULT_TIMEOUT,
):
    """
    Retrieve negotiated TLS version and cipher suite.

    Certificate verification is intentionally disabled here because
    certificate validity and hostname identity are handled separately
    by tls_intelligence.py.
    """

    result = {
        "success": False,
        "hostname": hostname,
        "port": port,
        "tls_version": None,
        "cipher": None,
        "error": None,
    }

    if not hostname:
        result["error"] = "Hostname unavailable"
        return result

    try:
        context = ssl.create_default_context()

        # TLS configuration analysis must still work when the
        # certificate chain cannot be verified locally.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection(
            (hostname, port),
            timeout=timeout,
        ) as raw_socket:

            with context.wrap_socket(
                raw_socket,
                server_hostname=hostname,
            ) as secure_socket:

                result["success"] = True
                result["tls_version"] = secure_socket.version()
                result["cipher"] = secure_socket.cipher()

    except Exception as exc:
        result["error"] = str(exc)

    return result


def analyze_tls_version(tls_version):
    """
    Analyze negotiated TLS protocol version.
    """

    result = {
        "tls_version": tls_version,
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
    }

    if not tls_version:
        result["risk_score"] = 20
        result["risk_level"] = "LOW"
        result["indicators"].append(
            "TLS version unavailable"
        )
        return result

    normalized = tls_version.upper()

    if normalized in ("SSLV2", "SSLV3"):
        result["risk_score"] = 50
        result["risk_level"] = "HIGH"
        result["indicators"].append(
            f"Weak TLS protocol version: {tls_version}"
        )

    elif normalized == "TLSV1":
        result["risk_score"] = 40
        result["risk_level"] = "HIGH"
        result["indicators"].append(
            f"Deprecated TLS protocol version: {tls_version}"
        )

    elif normalized == "TLSV1.1":
        result["risk_score"] = 30
        result["risk_level"] = "MEDIUM"
        result["indicators"].append(
            f"Deprecated TLS protocol version: {tls_version}"
        )

    elif normalized in ("TLSV1.2", "TLSV1.3"):
        result["risk_score"] = 0
        result["risk_level"] = "SAFE"

    else:
        result["risk_score"] = 20
        result["risk_level"] = "LOW"
        result["indicators"].append(
            f"Unknown TLS protocol version: {tls_version}"
        )

    return result


def analyze_cipher(cipher):
    """
    Analyze negotiated TLS cipher suite.
    """

    result = {
        "cipher": cipher,
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
    }

    if not cipher:
        result["risk_score"] = 20
        result["risk_level"] = "MEDIUM"
        result["indicators"].append(
            "TLS cipher suite unavailable"
        )
        return result

    if isinstance(cipher, (tuple, list)):
        cipher_name = str(cipher[0]) if cipher else ""
    else:
        cipher_name = str(cipher)

    normalized = cipher_name.upper()

    weak_patterns = (
        "RC4",
        "3DES",
        "DES",
        "NULL",
        "EXPORT",
        "RC2",
        "MD5",
    )

    matched = [
        pattern
        for pattern in weak_patterns
        if pattern in normalized
    ]

    if matched:
        result["risk_score"] = 40
        result["risk_level"] = "HIGH"
        result["indicators"].append(
            f"Weak TLS cipher suite detected: {cipher_name}"
        )

    return result


def analyze_tls_security(url, timeout=DEFAULT_TIMEOUT):
    """
    Complete TLS security configuration analysis.
    """

    hostname = extract_hostname(url)
    https = is_https_url(url)

    result = {
        "url": url,
        "hostname": hostname,
        "https": https,
        "tls_version": None,
        "cipher": None,
        "connection": None,
        "version_analysis": None,
        "cipher_analysis": None,
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

    if not https:
        result["risk_score"] = 20
        result["risk_level"] = "MEDIUM"
        result["indicators"].append(
            "URL does not use HTTPS"
        )
        return result

    connection = fetch_tls_configuration(
        hostname,
        timeout=timeout,
    )

    result["connection"] = connection

    if not connection.get("success"):
        result["risk_score"] = 30
        result["risk_level"] = "MEDIUM"
        result["indicators"].append(
            "Unable to retrieve TLS configuration"
        )

        if connection.get("error"):
            result["error"] = connection["error"]

        return result

    result["tls_version"] = connection.get(
        "tls_version"
    )

    result["cipher"] = connection.get(
        "cipher"
    )

    version_analysis = analyze_tls_version(
        result["tls_version"]
    )

    cipher_analysis = analyze_cipher(
        result["cipher"]
    )

    result["version_analysis"] = version_analysis
    result["cipher_analysis"] = cipher_analysis

    indicators = []

    for indicator in (
        version_analysis.get("indicators", [])
        + cipher_analysis.get("indicators", [])
    ):
        if indicator not in indicators:
            indicators.append(indicator)

    result["indicators"] = indicators

    result["risk_score"] = min(
        100,
        version_analysis.get("risk_score", 0)
        + cipher_analysis.get("risk_score", 0),
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
