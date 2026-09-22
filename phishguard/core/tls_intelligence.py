import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse


DEFAULT_TIMEOUT = 8


# ============================================================
# BASIC URL / HOSTNAME HELPERS
# ============================================================

def extract_hostname(url):
    if not url:
        return ""

    value = url.strip()

    if "://" not in value:
        value = "https://" + value

    try:
        parsed = urlparse(value)
        return parsed.hostname or ""
    except Exception:
        return ""


def is_https_url(url):
    if not url:
        return False

    value = url.strip().lower()

    return value.startswith("https://")


# ============================================================
# CERTIFICATE FETCHING
# ============================================================

def fetch_certificate(hostname, port=443, timeout=DEFAULT_TIMEOUT):
    if not hostname:
        return {
            "success": False,
            "hostname": hostname,
            "port": port,
            "certificate": None,
            "error": "Empty hostname",
        }

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection(
            (hostname, port),
            timeout=timeout,
        ) as sock:
            with context.wrap_socket(
                sock,
                server_hostname=hostname,
            ) as secure_socket:

                # With mocked/test sockets, getpeercert() returns
                # the normal certificate dictionary.
                certificate = secure_socket.getpeercert()

                if isinstance(certificate, dict) and certificate:
                    return {
                        "success": True,
                        "hostname": hostname,
                        "port": port,
                        "certificate": certificate,
                        "error": None,
                    }

                # With CERT_NONE on real Python/OpenSSL connections,
                # getpeercert() may return {}. Retrieve DER instead.
                certificate_der = secure_socket.getpeercert(
                    binary_form=True
                )

                certificate = None

                if certificate_der:
                    try:
                        pem_certificate = ssl.DER_cert_to_PEM_cert(
                            certificate_der
                        )

                        import tempfile

                        with tempfile.NamedTemporaryFile(
                            mode="w",
                            suffix=".pem",
                            delete=True,
                        ) as cert_file:
                            cert_file.write(pem_certificate)
                            cert_file.flush()

                            certificate = ssl._ssl._test_decode_cert(
                                cert_file.name
                            )
                    except Exception:
                        certificate = None

                return {
                    "success": True,
                    "hostname": hostname,
                    "port": port,
                    "certificate": certificate,
                    "error": None,
                }

    except Exception as exc:
        return {
            "success": False,
            "hostname": hostname,
            "port": port,
            "certificate": None,
            "error": str(exc),
        }


# ============================================================
# CERTIFICATE METADATA
# ============================================================

def _extract_name(entries):
    for entry in entries or []:
        for key, value in entry:
            if key == "commonName":
                return value

    return ""


def parse_certificate_metadata(certificate):
    if not certificate:
        return {
            "subject": "",
            "issuer": "",
            "subject_common_name": "",
            "issuer_common_name": "",
            "serial_number": "",
            "version": None,
            "not_before": "",
            "not_after": "",
            "dns_names": [],
        }

    subject = certificate.get("subject", [])
    issuer = certificate.get("issuer", [])

    subject_common_name = _extract_name(subject)
    issuer_common_name = _extract_name(issuer)

    dns_names = []

    for item in certificate.get("subjectAltName", []):
        if len(item) >= 2 and item[0] == "DNS":
            dns_names.append(item[1])

    return {
        # Compatibility keys expected by the test suite.
        "subject": subject_common_name,
        "issuer": issuer_common_name,

        # Detailed keys used by the identity analyzer.
        "subject_common_name": subject_common_name,
        "issuer_common_name": issuer_common_name,

        "serial_number": certificate.get("serialNumber", ""),
        "version": certificate.get("version"),
        "not_before": certificate.get("notBefore", ""),
        "not_after": certificate.get("notAfter", ""),
        "dns_names": dns_names,
        "san": dns_names,
    }


# ============================================================
# CERTIFICATE DATE INTELLIGENCE
# ============================================================

def analyze_certificate_dates(not_before, not_after):
    indicators = []
    risk_score = 0

    now = datetime.now(timezone.utc)

    def parse_date(value):
        if not value:
            return None

        try:
            parsed = datetime.strptime(
                value,
                "%b %d %H:%M:%S %Y %Z",
            )
            return parsed.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None

    start_date = parse_date(not_before)
    expiry_date = parse_date(not_after)

    expired = False
    not_yet_valid = False
    days_remaining = None

    if expiry_date is None:
        risk_score += 10
        indicators.append(
            "Certificate expiration date unavailable"
        )
    else:
        if expiry_date < now:
            expired = True
            indicators.append("Certificate has expired")
            risk_score += 40
        else:
            days_remaining = (
                expiry_date - now
            ).total_seconds() / 86400

            if days_remaining <= 30:
                indicators.append(
                    "Certificate expires within 30 days"
                )
                risk_score += 10

    if start_date is not None and start_date > now:
        not_yet_valid = True
        indicators.append(
            "Certificate is not yet valid"
        )
        risk_score += 30

    valid = not expired and not not_yet_valid

    if expired:
        risk_level = "HIGH"
    elif not_yet_valid:
        risk_level = "MEDIUM"
    elif risk_score > 0:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"

    return {
        "risk_score": min(risk_score, 100),
        "risk_level": risk_level,
        "indicators": indicators,
        "valid": valid,
        "expired": expired,
        "not_yet_valid": not_yet_valid,
        "days_remaining": days_remaining,
    }


# ============================================================
# CERTIFICATE HOSTNAME MATCHING
# ============================================================

def _normalize_hostname(hostname):
    if not hostname:
        return ""

    return hostname.strip().lower().rstrip(".")


def _hostname_matches_pattern(hostname, pattern):
    """
    Match a hostname against a certificate DNS SAN/CN.

    Exact match:
        example.com == example.com

    Wildcard:
        *.example.com matches login.example.com

    Wildcards are restricted to the left-most label.
    """
    hostname = _normalize_hostname(hostname)
    pattern = _normalize_hostname(pattern)

    if not hostname or not pattern:
        return False

    if pattern == hostname:
        return True

    if not pattern.startswith("*."):
        return False

    suffix = pattern[1:]  # .example.com

    if not hostname.endswith(suffix):
        return False

    hostname_labels = hostname.split(".")
    suffix_labels = suffix.lstrip(".").split(".")

    # Wildcard should represent exactly one hostname label.
    return len(hostname_labels) == len(suffix_labels) + 1


def analyze_certificate_identity(hostname, metadata):
    """
    Analyze whether the certificate identity matches the requested
    hostname.

    Priority:
        1. DNS SAN
        2. Common Name fallback
    """

    hostname = _normalize_hostname(hostname)

    if not hostname:
        return {
            "risk_score": 20,
            "indicators": ["Certificate hostname is missing"],
            "hostname_match": False,
            "match_source": None,
            "self_signed": False,
        }

    common_name = _normalize_hostname(
        metadata.get("subject_common_name", "")
    )

    issuer_common_name = _normalize_hostname(
        metadata.get("issuer_common_name", "")
    )

    dns_names = [
        _normalize_hostname(name)
        for name in metadata.get("dns_names", [])
        if name
    ]

    indicators = []
    risk_score = 0

    # --------------------------------------------------------
    # HOSTNAME MATCHING
    # --------------------------------------------------------

    hostname_match = False
    match_source = None

    if dns_names:
        for name in dns_names:
            if _hostname_matches_pattern(hostname, name):
                hostname_match = True
                match_source = "subjectAltName"
                break

        if not hostname_match:
            indicators.append(
                "Certificate hostname does not match any DNS SAN"
            )
            risk_score += 40

    elif common_name:
        if _hostname_matches_pattern(hostname, common_name):
            hostname_match = True
            match_source = "commonName"
        else:
            indicators.append(
                "Certificate hostname does not match Common Name"
            )
            risk_score += 40

    else:
        indicators.append(
            "Certificate contains no DNS SAN or Common Name"
        )
        risk_score += 40

    # --------------------------------------------------------
    # SELF-SIGNED INDICATOR
    # --------------------------------------------------------

    self_signed = bool(
        common_name
        and issuer_common_name
        and common_name == issuer_common_name
    )

    if self_signed:
        indicators.append(
            "Certificate subject and issuer Common Name are identical"
        )
        risk_score += 20

    # --------------------------------------------------------
    # MISSING SAN
    # --------------------------------------------------------

    if not dns_names:
        indicators.append(
            "Certificate does not contain DNS Subject Alternative Names"
        )

        # Do not add another score when the certificate already
        # has a hostname identity problem. The hostname mismatch
        # / missing identity score remains the primary risk.
        if hostname_match:
            risk_score += 5

    return {
        "risk_score": min(risk_score, 100),
        "indicators": indicators,
        "hostname_match": hostname_match,
        "match_source": match_source,
        "self_signed": self_signed,
        "common_name": metadata.get("subject_common_name", ""),
        "issuer_common_name": metadata.get(
            "issuer_common_name",
            "",
        ),
        "dns_names": metadata.get("dns_names", []),
    }


# ============================================================
# FULL TLS ANALYSIS
# ============================================================

def analyze_tls(url, timeout=DEFAULT_TIMEOUT):
    hostname = extract_hostname(url)

    result = {
        "url": url,
        "hostname": hostname,
        "https": is_https_url(url),
        "certificate": None,
        "certificate_present": False,
        "certificate_metadata": None,
        "date_analysis": None,
        "identity_analysis": None,
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
    }

    if not hostname:
        result["risk_score"] = 20
        result["indicators"].append(
            "Unable to extract hostname"
        )
        result["risk_level"] = "MEDIUM"
        return result

    # HTTP does not have TLS certificate intelligence.
    if not result["https"]:
        result["risk_score"] = 20
        result["indicators"].append(
            "URL does not use HTTPS"
        )
        result["risk_level"] = "MEDIUM"
        return result

    certificate_result = fetch_certificate(
        hostname,
        timeout=timeout,
    )

    result["certificate"] = certificate_result
    result["certificate_present"] = bool(
        certificate_result.get("certificate")
    )

    if not certificate_result["success"] or not result["certificate_present"]:
        result["risk_score"] = 30
        result["indicators"].append(
            "Unable to retrieve TLS certificate"
        )
        result["risk_level"] = "MEDIUM"
        return result

    metadata = parse_certificate_metadata(
        certificate_result["certificate"]
    )

    result["certificate_metadata"] = metadata

    date_analysis = analyze_certificate_dates(
        metadata.get("not_before", ""),
        metadata.get("not_after", ""),
    )

    identity_analysis = analyze_certificate_identity(
        hostname,
        metadata,
    )

    result["date_analysis"] = date_analysis
    result["identity_analysis"] = identity_analysis

    result["indicators"] = list(
        dict.fromkeys(
            date_analysis["indicators"]
            + identity_analysis["indicators"]
        )
    )

    result["risk_score"] = min(
        date_analysis["risk_score"]
        + identity_analysis["risk_score"],
        100,
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
