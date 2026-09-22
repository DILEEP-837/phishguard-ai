from unittest.mock import patch

from phishguard.core.tls_intelligence import (
    extract_hostname,
    is_https_url,
    fetch_certificate,
    parse_certificate_metadata,
    analyze_certificate_dates,
    analyze_tls,
)


def test_extract_hostname():
    assert (
        extract_hostname("https://Example.COM/login")
        == "example.com"
    )


def test_extract_hostname_without_scheme():
    assert (
        extract_hostname("example.com/path")
        == "example.com"
    )


def test_extract_hostname_empty():
    assert extract_hostname("") == ""


def test_is_https_url_true():
    assert is_https_url("https://example.com") is True


def test_is_https_url_false_for_http():
    assert is_https_url("http://example.com") is False


def test_is_https_url_false_without_scheme():
    assert is_https_url("example.com") is False


@patch(
    "phishguard.core.tls_intelligence.socket.create_connection"
)
def test_fetch_certificate_success(mock_connection):
    mock_socket = mock_connection.return_value.__enter__.return_value

    mock_tls_socket = mock_socket

    mock_context_socket = (
        mock_tls_socket
    )

    certificate = {
        "subject": (
            (
                (
                    "commonName",
                    "example.com",
                ),
            ),
        ),
        "issuer": (
            (
                (
                    "commonName",
                    "Example CA",
                ),
            ),
        ),
        "serialNumber": "123456",
        "version": 3,
        "notBefore": "Jan 01 00:00:00 2026 GMT",
        "notAfter": "Jan 01 00:00:00 2027 GMT",
        "subjectAltName": (
            ("DNS", "example.com"),
        ),
    }

    with patch(
        "phishguard.core.tls_intelligence.ssl.create_default_context"
    ) as mock_context:

        context = mock_context.return_value

        wrapped_socket = (
            context.wrap_socket.return_value
        )

        wrapped_socket.__enter__.return_value.getpeercert.return_value = (
            certificate
        )

        result = fetch_certificate(
            "example.com"
        )

    assert result["success"] is True
    assert result["hostname"] == "example.com"
    assert result["certificate"] == certificate


@patch(
    "phishguard.core.tls_intelligence.socket.create_connection",
    side_effect=OSError("Connection failed"),
)
def test_fetch_certificate_failure(mock_connection):
    result = fetch_certificate(
        "example.com"
    )

    assert result["success"] is False
    assert result["certificate"] is None
    assert "Connection failed" in result["error"]


def test_parse_certificate_metadata():
    certificate = {
        "subject": (
            (
                (
                    "commonName",
                    "example.com",
                ),
            ),
        ),
        "issuer": (
            (
                (
                    "commonName",
                    "Example CA",
                ),
            ),
        ),
        "serialNumber": "123456",
        "version": 3,
        "notBefore": "Jan 01 00:00:00 2026 GMT",
        "notAfter": "Jan 01 00:00:00 2027 GMT",
        "subjectAltName": (
            ("DNS", "example.com"),
            ("DNS", "www.example.com"),
        ),
    }

    result = parse_certificate_metadata(
        certificate
    )

    assert result["subject"] == "example.com"
    assert result["issuer"] == "Example CA"
    assert result["serial_number"] == "123456"
    assert result["version"] == 3
    assert result["not_before"] == "Jan 01 00:00:00 2026 GMT"
    assert result["not_after"] == "Jan 01 00:00:00 2027 GMT"
    assert result["san"] == [
        "example.com",
        "www.example.com",
    ]


def test_certificate_dates_expired():
    result = analyze_certificate_dates(
        "Jan 01 00:00:00 2020 GMT",
        "Jan 01 00:00:00 2021 GMT",
    )

    assert result["expired"] is True
    assert result["valid"] is False
    assert result["risk_score"] == 40
    assert result["risk_level"] == "HIGH"
    assert "Certificate has expired" in result["indicators"]


def test_certificate_dates_not_yet_valid():
    result = analyze_certificate_dates(
        "Jan 01 00:00:00 2030 GMT",
        "Jan 01 00:00:00 2031 GMT",
    )

    assert result["not_yet_valid"] is True
    assert result["valid"] is False
    assert result["risk_score"] == 30
    assert result["risk_level"] == "MEDIUM"


def test_certificate_dates_missing_expiration():
    result = analyze_certificate_dates(
        None,
        None,
    )

    assert result["valid"] is True
    assert result["risk_score"] == 10
    assert result["risk_level"] == "LOW"
    assert (
        "Certificate expiration date unavailable"
        in result["indicators"]
    )


@patch(
    "phishguard.core.tls_intelligence.fetch_certificate"
)
def test_analyze_tls_http_url(mock_fetch):
    result = analyze_tls(
        "http://example.com"
    )

    mock_fetch.assert_not_called()

    assert result["https"] is False
    assert result["certificate_present"] is False
    assert result["risk_score"] == 20
    assert result["risk_level"] == "MEDIUM"
    assert (
        "URL does not use HTTPS"
        in result["indicators"]
    )


@patch(
    "phishguard.core.tls_intelligence.fetch_certificate",
    return_value={
        "success": False,
        "hostname": "example.com",
        "port": 443,
        "certificate": None,
        "error": "TLS connection failed",
    },
)
def test_analyze_tls_certificate_failure(mock_fetch):
    result = analyze_tls(
        "https://example.com"
    )

    assert result["https"] is True
    assert result["certificate_present"] is False
    assert result["risk_score"] == 30
    assert result["risk_level"] == "MEDIUM"
    assert (
        "Unable to retrieve TLS certificate"
        in result["indicators"]
    )


def test_analyze_tls_empty_url():
    result = analyze_tls("")

    assert result["hostname"] == ""
    assert result["risk_score"] == 20
    assert result["risk_level"] == "MEDIUM"
    assert (
        "Unable to extract hostname"
        in result["indicators"]
    )
