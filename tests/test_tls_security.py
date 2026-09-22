from unittest.mock import patch, MagicMock

from phishguard.core.tls_security import (
    extract_hostname,
    is_https_url,
    fetch_tls_configuration,
    analyze_tls_version,
    analyze_cipher,
    analyze_tls_security,
)


def test_extract_hostname():
    assert extract_hostname(
        "https://example.com/login"
    ) == "example.com"


def test_extract_hostname_without_scheme():
    assert extract_hostname(
        "example.com"
    ) == "example.com"


def test_extract_hostname_empty():
    assert extract_hostname("") == ""


def test_is_https_url_true():
    assert is_https_url(
        "https://example.com"
    ) is True


def test_is_https_url_false():
    assert is_https_url(
        "http://example.com"
    ) is False


def test_tls_version_tls13():
    result = analyze_tls_version("TLSv1.3")

    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"
    assert result["indicators"] == []


def test_tls_version_tls12():
    result = analyze_tls_version("TLSv1.2")

    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"


def test_tls_version_tls10():
    result = analyze_tls_version("TLSv1")

    assert result["risk_score"] == 40
    assert result["risk_level"] == "HIGH"


def test_tls_version_tls11():
    result = analyze_tls_version("TLSv1.1")

    assert result["risk_score"] == 30
    assert result["risk_level"] == "MEDIUM"


def test_tls_version_unknown():
    result = analyze_tls_version("UNKNOWN")

    assert result["risk_score"] == 20
    assert result["risk_level"] == "LOW"


def test_cipher_secure():
    result = analyze_cipher(
        ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)
    )

    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"


def test_cipher_rc4():
    result = analyze_cipher(
        ("RC4-SHA", "TLSv1", 128)
    )

    assert result["risk_score"] == 40
    assert result["risk_level"] == "HIGH"


def test_cipher_missing():
    result = analyze_cipher(None)

    assert result["risk_score"] == 20
    assert result["risk_level"] == "MEDIUM"


@patch(
    "phishguard.core.tls_security.socket.create_connection"
)
@patch(
    "phishguard.core.tls_security.ssl.create_default_context"
)
def test_fetch_tls_configuration_success(
    mock_context_factory,
    mock_connection,
):
    mock_socket = MagicMock()
    mock_connection.return_value.__enter__.return_value = (
        mock_socket
    )

    context = mock_context_factory.return_value

    tls_socket = MagicMock()
    context.wrap_socket.return_value.__enter__.return_value = (
        tls_socket
    )

    tls_socket.version.return_value = "TLSv1.3"
    tls_socket.cipher.return_value = (
        "TLS_AES_128_GCM_SHA256",
        "TLSv1.3",
        128,
    )

    result = fetch_tls_configuration(
        "example.com"
    )

    assert result["success"] is True
    assert result["tls_version"] == "TLSv1.3"
    assert result["cipher"][0] == "TLS_AES_128_GCM_SHA256"


@patch(
    "phishguard.core.tls_security.socket.create_connection",
)
def test_fetch_tls_configuration_failure(
    mock_connection,
):
    mock_connection.side_effect = OSError(
        "Connection failed"
    )

    result = fetch_tls_configuration(
        "example.com"
    )

    assert result["success"] is False
    assert result["tls_version"] is None


@patch(
    "phishguard.core.tls_security.fetch_tls_configuration"
)
def test_analyze_tls_security_http(
    mock_fetch,
):
    result = analyze_tls_security(
        "http://example.com"
    )

    mock_fetch.assert_not_called()

    assert result["https"] is False
    assert result["risk_score"] == 20


@patch(
    "phishguard.core.tls_security.fetch_tls_configuration"
)
def test_analyze_tls_security_success(
    mock_fetch,
):
    mock_fetch.return_value = {
        "success": True,
        "hostname": "example.com",
        "port": 443,
        "tls_version": "TLSv1.3",
        "cipher": (
            "TLS_AES_128_GCM_SHA256",
            "TLSv1.3",
            128,
        ),
        "error": None,
    }

    result = analyze_tls_security(
        "https://example.com"
    )

    assert result["tls_version"] == "TLSv1.3"
    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"


@patch(
    "phishguard.core.tls_security.fetch_tls_configuration"
)
def test_analyze_tls_security_failure(
    mock_fetch,
):
    mock_fetch.return_value = {
        "success": False,
        "hostname": "example.com",
        "port": 443,
        "tls_version": None,
        "cipher": None,
        "error": "TLS connection failed",
    }

    result = analyze_tls_security(
        "https://example.com"
    )

    assert result["risk_score"] == 30
    assert result["risk_level"] == "MEDIUM"
