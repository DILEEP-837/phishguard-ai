from unittest.mock import MagicMock, patch

from phishguard.core.http_security import (
    extract_hostname,
    is_https_url,
    analyze_security_headers,
    analyze_cookies,
    fetch_http_response,
    analyze_http_security,
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


def test_security_headers_all_present():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }

    result = analyze_security_headers(
        headers,
        https=True,
    )

    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"
    assert result["headers_missing"] == []


def test_security_headers_missing():
    result = analyze_security_headers(
        {},
        https=True,
    )

    assert result["risk_score"] == 60
    assert result["risk_level"] == "HIGH"
    assert len(result["headers_missing"]) == 6


def test_security_headers_http():
    result = analyze_security_headers(
        {},
        https=False,
    )

    assert result["risk_score"] == 45
    assert result["risk_level"] == "HIGH"
    assert "Strict-Transport-Security" in result["headers_missing"]


def test_security_headers_partial():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
    }

    result = analyze_security_headers(
        headers,
        https=True,
    )

    assert result["risk_score"] == 35
    assert result["risk_level"] == "MEDIUM"


def test_cookies_secure():
    cookies = [
        {
            "name": "session",
            "secure": True,
            "httponly": True,
            "samesite": "Lax",
        }
    ]

    result = analyze_cookies(
        cookies,
        https=True,
    )

    assert result["cookie_count"] == 1
    assert result["secure_cookies"] == 1
    assert result["httponly_cookies"] == 1
    assert result["samesite_cookies"] == 1
    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"


def test_cookies_insecure():
    cookies = [
        {
            "name": "session",
            "secure": False,
            "httponly": False,
            "samesite": None,
        }
    ]

    result = analyze_cookies(
        cookies,
        https=True,
    )

    assert result["risk_score"] == 20
    assert result["risk_level"] == "MEDIUM"
    assert result["insecure_cookies"] == 1
    assert result["missing_httponly"] == 1
    assert result["missing_samesite"] == 1


def test_cookies_http():
    cookies = [
        {
            "name": "session",
            "secure": False,
            "httponly": False,
            "samesite": None,
        }
    ]

    result = analyze_cookies(
        cookies,
        https=False,
    )

    assert result["risk_score"] == 10
    assert result["risk_level"] == "LOW"


@patch(
    "phishguard.core.http_security.requests.get"
)
def test_fetch_http_response_success(mock_get):
    response = MagicMock()

    response.status_code = 200
    response.headers = {
        "Content-Type": "text/html"
    }
    response.url = "https://example.com"

    cookie = MagicMock()
    cookie.name = "session"
    cookie.secure = True

    response.cookies = [cookie]

    mock_get.return_value = response

    result = fetch_http_response(
        "https://example.com"
    )

    assert result["success"] is True
    assert result["status_code"] == 200
    assert result["url"] == "https://example.com"
    assert result["headers"]["Content-Type"] == "text/html"
    assert result["cookies"][0]["name"] == "session"


@patch(
    "phishguard.core.http_security.requests.get"
)
def test_fetch_http_response_failure(mock_get):
    mock_get.side_effect = Exception(
        "Connection failed"
    )

    result = fetch_http_response(
        "https://example.com"
    )

    assert result["success"] is False
    assert "Connection failed" in result["error"]


@patch(
    "phishguard.core.http_security.fetch_http_response"
)
def test_analyze_http_security_success(mock_fetch):
    mock_fetch.return_value = {
        "success": True,
        "status_code": 200,
        "headers": {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        },
        "cookies": [
            {
                "name": "session",
                "secure": True,
                "httponly": True,
                "samesite": "Lax",
            }
        ],
        "url": "https://example.com",
        "error": None,
    }

    result = analyze_http_security(
        "https://example.com"
    )

    assert result["status_code"] == 200
    assert result["security_headers"]["risk_score"] == 0
    assert result["cookies"]["risk_score"] == 0
    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"


@patch(
    "phishguard.core.http_security.fetch_http_response"
)
def test_analyze_http_security_missing_headers(mock_fetch):
    mock_fetch.return_value = {
        "success": True,
        "status_code": 200,
        "headers": {},
        "cookies": [],
        "url": "https://example.com",
        "error": None,
    }

    result = analyze_http_security(
        "https://example.com"
    )

    assert result["risk_score"] == 60
    assert result["risk_level"] == "HIGH"


@patch(
    "phishguard.core.http_security.fetch_http_response"
)
def test_analyze_http_security_failure(mock_fetch):
    mock_fetch.return_value = {
        "success": False,
        "status_code": None,
        "headers": {},
        "cookies": [],
        "url": "https://example.com",
        "error": "Connection failed",
    }

    result = analyze_http_security(
        "https://example.com"
    )

    assert result["risk_score"] == 30
    assert result["risk_level"] == "MEDIUM"
    assert "Unable to retrieve HTTP response" in result["indicators"]


def test_analyze_http_security_invalid_url():
    result = analyze_http_security("")

    assert result["risk_score"] == 20
    assert result["risk_level"] == "MEDIUM"
    assert "Unable to determine hostname" in result["indicators"]
