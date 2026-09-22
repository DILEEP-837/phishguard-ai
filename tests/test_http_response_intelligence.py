from unittest.mock import Mock, patch

from phishguard.core.http_response_intelligence import (
    analyze_content_type,
    analyze_http_response,
    analyze_response_headers,
    analyze_server_headers,
    analyze_status_code,
    extract_hostname,
    fetch_http_response,
    normalize_content_type,
)


def test_extract_hostname():
    assert extract_hostname("https://example.com/login") == "example.com"


def test_extract_hostname_without_scheme():
    assert extract_hostname("example.com/login") == "example.com"


def test_extract_hostname_invalid():
    assert extract_hostname("") is None


def test_normalize_content_type():
    assert (
        normalize_content_type("text/html; charset=UTF-8")
        == "text/html"
    )


def test_normalize_content_type_missing():
    assert normalize_content_type(None) is None


def test_status_200_is_safe():
    result = analyze_status_code(200)

    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"


def test_status_404_is_low():
    result = analyze_status_code(404)

    assert result["risk_score"] == 3
    assert result["risk_level"] == "LOW"


def test_status_500_is_medium():
    result = analyze_status_code(500)

    assert result["risk_score"] == 10
    assert result["risk_level"] == "MEDIUM"


def test_status_missing():
    result = analyze_status_code(None)

    assert result["risk_score"] == 10
    assert result["risk_level"] == "LOW"
    assert result["indicator"] == "HTTP status code unavailable"


def test_html_content_type_is_safe():
    result = analyze_content_type(
        "text/html; charset=UTF-8",
        "https://example.com",
    )

    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"


def test_missing_content_type():
    result = analyze_content_type(
        None,
        "https://example.com",
    )

    assert result["risk_score"] == 10
    assert result["risk_level"] == "LOW"
    assert "HTTP Content-Type header is missing" in result["indicators"]


def test_risky_content_type():
    result = analyze_content_type(
        "application/octet-stream",
        "https://example.com",
    )

    assert result["risk_score"] == 10
    assert result["risk_level"] == "MEDIUM"


def test_server_disclosure():
    result = analyze_server_headers(
        {
            "Server": "nginx/1.25",
            "X-Powered-By": "PHP/8.3",
        }
    )

    assert result["disclosure_count"] == 2
    assert result["risk_score"] == 8
    assert result["risk_level"] == "LOW"


def test_no_server_disclosure():
    result = analyze_server_headers(
        {
            "Content-Type": "text/html",
        }
    )

    assert result["disclosure_count"] == 0
    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"


def test_location_header():
    result = analyze_response_headers(
        {
            "Location": "https://example.com/login",
        }
    )

    assert result["risk_score"] == 4
    assert result["risk_level"] == "LOW"
    assert len(result["indicators"]) >= 1


def test_attachment_header():
    result = analyze_response_headers(
        {
            "Content-Disposition": "attachment; filename=test.exe",
        }
    )

    assert result["risk_score"] == 3
    assert result["risk_level"] == "LOW"


def test_normal_response_headers():
    result = analyze_response_headers(
        {
            "Content-Type": "text/html",
        }
    )

    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"


@patch("phishguard.core.http_response_intelligence.requests.get")
def test_fetch_http_response_success(mock_get):
    response = Mock()

    response.status_code = 200
    response.reason = "OK"
    response.headers = {
        "Content-Type": "text/html; charset=UTF-8",
        "Server": "nginx",
    }
    response.content = b"<html>Hello</html>"
    response.url = "https://example.com"

    mock_get.return_value = response

    result = fetch_http_response("https://example.com")

    assert result["success"] is True
    assert result["status_code"] == 200
    assert result["content_type"] == "text/html"
    assert result["content_length"] > 0


@patch("phishguard.core.http_response_intelligence.requests.get")
def test_fetch_http_response_failure(mock_get):
    import requests

    mock_get.side_effect = requests.RequestException(
        "Connection failed"
    )

    result = fetch_http_response("https://example.com")

    assert result["success"] is False
    assert result["status_code"] is None
    assert result["error"] == "Connection failed"


@patch(
    "phishguard.core.http_response_intelligence.fetch_http_response"
)
def test_analyze_http_response_safe(mock_fetch):
    mock_fetch.return_value = {
        "success": True,
        "status_code": 200,
        "reason": "OK",
        "headers": {
            "Content-Type": "text/html",
        },
        "content_type": "text/html",
        "content_length": 1000,
        "url": "https://example.com",
        "error": None,
    }

    result = analyze_http_response("https://example.com")

    assert result["success"] is True
    assert result["status_code"] == 200
    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"


@patch(
    "phishguard.core.http_response_intelligence.fetch_http_response"
)
def test_analyze_http_response_with_disclosure(mock_fetch):
    mock_fetch.return_value = {
        "success": True,
        "status_code": 200,
        "reason": "OK",
        "headers": {
            "Content-Type": "text/html",
            "Server": "nginx/1.25",
            "X-Powered-By": "PHP/8.3",
        },
        "content_type": "text/html",
        "content_length": 1000,
        "url": "https://example.com",
        "error": None,
    }

    result = analyze_http_response("https://example.com")

    assert result["success"] is True
    assert result["risk_score"] == 8
    assert result["risk_level"] == "LOW"
    assert len(result["indicators"]) >= 1


@patch(
    "phishguard.core.http_response_intelligence.fetch_http_response"
)
def test_analyze_http_response_failure(mock_fetch):
    mock_fetch.return_value = {
        "success": False,
        "status_code": None,
        "reason": None,
        "headers": {},
        "content_type": None,
        "content_length": 0,
        "url": "https://example.com",
        "error": "Connection failed",
    }

    result = analyze_http_response("https://example.com")

    assert result["success"] is False
    assert result["risk_score"] == 30
    assert result["risk_level"] == "MEDIUM"
    assert "Unable to retrieve HTTP response" in result["indicators"]


def test_analyze_http_response_invalid_url():
    result = analyze_http_response("not a valid url")

    assert result["success"] is False
    assert result["risk_score"] == 30
    assert result["risk_level"] == "MEDIUM"
    assert "Unable to determine hostname" in result["indicators"]
