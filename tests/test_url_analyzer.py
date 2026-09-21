import pytest

from phishguard.core.url_analyzer import analyze_url


# =========================================================
# BASIC URL TESTS
# =========================================================

def test_safe_https_domain():
    result = analyze_url("https://example.com")

    assert result["hostname"] == "example.com"
    assert result["https"] is True
    assert result["is_ip"] is False
    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"


def test_http_url_detected():
    result = analyze_url("http://example.com")

    assert result["https"] is False
    assert result["risk_score"] >= 10
    assert result["suspicious"] is True


# =========================================================
# BRAND / TYPOSQUATTING TESTS
# =========================================================

def test_google_typosquatting():
    result = analyze_url("https://g00gle.com")

    assert result["suspicious"] is True
    assert result["risk_score"] > 0

    assert any(
        "google" in indicator.lower()
        for indicator in result["indicators"]
    )


def test_paypal_typosquatting():
    result = analyze_url("https://paypa1.com")

    assert result["suspicious"] is True
    assert result["risk_score"] > 0

    assert any(
        "paypal" in indicator.lower()
        for indicator in result["indicators"]
    )


# =========================================================
# IP ADDRESS TESTS
# =========================================================

def test_public_ip_detection():
    result = analyze_url("http://8.8.8.8")

    assert result["is_ip"] is True
    assert result["suspicious"] is True
    assert result["risk_score"] > 0


def test_private_ip_detection():
    result = analyze_url("http://192.168.1.10")

    assert result["is_ip"] is True
    assert result["suspicious"] is True
    assert result["risk_score"] > 0


# =========================================================
# SENSITIVE KEYWORD TESTS
# =========================================================

def test_login_keyword():
    result = analyze_url(
        "https://example.com/login"
    )

    assert result["risk_score"] > 0

    assert any(
        "sensitive keywords" in indicator.lower()
        for indicator in result["indicators"]
    )


def test_multiple_sensitive_keywords():
    result = analyze_url(
        "https://example.com/login/verify/password"
    )

    assert result["risk_score"] >= 15

    assert any(
        "sensitive keywords" in indicator.lower()
        for indicator in result["indicators"]
    )


# =========================================================
# URL STRUCTURE TESTS
# =========================================================

def test_long_url():
    long_path = "a" * 160

    result = analyze_url(
        f"https://example.com/{long_path}"
    )

    assert result["suspicious"] is True

    assert any(
        "long" in indicator.lower()
        for indicator in result["indicators"]
    )


def test_many_subdomains():
    result = analyze_url(
        "https://a.b.c.example.com"
    )

    assert result["suspicious"] is True

    assert any(
        "subdomain" in indicator.lower()
        for indicator in result["indicators"]
    )


def test_excessive_subdomains():
    result = analyze_url(
        "https://a.b.c.d.e.example.com"
    )

    assert result["suspicious"] is True

    assert any(
        "subdomain" in indicator.lower()
        for indicator in result["indicators"]
    )


# =========================================================
# @ SYMBOL TEST
# =========================================================

def test_at_symbol():
    result = analyze_url(
        "https://example.com@evil.com"
    )

    assert result["suspicious"] is True
    assert result["risk_score"] >= 20

    assert any(
        "@" in indicator
        for indicator in result["indicators"]
    )


# =========================================================
# ENCODED URL TEST
# =========================================================

def test_encoded_characters():
    result = analyze_url(
        "https://example.com/%41%42%43%44"
    )

    assert result["suspicious"] is True

    assert any(
        "encoded" in indicator.lower()
        for indicator in result["indicators"]
    )


# =========================================================
# DANGEROUS FILE TEST
# =========================================================

def test_dangerous_file_extension():
    result = analyze_url(
        "https://example.com/download.exe"
    )

    assert result["suspicious"] is True

    assert any(
        ".exe" in indicator.lower()
        for indicator in result["indicators"]
    )


# =========================================================
# SUSPICIOUS PORT TEST
# =========================================================

def test_suspicious_port():
    result = analyze_url(
        "https://example.com:8080/login"
    )

    assert result["suspicious"] is True

    assert any(
        "port" in indicator.lower()
        for indicator in result["indicators"]
    )


# =========================================================
# MARKDOWN URL TEST
# =========================================================

def test_markdown_url_cleanup():
    result = analyze_url(
        "[https://example.com](https://example.com)"
    )

    assert result["url"] == "https://example.com"
    assert result["hostname"] == "example.com"


# =========================================================
# URL WITHOUT SCHEME
# =========================================================

def test_missing_scheme():
    result = analyze_url(
        "example.com"
    )

    assert result["hostname"] == "example.com"
    assert result["https"] is False
    assert result["risk_score"] > 0


# =========================================================
# RESULT STRUCTURE
# =========================================================

def test_result_structure():

    result = analyze_url(
        "https://example.com"
    )

    required_keys = [
        "url",
        "https",
        "hostname",
        "domain",
        "tld",
        "is_ip",
        "suspicious",
        "risk_score",
        "risk_level",
        "indicators",
    ]

    for key in required_keys:
        assert key in result
