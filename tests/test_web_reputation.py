from phishguard.core.web_reputation import (
    analyze_domain_labels,
    analyze_domain_reputation,
    analyze_hosting_reputation,
    analyze_infrastructure,
    calculate_numeric_ratio,
    extract_hostname,
    get_registered_domain,
    get_tld,
    is_ip_address,
)


def test_extract_hostname():
    assert (
        extract_hostname("https://example.com/login")
        == "example.com"
    )


def test_extract_hostname_without_scheme():
    assert (
        extract_hostname("example.com/login")
        == "example.com"
    )


def test_extract_hostname_empty():
    assert extract_hostname("") is None


def test_is_ip_address_ipv4():
    assert is_ip_address("192.168.1.10") is True


def test_is_ip_address_domain():
    assert is_ip_address("example.com") is False


def test_get_registered_domain():
    assert (
        get_registered_domain("login.example.com")
        == "example.com"
    )


def test_get_registered_domain_ip():
    assert (
        get_registered_domain("192.168.1.10")
        == "192.168.1.10"
    )


def test_get_tld():
    assert get_tld("example.com") == "com"


def test_get_tld_missing():
    assert get_tld(None) is None


def test_numeric_ratio():
    ratio = calculate_numeric_ratio("abc123")

    assert ratio == 0.5


def test_normal_domain_is_safe():
    result = analyze_domain_reputation("example.com")

    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"
    assert result["indicators"] == []


def test_ip_address_domain():
    result = analyze_domain_reputation("192.168.1.10")

    assert result["is_ip"] is True
    assert result["risk_score"] == 15
    assert result["risk_level"] == "LOW"
    assert (
        "URL uses an IP address instead of a domain name"
        in result["indicators"]
    )


def test_suspicious_tld():
    result = analyze_domain_reputation("example.xyz")

    assert result["risk_score"] == 10
    assert result["risk_level"] == "LOW"
    assert any(
        "higher-risk TLD" in indicator
        for indicator in result["indicators"]
    )


def test_punycode_domain():
    result = analyze_domain_reputation(
        "xn--example-9za.com"
    )

    assert result["risk_score"] >= 15
    assert any(
        "Punycode" in indicator
        for indicator in result["indicators"]
    )


def test_deep_subdomain():
    result = analyze_domain_reputation(
        "a.b.c.example.com"
    )

    assert any(
        "Deep subdomain" in indicator
        for indicator in result["indicators"]
    )


def test_numeric_heavy_hostname():
    result = analyze_domain_reputation(
        "1234567890.example.com"
    )

    assert any(
        "numeric" in indicator.lower()
        for indicator in result["indicators"]
    )


def test_excessive_hyphens():
    result = analyze_domain_reputation(
        "secure-login-account-verify.example.com"
    )

    assert any(
        "hyphens" in indicator
        for indicator in result["indicators"]
    )


def test_suspicious_authentication_label():
    result = analyze_domain_reputation(
        "login.example.com"
    )

    assert any(
        "authentication-related" in indicator
        for indicator in result["indicators"]
    )


def test_free_hosting_platform():
    result = analyze_hosting_reputation(
        "myproject.github.io"
    )

    assert result["hosting_platform"] == "github.io"
    assert result["risk_score"] == 5
    assert result["risk_level"] == "LOW"


def test_normal_hosting():
    result = analyze_hosting_reputation(
        "example.com"
    )

    assert result["hosting_platform"] is None
    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"


def test_domain_labels():
    result = analyze_domain_labels(
        "login.example.com"
    )

    assert "login" in result["suspicious_labels"]
    assert result["risk_score"] == 5
    assert result["risk_level"] == "LOW"


def test_normal_domain_labels():
    result = analyze_domain_labels(
        "example.com"
    )

    assert result["suspicious_labels"] == []
    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"


def test_long_domain_label():
    long_label = "a" * 41 + ".com"

    result = analyze_domain_labels(long_label)

    assert result["risk_score"] == 5
    assert any(
        "long hostname label" in indicator
        for indicator in result["indicators"]
    )


def test_infrastructure_normal_domain():
    result = analyze_infrastructure(
        "https://example.com"
    )

    assert result["success"] is True
    assert result["hostname"] == "example.com"
    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"


def test_infrastructure_suspicious_domain():
    result = analyze_infrastructure(
        "https://login.example.xyz"
    )

    assert result["success"] is True
    assert result["risk_score"] > 0
    assert result["risk_level"] == "LOW"


def test_infrastructure_invalid_url():
    result = analyze_infrastructure(
        "not a valid url"
    )

    assert result["success"] is False
    assert result["risk_score"] == 30
    assert result["risk_level"] == "MEDIUM"
    assert (
        "Unable to determine hostname"
        in result["indicators"]
    )
