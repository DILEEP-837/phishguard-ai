from phishguard.core.reputation_intelligence import analyze_reputation


def test_normal_domain():
    result = analyze_reputation("example.com", "example", "com")
    assert result["score"] == 0
    assert result["indicators"] == []


def test_high_risk_tld():
    result = analyze_reputation("example.xyz", "example", "xyz")
    assert result["score"] > 0
    assert any("high-risk tld" in i.lower() for i in result["indicators"])


def test_suspicious_dns_provider():
    result = analyze_reputation("login.duckdns.org", "login", "org")
    assert result["score"] > 0
    assert any("dns provider" in i.lower() for i in result["indicators"])


def test_suspicious_domain_keyword():
    result = analyze_reputation("secure-login.com", "secure-login", "com")
    assert result["score"] > 0
    assert any("keyword" in i.lower() for i in result["indicators"])


def test_multiple_hyphens():
    result = analyze_reputation(
        "secure-login-account.com",
        "secure-login-account",
        "com",
    )
    assert result["score"] > 0
    assert any("hyphen" in i.lower() for i in result["indicators"])


def test_multiple_numbers():
    result = analyze_reputation("secure123456.com", "secure123456", "com")
    assert result["score"] > 0
    assert any("numeric" in i.lower() for i in result["indicators"])


def test_random_domain():
    result = analyze_reputation(
        "xqztrplmnbv123.com",
        "xqztrplmnbv123",
        "com",
    )
    assert result["score"] > 0
    assert any("random" in i.lower() for i in result["indicators"])
