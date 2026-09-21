from phishguard.core.phishing_patterns import detect_phishing_patterns


def test_brand_phishing_hostname():
    result = detect_phishing_patterns(
        "google-login.example.com"
    )

    assert result["score"] > 0

    assert any(
        "brand" in indicator.lower()
        for indicator in result["indicators"]
    )


def test_paypal_verification_hostname():
    result = detect_phishing_patterns(
        "paypal-verify.example.com"
    )

    assert result["score"] > 0

    assert any(
        "brand" in indicator.lower()
        for indicator in result["indicators"]
    )


def test_multiple_phishing_terms():
    result = detect_phishing_patterns(
        "secure-login-verify.example.com"
    )

    assert result["score"] > 0

    assert any(
        "multiple" in indicator.lower()
        for indicator in result["indicators"]
    )


def test_phishing_term_in_subdomain():
    result = detect_phishing_patterns(
        "login.example.com"
    )

    assert result["score"] > 0

    assert any(
        "subdomain" in indicator.lower()
        for indicator in result["indicators"]
    )


def test_multiple_path_terms():
    result = detect_phishing_patterns(
        "example.com",
        "/login/verify/password"
    )

    assert result["score"] > 0

    assert any(
        "path" in indicator.lower()
        for indicator in result["indicators"]
    )


def test_brand_sensitive_path():
    result = detect_phishing_patterns(
        "paypal.example.com",
        "/account/password"
    )

    assert result["score"] > 0

    assert any(
        "sensitive" in indicator.lower()
        for indicator in result["indicators"]
    )


def test_normal_domain():
    result = detect_phishing_patterns(
        "example.com"
    )

    assert result["score"] == 0
    assert result["indicators"] == []


def test_normal_google_domain():
    result = detect_phishing_patterns(
        "google.com"
    )

    assert result["score"] == 0
    assert result["indicators"] == []


def test_empty_hostname():
    result = detect_phishing_patterns("")

    assert result["score"] == 0
    assert result["indicators"] == []
