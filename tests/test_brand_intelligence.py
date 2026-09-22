from phishguard.core.brand_intelligence import (
    analyze_brand_domain,
    extract_hostname,
    levenshtein_distance,
    normalize_brand_candidate,
)


def test_extract_hostname():
    assert (
        extract_hostname("https://example.com/login")
        == "example.com"
    )


def test_normalize_brand_candidate():
    assert (
        normalize_brand_candidate("g00gle")
        == "google"
    )


def test_levenshtein_distance():
    assert levenshtein_distance("google", "gogle") == 1


def test_safe_domain():
    result = analyze_brand_domain(
        "https://example.com"
    )

    assert result["classification"] == "SAFE"
    assert result["risk_score"] == 0


def test_google_typosquatting():
    result = analyze_brand_domain(
        "https://gogle.com"
    )

    assert result["classification"] == "SUSPICIOUS"
    assert result["risk_score"] > 0
    assert result["typosquatting_matches"]


def test_character_substitution_typosquatting():
    result = analyze_brand_domain(
        "https://g00gle.com"
    )

    assert result["classification"] == "SUSPICIOUS"
    assert result["typosquatting_matches"]


def test_brand_login_domain():
    result = analyze_brand_domain(
        "https://google-login.com"
    )

    assert result["classification"] == "SUSPICIOUS"
    assert result["suspicious_keywords"]


def test_paypal_typosquatting():
    result = analyze_brand_domain(
        "https://paypa1.com"
    )

    assert result["classification"] == "SUSPICIOUS"
    assert result["typosquatting_matches"]


def test_normal_domain_with_login_path():
    result = analyze_brand_domain(
        "https://example.com/login"
    )

    assert result["classification"] == "SAFE"
