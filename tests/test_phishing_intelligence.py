from phishguard.core.phishing_intelligence import (
    extract_hostname,
    hostnames_match,
    is_external_form,
    analyze_phishing_content,
    analyze_phishing,
)


def test_extract_hostname():
    assert extract_hostname("https://example.com/login") == "example.com"


def test_extract_hostname_without_scheme():
    assert extract_hostname("example.com/login") == "example.com"


def test_hostnames_match():
    assert hostnames_match(
        "https://example.com/login",
        "https://example.com/submit",
    )


def test_external_form():
    assert is_external_form(
        "https://victim.example/login",
        "https://collector.example/submit",
    )


def test_login_page_alone_is_not_phishing():
    result = analyze_phishing_content({
        "forms": 1,
        "login_forms": 1,
        "password_fields": 1,
        "username_fields": 1,
        "email_fields": 0,
        "external_forms": 0,
        "external_cred_forms": 0,
    })

    assert result["classification"] != "PHISHING"
    assert result["risk_score"] > 0


def test_external_credential_form_is_phishing():
    result = analyze_phishing_content({
        "forms": 1,
        "login_forms": 1,
        "password_fields": 1,
        "username_fields": 1,
        "email_fields": 1,
        "external_forms": 1,
        "external_cred_forms": 1,
    })

    assert result["classification"] == "PHISHING"
    assert result["risk_score"] >= 60
    assert result["confidence"] >= 85


def test_password_and_external_form_are_strong_evidence():
    result = analyze_phishing_content({
        "forms": 1,
        "login_forms": 1,
        "password_fields": 1,
        "username_fields": 1,
        "email_fields": 1,
        "external_forms": 1,
        "external_cred_forms": 0,
    })

    assert result["classification"] == "PHISHING"
    assert result["confidence"] >= 80


def test_external_noncredential_form_is_not_automatically_phishing():
    result = analyze_phishing_content({
        "forms": 1,
        "login_forms": 0,
        "password_fields": 0,
        "username_fields": 0,
        "email_fields": 0,
        "external_forms": 1,
        "external_cred_forms": 0,
    })

    assert result["classification"] != "PHISHING"


def test_safe_page():
    result = analyze_phishing_content({
        "forms": 0,
        "login_forms": 0,
        "password_fields": 0,
        "username_fields": 0,
        "email_fields": 0,
        "external_forms": 0,
        "external_cred_forms": 0,
    })

    assert result["classification"] == "SAFE"
    assert result["risk_score"] == 0
    assert result["confidence"] == 0


def test_main_analyze_phishing():
    result = analyze_phishing(
        "https://example.com/login",
        {
            "forms": 1,
            "login_forms": 1,
            "password_fields": 1,
            "username_fields": 1,
            "email_fields": 1,
            "external_forms": 1,
            "external_cred_forms": 1,
        },
    )

    assert result["hostname"] == "example.com"
    assert result["classification"] == "PHISHING"
    assert result["risk_score"] >= 60
