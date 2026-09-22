from phishguard.core.relationship_intelligence import (
    analyze_dns_hostname_relationship,
    analyze_https_consistency,
    analyze_hostname_redirect_relationship,
    analyze_relationships,
    analyze_tls_hostname_relationship,
    extract_hostname,
    hostnames_match,
    is_https_url,
    is_subdomain,
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


def test_extract_hostname_invalid():
    assert extract_hostname("") is None


def test_is_https_url():
    assert is_https_url("https://example.com") is True


def test_is_https_url_http():
    assert is_https_url("http://example.com") is False


def test_hostnames_match():
    assert hostnames_match(
        "Example.COM",
        "example.com",
    ) is True


def test_hostnames_do_not_match():
    assert hostnames_match(
        "example.com",
        "evil.com",
    ) is False


def test_is_subdomain():
    assert is_subdomain(
        "login.example.com",
        "example.com",
    ) is True


def test_is_not_subdomain():
    assert is_subdomain(
        "example.com",
        "example.com",
    ) is False


def test_same_domain_redirect():
    result = analyze_hostname_redirect_relationship(
        "https://example.com",
        "https://example.com/login",
    )

    assert result["same_domain"] is True
    assert result["cross_domain"] is False
    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"


def test_cross_domain_redirect():
    result = analyze_hostname_redirect_relationship(
        "https://example.com",
        "https://evil.com/login",
    )

    assert result["cross_domain"] is True
    assert result["risk_score"] == 10
    assert result["risk_level"] == "LOW"
    assert (
        "Redirect destination uses a different hostname"
        in result["indicators"]
    )


def test_related_subdomain_redirect():
    result = analyze_hostname_redirect_relationship(
        "https://example.com",
        "https://login.example.com",
    )

    assert result["cross_domain"] is True
    assert result["subdomain_redirect"] is True
    assert result["risk_score"] == 5


def test_invalid_redirect_relationship():
    result = analyze_hostname_redirect_relationship(
        "",
        "https://example.com",
    )

    assert result["risk_score"] == 10
    assert result["risk_level"] == "LOW"


def test_tls_hostname_match():
    result = analyze_tls_hostname_relationship(
        "https://example.com",
        {
            "certificate_present": True,
            "hostname_match": True,
        },
    )

    assert result["certificate_present"] is True
    assert result["hostname_match"] is True
    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"


def test_tls_hostname_mismatch():
    result = analyze_tls_hostname_relationship(
        "https://example.com",
        {
            "certificate_present": True,
            "hostname_match": False,
        },
    )

    assert result["risk_score"] == 30
    assert result["risk_level"] == "MEDIUM"
    assert (
        "HTTPS hostname does not match the TLS certificate"
        in result["indicators"]
    )


def test_https_without_certificate():
    result = analyze_tls_hostname_relationship(
        "https://example.com",
        {
            "certificate_present": False,
        },
    )

    assert result["risk_score"] == 10
    assert result["risk_level"] == "LOW"


def test_http_tls_relationship():
    result = analyze_tls_hostname_relationship(
        "http://example.com",
        {},
    )

    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"


def test_dns_with_records():
    result = analyze_dns_hostname_relationship(
        "https://example.com",
        {
            "a_records": ["93.184.216.34"],
        },
    )

    assert result["dns_available"] is True
    assert result["resolved_addresses"] == [
        "93.184.216.34"
    ]
    assert result["risk_score"] == 0


def test_dns_without_records():
    result = analyze_dns_hostname_relationship(
        "https://example.com",
        {},
    )

    assert result["dns_available"] is False
    assert result["risk_score"] == 5
    assert result["risk_level"] == "LOW"


def test_dns_multiple_record_types():
    result = analyze_dns_hostname_relationship(
        "https://example.com",
        {
            "a_records": ["1.2.3.4"],
            "aaaa_records": ["2001:db8::1"],
        },
    )

    assert result["dns_available"] is True
    assert len(result["resolved_addresses"]) == 2


def test_https_consistency_with_tls():
    result = analyze_https_consistency(
        "https://example.com",
        {
            "certificate_present": True,
        },
    )

    assert result["https"] is True
    assert result["tls_available"] is True
    assert result["risk_score"] == 0


def test_https_consistency_without_tls():
    result = analyze_https_consistency(
        "https://example.com",
        {},
    )

    assert result["https"] is True
    assert result["tls_available"] is False
    assert result["risk_score"] == 10
    assert result["risk_level"] == "LOW"


def test_http_consistency():
    result = analyze_https_consistency(
        "http://example.com",
        {},
    )

    assert result["https"] is False
    assert result["risk_score"] == 0


def test_complete_safe_relationship():
    result = analyze_relationships(
        "https://example.com",
        redirect_result={
            "final_url": "https://example.com/login",
        },
        dns_result={
            "a_records": ["93.184.216.34"],
        },
        tls_result={
            "certificate_present": True,
            "hostname_match": True,
        },
    )

    assert result["success"] is True
    assert result["hostname"] == "example.com"
    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"


def test_complete_cross_domain_relationship():
    result = analyze_relationships(
        "https://example.com",
        redirect_result={
            "final_url": "https://evil.com/login",
        },
        dns_result={
            "a_records": ["1.2.3.4"],
        },
        tls_result={
            "certificate_present": True,
            "hostname_match": True,
        },
    )

    assert result["success"] is True
    assert result["risk_score"] == 10
    assert result["risk_level"] == "LOW"
    assert (
        "Redirect destination uses a different hostname"
        in result["indicators"]
    )


def test_complete_tls_mismatch_relationship():
    result = analyze_relationships(
        "https://example.com",
        redirect_result={
            "final_url": "https://example.com",
        },
        dns_result={
            "a_records": ["93.184.216.34"],
        },
        tls_result={
            "certificate_present": True,
            "hostname_match": False,
        },
    )

    assert result["risk_score"] == 30
    assert result["risk_level"] == "MEDIUM"


def test_complete_invalid_relationship():
    result = analyze_relationships(
        "not a valid url",
    )

    assert result["success"] is False
    assert result["risk_score"] == 30
    assert result["risk_level"] == "MEDIUM"
    assert (
        "Unable to determine hostname for relationship analysis"
        in result["indicators"]
    )
