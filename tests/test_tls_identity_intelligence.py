from phishguard.core.tls_intelligence import (
    analyze_certificate_identity,
)


def make_metadata(
    common_name="example.com",
    issuer_common_name="Example CA",
    dns_names=None,
):
    if dns_names is None:
        dns_names = ["example.com"]

    return {
        "subject_common_name": common_name,
        "issuer_common_name": issuer_common_name,
        "serial_number": "123456",
        "version": 3,
        "not_before": "Jan 01 00:00:00 2026 GMT",
        "not_after": "Jan 01 00:00:00 2027 GMT",
        "dns_names": dns_names,
    }


def test_exact_san_match():
    result = analyze_certificate_identity(
        "example.com",
        make_metadata(
            dns_names=["example.com"],
        ),
    )

    assert result["hostname_match"] is True
    assert result["match_source"] == "subjectAltName"
    assert result["risk_score"] == 0


def test_san_mismatch():
    result = analyze_certificate_identity(
        "evil.example.com",
        make_metadata(
            dns_names=["example.com"],
        ),
    )

    assert result["hostname_match"] is False
    assert result["risk_score"] == 40
    assert any(
        "does not match" in item
        for item in result["indicators"]
    )


def test_wildcard_san_match():
    result = analyze_certificate_identity(
        "login.example.com",
        make_metadata(
            dns_names=["*.example.com"],
        ),
    )

    assert result["hostname_match"] is True
    assert result["match_source"] == "subjectAltName"


def test_wildcard_does_not_match_multiple_levels():
    result = analyze_certificate_identity(
        "login.secure.example.com",
        make_metadata(
            dns_names=["*.example.com"],
        ),
    )

    assert result["hostname_match"] is False


def test_common_name_fallback():
    result = analyze_certificate_identity(
        "example.com",
        make_metadata(
            common_name="example.com",
            dns_names=[],
        ),
    )

    assert result["hostname_match"] is True
    assert result["match_source"] == "commonName"
    assert result["risk_score"] == 5


def test_common_name_mismatch():
    result = analyze_certificate_identity(
        "example.com",
        make_metadata(
            common_name="evil.com",
            dns_names=[],
        ),
    )

    assert result["hostname_match"] is False
    assert result["risk_score"] == 40


def test_self_signed_indicator():
    result = analyze_certificate_identity(
        "example.com",
        make_metadata(
            common_name="example.com",
            issuer_common_name="example.com",
            dns_names=["example.com"],
        ),
    )

    assert result["self_signed"] is True
    assert result["risk_score"] == 20
    assert any(
        "subject and issuer" in item
        for item in result["indicators"]
    )


def test_missing_san_indicator():
    result = analyze_certificate_identity(
        "example.com",
        make_metadata(
            common_name="example.com",
            dns_names=[],
        ),
    )

    assert any(
        "does not contain DNS Subject Alternative Names" in item
        for item in result["indicators"]
    )


def test_missing_identity():
    result = analyze_certificate_identity(
        "example.com",
        make_metadata(
            common_name="",
            issuer_common_name="",
            dns_names=[],
        ),
    )

    assert result["hostname_match"] is False
    assert result["risk_score"] == 40


def test_empty_hostname():
    result = analyze_certificate_identity(
        "",
        make_metadata(),
    )

    assert result["hostname_match"] is False
    assert result["risk_score"] == 20
