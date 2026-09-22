from unittest.mock import patch

from phishguard.core.dns_intelligence import (
    extract_hostname,
    resolve_a_records,
    resolve_aaaa_records,
    resolve_cname,
    resolve_mx_records,
    resolve_ns_records,
    analyze_dns,
)


def test_extract_hostname():
    assert extract_hostname("https://Example.COM/login") == "example.com"


def test_extract_hostname_without_scheme():
    assert extract_hostname("example.com/path") == "example.com"


@patch(
    "phishguard.core.dns_intelligence.socket.getaddrinfo",
    return_value=[
        (2, 1, 6, "", ("93.184.216.34", 0)),
    ],
)
def test_resolve_a_records(mock_getaddrinfo):
    result = resolve_a_records("example.com")

    assert result == ["93.184.216.34"]
    mock_getaddrinfo.assert_called_once()


@patch(
    "phishguard.core.dns_intelligence.socket.getaddrinfo",
    return_value=[
        (10, 1, 6, "", ("2001:db8::1", 0, 0, 0)),
    ],
)
def test_resolve_aaaa_records(mock_getaddrinfo):
    result = resolve_aaaa_records("example.com")

    assert result == ["2001:db8::1"]
    mock_getaddrinfo.assert_called_once()


@patch(
    "phishguard.core.dns_intelligence.socket.gethostbyname_ex",
    return_value=(
        "example.com",
        ["alias.example.com"],
        ["93.184.216.34"],
    ),
)
def test_resolve_cname(mock_gethostbyname_ex):
    result = resolve_cname("example.com")

    assert result == ["alias.example.com"]


@patch(
    "phishguard.core.dns_intelligence.dns.resolver.resolve"
)
def test_resolve_mx_records(mock_resolve):
    answer1 = type(
        "MXAnswer",
        (),
        {"exchange": "mail.example.com.", "preference": 10},
    )()

    answer2 = type(
        "MXAnswer",
        (),
        {"exchange": "backup.example.com.", "preference": 20},
    )()

    mock_resolve.return_value = [answer2, answer1]

    result = resolve_mx_records("example.com")

    assert result == [
        {
            "priority": 10,
            "exchange": "mail.example.com",
        },
        {
            "priority": 20,
            "exchange": "backup.example.com",
        },
    ]


@patch(
    "phishguard.core.dns_intelligence.dns.resolver.resolve"
)
def test_resolve_ns_records(mock_resolve):
    answer1 = type(
        "NSAnswer",
        (),
        {"target": "ns2.example.com."},
    )()

    answer2 = type(
        "NSAnswer",
        (),
        {"target": "ns1.example.com."},
    )()

    mock_resolve.return_value = [answer1, answer2]

    result = resolve_ns_records("example.com")

    assert result == [
        "ns1.example.com",
        "ns2.example.com",
    ]


@patch(
    "phishguard.core.dns_intelligence.resolve_cname",
    return_value=[],
)
@patch(
    "phishguard.core.dns_intelligence.resolve_aaaa_records",
    return_value=[],
)
@patch(
    "phishguard.core.dns_intelligence.resolve_a_records",
    return_value=["93.184.216.34"],
)
@patch(
    "phishguard.core.dns_intelligence.resolve_mx_records",
    return_value=[
        {
            "priority": 10,
            "exchange": "mail.example.com",
        }
    ],
)
@patch(
    "phishguard.core.dns_intelligence.resolve_ns_records",
    return_value=[
        "ns1.example.com",
        "ns2.example.com",
    ],
)
def test_analyze_dns_resolved(
    mock_ns,
    mock_mx,
    mock_a,
    mock_aaaa,
    mock_cname,
):
    result = analyze_dns("https://example.com")

    assert result["hostname"] == "example.com"
    assert result["resolved"] is True
    assert result["a_records"] == ["93.184.216.34"]
    assert result["mx_records"][0]["exchange"] == "mail.example.com"
    assert result["ns_records"] == [
        "ns1.example.com",
        "ns2.example.com",
    ]
    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"


@patch(
    "phishguard.core.dns_intelligence.resolve_cname",
    return_value=[],
)
@patch(
    "phishguard.core.dns_intelligence.resolve_aaaa_records",
    return_value=[],
)
@patch(
    "phishguard.core.dns_intelligence.resolve_a_records",
    return_value=[],
)
@patch(
    "phishguard.core.dns_intelligence.resolve_mx_records",
    return_value=[],
)
@patch(
    "phishguard.core.dns_intelligence.resolve_ns_records",
    return_value=[],
)
def test_analyze_dns_resolution_failure(
    mock_ns,
    mock_mx,
    mock_a,
    mock_aaaa,
    mock_cname,
):
    result = analyze_dns("https://nonexistent.invalid")

    assert result["resolved"] is False
    assert result["risk_score"] == 30
    assert result["risk_level"] == "MEDIUM"
    assert "DNS resolution failed" in result["indicators"]


def test_analyze_dns_empty_hostname():
    result = analyze_dns("")

    assert result["hostname"] == ""
    assert result["resolved"] is False
    assert result["risk_level"] == "MEDIUM"
    assert "Unable to extract hostname" in result["indicators"]


@patch(
    "phishguard.core.dns_intelligence.resolve_cname",
    return_value=[],
)
@patch(
    "phishguard.core.dns_intelligence.resolve_aaaa_records",
    return_value=[],
)
@patch(
    "phishguard.core.dns_intelligence.resolve_a_records",
    return_value=["1.2.3.4"],
)
@patch(
    "phishguard.core.dns_intelligence.resolve_mx_records",
    return_value=[],
)
@patch(
    "phishguard.core.dns_intelligence.resolve_ns_records",
    return_value=["ns1.example.com"],
)
def test_missing_mx_indicator(
    mock_ns,
    mock_mx,
    mock_a,
    mock_aaaa,
    mock_cname,
):
    result = analyze_dns("https://example.com")

    assert result["resolved"] is True
    assert "No MX records detected" in result["indicators"]


@patch(
    "phishguard.core.dns_intelligence.resolve_cname",
    return_value=[],
)
@patch(
    "phishguard.core.dns_intelligence.resolve_aaaa_records",
    return_value=[],
)
@patch(
    "phishguard.core.dns_intelligence.resolve_a_records",
    return_value=["1.2.3.4"],
)
@patch(
    "phishguard.core.dns_intelligence.resolve_mx_records",
    return_value=[
        {
            "priority": 10,
            "exchange": "mail.example.com",
        }
    ],
)
@patch(
    "phishguard.core.dns_intelligence.resolve_ns_records",
    return_value=[],
)
def test_missing_ns_indicator(
    mock_ns,
    mock_mx,
    mock_a,
    mock_aaaa,
    mock_cname,
):
    result = analyze_dns("https://example.com")

    assert result["resolved"] is True
    assert "No NS records detected" in result["indicators"]


from phishguard.core.dns_intelligence import analyze_dns_infrastructure


def test_dns_infrastructure_safe():
    result = analyze_dns_infrastructure(
        "example.com",
        a_records=["93.184.216.34"],
        ns_records=["ns1.example.com", "ns2.example.com"],
    )

    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"
    assert result["indicators"] == []


def test_dns_infrastructure_ip_hostname():
    result = analyze_dns_infrastructure("192.168.1.10")

    assert result["risk_score"] == 35
    assert result["risk_level"] == "MEDIUM"
    assert "Hostname appears to be an IPv4 address" in result["indicators"]


def test_dns_infrastructure_numeric_hostname():
    result = analyze_dns_infrastructure("login12345.example.com")

    assert "Hostname contains many numeric characters" in result["indicators"]
    assert result["risk_score"] >= 10


def test_dns_infrastructure_excessive_records():
    result = analyze_dns_infrastructure(
        "example.com",
        a_records=[f"192.0.2.{i}" for i in range(1, 12)],
        ns_records=[
            "ns1.example.com",
            "ns2.example.com",
            "ns3.example.com",
            "ns4.example.com",
            "ns5.example.com",
            "ns6.example.com",
            "ns7.example.com",
        ],
    )

    assert "Excessive IPv4 addresses detected" in result["indicators"]
    assert "Large number of nameservers detected" in result["indicators"]
    assert result["risk_score"] >= 25


def test_dns_infrastructure_long_hostname():
    hostname = "this-is-an-unusually-long-subdomain-name.example.com"

    result = analyze_dns_infrastructure(hostname)

    assert "Unusually long hostname detected" in result["indicators"]
    assert result["risk_score"] >= 10


def test_dns_infrastructure_deep_subdomain():
    result = analyze_dns_infrastructure(
        "a.b.c.d.e.example.com"
    )

    assert "Deep subdomain structure detected" in result["indicators"]
    assert result["risk_score"] >= 10


from phishguard.core.dns_intelligence import analyze_domain_structure


def test_domain_structure_safe():
    result = analyze_domain_structure("example.com")

    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"
    assert result["indicators"] == []


def test_domain_structure_punycode():
    result = analyze_domain_structure("xn--example-9za.com")

    assert result["risk_score"] >= 15
    assert "Punycode/IDN domain detected" in result["indicators"]


def test_domain_structure_excessive_hyphens():
    result = analyze_domain_structure(
        "secure-login-account-verification-required.example.com"
    )

    assert "Excessive hyphens detected" in result["indicators"]
    assert result["risk_score"] >= 10


def test_domain_structure_numeric_ratio():
    result = analyze_domain_structure(
        "login123456789.example.com"
    )

    assert "High numeric character ratio detected" in result["indicators"]
    assert result["risk_score"] >= 10


def test_domain_structure_deep_subdomain():
    result = analyze_domain_structure(
        "a.b.c.d.e.example.com"
    )

    assert "Deep subdomain structure detected" in result["indicators"]
    assert result["risk_score"] >= 10


def test_domain_structure_long_label():
    hostname = (
        "abcdefghijklmnopqrstuvwxyz12345.example.com"
    )

    result = analyze_domain_structure(hostname)

    assert "Very long domain label detected" in result["indicators"]
    assert result["risk_score"] >= 10


def test_domain_structure_empty():
    result = analyze_domain_structure("")

    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"
    assert result["indicators"] == []
