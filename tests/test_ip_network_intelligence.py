from phishguard.core.ip_network_intelligence import (
    extract_hostname,
    is_ip_address,
    is_ipv4,
    is_ipv6,
    classify_ip,
    analyze_ip_addresses,
    analyze_ip_hostname_relationship,
    analyze_ip_network,
)


def test_extract_hostname():
    assert extract_hostname("https://example.com/login") == "example.com"


def test_extract_hostname_without_scheme():
    assert extract_hostname("example.com/login") == "example.com"


def test_extract_hostname_lowercase():
    assert extract_hostname("https://EXAMPLE.COM") == "example.com"


def test_invalid_hostname():
    assert extract_hostname("not a valid url") is None


def test_ipv4_detection():
    assert is_ip_address("192.168.1.10") is True
    assert is_ipv4("192.168.1.10") is True
    assert is_ipv6("192.168.1.10") is False


def test_ipv6_detection():
    assert is_ip_address("2001:db8::1") is True
    assert is_ipv6("2001:db8::1") is True
    assert is_ipv4("2001:db8::1") is False


def test_invalid_ip():
    assert is_ip_address("999.999.999.999") is False


def test_private_ip_classification():
    result = classify_ip("192.168.1.10")

    assert result["version"] == 4
    assert result["private"] is True
    assert result["classification"] == "private"


def test_loopback_ip_classification():
    result = classify_ip("127.0.0.1")

    assert result["loopback"] is True
    assert result["classification"] == "loopback"


def test_global_ip_classification():
    result = classify_ip("8.8.8.8")

    assert result["global"] is True
    assert result["classification"] == "global"


def test_invalid_ip_classification():
    result = classify_ip("not-an-ip")

    assert result["classification"] == "invalid"


def test_analyze_global_addresses():
    result = analyze_ip_addresses([
        "8.8.8.8",
        "1.1.1.1",
    ])

    assert result["address_count"] == 2
    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"


def test_analyze_private_address():
    result = analyze_ip_addresses([
        "192.168.1.10",
    ])

    assert result["private_addresses"] == ["192.168.1.10"]
    assert result["risk_score"] == 15
    assert result["risk_level"] == "LOW"


def test_analyze_loopback_address():
    result = analyze_ip_addresses([
        "127.0.0.1",
    ])

    assert result["loopback_addresses"] == ["127.0.0.1"]
    assert result["risk_score"] == 25
    assert result["risk_level"] == "LOW"


def test_multiple_ip_addresses():
    addresses = [
        "1.1.1.1",
        "8.8.8.8",
        "9.9.9.9",
        "208.67.222.222",
        "8.26.56.26",
    ]

    result = analyze_ip_addresses(addresses)

    assert result["address_count"] == 5
    assert result["risk_score"] == 10
    assert "Multiple IP addresses detected" in result["indicators"]


def test_excessive_ip_addresses():
    addresses = [
        "1.1.1.1",
        "2.2.2.2",
        "3.3.3.3",
        "4.4.4.4",
        "5.5.5.5",
        "6.6.6.6",
        "7.7.7.7",
        "8.8.8.8",
        "9.9.9.9",
        "11.11.11.11",
    ]

    result = analyze_ip_addresses(addresses)

    assert result["address_count"] == 10
    assert result["risk_score"] == 20
    assert "Excessive IP address count detected" in result["indicators"]


def test_direct_ip_relationship():
    result = analyze_ip_hostname_relationship(
        "https://8.8.8.8"
    )

    assert result["direct_ip"] is True
    assert result["ip_version"] == 4
    assert result["risk_score"] == 20
    assert "URL uses a direct IP address instead of a hostname" in result["indicators"]


def test_private_direct_ip_relationship():
    result = analyze_ip_hostname_relationship(
        "http://192.168.1.10"
    )

    assert result["direct_ip"] is True
    assert result["risk_score"] == 35
    assert "Direct URL uses a private IP address" in result["indicators"]


def test_loopback_direct_ip_relationship():
    result = analyze_ip_hostname_relationship(
        "http://127.0.0.1"
    )

    assert result["direct_ip"] is True
    assert result["risk_score"] == 45
    assert "Direct URL uses a loopback IP address" in result["indicators"]


def test_invalid_relationship():
    result = analyze_ip_hostname_relationship(
        "not a valid url"
    )

    assert result["risk_score"] == 30
    assert result["risk_level"] == "MEDIUM"


def test_complete_direct_ip_analysis():
    result = analyze_ip_network(
        "https://8.8.8.8"
    )

    assert result["success"] is True
    assert result["direct_ip"] is True
    assert result["hostname"] == "8.8.8.8"
    assert result["resolution"]["addresses"] == ["8.8.8.8"]
    assert result["risk_score"] == 20
    assert result["risk_level"] == "LOW"


def test_complete_private_ip_analysis():
    result = analyze_ip_network(
        "http://192.168.1.10"
    )

    assert result["direct_ip"] is True
    assert result["risk_score"] == 50
    assert result["risk_level"] == "MEDIUM"


def test_complete_global_ip_analysis():
    result = analyze_ip_network(
        "https://8.8.8.8"
    )

    assert result["ip_analysis"]["global"] if "global" in result["ip_analysis"] else True
    assert result["risk_score"] == 20


def test_dns_resolution_mock(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (2, 1, 6, "", ("93.184.216.34", 0)),
            (2, 1, 6, "", ("93.184.216.34", 0)),
        ]

    monkeypatch.setattr(
        "phishguard.core.ip_network_intelligence.socket.getaddrinfo",
        fake_getaddrinfo,
    )

    result = analyze_ip_network("https://example.com")

    assert result["success"] is True
    assert result["resolution"]["addresses"] == ["93.184.216.34"]
    assert result["risk_score"] == 0


def test_dns_resolution_failure(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        raise OSError("DNS failure")

    monkeypatch.setattr(
        "phishguard.core.ip_network_intelligence.socket.getaddrinfo",
        fake_getaddrinfo,
    )

    result = analyze_ip_network("https://example.com")

    assert result["success"] is False
    assert result["risk_score"] == 10
    assert "Hostname did not resolve to an IP address" in result["indicators"]


def test_ipv6_network_analysis():
    result = analyze_ip_network(
        "https://2001:db8::1"
    )

    assert result["direct_ip"] is True
    assert result["resolution"]["ipv6_addresses"] == ["2001:db8::1"]
    assert result["relationship"]["ip_version"] == 6
