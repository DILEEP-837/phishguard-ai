from phishguard.core.threat_correlation import (
    THREAT,
    POSTURE,
    DIAGNOSTIC,
    classify_evidence_type,
    is_posture_indicator,
    is_diagnostic_indicator,
    classify_indicator,
    normalize_indicator,
    deduplicate_indicators,
    extract_module_indicators,
    correlate_evidence,
    detect_threat_patterns,
    calculate_posture_score,
    calculate_diagnostic_count,
    calculate_correlated_score,
    calculate_confidence,
    classify_threat,
    analyze_threat,
)


# =========================================================
# EVIDENCE TYPE
# =========================================================

def test_threat_evidence_type():

    assert (
        classify_evidence_type(
            "Known malicious payload detected"
        )
        == THREAT
    )


def test_posture_evidence_type():

    assert (
        classify_evidence_type(
            "Missing security header: Content-Security-Policy"
        )
        == POSTURE
    )


def test_diagnostic_evidence_type():

    assert (
        classify_evidence_type(
            "Unable to retrieve TLS certificate"
        )
        == DIAGNOSTIC
    )


def test_dns_failure_is_diagnostic():

    assert (
        classify_evidence_type(
            "Hostname did not resolve to an IP address"
        )
        == DIAGNOSTIC
    )


def test_http_failure_is_diagnostic():

    assert (
        classify_evidence_type(
            "Unable to retrieve HTTP response"
        )
        == DIAGNOSTIC
    )


def test_posture_helper():

    assert is_posture_indicator(
        "Server technology disclosed"
    )


def test_diagnostic_helper():

    assert is_diagnostic_indicator(
        "No DNS address information available for correlation"
    )


# =========================================================
# SEVERITY CLASSIFICATION
# =========================================================

def test_classify_critical_indicator():

    assert (
        classify_indicator(
            "Known malicious payload detected"
        )
        == "critical"
    )


def test_classify_high_indicator():

    assert (
        classify_indicator(
            "HTTPS hostname does not match TLS certificate"
        )
        == "high"
    )


def test_classify_medium_indicator():

    assert (
        classify_indicator(
            "Punycode detected in hostname"
        )
        == "medium"
    )


def test_classify_low_indicator():

    assert (
        classify_indicator(
            "Minor network observation"
        )
        == "low"
    )


def test_diagnostic_indicator_has_low_severity():

    assert (
        classify_indicator(
            "Unable to retrieve TLS certificate"
        )
        == "low"
    )


# =========================================================
# NORMALIZATION
# =========================================================

def test_normalize_indicator():

    assert (
        normalize_indicator(
            "  Punycode   Detected  "
        )
        == "punycode detected"
    )


def test_normalize_empty_indicator():

    assert normalize_indicator("   ") is None


def test_deduplicate_indicators():

    result = deduplicate_indicators([
        "Punycode detected",
        "  Punycode   detected  ",
        "Login form detected",
        "Login form detected",
    ])

    assert result == [
        "Punycode detected",
        "Login form detected",
    ]


# =========================================================
# EXTRACTION
# =========================================================

def test_extract_module_indicators():

    modules = {
        "dns": {
            "indicators": [
                "Punycode detected",
                "Deep subdomain detected",
            ]
        },
        "tls": {
            "indicators": [
                "Certificate has expired",
            ]
        },
    }

    result = extract_module_indicators(
        modules
    )

    assert len(result) == 3
    assert result[0]["module"] == "dns"
    assert result[0]["severity"] == "medium"
    assert result[0]["evidence_type"] == THREAT
    assert result[2]["severity"] == "medium"


def test_extract_posture_indicator():

    result = extract_module_indicators({
        "http_security": {
            "indicators": [
                "Missing security header: Strict-Transport-Security"
            ]
        }
    })

    assert len(result) == 1
    assert result[0]["evidence_type"] == POSTURE
    assert result[0]["posture"] is True
    assert result[0]["diagnostic"] is False


def test_extract_diagnostic_indicator():

    result = extract_module_indicators({
        "tls": {
            "indicators": [
                "Unable to retrieve TLS certificate"
            ]
        }
    })

    assert len(result) == 1
    assert result[0]["evidence_type"] == DIAGNOSTIC
    assert result[0]["diagnostic"] is True
    assert result[0]["posture"] is False


def test_extract_ignores_invalid_modules():

    result = extract_module_indicators({
        "dns": None,
        "tls": "invalid",
        "http": {
            "indicators": "Login form detected",
        },
    })

    assert len(result) == 1
    assert result[0]["indicator"] == "Login form detected"


# =========================================================
# CORRELATION
# =========================================================

def test_correlate_duplicate_evidence():

    modules = {
        "dns": {
            "indicators": [
                "Punycode detected",
            ]
        },
        "domain": {
            "indicators": [
                "Punycode detected",
            ]
        },
    }

    result = correlate_evidence(
        modules
    )

    assert len(result) == 1
    assert result[0]["module_count"] == 2
    assert result[0]["modules"] == [
        "dns",
        "domain",
    ]
    assert result[0]["evidence_type"] == THREAT


def test_correlate_different_evidence():

    modules = {
        "dns": {
            "indicators": [
                "Punycode detected",
            ]
        },
        "tls": {
            "indicators": [
                "Certificate has expired",
            ]
        },
    }

    result = correlate_evidence(
        modules
    )

    assert len(result) == 2


def test_correlate_diagnostic_evidence():

    modules = {
        "tls": {
            "indicators": [
                "Unable to retrieve TLS certificate",
            ]
        },
        "http": {
            "indicators": [
                "Unable to retrieve HTTP response",
            ]
        },
    }

    result = correlate_evidence(
        modules
    )

    assert all(
        item["evidence_type"] == DIAGNOSTIC
        for item in result
    )


# =========================================================
# THREAT PATTERNS
# =========================================================

def test_credential_phishing_pattern():

    evidence = [
        {
            "indicator": "Login form detected",
            "severity": "high",
            "modules": ["content"],
            "module_count": 1,
            "evidence_type": THREAT,
        },
        {
            "indicator": "External form destination detected",
            "severity": "high",
            "modules": ["content"],
            "module_count": 1,
            "evidence_type": THREAT,
        },
    ]

    patterns = detect_threat_patterns(
        evidence
    )

    names = [
        item["name"]
        for item in patterns
    ]

    assert "Credential Phishing" in names


def test_tls_anomaly_pattern():

    evidence = [
        {
            "indicator": (
                "HTTPS hostname does not match certificate"
            ),
            "severity": "high",
            "modules": ["tls"],
            "module_count": 1,
            "evidence_type": THREAT,
        }
    ]

    patterns = detect_threat_patterns(
        evidence
    )

    names = [
        item["name"]
        for item in patterns
    ]

    assert "TLS Security Anomaly" in names


def test_suspicious_infrastructure_pattern():

    evidence = [
        {
            "indicator": "Punycode detected",
            "severity": "medium",
            "modules": ["dns"],
            "module_count": 1,
            "evidence_type": THREAT,
        },
        {
            "indicator": (
                "Known hosting provider detected"
            ),
            "severity": "medium",
            "modules": ["reputation"],
            "module_count": 1,
            "evidence_type": THREAT,
        },
    ]

    patterns = detect_threat_patterns(
        evidence
    )

    names = [
        item["name"]
        for item in patterns
    ]

    assert "Suspicious Infrastructure" in names


def test_malware_pattern():

    evidence = [
        {
            "indicator": "Malware payload detected",
            "severity": "critical",
            "modules": ["payload"],
            "module_count": 1,
            "evidence_type": THREAT,
        }
    ]

    patterns = detect_threat_patterns(
        evidence
    )

    names = [
        item["name"]
        for item in patterns
    ]

    assert "Malicious Payload Activity" in names


def test_diagnostic_evidence_does_not_create_pattern():

    evidence = [
        {
            "indicator": (
                "Unable to retrieve TLS certificate"
            ),
            "severity": "low",
            "modules": ["tls"],
            "module_count": 1,
            "evidence_type": DIAGNOSTIC,
        }
    ]

    patterns = detect_threat_patterns(
        evidence
    )

    assert patterns == []


# =========================================================
# POSTURE / DIAGNOSTIC SCORING
# =========================================================

def test_posture_score():

    evidence = [
        {
            "indicator": (
                "Missing security header: "
                "Strict-Transport-Security"
            ),
            "severity": "low",
            "modules": ["http_security"],
            "module_count": 1,
            "evidence_type": POSTURE,
        },
        {
            "indicator": (
                "Server technology disclosed"
            ),
            "severity": "low",
            "modules": ["http_response"],
            "module_count": 1,
            "evidence_type": POSTURE,
        },
    ]

    assert (
        calculate_posture_score(
            evidence
        )
        == 8
    )


def test_diagnostic_count():

    evidence = [
        {
            "indicator": (
                "Unable to retrieve TLS certificate"
            ),
            "severity": "low",
            "modules": ["tls"],
            "module_count": 1,
            "evidence_type": DIAGNOSTIC,
        },
        {
            "indicator": (
                "Unable to retrieve HTTP response"
            ),
            "severity": "low",
            "modules": ["http"],
            "module_count": 1,
            "evidence_type": DIAGNOSTIC,
        },
    ]

    assert (
        calculate_diagnostic_count(
            evidence
        )
        == 2
    )


# =========================================================
# THREAT SCORE
# =========================================================

def test_correlated_score_is_bounded():

    evidence = [
        {
            "indicator": "Known malicious payload",
            "severity": "critical",
            "modules": ["a", "b", "c"],
            "module_count": 3,
            "evidence_type": THREAT,
        }
    ]

    patterns = [
        {
            "name": "Malicious Payload Activity",
            "severity": "critical",
        },
    ]

    score = calculate_correlated_score(
        evidence,
        patterns,
    )

    assert score <= 100


def test_empty_evidence_score():

    assert (
        calculate_correlated_score(
            [],
            []
        )
        == 0
    )


def test_posture_does_not_increase_threat_score():

    evidence = [
        {
            "indicator": (
                "Missing security header: "
                "Content-Security-Policy"
            ),
            "severity": "low",
            "modules": ["http_security"],
            "module_count": 1,
            "evidence_type": POSTURE,
        }
    ]

    assert (
        calculate_correlated_score(
            evidence,
            []
        )
        == 0
    )


def test_diagnostic_does_not_increase_threat_score():

    evidence = [
        {
            "indicator": (
                "Unable to retrieve TLS certificate"
            ),
            "severity": "low",
            "modules": ["tls"],
            "module_count": 1,
            "evidence_type": DIAGNOSTIC,
        }
    ]

    assert (
        calculate_correlated_score(
            evidence,
            []
        )
        == 0
    )


# =========================================================
# CONFIDENCE
# =========================================================

def test_confidence_empty():

    assert calculate_confidence(
        [],
        []
    ) == 0


def test_confidence_increases_with_independent_modules():

    evidence = [
        {
            "indicator": "Punycode detected",
            "severity": "medium",
            "modules": ["dns", "domain"],
            "module_count": 2,
            "evidence_type": THREAT,
        }
    ]

    confidence = calculate_confidence(
        evidence,
        []
    )

    assert confidence > 20


def test_diagnostic_does_not_increase_confidence():

    evidence = [
        {
            "indicator": (
                "Unable to retrieve TLS certificate"
            ),
            "severity": "low",
            "modules": ["tls"],
            "module_count": 1,
            "evidence_type": DIAGNOSTIC,
        }
    ]

    assert (
        calculate_confidence(
            evidence,
            []
        )
        == 0
    )


# =========================================================
# CLASSIFICATION
# =========================================================

def test_safe_classification():

    assert classify_threat(
        0,
        0,
        [],
        [],
    ) == "SAFE"


def test_suspicious_classification():

    evidence = [
        {
            "indicator": "Punycode detected",
            "severity": "medium",
            "modules": ["dns"],
            "module_count": 1,
            "evidence_type": THREAT,
        }
    ]

    assert classify_threat(
        30,
        30,
        evidence,
        [],
    ) == "SUSPICIOUS"


def test_malicious_classification_from_critical_evidence():

    evidence = [
        {
            "indicator": (
                "Known malicious payload detected"
            ),
            "severity": "critical",
            "modules": ["payload"],
            "module_count": 1,
            "evidence_type": THREAT,
        }
    ]

    assert classify_threat(
        30,
        40,
        evidence,
        [],
    ) == "MALICIOUS"


def test_malicious_classification_from_high_score():

    evidence = [
        {
            "indicator": "Strong phishing signal",
            "severity": "high",
            "modules": ["url", "content"],
            "module_count": 2,
            "evidence_type": THREAT,
        }
    ]

    assert classify_threat(
        80,
        70,
        evidence,
        [],
    ) == "MALICIOUS"


def test_diagnostic_evidence_alone_is_safe():

    evidence = [
        {
            "indicator": (
                "Unable to retrieve HTTP response"
            ),
            "severity": "low",
            "modules": ["http"],
            "module_count": 1,
            "evidence_type": DIAGNOSTIC,
        }
    ]

    assert classify_threat(
        0,
        0,
        evidence,
        [],
    ) == "SAFE"


# =========================================================
# COMPLETE ANALYSIS
# =========================================================

def test_complete_safe_analysis():

    result = analyze_threat({
        "url": {
            "indicators": [],
        },
        "dns": {
            "indicators": [],
        },
    })

    assert result["classification"] == "SAFE"
    assert result["risk_score"] == 0
    assert result["confidence"] == 0
    assert result["evidence_count"] == 0
    assert result["threat_evidence_count"] == 0
    assert result["diagnostic_evidence_count"] == 0


def test_complete_diagnostic_analysis():

    result = analyze_threat({
        "tls": {
            "indicators": [
                "Unable to retrieve TLS certificate",
                "Unable to retrieve TLS configuration",
            ]
        },
        "http": {
            "indicators": [
                "Unable to retrieve HTTP response",
            ]
        },
        "dns": {
            "indicators": [
                "Hostname did not resolve to an IP address",
            ]
        },
    })

    assert result["classification"] == "SAFE"
    assert result["risk_score"] == 0
    assert result["confidence"] == 0
    assert result["threat_evidence_count"] == 0
    assert result["diagnostic_evidence_count"] == 4


def test_complete_posture_analysis():

    result = analyze_threat({
        "http_security": {
            "indicators": [
                "Missing security header: Strict-Transport-Security",
                "Missing security header: Content-Security-Policy",
            ]
        },
        "http_response": {
            "indicators": [
                "Server technology disclosed",
            ]
        },
    })

    assert result["classification"] == "SAFE"
    assert result["risk_score"] == 0
    assert result["threat_evidence_count"] == 0
    assert result["posture_evidence_count"] == 3
    assert result["posture_score"] == 13


def test_complete_phishing_analysis():

    result = analyze_threat({
        "content": {
            "indicators": [
                "Login form detected",
                "External form destination detected",
            ]
        },
        "redirect": {
            "indicators": [
                "Cross-domain redirect detected",
            ]
        },
        "tls": {
            "indicators": [
                "HTTPS hostname does not match TLS certificate",
            ]
        },
    })

    assert result["classification"] in {
        "SUSPICIOUS",
        "MALICIOUS",
    }

    assert result["threat_evidence_count"] >= 3
    assert result["risk_score"] > 0
    assert result["confidence"] > 0
