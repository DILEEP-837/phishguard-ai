"""
PhishGuard AI
V3.0 Phase 9A - Threat Correlation & Evidence Quality Engine
"""

from collections import defaultdict


# =========================================================
# EVIDENCE WEIGHTS
# =========================================================

EVIDENCE_WEIGHTS = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 5,
}


# =========================================================
# EVIDENCE CATEGORIES
# =========================================================

THREAT = "threat"
POSTURE = "posture"
DIAGNOSTIC = "diagnostic"


POSTURE_PATTERNS = [
    "missing security header",
    "server technology disclosed",
    "chunked transfer encoding detected",
    "hostname successfully resolved to ip address",
]


DIAGNOSTIC_PATTERNS = [
    "resource not found",
    "unable to retrieve",
    "unable to retrieve http response",
    "unable to retrieve tls certificate",
    "unable to retrieve tls configuration",
    "no dns address information",
    "hostname did not resolve",
    "no correlated tls information",
    "https url has no certificate information available",
    "no mx records detected",
    "no ns records detected",
    "dns resolution failed",
]


def classify_evidence_type(indicator):
    """Classify an indicator as threat, posture, or diagnostic."""

    if not isinstance(indicator, str):
        return DIAGNOSTIC

    text = indicator.lower().strip()

    if any(
        pattern in text
        for pattern in POSTURE_PATTERNS
    ):
        return POSTURE

    if any(
        pattern in text
        for pattern in DIAGNOSTIC_PATTERNS
    ):
        return DIAGNOSTIC

    return THREAT


def is_posture_indicator(indicator):
    """Backward-compatible posture check."""

    return (
        classify_evidence_type(indicator)
        == POSTURE
    )


def is_diagnostic_indicator(indicator):
    """Return True when an indicator is diagnostic only."""

    return (
        classify_evidence_type(indicator)
        == DIAGNOSTIC
    )


# =========================================================
# INDICATOR CLASSIFICATION
# =========================================================

def classify_indicator(indicator):
    """Classify threat evidence severity."""

    if not isinstance(indicator, str):
        return "low"

    text = indicator.lower()

    if (
        classify_evidence_type(indicator)
        != THREAT
    ):
        return "low"

    critical_patterns = [
        "malware",
        "payload",
        "credential harvesting",
        "credential theft",
        "known malicious",
        "active phishing",
    ]

    high_patterns = [
        "certificate mismatch",
        "hostname does not match",
        "cross-domain redirect",
        "external form",
        "password",
        "login form",
        "phishing",
        "suspicious redirect",
        "loopback ip",
        "private ip",
        "typosquatting",
        "possible typosquatting",
        "brand impersonation",
        "potentially dangerous file extension",
        "suspicious double file extension",
        "executable mime type detected",
        "script mime type detected",
    ]

    medium_patterns = [
        "punycode",
        "idn",
        "redirect",
        "suspicious hosting",
        "hosting provider",
        "cloud infrastructure",
        "direct ip",
        "reserved ip",
        "weak cipher",
        "expired",
        "obfuscation",
        "suspicious",
    ]

    for pattern in critical_patterns:
        if pattern in text:
            return "critical"

    for pattern in high_patterns:
        if pattern in text:
            return "high"

    for pattern in medium_patterns:
        if pattern in text:
            return "medium"

    return "low"


# =========================================================
# INDICATOR NORMALIZATION
# =========================================================

def normalize_indicator(indicator):
    """Normalize an indicator for duplicate detection."""

    if not isinstance(indicator, str):
        return None

    normalized = " ".join(
        indicator.strip().lower().split()
    )

    if not normalized:
        return None

    return normalized


def deduplicate_indicators(indicators):
    """Remove duplicate indicators while preserving order."""

    if not isinstance(
        indicators,
        (list, tuple, set),
    ):
        return []

    result = []
    seen = set()

    for indicator in indicators:
        normalized = normalize_indicator(
            indicator
        )

        if not normalized:
            continue

        if normalized in seen:
            continue

        seen.add(normalized)

        result.append(
            indicator.strip()
        )

    return result


# =========================================================
# RESULT EXTRACTION
# =========================================================

def extract_module_indicators(module_results):
    """
    Extract indicators from intelligence modules.

    Each indicator retains:
    - originating module
    - severity
    - evidence category
    """

    if not isinstance(
        module_results,
        dict,
    ):
        return []

    indicators = []

    for module_name, result in module_results.items():

        if not isinstance(result, dict):
            continue

        module_indicators = result.get(
            "indicators",
            [],
        )

        if isinstance(
            module_indicators,
            str,
        ):
            module_indicators = [
                module_indicators
            ]

        if not isinstance(
            module_indicators,
            (list, tuple, set),
        ):
            continue

        for indicator in module_indicators:

            if not isinstance(
                indicator,
                str,
            ):
                continue

            indicator = indicator.strip()

            if not indicator:
                continue

            evidence_type = classify_evidence_type(
                indicator
            )

            indicators.append({
                "indicator": indicator,
                "module": module_name,
                "severity": classify_indicator(
                    indicator
                ),
                "evidence_type": evidence_type,
                "posture": (
                    evidence_type == POSTURE
                ),
                "diagnostic": (
                    evidence_type == DIAGNOSTIC
                ),
            })

    return indicators


# =========================================================
# EVIDENCE CORRELATION
# =========================================================

def correlate_evidence(module_results):
    """
    Correlate identical evidence across modules.

    Evidence retains its category so that:
    THREAT != POSTURE != DIAGNOSTIC
    """

    extracted = extract_module_indicators(
        module_results
    )

    grouped = defaultdict(list)

    for evidence in extracted:

        normalized = normalize_indicator(
            evidence["indicator"]
        )

        if normalized:
            grouped[normalized].append(
                evidence
            )

    severity_order = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    correlated = []

    for normalized, evidence_items in grouped.items():

        strongest = max(
            evidence_items,
            key=lambda item:
            severity_order[
                item["severity"]
            ],
        )

        modules = sorted({
            item["module"]
            for item in evidence_items
        })

        evidence_types = {
            item.get(
                "evidence_type",
                THREAT,
            )
            for item in evidence_items
        }

        # If the same indicator is classified
        # differently by modules, threat takes priority.
        if THREAT in evidence_types:
            evidence_type = THREAT
        elif POSTURE in evidence_types:
            evidence_type = POSTURE
        else:
            evidence_type = DIAGNOSTIC

        correlated.append({
            "indicator": strongest["indicator"],
            "severity": strongest["severity"],
            "modules": modules,
            "module_count": len(modules),
            "evidence_type": evidence_type,
            "posture": (
                evidence_type == POSTURE
            ),
            "diagnostic": (
                evidence_type == DIAGNOSTIC
            ),
        })

    return correlated


# =========================================================
# THREAT PATTERN DETECTION
# =========================================================

def detect_threat_patterns(evidence):
    """Identify higher-level attack patterns."""

    if not isinstance(
        evidence,
        list,
    ):
        return []

    threat_evidence = [
        item
        for item in evidence
        if item.get(
            "evidence_type"
        ) == THREAT
    ]

    text = " ".join(
        item.get(
            "indicator",
            "",
        ).lower()
        for item in threat_evidence
    )

    patterns = []

    # -----------------------------------------------------
    # Credential phishing
    # -----------------------------------------------------

    login_signals = any(
        keyword in text
        for keyword in [
            "login form",
            "credential",
            "password",
            "authentication",
            "external form",
        ]
    )

    if login_signals:

        patterns.append({
            "name": "Credential Phishing",
            "description": (
                "Evidence indicates possible credential "
                "or authentication data collection."
            ),
            "severity": "high",
        })

    # -----------------------------------------------------
    # Redirect abuse
    # -----------------------------------------------------

    redirect_signals = sum(
        keyword in text
        for keyword in [
            "cross-domain redirect",
            "redirect destination",
            "suspicious redirect",
            "redirect",
        ]
    )

    if redirect_signals >= 2:

        patterns.append({
            "name": "Suspicious Redirect Chain",
            "description": (
                "Multiple indicators suggest potentially "
                "suspicious redirect behavior."
            ),
            "severity": "medium",
        })

    # -----------------------------------------------------
    # TLS anomalies
    # -----------------------------------------------------

    tls_signals = any(
        keyword in text
        for keyword in [
            "certificate mismatch",
            "hostname does not match",
            "certificate has expired",
            "weak cipher",
        ]
    )

    if tls_signals:

        patterns.append({
            "name": "TLS Security Anomaly",
            "description": (
                "TLS or certificate evidence contains "
                "security anomalies."
            ),
            "severity": "medium",
        })

    # -----------------------------------------------------
    # Suspicious infrastructure
    # -----------------------------------------------------

    infrastructure_signals = sum(
        keyword in text
        for keyword in [
            "punycode",
            "suspicious hosting",
            "hosting provider",
            "cloud infrastructure",
            "direct ip",
            "private ip",
            "reserved ip",
        ]
    )

    if infrastructure_signals >= 2:

        patterns.append({
            "name": "Suspicious Infrastructure",
            "description": (
                "Multiple indicators point to potentially "
                "suspicious network or hosting infrastructure."
            ),
            "severity": "medium",
        })

    # -----------------------------------------------------
    # Malware / payload
    # -----------------------------------------------------

    malware_signals = any(
        keyword in text
        for keyword in [
            "malware",
            "payload",
            "known malicious",
            "active phishing",
        ]
    )

    if malware_signals:

        patterns.append({
            "name": "Malicious Payload Activity",
            "description": (
                "Evidence contains indicators associated "
                "with malicious payload or known malicious activity."
            ),
            "severity": "critical",
        })

    return patterns


# =========================================================
# POSTURE SCORE
# =========================================================

def calculate_posture_score(evidence):
    """Calculate security-hardening posture separately."""

    if not isinstance(
        evidence,
        list,
    ):
        return 0

    score = 0

    for item in evidence:

        if item.get(
            "evidence_type"
        ) != POSTURE:
            continue

        indicator = item.get(
            "indicator",
            "",
        ).lower()

        if "missing security header" in indicator:
            score += 5

        elif "server technology disclosed" in indicator:
            score += 3

        elif "chunked transfer encoding" in indicator:
            score += 1

    return min(
        100,
        score,
    )


# =========================================================
# DIAGNOSTIC COUNT
# =========================================================

def calculate_diagnostic_count(evidence):
    """Count diagnostic-only observations."""

    if not isinstance(
        evidence,
        list,
    ):
        return 0

    return sum(
        1
        for item in evidence
        if item.get(
            "evidence_type"
        ) == DIAGNOSTIC
    )


# =========================================================
# THREAT EVIDENCE
# =========================================================

def get_threat_evidence(evidence):
    """Return genuine threat evidence only."""

    if not isinstance(
        evidence,
        list,
    ):
        return []

    return [
        item
        for item in evidence
        if item.get(
            "evidence_type"
        ) == THREAT
    ]


# =========================================================
# CORRELATED RISK SCORE
# =========================================================

def calculate_correlated_score(
    evidence,
    patterns,
):
    """Calculate threat score using threat evidence only."""

    if not isinstance(
        evidence,
        list,
    ):
        evidence = []

    if not isinstance(
        patterns,
        list,
    ):
        patterns = []

    score = 0

    severity_weights = {
        "low": 5,
        "medium": 10,
        "high": 20,
        "critical": 30,
    }

    threat_evidence = get_threat_evidence(
        evidence
    )

    for item in threat_evidence:

        severity = item.get(
            "severity",
            "low",
        )

        modules = item.get(
            "modules",
            [],
        )

        weight = severity_weights.get(
            severity,
            5,
        )

        module_bonus = min(
            10,
            max(
                0,
                len(modules) - 1,
            ) * 5,
        )

        score += (
            weight
            + module_bonus
        )

    pattern_weights = {
        "low": 5,
        "medium": 10,
        "high": 20,
        "critical": 30,
    }

    for pattern in patterns:

        severity = pattern.get(
            "severity",
            "low",
        )

        score += pattern_weights.get(
            severity,
            5,
        )

    return min(
        100,
        score,
    )


# =========================================================
# CONFIDENCE
# =========================================================

def calculate_confidence(
    evidence,
    patterns,
):
    """Calculate confidence from threat evidence only."""

    if not isinstance(
        evidence,
        list,
    ):
        evidence = []

    if not isinstance(
        patterns,
        list,
    ):
        patterns = []

    threat_evidence = get_threat_evidence(
        evidence
    )

    if not threat_evidence:
        return 0

    confidence = 20

    unique_modules = set()

    for item in threat_evidence:

        for module in item.get(
            "modules",
            [],
        ):
            unique_modules.add(module)

    confidence += min(
        40,
        len(unique_modules) * 5,
    )

    confidence += min(
        20,
        len(threat_evidence) * 3,
    )

    confidence += min(
        20,
        len(patterns) * 10,
    )

    return min(
        100,
        confidence,
    )


# =========================================================
# FINAL CLASSIFICATION
# =========================================================

def classify_threat(
    risk_score,
    confidence,
    evidence,
    patterns,
):
    """Produce the final PhishGuard classification."""

    if not isinstance(evidence, list):
        evidence = []

    if not isinstance(patterns, list):
        patterns = []

    threat_evidence = get_threat_evidence(evidence)

    critical_evidence = any(
        item.get("severity") == "critical"
        for item in threat_evidence
    )

    critical_pattern = any(
        item.get("severity") == "critical"
        or item.get("name") == "Credential Phishing"
        for item in patterns
    )

    high_signal_count = sum(
        1
        for item in threat_evidence
        if item.get("severity") in {"high", "critical"}
    )

    if critical_evidence or critical_pattern:
        return "MALICIOUS"

    if (
        risk_score >= 75
        and confidence >= 60
        and high_signal_count >= 1
    ):
        return "MALICIOUS"

    if (
        risk_score >= 30
        or high_signal_count >= 1
        or patterns
    ):
        return "SUSPICIOUS"

    return "SAFE"


# =========================================================
# COMPLETE THREAT CORRELATION
# =========================================================

def analyze_threat(module_results):
    """Complete Phase 9A threat correlation analysis."""

    evidence = correlate_evidence(
        module_results
    )

    patterns = detect_threat_patterns(
        evidence
    )

    risk_score = calculate_correlated_score(
        evidence,
        patterns,
    )

    posture_score = calculate_posture_score(
        evidence
    )

    diagnostic_count = calculate_diagnostic_count(
        evidence
    )

    confidence = calculate_confidence(
        evidence,
        patterns,
    )

    classification = classify_threat(
        risk_score,
        confidence,
        evidence,
        patterns,
    )

    threat_evidence = get_threat_evidence(
        evidence
    )

    posture_evidence = [
        item
        for item in evidence
        if item.get(
            "evidence_type"
        ) == POSTURE
    ]

    diagnostic_evidence = [
        item
        for item in evidence
        if item.get(
            "evidence_type"
        ) == DIAGNOSTIC
    ]

    indicators = [
        item["indicator"]
        for item in evidence
    ]

    threat_indicators = [
        item["indicator"]
        for item in threat_evidence
    ]

    posture_indicators = [
        item["indicator"]
        for item in posture_evidence
    ]

    diagnostic_indicators = [
        item["indicator"]
        for item in diagnostic_evidence
    ]

    return {
        "classification": classification,
        "risk_score": risk_score,
        "posture_score": posture_score,
        "confidence": confidence,

        "evidence": evidence,
        "threat_evidence": threat_evidence,
        "posture_evidence": posture_evidence,
        "diagnostic_evidence": diagnostic_evidence,

        "patterns": patterns,

        "indicators": indicators,
        "threat_indicators": threat_indicators,
        "posture_indicators": posture_indicators,
        "diagnostic_indicators": diagnostic_indicators,

        "evidence_count": len(evidence),
        "threat_evidence_count": len(
            threat_evidence
        ),
        "posture_evidence_count": len(
            posture_evidence
        ),
        "diagnostic_evidence_count": diagnostic_count,
        "pattern_count": len(patterns),
    }
