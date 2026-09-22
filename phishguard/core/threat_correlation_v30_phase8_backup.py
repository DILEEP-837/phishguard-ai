"""
PhishGuard AI
V3.0 Phase 8 - Threat Correlation & Decision Engine
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
# SECURITY POSTURE INDICATORS
# =========================================================

POSTURE_PATTERNS = [
    "missing security header",
    "server technology disclosed",
    "chunked transfer encoding detected",
    "hostname successfully resolved to ip address",
]


def is_posture_indicator(indicator):
    """Return True when an indicator describes security posture."""
    if not isinstance(indicator, str):
        return False

    text = indicator.lower()

    return any(
        pattern in text
        for pattern in POSTURE_PATTERNS
    )


# =========================================================
# INDICATOR CLASSIFICATION
# =========================================================

def classify_indicator(indicator):
    """Classify an indicator into a threat-evidence category."""

    if not isinstance(indicator, str):
        return "low"

    text = indicator.lower()

    # Security-hardening observations are intentionally low.
    if is_posture_indicator(text):
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

    if not isinstance(indicators, (list, tuple, set)):
        return []

    result = []
    seen = set()

    for indicator in indicators:

        normalized = normalize_indicator(indicator)

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
    Extract indicators from PhishGuard intelligence modules.

    Each indicator keeps its originating module so that
    independent evidence can be correlated correctly.
    """

    if not isinstance(module_results, dict):
        return []

    indicators = []

    for module_name, result in module_results.items():

        if not isinstance(result, dict):
            continue

        module_indicators = result.get(
            "indicators",
            [],
        )

        if isinstance(module_indicators, str):
            module_indicators = [
                module_indicators
            ]

        if not isinstance(
            module_indicators,
            (list, tuple, set),
        ):
            continue

        for indicator in module_indicators:

            if not isinstance(indicator, str):
                continue

            indicator = indicator.strip()

            if not indicator:
                continue

            indicators.append({
                "indicator": indicator,
                "module": module_name,
                "severity": classify_indicator(
                    indicator
                ),
                "posture": is_posture_indicator(
                    indicator
                ),
            })

    return indicators


# =========================================================
# EVIDENCE CORRELATION
# =========================================================

def correlate_evidence(module_results):
    """
    Correlate identical evidence across modules.

    Duplicate evidence is represented once and its originating
    modules are retained for corroboration analysis.
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
            severity_order[item["severity"]],
        )

        modules = sorted({
            item["module"]
            for item in evidence_items
        })

        correlated.append({
            "indicator": strongest["indicator"],
            "severity": strongest["severity"],
            "modules": modules,
            "module_count": len(modules),
            "posture": all(
                item.get("posture", False)
                for item in evidence_items
            ),
        })

    return correlated


# =========================================================
# THREAT PATTERN DETECTION
# =========================================================

def detect_threat_patterns(evidence):
    """
    Identify higher-level attack patterns.

    Security-posture observations are excluded from threat
    pattern detection.
    """

    if not isinstance(evidence, list):
        return []

    threat_evidence = [
        item
        for item in evidence
        if not item.get("posture", False)
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
    """
    Calculate a separate score for security-hardening
    observations.

    Posture score is intentionally NOT threat evidence.
    """

    if not isinstance(evidence, list):
        return 0

    score = 0

    for item in evidence:

        if not item.get("posture", False):
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

        elif "hostname successfully resolved" in indicator:
            score += 0

    return min(100, score)


# =========================================================
# CORRELATED RISK SCORE
# =========================================================

def calculate_correlated_score(evidence, patterns):
    """
    Calculate a bounded score using threat evidence only.

    Security-posture observations are deliberately excluded.
    """

    if not isinstance(evidence, list):
        evidence = []

    if not isinstance(patterns, list):
        patterns = []

    score = 0

    severity_weights = {
        "low": 5,
        "medium": 10,
        "high": 20,
        "critical": 30,
    }

    # -----------------------------------------------------
    # Threat evidence contribution
    # -----------------------------------------------------

    for item in evidence:

        if item.get("posture", False):
            continue

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

        # Corroboration is capped and only applies
        # to genuinely independent modules.
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

    # -----------------------------------------------------
    # Threat pattern contribution
    # -----------------------------------------------------

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

    return min(100, score)


# =========================================================
# CONFIDENCE
# =========================================================

def calculate_confidence(evidence, patterns):
    """
    Calculate confidence from threat evidence only.

    Security-posture observations do not increase threat
    confidence.
    """

    if not isinstance(evidence, list):
        evidence = []

    if not isinstance(patterns, list):
        patterns = []

    threat_evidence = [
        item
        for item in evidence
        if not item.get("posture", False)
    ]

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
    """
    Produce the final PhishGuard threat classification.

    Classification is based on threat evidence, not merely
    security-hardening observations.
    """

    if not isinstance(evidence, list):
        evidence = []

    if not isinstance(patterns, list):
        patterns = []

    threat_evidence = [
        item
        for item in evidence
        if not item.get("posture", False)
    ]

    critical_evidence = any(
        item.get("severity") == "critical"
        for item in threat_evidence
    )

    critical_pattern = any(
        item.get("severity") == "critical"
        for item in patterns
    )

    high_signal_count = sum(
        1
        for item in threat_evidence
        if item.get("severity")
        in {
            "high",
            "critical",
        }
    )

    # -----------------------------------------------------
    # Confirmed / strong malicious evidence
    # -----------------------------------------------------

    if (
        critical_evidence
        or critical_pattern
    ):
        return "MALICIOUS"

    # -----------------------------------------------------
    # Multiple strong independent signals
    # -----------------------------------------------------

    if (
        risk_score >= 75
        and confidence >= 60
        and high_signal_count >= 1
    ):
        return "MALICIOUS"

    # -----------------------------------------------------
    # Suspicious evidence
    # -----------------------------------------------------

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
    """
    Complete V3.0 Phase 8 Threat Correlation analysis.
    """

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

    indicators = [
        item["indicator"]
        for item in evidence
    ]

    threat_evidence = [
        item
        for item in evidence
        if not item.get("posture", False)
    ]

    return {
        "classification": classification,
        "risk_score": risk_score,
        "posture_score": posture_score,
        "confidence": confidence,
        "evidence": evidence,
        "threat_evidence": threat_evidence,
        "patterns": patterns,
        "indicators": indicators,
        "evidence_count": len(evidence),
        "threat_evidence_count": len(
            threat_evidence
        ),
        "pattern_count": len(patterns),
    }
