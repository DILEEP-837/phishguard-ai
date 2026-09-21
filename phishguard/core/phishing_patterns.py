"""
PHISHGUARD AI
Phishing Pattern Intelligence
Version 2.4
"""


# =========================================================
# SUSPICIOUS PHISHING TERMS
# =========================================================

PHISHING_TERMS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "password",
    "credential",
    "payment",
    "billing",
    "confirm",
    "confirmation",
    "update",
    "recover",
    "recovery",
    "unlock",
    "suspended",
}


# =========================================================
# BRAND NAMES
# =========================================================

KNOWN_BRANDS = {
    "google",
    "microsoft",
    "apple",
    "amazon",
    "paypal",
    "facebook",
    "instagram",
    "linkedin",
    "github",
}


def detect_phishing_patterns(hostname, path=""):
    """
    Detect contextual phishing patterns.

    Returns:

        {
            "score": int,
            "indicators": list
        }
    """

    hostname = (hostname or "").lower().strip()
    path = (path or "").lower().strip()

    score = 0
    indicators = []

    # =====================================================
    # HOSTNAME LABELS
    # =====================================================

    hostname_labels = [
        label
        for label in hostname.split(".")
        if label
    ]

    # =====================================================
    # 1. BRAND + PHISHING TERM
    # =====================================================

    for brand in KNOWN_BRANDS:

        brand_present = any(
            brand in label
            for label in hostname_labels
        )

        if not brand_present:
            continue

        phishing_term_present = any(
            term in hostname
            for term in PHISHING_TERMS
        )

        if phishing_term_present:

            score += 25

            indicators.append(
                f"Brand name combined with phishing-related "
                f"hostname terms: {brand}"
            )

            break

    # =====================================================
    # 2. MULTIPLE PHISHING TERMS IN HOSTNAME
    # =====================================================

    hostname_terms = [
        term
        for term in PHISHING_TERMS
        if term in hostname
    ]

    if len(hostname_terms) >= 2:

        score += 15

        indicators.append(
            "Multiple phishing-related terms detected "
            "in hostname"
        )

    # =====================================================
    # 3. PHISHING TERM IN SUBDOMAIN
    # =====================================================

    if len(hostname_labels) >= 3:

        subdomains = hostname_labels[:-2]

        subdomain_terms = []

        for label in subdomains:

            for term in PHISHING_TERMS:

                if term in label:
                    subdomain_terms.append(term)

        if subdomain_terms:

            score += 10

            indicators.append(
                "Phishing-related term detected in subdomain"
            )

    # =====================================================
    # 4. MULTIPLE PHISHING TERMS IN PATH
    # =====================================================

    path_terms = [
        term
        for term in PHISHING_TERMS
        if term in path
    ]

    if len(path_terms) >= 2:

        score += 10

        indicators.append(
            "Multiple phishing-related terms detected "
            "in URL path"
        )

    # =====================================================
    # 5. BRAND + ACCOUNT/PASSWORD PATH
    # =====================================================

    brand_in_url = any(
        brand in hostname or brand in path
        for brand in KNOWN_BRANDS
    )

    sensitive_path_terms = [
        "account",
        "password",
        "credential",
        "payment",
        "billing",
    ]

    sensitive_path_present = any(
        term in path
        for term in sensitive_path_terms
    )

    if brand_in_url and sensitive_path_present:

        score += 15

        indicators.append(
            "Known brand combined with sensitive "
            "account-related path"
        )

    # =====================================================
    # LIMIT SCORE
    # =====================================================

    score = min(score, 40)

    return {
        "score": score,
        "indicators": indicators,
    }
