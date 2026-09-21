from difflib import SequenceMatcher


# =========================================================
# KNOWN BRANDS
# =========================================================

KNOWN_BRANDS = {
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "paypal": "paypal.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "linkedin": "linkedin.com",
    "github": "github.com",
}


# =========================================================
# COMMON HOMOGLYPH / DIGIT SUBSTITUTIONS
# =========================================================

CHARACTER_SUBSTITUTIONS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    "@": "a",
}


def normalize_brand_text(value):
    """
    Basic normalization for brand comparison.
    """

    return "".join(
        character.lower()
        for character in value
        if character.isalnum()
    )


def normalize_lookalike_text(value):
    """
    Normalize common digit/character substitutions.

    Examples:

        g00gle -> google
        paypa1 -> paypal
    """

    value = normalize_brand_text(value)

    normalized = []

    for character in value:
        normalized.append(
            CHARACTER_SUBSTITUTIONS.get(
                character,
                character
            )
        )

    return "".join(normalized)


def similarity_score(first, second):
    """
    Return similarity between 0 and 1.
    """

    first_normalized = normalize_brand_text(first)
    second_normalized = normalize_brand_text(second)

    return SequenceMatcher(
        None,
        first_normalized,
        second_normalized
    ).ratio()


def lookalike_similarity_score(first, second):
    """
    Compare strings after common look-alike substitutions
    have been normalized.
    """

    first_normalized = normalize_lookalike_text(first)
    second_normalized = normalize_lookalike_text(second)

    return SequenceMatcher(
        None,
        first_normalized,
        second_normalized
    ).ratio()


def analyze_brand_similarity(hostname):
    """
    Detect domains that resemble known brands.

    Returns:

        {
            "score": int,
            "indicators": list
        }
    """

    hostname = (hostname or "").lower().strip()

    if not hostname:
        return {
            "score": 0,
            "indicators": []
        }

    # Remove www.
    hostname = hostname.removeprefix("www.")

    # Split hostname.
    parts = hostname.split(".")

    if len(parts) < 2:
        return {
            "score": 0,
            "indicators": []
        }

    # Inspect the registered-looking domain label.
    domain_label = parts[-2]

    score = 0
    indicators = []

    # =========================================================
    # CHECK AGAINST KNOWN BRANDS
    # =========================================================

    for brand, legitimate_domain in KNOWN_BRANDS.items():

        # Exact legitimate brand is not suspicious.
        if domain_label == brand:
            continue

        # -----------------------------------------------------
        # NORMAL SIMILARITY
        # -----------------------------------------------------

        normal_similarity = similarity_score(
            domain_label,
            brand
        )

        # -----------------------------------------------------
        # LOOKALIKE SIMILARITY
        # -----------------------------------------------------

        lookalike_similarity = lookalike_similarity_score(
            domain_label,
            brand
        )

        # =====================================================
        # VERY STRONG LOOKALIKE
        # =====================================================

        if lookalike_similarity >= 0.90:

            score += 25

            indicators.append(
                f"Domain closely resembles known brand: {brand}"
            )

            break

        # =====================================================
        # STRONG LOOKALIKE
        # =====================================================

        elif (
            normal_similarity >= 0.80
            or lookalike_similarity >= 0.80
        ):

            score += 20

            indicators.append(
                f"Domain resembles known brand: {brand}"
            )

            break

        # =====================================================
        # MODERATE LOOKALIKE
        # =====================================================

        elif (
            normal_similarity >= 0.70
            or lookalike_similarity >= 0.70
        ):

            score += 15

            indicators.append(
                f"Domain may resemble known brand: {brand}"
            )

            break

    return {
        "score": min(score, 25),
        "indicators": indicators
    }
