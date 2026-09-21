"""
PHISHGUARD AI
Obfuscation & Unicode Intelligence
Version 2.5
"""

import re


# =========================================================
# SUSPICIOUS URL CHARACTERS
# =========================================================

SUSPICIOUS_SEPARATORS = {
    "\\",
    "|",
    "{",
    "}",
    "[",
    "]",
}


# =========================================================
# COMMON LOOK-ALIKE CHARACTERS
# =========================================================

CONFUSABLE_CHARACTERS = {
    "а": "a",   # Cyrillic a
    "е": "e",   # Cyrillic e
    "о": "o",   # Cyrillic o
    "р": "p",   # Cyrillic p
    "с": "c",   # Cyrillic c
    "х": "x",   # Cyrillic x
    "у": "y",   # Cyrillic y
    "і": "i",   # Cyrillic i
    "ј": "j",   # Cyrillic j
    "ѕ": "s",   # Cyrillic s
}


def contains_unicode(text):
    """
    Determine whether text contains non-ASCII characters.
    """

    return any(
        ord(character) > 127
        for character in text
    )


def detect_punycode(hostname):
    """
    Detect IDN/Punycode labels.

    Punycode domains commonly contain:
        xn--
    """

    labels = hostname.lower().split(".")

    return any(
        label.startswith("xn--")
        for label in labels
    )


def detect_confusable_characters(hostname):
    """
    Detect known Unicode characters that visually resemble
    common Latin characters.
    """

    found = []

    for character in hostname:

        if character in CONFUSABLE_CHARACTERS:

            found.append(character)

    return found


def detect_mixed_character_scripts(hostname):
    """
    Detect hostnames containing a mixture of ASCII and
    non-ASCII characters.
    """

    has_ascii = any(
        ord(character) < 128
        for character in hostname
    )

    has_unicode = any(
        ord(character) > 127
        for character in hostname
    )

    return has_ascii and has_unicode


def detect_suspicious_separators(url):
    """
    Detect unusual separator characters in the URL.
    """

    return [
        character
        for character in url
        if character in SUSPICIOUS_SEPARATORS
    ]


def detect_obfuscation(url, hostname):
    """
    PHISHGUARD V2.5 Obfuscation Intelligence.

    Returns:

        {
            "score": int,
            "indicators": list
        }
    """

    url = url or ""
    hostname = hostname or ""

    score = 0
    indicators = []

    # =====================================================
    # 1. UNICODE HOSTNAME
    # =====================================================

    if contains_unicode(hostname):

        score += 20

        indicators.append(
            "Non-ASCII Unicode characters detected "
            "in hostname"
        )

    # =====================================================
    # 2. PUNYCODE
    # =====================================================

    if detect_punycode(hostname):

        score += 20

        indicators.append(
            "Punycode/IDN hostname detected"
        )

    # =====================================================
    # 3. CONFUSABLE CHARACTERS
    # =====================================================

    confusable_characters = (
        detect_confusable_characters(hostname)
    )

    if confusable_characters:

        score += 25

        unique_characters = "".join(
            dict.fromkeys(
                confusable_characters
            )
        )

        indicators.append(
            "Unicode look-alike characters detected: "
            + unique_characters
        )

    # =====================================================
    # 4. MIXED CHARACTER SCRIPTS
    # =====================================================

    if detect_mixed_character_scripts(hostname):

        score += 15

        indicators.append(
            "Mixed ASCII and Unicode characters "
            "detected in hostname"
        )

    # =====================================================
    # 5. SUSPICIOUS SEPARATORS
    # =====================================================

    suspicious_separators = (
        detect_suspicious_separators(url)
    )

    if suspicious_separators:

        score += 5

        unique_separators = "".join(
            dict.fromkeys(
                suspicious_separators
            )
        )

        indicators.append(
            "Unusual separator characters detected: "
            + unique_separators
        )

    # =====================================================
    # 6. URL PERCENT ENCODING
    # =====================================================

    encoded_sequences = re.findall(
        r"%[0-9A-Fa-f]{2}",
        url
    )

    if len(encoded_sequences) >= 3:

        score += 10

        indicators.append(
            "Multiple percent-encoded characters "
            "detected"
        )

    # =====================================================
    # SCORE LIMIT
    # =====================================================

    score = min(score, 50)

    return {
        "score": score,
        "indicators": indicators,
    }
