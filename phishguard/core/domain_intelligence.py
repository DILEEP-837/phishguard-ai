import math
import re
from collections import Counter


# TLDs that can deserve a small additional signal.
# This is NOT a malicious-TLD list.
MONITORED_TLDS = {
    "zip",
    "mov",
    "click",
    "top",
    "work",
    "live",
    "online",
    "site",
}


def calculate_entropy(value):
    """
    Calculate Shannon entropy of a string.
    Higher entropy can indicate randomly generated strings.
    """

    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def analyze_hostname(hostname, tld=""):
    """
    Analyze hostname characteristics.

    Returns:
        {
            "score": int,
            "indicators": list
        }
    """

    score = 0
    indicators = []

    hostname = (hostname or "").lower().strip()

    if not hostname:
        return {
            "score": 0,
            "indicators": []
        }

    # =========================================================
    # 1. PUNYCODE / IDN
    # =========================================================

    if "xn--" in hostname:
        score += 15
        indicators.append(
            "Punycode/IDN hostname detected"
        )

    # =========================================================
    # 2. VERY LONG HOSTNAME
    # =========================================================

    if len(hostname) > 80:
        score += 5
        indicators.append(
            "Hostname is unusually long"
        )

    if len(hostname) > 120:
        score += 5
        indicators.append(
            "Hostname is extremely long"
        )

    # =========================================================
    # 3. MANY SUBDOMAIN LEVELS
    # =========================================================

    labels = [
        label for label in hostname.split(".")
        if label
    ]

    if len(labels) >= 5:
        score += 5
        indicators.append(
            "Hostname contains many subdomain levels"
        )

    if len(labels) >= 7:
        score += 5
        indicators.append(
            "Hostname contains excessive subdomain levels"
        )

    # =========================================================
    # 4. NUMERIC-HEAVY HOSTNAME
    # =========================================================

    hostname_without_tld = hostname

    if tld and hostname.endswith("." + tld.lower()):
        hostname_without_tld = hostname[
            :-(len(tld) + 1)
        ]

    digits = sum(
        character.isdigit()
        for character in hostname_without_tld
    )

    letters = sum(
        character.isalpha()
        for character in hostname_without_tld
    )

    if digits >= 5 and digits > letters:
        score += 5
        indicators.append(
            "Hostname contains an unusually high number of digits"
        )

    # =========================================================
    # 5. EXCESSIVE HYPHENS
    # =========================================================

    hyphens = hostname.count("-")

    if hyphens >= 3:
        score += 5
        indicators.append(
            "Hostname contains multiple hyphens"
        )

    if hyphens >= 6:
        score += 5
        indicators.append(
            "Hostname contains excessive hyphens"
        )

    # =========================================================
    # 6. MONITORED TLD
    # =========================================================

    if tld.lower() in MONITORED_TLDS:
        score += 3
        indicators.append(
            f"Domain uses monitored TLD: .{tld.lower()}"
        )

    # =========================================================
    # 7. ENTROPY
    # =========================================================

    # Examine the main hostname rather than the full URL.
    main_part = hostname_without_tld.replace(".", "")

    entropy = calculate_entropy(main_part)

    if len(main_part) >= 12 and entropy >= 3.8:
        score += 5
        indicators.append(
            "Hostname has relatively high character entropy"
        )

    # =========================================================
    # 8. SUSPICIOUS LOCAL HOSTNAMES
    # =========================================================

    local_names = {
        "localhost",
        "localhost.localdomain",
        "local",
    }

    if hostname in local_names:
        score += 2
        indicators.append(
            "Local hostname detected"
        )

    return {
        "score": min(score, 40),
        "indicators": indicators
    }
