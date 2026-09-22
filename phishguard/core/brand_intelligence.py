import re
from urllib.parse import urlparse


KNOWN_BRANDS = {
    "google",
    "microsoft",
    "apple",
    "amazon",
    "facebook",
    "instagram",
    "whatsapp",
    "paypal",
    "netflix",
    "linkedin",
    "twitter",
    "github",
    "outlook",
    "adobe",
    "dropbox",
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "confirm",
    "password",
    "authenticate",
    "authentication",
}

CHARACTER_SUBSTITUTIONS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
}


def extract_hostname(url):
    if not isinstance(url, str):
        return None

    value = url.strip()

    if not value:
        return None

    if any(char.isspace() for char in value):
        return None

    try:
        parsed = urlparse(value)

        if not parsed.netloc:
            parsed = urlparse("https://" + value)

        hostname = parsed.hostname

        if not hostname:
            return None

        return hostname.lower().rstrip(".")

    except ValueError:
        return None


def get_registered_domain(hostname):
    if not hostname:
        return None

    parts = hostname.split(".")

    if len(parts) < 2:
        return hostname

    return ".".join(parts[-2:])


def get_domain_labels(hostname):
    if not hostname:
        return []

    registered = get_registered_domain(hostname)

    if not registered:
        return []

    return registered.split(".")[:-1]


def normalize_brand_candidate(value):
    if not value:
        return ""

    value = value.lower()

    for source, target in CHARACTER_SUBSTITUTIONS.items():
        value = value.replace(source, target)

    value = re.sub(r"[^a-z0-9]", "", value)

    return value


def levenshtein_distance(first, second):
    if first == second:
        return 0

    if not first:
        return len(second)

    if not second:
        return len(first)

    previous = list(range(len(second) + 1))

    for i, char_first in enumerate(first, start=1):
        current = [i]

        for j, char_second in enumerate(second, start=1):
            insert_cost = current[j - 1] + 1
            delete_cost = previous[j] + 1
            replace_cost = previous[j - 1] + (
                char_first != char_second
            )

            current.append(
                min(
                    insert_cost,
                    delete_cost,
                    replace_cost,
                )
            )

        previous = current

    return previous[-1]


def analyze_brand_domain(url):
    hostname = extract_hostname(url)

    result = {
        "url": url,
        "hostname": hostname,
        "registered_domain": None,
        "brand_matches": [],
        "typosquatting_matches": [],
        "suspicious_keywords": [],
        "indicators": [],
        "evidence": [],
        "risk_score": 0,
        "risk_level": "SAFE",
        "classification": "SAFE",
    }

    if not hostname:
        result["risk_score"] = 30
        result["risk_level"] = "MEDIUM"
        result["classification"] = "SUSPICIOUS"
        result["indicators"].append(
            "Unable to determine hostname for brand analysis"
        )
        return result

    result["registered_domain"] = get_registered_domain(hostname)

    labels = [
        label
        for label in hostname.lower().split(".")
        if label
    ]

    score = 0

    for label in labels:
        # Break labels such as:
        # google-login
        # paypal-secure
        components = [
            part
            for part in re.split(r"[-_]+", label)
            if part
        ]

        for component in components:
            for brand in sorted(KNOWN_BRANDS):

                # Exact brand must use the ORIGINAL component.
                # This prevents g00gle from becoming "google".
                if component == brand:
                    if brand not in result["brand_matches"]:
                        result["brand_matches"].append(brand)
                    continue

                normalized_component = (
                    normalize_brand_candidate(component)
                )
                normalized_brand = (
                    normalize_brand_candidate(brand)
                )

                # Character substitution:
                # g00gle -> google
                # paypa1 -> paypal
                if (
                    normalized_component == normalized_brand
                    and component != brand
                ):
                    result["typosquatting_matches"].append(
                        {
                            "brand": brand,
                            "distance": 0,
                            "label": label,
                        }
                    )
                    continue

                # Small edit-distance typo.
                distance = levenshtein_distance(
                    component,
                    brand,
                )

                if (
                    distance <= 1
                    and len(brand) >= 5
                ):
                    result["typosquatting_matches"].append(
                        {
                            "brand": brand,
                            "distance": distance,
                            "label": label,
                        }
                    )

    # Remove duplicate typosquatting matches.
    unique_matches = []
    seen = set()

    for match in result["typosquatting_matches"]:
        key = (
            match["brand"],
            match["label"],
        )

        if key not in seen:
            seen.add(key)
            unique_matches.append(match)

    result["typosquatting_matches"] = unique_matches

    # Authentication / phishing keywords.
    hostname_lower = hostname.lower()

    for keyword in sorted(SUSPICIOUS_KEYWORDS):
        if keyword in hostname_lower:
            result["suspicious_keywords"].append(keyword)

    # Typosquatting evidence.
    if result["typosquatting_matches"]:
        score += 35

        for match in result["typosquatting_matches"]:
            result["indicators"].append(
                "Possible typosquatting of "
                + match["brand"]
            )

    # Exact brand + suspicious keyword.
    if result["brand_matches"]:
        if result["suspicious_keywords"]:
            score += 30

            for brand in result["brand_matches"]:
                result["indicators"].append(
                    "Known brand combined with "
                    "suspicious authentication keywords: "
                    + brand
                )
        else:
            score += 5

    if result["suspicious_keywords"]:
        score += min(
            15,
            len(result["suspicious_keywords"]) * 5,
        )

    # Final classification.
    if (
        result["typosquatting_matches"]
        and result["suspicious_keywords"]
    ):
        result["classification"] = "PHISHING"

    elif result["typosquatting_matches"]:
        result["classification"] = "SUSPICIOUS"

    elif (
        result["brand_matches"]
        and result["suspicious_keywords"]
    ):
        result["classification"] = "SUSPICIOUS"

    result["risk_score"] = min(100, score)

    if result["risk_score"] >= 60:
        result["risk_level"] = "HIGH"
    elif result["risk_score"] >= 30:
        result["risk_level"] = "MEDIUM"
    elif result["risk_score"] > 0:
        result["risk_level"] = "LOW"
    else:
        result["risk_level"] = "SAFE"

    result["evidence"] = list(result["indicators"])

    return result


def analyze_brand_intelligence(url):
    return analyze_brand_domain(url)


# =========================================================
# BACKWARD COMPATIBILITY
# =========================================================

def analyze_brand_similarity(value):
    """
    Backward-compatible interface used by the legacy risk engine.

    The legacy risk engine passes a hostname, while the new
    brand intelligence engine accepts either a hostname or URL.
    """
    result = analyze_brand_domain(value)

    score = result.get("risk_score", 0)

    return {
        "score": score,
        "risk_score": score,
        "risk_level": result.get(
            "risk_level",
            "SAFE",
        ),
        "suspicious": (
            result.get("classification")
            in {
                "SUSPICIOUS",
                "PHISHING",
            }
        ),
        "indicators": result.get(
            "indicators",
            [],
        ),
        "brand_matches": result.get(
            "brand_matches",
            [],
        ),
        "typosquatting_matches": result.get(
            "typosquatting_matches",
            [],
        ),
        "suspicious_keywords": result.get(
            "suspicious_keywords",
            [],
        ),
    }

