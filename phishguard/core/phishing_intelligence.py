from urllib.parse import urlparse


PHISHING_WEIGHTS = {
    "login_form": 15,
    "password_field": 15,
    "username_field": 10,
    "email_field": 10,
    "external_form": 20,
    "external_credential_form": 30,
    "credential_harvesting": 30,
}


def extract_hostname(url):
    if not isinstance(url, str):
        return ""

    value = url.strip()

    if not value or any(ch.isspace() for ch in value):
        return ""

    parsed = urlparse(value)

    if not parsed.netloc:
        parsed = urlparse("https://" + value)

    hostname = parsed.hostname

    if not hostname:
        return ""

    return hostname.lower().rstrip(".")


def hostnames_match(first, second):
    first_host = extract_hostname(first)
    second_host = extract_hostname(second)

    return bool(first_host and second_host and first_host == second_host)


def is_external_form(page_url, form_action):
    page_host = extract_hostname(page_url)
    action_host = extract_hostname(form_action)

    if not page_host or not action_host:
        return False

    return page_host != action_host


def analyze_phishing_content(content_result):
    """
    Analyze already-collected content intelligence.

    This function does not retrieve pages itself.
    It only evaluates evidence supplied by the content analyzer.
    """

    if not isinstance(content_result, dict):
        content_result = {}

    forms = int(content_result.get("forms", 0) or 0)
    password_fields = int(
        content_result.get("password_fields", 0) or 0
    )
    username_fields = int(
        content_result.get("username_fields", 0) or 0
    )
    email_fields = int(
        content_result.get("email_fields", 0) or 0
    )
    login_forms = int(
        content_result.get("login_forms", 0) or 0
    )
    external_forms = int(
        content_result.get("external_forms", 0) or 0
    )
    external_credential_forms = int(
        content_result.get("external_cred_forms", 0) or 0
    )

    indicators = []
    evidence = []
    score = 0

    def add_evidence(name, weight, description):
        nonlocal score

        score += weight

        evidence.append({
            "signal": name,
            "weight": weight,
            "description": description,
        })

        indicators.append(description)

    if login_forms > 0:
        add_evidence(
            "login_form",
            PHISHING_WEIGHTS["login_form"],
            "Login form detected",
        )

    if password_fields > 0:
        add_evidence(
            "password_field",
            PHISHING_WEIGHTS["password_field"],
            "Password field detected",
        )

    if username_fields > 0:
        add_evidence(
            "username_field",
            PHISHING_WEIGHTS["username_field"],
            "Username field detected",
        )

    if email_fields > 0:
        add_evidence(
            "email_field",
            PHISHING_WEIGHTS["email_field"],
            "Email field detected",
        )

    if external_forms > 0:
        add_evidence(
            "external_form",
            PHISHING_WEIGHTS["external_form"],
            "Form submits to an external domain",
        )

    if external_credential_forms > 0:
        add_evidence(
            "external_credential_form",
            PHISHING_WEIGHTS["external_credential_form"],
            "Credential form submits to an external domain",
        )

    credential_fields = (
        password_fields
        + username_fields
        + email_fields
    )

    if (
        credential_fields > 0
        and external_forms > 0
    ):
        add_evidence(
            "credential_harvesting",
            PHISHING_WEIGHTS["credential_harvesting"],
            "Credential collection combined with an external form",
        )

    score = min(100, score)

    if score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    elif score > 0:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"

    if (
        external_credential_forms > 0
        or (
            password_fields > 0
            and external_forms > 0
        )
    ):
        classification = "PHISHING"
    elif score >= 30:
        classification = "SUSPICIOUS"
    else:
        classification = "SAFE"

    if score == 0:
        confidence = 0
    elif external_credential_forms > 0:
        confidence = 90
    elif password_fields > 0 and external_forms > 0:
        confidence = 85
    elif login_forms > 0 and password_fields > 0:
        confidence = 70
    else:
        confidence = 40

    return {
        "classification": classification,
        "risk_score": score,
        "confidence": confidence,
        "risk_level": risk_level,
        "forms": forms,
        "login_forms": login_forms,
        "password_fields": password_fields,
        "username_fields": username_fields,
        "email_fields": email_fields,
        "external_forms": external_forms,
        "external_credential_forms": external_credential_forms,
        "credential_fields": credential_fields,
        "indicators": indicators,
        "evidence": evidence,
    }


def analyze_phishing(url, content_result):
    """
    Main Phase 9B phishing intelligence entry point.
    """

    hostname = extract_hostname(url)

    result = analyze_phishing_content(content_result)

    result["url"] = url
    result["hostname"] = hostname

    return result
