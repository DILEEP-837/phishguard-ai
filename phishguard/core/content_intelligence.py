"""
PhishGuard AI - V2.8 Content Intelligence

Phase 1:
- HTML retrieval
- HTML parsing
- Basic page metadata extraction
"""

from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


DEFAULT_TIMEOUT = 8

USER_AGENT = (
    "Mozilla/5.0 "
    "(compatible; PhishGuard-AI/2.8; "
    "+https://example.com/security)"
)


def fetch_page(url, timeout=DEFAULT_TIMEOUT):
    """
    Fetch webpage HTML without automatically following redirects.

    Returns:
        {
            "success": bool,
            "url": str,
            "status_code": int or None,
            "content_type": str or None,
            "html": str,
            "error": str or None
        }
    """

    try:

        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            headers={
                "User-Agent": USER_AGENT
            }
        )

        content_type = response.headers.get(
            "Content-Type",
            ""
        )

        return {
            "success": True,
            "url": url,
            "status_code": response.status_code,
            "content_type": content_type,
            "html": response.text,
            "error": None,
        }

    except Exception as exc:

        return {
            "success": False,
            "url": url,
            "status_code": None,
            "content_type": None,
            "html": "",
            "error": str(exc),
        }


def parse_html(html):
    """
    Parse HTML and extract basic structural information.
    """

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    title_tag = soup.find("title")

    title = (
        title_tag.get_text(
            strip=True
        )
        if title_tag
        else ""
    )

    forms = soup.find_all("form")
    inputs = soup.find_all("input")
    scripts = soup.find_all("script")
    iframes = soup.find_all("iframe")
    links = soup.find_all("a")

    return {
        "title": title,
        "form_count": len(forms),
        "input_count": len(inputs),
        "script_count": len(scripts),
        "iframe_count": len(iframes),
        "link_count": len(links),
    }


def analyze_content(url, timeout=DEFAULT_TIMEOUT):
    """
    Fetch and analyze basic webpage content.
    """

    result = {
        "url": url,
        "success": False,
        "status_code": None,
        "content_type": None,
        "title": "",
        "form_count": 0,
        "input_count": 0,
        "script_count": 0,
        "iframe_count": 0,
        "link_count": 0,
        "indicators": [],
        "error": None,
    }

    parsed = urlparse(url)

    if parsed.scheme not in (
        "http",
        "https",
    ):
        result["error"] = (
            "Unsupported URL scheme"
        )
        return result

    page = fetch_page(
        url,
        timeout=timeout
    )

    if not page["success"]:

        result["error"] = page["error"]

        return result

    result["success"] = True
    result["status_code"] = page["status_code"]
    result["content_type"] = page["content_type"]

    # Only parse HTML content.
    if (
        "text/html"
        not in page["content_type"].lower()
    ):

        result["indicators"].append(
            "Response is not HTML content"
        )

        return result

    parsed_html = parse_html(
        page["html"]
    )

    result.update(
        parsed_html
    )

    return result
# =========================================================
# V2.8 PHASE 2
# CREDENTIAL / LOGIN FORM INTELLIGENCE
# =========================================================

CREDENTIAL_INPUT_TYPES = {
    "password",
    "email",
}

USERNAME_KEYWORDS = {
    "user",
    "username",
    "login",
    "email",
    "account",
}

PASSWORD_KEYWORDS = {
    "password",
    "passwd",
    "pass",
    "pwd",
}


def detect_credential_fields(html):
    """
    Detect username, email, and password fields
    in webpage HTML.
    """

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    password_fields = []
    username_fields = []
    email_fields = []
    hidden_fields = []

    inputs = soup.find_all("input")

    for field in inputs:

        input_type = (
            field.get("type", "text")
            .lower()
        )

        name = (
            field.get("name", "")
            .lower()
        )

        field_id = (
            field.get("id", "")
            .lower()
        )

        placeholder = (
            field.get("placeholder", "")
            .lower()
        )

        combined = (
            f"{name} "
            f"{field_id} "
            f"{placeholder}"
        )

        # ---------------------------------------------
        # Password
        # ---------------------------------------------

        if input_type == "password":

            password_fields.append(
                {
                    "name": name,
                    "id": field_id,
                    "type": input_type,
                }
            )

        # ---------------------------------------------
        # Email
        # ---------------------------------------------

        elif input_type == "email":

            email_fields.append(
                {
                    "name": name,
                    "id": field_id,
                    "type": input_type,
                }
            )

        # ---------------------------------------------
        # Username / login
        # ---------------------------------------------

        elif any(
            keyword in combined
            for keyword in USERNAME_KEYWORDS
        ):

            username_fields.append(
                {
                    "name": name,
                    "id": field_id,
                    "type": input_type,
                }
            )

        # ---------------------------------------------
        # Hidden fields
        # ---------------------------------------------

        if input_type == "hidden":

            hidden_fields.append(
                {
                    "name": name,
                    "id": field_id,
                }
            )

    return {
        "password_fields": password_fields,
        "username_fields": username_fields,
        "email_fields": email_fields,
        "hidden_fields": hidden_fields,
    }


def detect_login_forms(html):
    """
    Detect forms that appear to be login or
    credential-collection forms.
    """

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    login_forms = []

    for form in soup.find_all("form"):

        form_text = form.get_text(
            " ",
            strip=True
        ).lower()

        action = form.get(
            "action",
            ""
        )

        method = form.get(
            "method",
            "get"
        ).lower()

        password_fields = form.find_all(
            "input",
            {
                "type": "password"
            }
        )

        credential_keywords = (
            "login",
            "log in",
            "sign in",
            "signin",
            "password",
            "username",
            "verify",
            "verification",
            "account",
        )

        keyword_match = any(
            keyword in form_text
            for keyword in credential_keywords
        )

        if password_fields or keyword_match:

            login_forms.append(
                {
                    "action": action,
                    "method": method,
                    "password_field_count": len(
                        password_fields
                    ),
                }
            )

    return login_forms


def analyze_credential_forms(html):
    """
    Analyze webpage HTML for credential-collection
    behavior.
    """

    fields = detect_credential_fields(
        html
    )

    login_forms = detect_login_forms(
        html
    )

    indicators = []

    risk_score = 0

    password_count = len(
        fields["password_fields"]
    )

    username_count = len(
        fields["username_fields"]
    )

    email_count = len(
        fields["email_fields"]
    )

    hidden_count = len(
        fields["hidden_fields"]
    )

    # ---------------------------------------------
    # Password fields
    # ---------------------------------------------

    if password_count > 0:

        risk_score += 20

        indicators.append(
            f"Password field detected: "
            f"{password_count}"
        )

    # ---------------------------------------------
    # Username fields
    # ---------------------------------------------

    if username_count > 0:

        risk_score += 10

        indicators.append(
            f"Username/login field detected: "
            f"{username_count}"
        )

    # ---------------------------------------------
    # Email fields
    # ---------------------------------------------

    if email_count > 0:

        risk_score += 10

        indicators.append(
            f"Email field detected: "
            f"{email_count}"
        )

    # ---------------------------------------------
    # Login forms
    # ---------------------------------------------

    if login_forms:

        risk_score += 20

        indicators.append(
            f"Login/credential form detected: "
            f"{len(login_forms)}"
        )

    # ---------------------------------------------
    # Hidden fields
    # ---------------------------------------------

    if hidden_count > 0:

        indicators.append(
            f"Hidden input fields detected: "
            f"{hidden_count}"
        )

    # ---------------------------------------------
    # Risk level
    # ---------------------------------------------

    if risk_score >= 50:

        risk_level = "HIGH"

    elif risk_score >= 30:

        risk_level = "MEDIUM"

    elif risk_score > 0:

        risk_level = "LOW"

    else:

        risk_level = "SAFE"

    return {
        "password_fields": fields[
            "password_fields"
        ],
        "username_fields": fields[
            "username_fields"
        ],
        "email_fields": fields[
            "email_fields"
        ],
        "hidden_fields": fields[
            "hidden_fields"
        ],
        "login_forms": login_forms,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
    }
# =========================================================
# V2.8 PHASE 2
# CREDENTIAL / LOGIN FORM INTELLIGENCE
# =========================================================

CREDENTIAL_INPUT_TYPES = {
    "password",
    "email",
}

USERNAME_KEYWORDS = {
    "user",
    "username",
    "login",
    "email",
    "account",
}

PASSWORD_KEYWORDS = {
    "password",
    "passwd",
    "pass",
    "pwd",
}


def detect_credential_fields(html):
    """
    Detect username, email, and password fields
    in webpage HTML.
    """

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    password_fields = []
    username_fields = []
    email_fields = []
    hidden_fields = []

    inputs = soup.find_all("input")

    for field in inputs:

        input_type = (
            field.get("type", "text")
            .lower()
        )

        name = (
            field.get("name", "")
            .lower()
        )

        field_id = (
            field.get("id", "")
            .lower()
        )

        placeholder = (
            field.get("placeholder", "")
            .lower()
        )

        combined = (
            f"{name} "
            f"{field_id} "
            f"{placeholder}"
        )

        # ---------------------------------------------
        # Password
        # ---------------------------------------------

        if input_type == "password":

            password_fields.append(
                {
                    "name": name,
                    "id": field_id,
                    "type": input_type,
                }
            )

        # ---------------------------------------------
        # Email
        # ---------------------------------------------

        elif input_type == "email":

            email_fields.append(
                {
                    "name": name,
                    "id": field_id,
                    "type": input_type,
                }
            )

        # ---------------------------------------------
        # Username / login
        # ---------------------------------------------

        elif any(
            keyword in combined
            for keyword in USERNAME_KEYWORDS
        ):

            username_fields.append(
                {
                    "name": name,
                    "id": field_id,
                    "type": input_type,
                }
            )

        # ---------------------------------------------
        # Hidden fields
        # ---------------------------------------------

        if input_type == "hidden":

            hidden_fields.append(
                {
                    "name": name,
                    "id": field_id,
                }
            )

    return {
        "password_fields": password_fields,
        "username_fields": username_fields,
        "email_fields": email_fields,
        "hidden_fields": hidden_fields,
    }


def detect_login_forms(html):
    """
    Detect forms that appear to be login or
    credential-collection forms.
    """

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    login_forms = []

    for form in soup.find_all("form"):

        form_text = form.get_text(
            " ",
            strip=True
        ).lower()

        action = form.get(
            "action",
            ""
        )

        method = form.get(
            "method",
            "get"
        ).lower()

        password_fields = form.find_all(
            "input",
            {
                "type": "password"
            }
        )

        credential_keywords = (
            "login",
            "log in",
            "sign in",
            "signin",
            "password",
            "username",
            "verify",
            "verification",
            "account",
        )

        keyword_match = any(
            keyword in form_text
            for keyword in credential_keywords
        )

        if password_fields or keyword_match:

            login_forms.append(
                {
                    "action": action,
                    "method": method,
                    "password_field_count": len(
                        password_fields
                    ),
                }
            )

    return login_forms


def analyze_credential_forms(html):
    """
    Analyze webpage HTML for credential-collection
    behavior.
    """

    fields = detect_credential_fields(
        html
    )

    login_forms = detect_login_forms(
        html
    )

    indicators = []

    risk_score = 0

    password_count = len(
        fields["password_fields"]
    )

    username_count = len(
        fields["username_fields"]
    )

    email_count = len(
        fields["email_fields"]
    )

    hidden_count = len(
        fields["hidden_fields"]
    )

    # ---------------------------------------------
    # Password fields
    # ---------------------------------------------

    if password_count > 0:

        risk_score += 20

        indicators.append(
            f"Password field detected: "
            f"{password_count}"
        )

    # ---------------------------------------------
    # Username fields
    # ---------------------------------------------

    if username_count > 0:

        risk_score += 10

        indicators.append(
            f"Username/login field detected: "
            f"{username_count}"
        )

    # ---------------------------------------------
    # Email fields
    # ---------------------------------------------

    if email_count > 0:

        risk_score += 10

        indicators.append(
            f"Email field detected: "
            f"{email_count}"
        )

    # ---------------------------------------------
    # Login forms
    # ---------------------------------------------

    if login_forms:

        risk_score += 20

        indicators.append(
            f"Login/credential form detected: "
            f"{len(login_forms)}"
        )

    # ---------------------------------------------
    # Hidden fields
    # ---------------------------------------------

    if hidden_count > 0:

        indicators.append(
            f"Hidden input fields detected: "
            f"{hidden_count}"
        )

    # ---------------------------------------------
    # Risk level
    # ---------------------------------------------

    if risk_score >= 50:

        risk_level = "HIGH"

    elif risk_score >= 30:

        risk_level = "MEDIUM"

    elif risk_score > 0:

        risk_level = "LOW"

    else:

        risk_level = "SAFE"

    return {
        "password_fields": fields[
            "password_fields"
        ],
        "username_fields": fields[
            "username_fields"
        ],
        "email_fields": fields[
            "email_fields"
        ],
        "hidden_fields": fields[
            "hidden_fields"
        ],
        "login_forms": login_forms,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
    }
# =========================================================
# V2.8 PHASE 3
# EXTERNAL FORM DESTINATION INTELLIGENCE
# =========================================================

from urllib.parse import urljoin, urlparse


def analyze_form_destinations(html, page_url):
    """
    Analyze HTML forms and determine whether credential
    forms submit data to an external domain.
    """

    soup = BeautifulSoup(html or "", "html.parser")

    page_domain = urlparse(page_url).netloc.lower()

    results = []

    external_count = 0
    credential_external_count = 0

    for form in soup.find_all("form"):

        action = form.get("action", "").strip()
        method = form.get("method", "get").lower()

        # Resolve relative form actions
        if action:
            absolute_action = urljoin(
                page_url,
                action
            )
        else:
            absolute_action = page_url

        action_domain = urlparse(
            absolute_action
        ).netloc.lower()

        # Detect credential fields
        password_fields = form.find_all(
            "input",
            attrs={
                "type": "password"
            }
        )

        email_fields = form.find_all(
            "input",
            attrs={
                "type": "email"
            }
        )

        credential_form = (
            len(password_fields) > 0
            or len(email_fields) > 0
        )

        is_external = False

        if action_domain:
            if action_domain != page_domain:
                is_external = True

        if is_external:
            external_count += 1

            if credential_form:
                credential_external_count += 1

        results.append(
            {
                "action": action,
                "absolute_action": absolute_action,
                "method": method,
                "action_domain": action_domain,
                "is_external": is_external,
                "is_credential_form": credential_form,
            }
        )

    indicators = []
    risk_score = 0

    if external_count > 0:

        indicators.append(
            "Form submits data to an external domain"
        )

        risk_score += 15

    if credential_external_count > 0:

        indicators.append(
            "Credential form submits data to an external domain"
        )

        risk_score += 35

    if risk_score >= 40:

        risk_level = "HIGH"

    elif risk_score >= 20:

        risk_level = "MEDIUM"

    elif risk_score > 0:

        risk_level = "LOW"

    else:

        risk_level = "SAFE"

    return {
        "forms": results,
        "external_form_count": external_count,
        "credential_external_count": credential_external_count,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
    }
# =========================================================
# V2.8 PHASE 4
# JAVASCRIPT & IFRAME INTELLIGENCE
# =========================================================

from urllib.parse import urljoin, urlparse


SUSPICIOUS_JS_PATTERNS = [
    "eval(",
    "atob(",
    "fromcharcode(",
    "document.cookie",
    "window.location",
    "location.href",
    "location.replace",
    "location.assign",
]


def analyze_javascript_iframes(html, page_url):
    """
    Perform static analysis of JavaScript and iframe usage.

    No JavaScript is executed.
    """

    soup = BeautifulSoup(html or "", "html.parser")

    page_domain = urlparse(
        page_url
    ).netloc.lower()

    scripts = soup.find_all("script")
    iframes = soup.find_all("iframe")

    inline_script_count = 0
    external_script_count = 0
    suspicious_script_count = 0

    script_results = []

    for script in scripts:

        src = script.get("src", "").strip()

        if src:

            external_script_count += 1

            absolute_src = urljoin(
                page_url,
                src
            )

            script_domain = urlparse(
                absolute_src
            ).netloc.lower()

            is_external = (
                script_domain != page_domain
                and script_domain != ""
            )

            script_text = ""

        else:

            inline_script_count += 1

            absolute_src = ""
            script_domain = ""
            is_external = False

            script_text = script.get_text(
                " ",
                strip=True
            )

        script_lower = script_text.lower()

        suspicious_patterns = []

        for pattern in SUSPICIOUS_JS_PATTERNS:

            if pattern in script_lower:

                suspicious_patterns.append(
                    pattern
                )

        if suspicious_patterns:

            suspicious_script_count += 1

        script_results.append(
            {
                "src": src,
                "absolute_src": absolute_src,
                "is_external": is_external,
                "inline": not bool(src),
                "suspicious_patterns": suspicious_patterns,
            }
        )

    external_iframe_count = 0
    hidden_iframe_count = 0

    iframe_results = []

    for iframe in iframes:

        src = iframe.get("src", "").strip()

        absolute_src = urljoin(
            page_url,
            src
        ) if src else page_url

        iframe_domain = urlparse(
            absolute_src
        ).netloc.lower()

        is_external = (
            iframe_domain != page_domain
            and iframe_domain != ""
        )

        style = iframe.get(
            "style",
            ""
        ).lower()

        width = iframe.get(
            "width",
            ""
        ).strip()

        height = iframe.get(
            "height",
            ""
        ).strip()

        hidden = False

        if "display:none" in style.replace(
            " ",
            ""
        ):
            hidden = True

        if "visibility:hidden" in style.replace(
            " ",
            ""
        ):
            hidden = True

        if width == "0" or height == "0":
            hidden = True

        if is_external:

            external_iframe_count += 1

        if hidden:

            hidden_iframe_count += 1

        iframe_results.append(
            {
                "src": src,
                "absolute_src": absolute_src,
                "is_external": is_external,
                "hidden": hidden,
            }
        )

    risk_score = 0
    indicators = []

    if suspicious_script_count > 0:

        risk_score += 25

        indicators.append(
            "Suspicious JavaScript patterns detected"
        )

    if external_script_count > 0:

        indicators.append(
            "External JavaScript detected"
        )

    if external_iframe_count > 0:

        risk_score += 15

        indicators.append(
            "External iframe detected"
        )

    if hidden_iframe_count > 0:

        risk_score += 20

        indicators.append(
            "Hidden iframe detected"
        )

    if risk_score >= 40:

        risk_level = "HIGH"

    elif risk_score >= 20:

        risk_level = "MEDIUM"

    elif risk_score > 0:

        risk_level = "LOW"

    else:

        risk_level = "SAFE"

    return {
        "script_count": len(scripts),
        "inline_script_count": inline_script_count,
        "external_script_count": external_script_count,
        "suspicious_script_count": suspicious_script_count,
        "iframe_count": len(iframes),
        "external_iframe_count": external_iframe_count,
        "hidden_iframe_count": hidden_iframe_count,
        "scripts": script_results,
        "iframes": iframe_results,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
    }
# =========================================================
# V2.8 PHASE 5
# CONTENT RISK SCORING
# =========================================================

def calculate_content_risk(
    credential_analysis,
    form_destination_analysis,
    javascript_analysis,
):
    """
    Combine credential, form-destination, JavaScript,
    and iframe intelligence into one content risk result.
    """

    credential_score = credential_analysis.get(
        "risk_score",
        0
    )

    form_score = form_destination_analysis.get(
        "risk_score",
        0
    )

    javascript_score = javascript_analysis.get(
        "risk_score",
        0
    )

    total_score = (
        credential_score
        + form_score
        + javascript_score
    )

    indicators = []

    indicators.extend(
        credential_analysis.get(
            "indicators",
            []
        )
    )

    indicators.extend(
        form_destination_analysis.get(
            "indicators",
            []
        )
    )

    indicators.extend(
        javascript_analysis.get(
            "indicators",
            []
        )
    )

    # Remove duplicate indicators
    indicators = list(
        dict.fromkeys(indicators)
    )

    if total_score >= 70:

        risk_level = "HIGH"

    elif total_score >= 40:

        risk_level = "MEDIUM"

    elif total_score > 0:

        risk_level = "LOW"

    else:

        risk_level = "SAFE"

    return {
        "credential_score": credential_score,
        "form_destination_score": form_score,
        "javascript_score": javascript_score,
        "total_score": total_score,
        "risk_level": risk_level,
        "indicators": indicators,
    }
