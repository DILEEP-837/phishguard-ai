from phishguard.core.web_behavior_intelligence import (
    analyze_web_behavior,
    detect_javascript_redirect,
    detect_meta_refresh,
    detect_javascript_links,
    detect_cookie_access,
    detect_obfuscated_javascript,
    detect_suspicious_combinations,
)


def test_javascript_redirect():
    html = """
    <script>
        window.location = "https://evil.example/login";
    </script>
    """

    assert detect_javascript_redirect(html) is True


def test_meta_refresh_redirect():
    html = """
    <meta http-equiv="refresh"
          content="0;url=https://evil.example">
    """

    assert detect_meta_refresh(html) is True


def test_javascript_link():
    html = """
    <a href="javascript:window.location='https://evil.example'">
        Click here
    </a>
    """

    assert detect_javascript_links(html) is True


def test_cookie_access():
    html = """
    <script>
        document.cookie;
    </script>
    """

    assert detect_cookie_access(html) is True


def test_obfuscated_javascript():
    html = """
    <script>
        eval(atob("d2luZG93LmxvY2F0aW9u"));
    </script>
    """

    assert detect_obfuscated_javascript(html) is True


def test_suspicious_combination():
    html = """
    <script>
        eval(atob("d2luZG93LmxvY2F0aW9u"));
        document.cookie;
        window.location = "https://evil.example";
    </script>

    <iframe
        src="https://evil.example/login"
        style="display:none">
    </iframe>
    """

    result = detect_suspicious_combinations(html)

    assert result["suspicious"] is True
    assert result["risk_score"] > 0


def test_normal_page_is_safe():
    html = """
    <html>
        <head>
            <title>Example</title>
        </head>
        <body>
            <h1>Hello World</h1>
        </body>
    </html>
    """

    result = analyze_web_behavior(
        html,
        "https://example.com",
    )

    assert result["classification"] == "SAFE"
    assert result["risk_score"] == 0


def test_full_web_behavior_analysis():
    html = """
    <script>
        eval(atob("d2luZG93LmxvY2F0aW9u"));
        document.cookie;
        window.location = "https://evil.example/login";
    </script>

    <meta http-equiv="refresh"
          content="0;url=https://evil.example">

    <a href="javascript:window.location='https://evil.example'">
        Continue
    </a>
    """

    result = analyze_web_behavior(
        html,
        "https://example.com",
    )

    assert result["risk_score"] > 0
    assert result["indicators"]
    assert result["classification"] in {
        "SUSPICIOUS",
        "MALICIOUS",
    }
