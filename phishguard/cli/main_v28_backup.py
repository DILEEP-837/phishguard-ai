import sys

from phishguard.core.input_normalizer import normalize_url
from phishguard.core.url_analyzer import analyze_url

from phishguard.core.redirect_intelligence import (
    analyze_redirect,
    analyze_redirect_chain,
)

from phishguard.core.content_intelligence import (
    fetch_page,
    parse_html,
    analyze_credential_forms,
    analyze_form_destinations,
    analyze_javascript_iframes,
    calculate_content_risk,
)


def scan_url(raw_url):

    """
    Normalize, analyze, and display URL threat assessment.

    Includes:
    V2.7 Redirect Intelligence
    V2.8 Content Intelligence
    """

    # =========================================================
    # 1. NORMALIZE INPUT
    # =========================================================

    url = normalize_url(raw_url)

    # Clean Markdown-style URL
    if url.startswith("[") and "](" in url and url.endswith(")"):
        url = url[url.find("[") + 1:url.find("](")]

    # =========================================================
    # 2. CORE URL ANALYSIS
    # =========================================================

    analysis = analyze_url(url)

    risk_score = analysis.get(
        "risk_score",
        0
    )

    risk_level = analysis.get(
        "risk_level",
        "SAFE"
    )

    indicators = list(
        analysis.get(
            "indicators",
            []
        )
    )

    # =========================================================
    # 3. V2.7 REDIRECT INTELLIGENCE
    # =========================================================

    redirect_analysis = analyze_redirect(url)

    redirect_chain = analyze_redirect_chain(url)

    # =========================================================
    # 4. ADD REDIRECT RISK
    # =========================================================

    redirect_score = max(
        redirect_analysis.get(
            "risk_score",
            0
        ),
        redirect_chain.get(
            "risk_score",
            0
        ),
    )

    if redirect_score > 0:

        risk_score = min(
            100,
            risk_score + redirect_score
        )

    # =========================================================
    # 5. ADD REDIRECT INDICATORS
    # =========================================================

    redirect_indicators = []

    redirect_indicators.extend(
        redirect_analysis.get(
            "indicators",
            []
        )
    )

    redirect_indicators.extend(
        redirect_chain.get(
            "indicators",
            []
        )
    )

    for indicator in redirect_indicators:

        if indicator not in indicators:

            indicators.append(
                indicator
            )

    # =========================================================
    # 6. V2.8 CONTENT INTELLIGENCE
    # =========================================================

    content_result = {
        "success": False,
        "status_code": None,
        "content_type": "",
        "title": "",
        "form_count": 0,
        "input_count": 0,
        "script_count": 0,
        "iframe_count": 0,
        "link_count": 0,
        "error": None,
    }

    credential_analysis = {
        "password_fields": [],
        "username_fields": [],
        "email_fields": [],
        "hidden_fields": [],
        "login_forms": [],
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
    }

    form_destination_analysis = {
        "forms": [],
        "external_form_count": 0,
        "credential_external_count": 0,
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
    }

    javascript_analysis = {
        "script_count": 0,
        "inline_script_count": 0,
        "external_script_count": 0,
        "suspicious_script_count": 0,
        "iframe_count": 0,
        "external_iframe_count": 0,
        "hidden_iframe_count": 0,
        "scripts": [],
        "iframes": [],
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
    }

    content_risk = {
        "credential_score": 0,
        "form_destination_score": 0,
        "javascript_score": 0,
        "total_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
    }

    html = ""

    # =========================================================
    # 7. FETCH PAGE
    # =========================================================

    try:

        fetched = fetch_page(url)

        content_result["success"] = fetched.get(
            "success",
            False
        )

        content_result["status_code"] = fetched.get(
            "status_code"
        )

        content_result["content_type"] = fetched.get(
            "content_type",
            ""
        )

        content_result["error"] = fetched.get(
            "error"
        )

        html = fetched.get(
            "html",
            ""
        )

    except Exception as exc:

        content_result["success"] = False
        content_result["error"] = str(exc)

    # =========================================================
    # 8. ANALYZE HTML CONTENT
    # =========================================================

    if (
        content_result["success"]
        and html
        and "text/html"
        in content_result["content_type"].lower()
    ):

        parsed_content = parse_html(
            html
        )

        content_result.update(
            parsed_content
        )

        # -----------------------------------------------------
        # Credential / Login Intelligence
        # -----------------------------------------------------

        credential_analysis = analyze_credential_forms(
            html
        )

        # -----------------------------------------------------
        # External Form Destination Intelligence
        # -----------------------------------------------------

        form_destination_analysis = analyze_form_destinations(
            html,
            url
        )

        # -----------------------------------------------------
        # JavaScript / iframe Intelligence
        # -----------------------------------------------------

        javascript_analysis = analyze_javascript_iframes(
            html,
            url
        )

        # -----------------------------------------------------
        # Combined Content Risk
        # -----------------------------------------------------

        content_risk = calculate_content_risk(
            credential_analysis,
            form_destination_analysis,
            javascript_analysis,
        )

    # =========================================================
    # 9. ADD CONTENT RISK TO OVERALL SCORE
    # =========================================================

    content_score = content_risk.get(
        "total_score",
        0
    )

    if content_score > 0:

        risk_score = min(
            100,
            risk_score + content_score
        )

    # =========================================================
    # 10. ADD CONTENT INDICATORS
    # =========================================================

    content_indicators = content_risk.get(
        "indicators",
        []
    )

    for indicator in content_indicators:

        if indicator not in indicators:

            indicators.append(
                indicator
            )

    # =========================================================
    # 11. FINAL RISK LEVEL
    # =========================================================

    if risk_score >= 80:

        risk_level = "CRITICAL"

    elif risk_score >= 60:

        risk_level = "HIGH"

    elif risk_score >= 30:

        risk_level = "MEDIUM"

    elif risk_score > 0:

        risk_level = "LOW"

    else:

        risk_level = "SAFE"

    analysis["risk_score"] = risk_score
    analysis["risk_level"] = risk_level
    analysis["indicators"] = indicators

    # =========================================================
    # 12. HEADER
    # =========================================================

    print()

    print("=" * 60)

    print(
        "                 PHISHGUARD AI"
    )

    print(
        "                  URL SCANNER"
    )

    print(
        "                      V2.8"
    )

    print("=" * 60)

    print()

    # =========================================================
    # 13. URL INFORMATION
    # =========================================================

    print("[URL INFORMATION]")

    print()

    print(
        f"  URL         : {analysis['url']}"
    )

    print(
        f"  Hostname    : {analysis['hostname']}"
    )

    print(
        f"  Domain      : {analysis['domain']}"
    )

    print(
        f"  TLD         : "
        f"{analysis['tld'] or 'N/A'}"
    )

    print(
        f"  HTTPS       : "
        f"{'YES' if analysis['https'] else 'NO'}"
    )

    print(
        f"  IP Address  : "
        f"{'YES' if analysis['is_ip'] else 'NO'}"
    )

    print()

    # =========================================================
    # 14. REDIRECT INTELLIGENCE
    # =========================================================

    print("[REDIRECT INTELLIGENCE]")

    print()

    print(
        f"  Redirect Parameters : "
        f"{len(redirect_analysis.get('redirect_parameters', []))}"
    )

    print(
        f"  Redirect Targets    : "
        f"{len(redirect_analysis.get('redirect_targets', []))}"
    )

    print(
        f"  HTTP Redirects      : "
        f"{redirect_chain.get('redirect_count', 0)}"
    )

    print(
        f"  Cross-Domain        : "
        f"{'YES' if redirect_chain.get('cross_domain_redirect') else 'NO'}"
    )

    print(
        f"  HTTPS → HTTP        : "
        f"{'YES' if redirect_chain.get('https_to_http') else 'NO'}"
    )

    print(
        f"  Redirect Loop       : "
        f"{'YES' if redirect_chain.get('redirect_loop') else 'NO'}"
    )

    final_url = redirect_chain.get(
        "final_url"
    )

    if final_url:

        print(
            f"  Final Destination   : "
            f"{final_url}"
        )

    print()

    # =========================================================
    # 15. CONTENT INTELLIGENCE
    # =========================================================

    print("[CONTENT INTELLIGENCE]")

    print()

    if content_result["success"]:

        print(
            f"  HTTP Status         : "
            f"{content_result['status_code']}"
        )

        print(
            f"  Content Type        : "
            f"{content_result['content_type'] or 'N/A'}"
        )

        print(
            f"  Page Title          : "
            f"{content_result.get('title') or 'N/A'}"
        )

        print(
            f"  Forms               : "
            f"{content_result.get('form_count', 0)}"
        )

        print(
            f"  Inputs              : "
            f"{content_result.get('input_count', 0)}"
        )

        print(
            f"  Scripts             : "
            f"{content_result.get('script_count', 0)}"
        )

        print(
            f"  Iframes             : "
            f"{content_result.get('iframe_count', 0)}"
        )

        print(
            f"  Links               : "
            f"{content_result.get('link_count', 0)}"
        )

        print()

        print(
            f"  Password Fields     : "
            f"{len(credential_analysis.get('password_fields', []))}"
        )

        print(
            f"  Username Fields     : "
            f"{len(credential_analysis.get('username_fields', []))}"
        )

        print(
            f"  Email Fields        : "
            f"{len(credential_analysis.get('email_fields', []))}"
        )

        print(
            f"  Login Forms         : "
            f"{len(credential_analysis.get('login_forms', []))}"
        )

        print(
            f"  External Forms      : "
            f"{form_destination_analysis.get('external_form_count', 0)}"
        )

        print(
            f"  External Credential: "
            f"{form_destination_analysis.get('credential_external_count', 0)}"
        )

        print(
            f"  Suspicious Scripts  : "
            f"{javascript_analysis.get('suspicious_script_count', 0)}"
        )

        print(
            f"  External Iframes    : "
            f"{javascript_analysis.get('external_iframe_count', 0)}"
        )

        print(
            f"  Hidden Iframes      : "
            f"{javascript_analysis.get('hidden_iframe_count', 0)}"
        )

        print()

        print(
            f"  Content Score       : "
            f"{content_score}"
        )

        print(
            f"  Content Risk        : "
            f"{content_risk.get('risk_level', 'SAFE')}"
        )

    else:

        print(
            "  Page retrieval failed."
        )

        if content_result.get("error"):

            print(
                f"  Error               : "
                f"{content_result['error']}"
            )

    print()

    # =========================================================
    # 16. THREAT ASSESSMENT
    # =========================================================

    print("[THREAT ASSESSMENT]")

    print()

    print(
        f"  Risk Score  : "
        f"{risk_score}/100"
    )

    print(
        f"  Risk Level  : "
        f"{risk_level}"
    )

    print(
        f"  Suspicious  : "
        f"{'YES' if analysis['suspicious'] or risk_score > 0 else 'NO'}"
    )

    print()

    # =========================================================
    # 17. DETECTED INDICATORS
    # =========================================================

    print("[DETECTED INDICATORS]")

    print()

    if indicators:

        for indicator in indicators:

            print(
                f"  [!] {indicator}"
            )

    else:

        print(
            "  None detected"
        )

    print()

    # =========================================================
    # 18. FINAL RESULT
    # =========================================================

    print("[PHISHGUARD RESULT]")

    print()

    if risk_level == "SAFE":

        print(
            "  No significant suspicious "
            "indicators detected."
        )

    elif risk_level == "LOW":

        print(
            "  Low-level suspicious "
            "characteristics detected."
        )

    elif risk_level == "MEDIUM":

        print(
            "  Multiple suspicious "
            "characteristics detected."
        )

    elif risk_level == "HIGH":

        print(
            "  High-risk characteristics "
            "detected."
        )

    else:

        print(
            "  Critical-risk characteristics "
            "detected."
        )

    print()

    print("=" * 60)

    print()


def main():

    # =========================================================
    # COMMAND VALIDATION
    # =========================================================

    if len(sys.argv) < 3:

        print()

        print(
            "PHISHGUARD AI V2.8"
        )

        print()

        print(
            "Usage:"
        )

        print(
            "  python -m phishguard.cli.main "
            "scan-url <URL>"
        )

        print()

        return

    command = sys.argv[1]

    raw_url = sys.argv[2]

    # =========================================================
    # SCAN URL
    # =========================================================

    if command == "scan-url":

        scan_url(
            raw_url
        )

    else:

        print()

        print(
            f"Unknown command: {command}"
        )

        print()

        print(
            "Available commands:"
        )

        print(
            "  scan-url <URL>"
        )

        print()


if __name__ == "__main__":

    main()
