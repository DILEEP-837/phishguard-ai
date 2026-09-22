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

from phishguard.core.dns_intelligence import analyze_dns
from phishguard.core.tls_intelligence import analyze_tls
from phishguard.core.tls_security import analyze_tls_security


def scan_url(raw_url):
    """
    Normalize, analyze, and display URL threat assessment.

    Includes:
    V2.7 Redirect Intelligence
    V2.8 Content Intelligence
    V2.9 DNS & Domain Intelligence
    """

    # =========================================================
    # 1. NORMALIZE INPUT
    # =========================================================

    url = normalize_url(raw_url)

    if url.startswith("[") and "](" in url and url.endswith(")"):
        url = url[url.find("[") + 1:url.find("](")]

    # =========================================================
    # 2. CORE URL ANALYSIS
    # =========================================================

    analysis = analyze_url(url)

    risk_score = analysis.get("risk_score", 0)
    risk_level = analysis.get("risk_level", "SAFE")

    indicators = list(
        analysis.get("indicators", [])
    )

    # =========================================================
    # 3. V2.7 REDIRECT INTELLIGENCE
    # =========================================================

    redirect_analysis = analyze_redirect(url)
    redirect_chain = analyze_redirect_chain(url)

    redirect_score = max(
        redirect_analysis.get("risk_score", 0),
        redirect_chain.get("risk_score", 0),
    )

    if redirect_score > 0:
        risk_score = min(
            100,
            risk_score + redirect_score
        )

    redirect_indicators = []

    redirect_indicators.extend(
        redirect_analysis.get("indicators", [])
    )

    redirect_indicators.extend(
        redirect_chain.get("indicators", [])
    )

    for indicator in redirect_indicators:
        if indicator not in indicators:
            indicators.append(indicator)

    # =========================================================
    # 4. V2.8 CONTENT INTELLIGENCE
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

    if (
        content_result["success"]
        and html
        and "text/html" in content_result["content_type"].lower()
    ):
        parsed_content = parse_html(html)

        content_result.update(
            parsed_content
        )

        credential_analysis = analyze_credential_forms(
            html
        )

        form_destination_analysis = analyze_form_destinations(
            html,
            url
        )

        javascript_analysis = analyze_javascript_iframes(
            html,
            url
        )

        content_risk = calculate_content_risk(
            credential_analysis,
            form_destination_analysis,
            javascript_analysis,
        )

    content_score = content_risk.get(
        "total_score",
        0
    )

    if content_score > 0:
        risk_score = min(
            100,
            risk_score + content_score
        )

    for indicator in content_risk.get(
        "indicators",
        []
    ):
        if indicator not in indicators:
            indicators.append(indicator)

    # =========================================================
    # 5. V2.9 DNS & DOMAIN INTELLIGENCE
    # =========================================================

    dns_result = {
        "hostname": analysis.get("hostname", ""),
        "a_records": [],
        "aaaa_records": [],
        "cname_records": [],
        "mx_records": [],
        "ns_records": [],
        "resolved": False,
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
        "infrastructure": {
            "risk_score": 0,
            "risk_level": "SAFE",
            "indicators": [],
        },
        "domain_structure": {
            "risk_score": 0,
            "risk_level": "SAFE",
            "indicators": [],
        },
    }

    try:
        dns_result = analyze_dns(url)

        dns_score = dns_result.get(
            "risk_score",
            0
        )

        if dns_score > 0:
            risk_score = min(
                100,
                risk_score + dns_score
            )

        for indicator in dns_result.get(
            "indicators",
            []
        ):
            if indicator not in indicators:
                indicators.append(indicator)

    except Exception as exc:
        dns_result["error"] = str(exc)

    # =========================================================
    # 6. V3.0 TLS / HTTPS CERTIFICATE INTELLIGENCE
    tls_result = {
        "https": False,
        "hostname": "",
        "port": 443,
        "certificate_metadata": None,
        "date_analysis": None,
        "identity_analysis": None,
        "risk_score": 0,
        "indicators": [],
        "error": None,
    }

    try:
        tls_result = analyze_tls(url)

        tls_score = tls_result.get("risk_score", 0)

        if tls_score > 0:
            risk_score = min(
                100,
                risk_score + tls_score
            )

        for indicator in tls_result.get("indicators", []):
            if indicator not in indicators:
                indicators.append(indicator)

    except Exception as exc:
        tls_result["error"] = str(exc)

    # 6B. V3.0 PHASE 2 - TLS SECURITY CONFIGURATION

    tls_security_result = analyze_tls_security(url)

    tls_security_score = tls_security_result.get("risk_score", 0)

    risk_score = min(
        100,
        risk_score + tls_security_score
    )

    for indicator in tls_security_result.get("indicators", []):
        if indicator not in indicators:
            indicators.append(indicator)

    # 7. FINAL RISK LEVEL
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
    # 8. HEADER
    # =========================================================

    print()
    print("=" * 60)
    print("                  PHISHGUARD AI")
    print("                  URL SCANNER")
    print("                      V3.0")
    print("=" * 60)
    print()

    # =========================================================
    # 9. URL INFORMATION
    # =========================================================

    print("[URL INFORMATION]")
    print()

    print(f"  URL         : {analysis['url']}")
    print(f"  Hostname    : {analysis['hostname']}")
    print(f"  Domain      : {analysis['domain']}")
    print(f"  TLD         : {analysis['tld'] or 'N/A'}")
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
    # 10. REDIRECT INTELLIGENCE
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
    # 11. CONTENT INTELLIGENCE
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
            f"  External Cred Forms : "
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

        print(
            f"  Content Risk Score  : "
            f"{content_risk.get('total_score', 0)}"
        )

        print(
            f"  Content Risk Level  : "
            f"{content_risk.get('risk_level', 'SAFE')}"
        )

    else:

        print("  Page retrieval failed.")
        print(
            f"  Error               : "
            f"{content_result.get('error') or 'Unknown error'}"
        )

    print()

    # =========================================================
    # 12. DNS & DOMAIN INTELLIGENCE
    # =========================================================

    print("[DNS & DOMAIN INTELLIGENCE]")
    print()

    print(
        f"  DNS Resolved        : "
        f"{'YES' if dns_result.get('resolved') else 'NO'}"
    )

    print(
        f"  A Records           : "
        f"{len(dns_result.get('a_records', []))}"
    )

    print(
        f"  AAAA Records        : "
        f"{len(dns_result.get('aaaa_records', []))}"
    )

    print(
        f"  CNAME Records       : "
        f"{len(dns_result.get('cname_records', []))}"
    )

    print(
        f"  MX Records          : "
        f"{len(dns_result.get('mx_records', []))}"
    )

    print(
        f"  NS Records          : "
        f"{len(dns_result.get('ns_records', []))}"
    )

    print()

    if dns_result.get("a_records"):
        print(
            f"  IPv4 Addresses      : "
            f"{', '.join(dns_result['a_records'])}"
        )

    if dns_result.get("aaaa_records"):
        print(
            f"  IPv6 Addresses      : "
            f"{', '.join(dns_result['aaaa_records'])}"
        )

    if dns_result.get("cname_records"):
        print(
            f"  CNAME Aliases       : "
            f"{', '.join(dns_result['cname_records'])}"
        )

    if dns_result.get("mx_records"):
        mx_values = [
            f"{item.get('exchange') or 'N/A'} "
            f"(priority {item.get('priority', 'N/A')})"
            for item in dns_result["mx_records"]
        ]

        print(
            f"  Mail Servers        : "
            f"{', '.join(mx_values)}"
        )

    if dns_result.get("ns_records"):
        print(
            f"  Nameservers         : "
            f"{', '.join(dns_result['ns_records'])}"
        )

    print()

    infrastructure = dns_result.get(
        "infrastructure",
        {}
    )

    domain_structure = dns_result.get(
        "domain_structure",
        {}
    )

    print(
        f"  Infrastructure Risk : "
        f"{infrastructure.get('risk_score', 0)} "
        f"({infrastructure.get('risk_level', 'SAFE')})"
    )

    print(
        f"  Domain Risk         : "
        f"{domain_structure.get('risk_score', 0)} "
        f"({domain_structure.get('risk_level', 'SAFE')})"
    )

    print(
        f"  DNS Risk Score      : "
        f"{dns_result.get('risk_score', 0)}"
    )

    print(
        f"  DNS Risk Level      : "
        f"{dns_result.get('risk_level', 'SAFE')}"
    )

    print()

    # =========================================================
    # 13. TLS / HTTPS CERTIFICATE INTELLIGENCE
    print("[TLS / HTTPS CERTIFICATE INTELLIGENCE]")
    print(
        f"  HTTPS              : "
        f"{'YES' if tls_result.get('https') else 'NO'}"
    )
    print(
        f"  Hostname           : "
        f"{tls_result.get('hostname') or 'N/A'}"
    )
    print(
        f"  TLS Port           : "
        f"{tls_result.get('port', 443)}"
    )

    certificate = tls_result.get("certificate_metadata")

    if certificate:
        print(
            f"  Subject CN         : "
            f"{certificate.get('subject_common_name') or 'N/A'}"
        )
        print(
            f"  Issuer CN          : "
            f"{certificate.get('issuer_common_name') or 'N/A'}"
        )
        print(
            f"  Serial Number      : "
            f"{certificate.get('serial_number') or 'N/A'}"
        )
        print(
            f"  Version            : "
            f"{certificate.get('version') or 'N/A'}"
        )
        print(
            f"  Valid From         : "
            f"{certificate.get('not_before') or 'N/A'}"
        )
        print(
            f"  Valid Until        : "
            f"{certificate.get('not_after') or 'N/A'}"
        )

        dns_names = certificate.get("dns_names", [])

        if dns_names:
            print(
                f"  DNS Names          : "
                f"{', '.join(dns_names)}"
            )

    date_analysis = tls_result.get("date_analysis")

    if date_analysis:
        print(
            f"  Certificate Valid   : "
            f"{'YES' if date_analysis.get('valid') else 'NO'}"
        )

        if date_analysis.get("days_remaining") is not None:
            print(
                f"  Days Remaining      : "
                f"{date_analysis.get('days_remaining')}"
            )

    identity_analysis = tls_result.get("identity_analysis")

    if identity_analysis:
        print(
            f"  Hostname Match      : "
            f"{'YES' if identity_analysis.get('hostname_match') else 'NO'}"
        )

    if tls_result.get("indicators"):
        print("  Indicators:")
        for indicator in tls_result["indicators"]:
            print(f"    - {indicator}")

    print(
        f"  TLS Risk Score      : "
        f"{tls_result.get('risk_score', 0)}"
    )

    if tls_result.get("error"):
        print(
            f"  TLS Error           : "
            f"{tls_result.get('error')}"
        )

    print()

    # 13B. V3.0 PHASE 2 - TLS SECURITY CONFIGURATION
    # =========================================================

    print("TLS SECURITY CONFIGURATION")
    print("-" * 55)

    print(
        f"  HTTPS                  : "
        f"{'YES' if tls_security_result.get('https') else 'NO'}"
    )

    print(
        f"  TLS Connection         : "
        f"{'SUCCESS' if tls_security_result.get('connection') else 'FAILED'}"
    )

    print(
        f"  TLS Version            : "
        f"{tls_security_result.get('tls_version') or 'N/A'}"
    )

    cipher = tls_security_result.get("cipher")

    if cipher:
        if isinstance(cipher, (tuple, list)):
            print(
                f"  Cipher Suite           : "
                f"{cipher[0] if len(cipher) > 0 else 'N/A'}"
            )
            print(
                f"  Cipher Protocol        : "
                f"{cipher[1] if len(cipher) > 1 else 'N/A'}"
            )
            print(
                f"  Cipher Bits            : "
                f"{cipher[2] if len(cipher) > 2 else 'N/A'}"
            )
        else:
            print(
                f"  Cipher Suite           : "
                f"{cipher}"
            )
    else:
        print("  Cipher Suite           : N/A")

    version_analysis = tls_security_result.get(
        "version_analysis", {}
    )

    print(
        f"  TLS Version Risk       : "
        f"{version_analysis.get('risk_level', 'SAFE')}"
    )

    print(
        f"  TLS Version Score      : "
        f"{version_analysis.get('risk_score', 0)}"
    )

    cipher_analysis = tls_security_result.get(
        "cipher_analysis", {}
    )

    print(
        f"  Cipher Risk            : "
        f"{cipher_analysis.get('risk_level', 'SAFE')}"
    )

    print(
        f"  Cipher Score           : "
        f"{cipher_analysis.get('risk_score', 0)}"
    )

    if tls_security_result.get("indicators"):
        print("  Security Indicators:")
        for indicator in tls_security_result["indicators"]:
            print(f"    - {indicator}")

    print(
        f"  TLS Security Score     : "
        f"{tls_security_result.get('risk_score', 0)}"
    )

    print(
        f"  TLS Security Risk      : "
        f"{tls_security_result.get('risk_level', 'SAFE')}"
    )

    if tls_security_result.get("error"):
        print(
            f"  TLS Security Error     : "
            f"{tls_security_result.get('error')}"
        )

    print()

    # 14. THREAT ASSESSMENT
    # =========================================================

    print("[THREAT ASSESSMENT]")
    print()

    print(
        f"  Risk Score          : "
        f"{risk_score}/100"
    )

    print(
        f"  Risk Level          : "
        f"{risk_level}"
    )

    print()

    if indicators:
        print("  Indicators:")

        for indicator in indicators:
            print(
                f"    - {indicator}"
            )

    else:
        print("  Indicators          : None")

    print()

    # =========================================================
    # 15. FINAL RESULT
    # =========================================================

    print("=" * 60)

    if risk_level in ("CRITICAL", "HIGH"):
        print("  RESULT: POTENTIAL THREAT DETECTED")
    elif risk_level == "MEDIUM":
        print("  RESULT: SUSPICIOUS — REVIEW REQUIRED")
    elif risk_level == "LOW":
        print("  RESULT: LOW RISK")
    else:
        print("  RESULT: NO SIGNIFICANT THREATS DETECTED")

    print("=" * 60)
    print()


def main():
    if len(sys.argv) < 3 or sys.argv[1] != "scan-url":
        print(
            "Usage: python -m phishguard.cli.main "
            "scan-url <URL>"
        )
        sys.exit(1)

    scan_url(sys.argv[2])


if __name__ == "__main__":
    main()
