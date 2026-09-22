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
from phishguard.core.http_security import analyze_http_security
from phishguard.core.http_response_intelligence import analyze_http_response
from phishguard.core.web_reputation import analyze_infrastructure
from phishguard.core.relationship_intelligence import analyze_relationships
from phishguard.core.ip_network_intelligence import analyze_ip_network
from phishguard.core.threat_correlation import analyze_threat


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

    # 6C. V3.0 PHASE 3 - HTTP SECURITY INTELLIGENCE

    http_security_result = analyze_http_security(url)

    http_security_score = http_security_result.get(
        "risk_score",
        0
    )

    risk_score = min(
        100,
        risk_score + http_security_score
    )

    for indicator in http_security_result.get(
        "indicators",
        []
    ):
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
        "version_analysis"
    ) or {}

    print(
        f"  TLS Version Risk       : "
        f"{version_analysis.get('risk_level', 'SAFE')}"
    )

    print(
        f"  TLS Version Score      : "
        f"{version_analysis.get('risk_score', 0)}"
    )

    cipher_analysis = tls_security_result.get(
        "cipher_analysis"
    ) or {}

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

    # 13C. V3.0 PHASE 3 - HTTP SECURITY INTELLIGENCE
    print("HTTP SECURITY INTELLIGENCE")
    print("-" * 55)

    print(
        f"  HTTP Status             : "
        f"{http_security_result.get('status_code') or 'N/A'}"
    )

    print(
        f"  Final URL               : "
        f"{http_security_result.get('final_url') or url}"
    )

    security_headers = http_security_result.get("security_headers") or {}

    print(
        f"  Security Headers Present: "
        f"{len(security_headers.get('present', []))}"
    )

    print(
        f"  Security Headers Missing: "
        f"{len(security_headers.get('missing', []))}"
    )

    if security_headers.get("missing"):
        print(
            f"  Missing Headers         : "
            f"{', '.join(security_headers.get('missing', []))}"
        )

    print(
        f"  Header Risk Score       : "
        f"{security_headers.get('risk_score', 0)}"
    )

    print(
        f"  Header Risk Level       : "
        f"{security_headers.get('risk_level', 'SAFE')}"
    )

    cookie_analysis = http_security_result.get("cookies") or {}

    print(
        f"  Cookies                 : "
        f"{cookie_analysis.get('cookie_count', 0)}"
    )

    print(
        f"  Secure Cookies          : "
        f"{cookie_analysis.get('secure_count', 0)}"
    )

    print(
        f"  Insecure Cookies        : "
        f"{cookie_analysis.get('insecure_count', 0)}"
    )

    print(
        f"  HttpOnly Cookies        : "
        f"{cookie_analysis.get('httponly_count', 0)}"
    )

    print(
        f"  Missing HttpOnly        : "
        f"{cookie_analysis.get('missing_httponly_count', 0)}"
    )

    print(
        f"  SameSite Cookies        : "
        f"{cookie_analysis.get('samesite_count', 0)}"
    )

    print(
        f"  Missing SameSite        : "
        f"{cookie_analysis.get('missing_samesite_count', 0)}"
    )

    print(
        f"  Cookie Risk Score       : "
        f"{cookie_analysis.get('risk_score', 0)}"
    )

    print(
        f"  Cookie Risk Level       : "
        f"{cookie_analysis.get('risk_level', 'SAFE')}"
    )

    if http_security_result.get("indicators"):
        print()
        print("  HTTP Security Indicators:")
        for indicator in http_security_result.get("indicators", []):
            print(f"    - {indicator}")

    print(
        f"  HTTP Security Score     : "
        f"{http_security_result.get('risk_score', 0)}"
    )

    print(
        f"  HTTP Security Risk      : "
        f"{http_security_result.get('risk_level', 'SAFE')}"
    )

    if http_security_result.get("error"):
        print(
            f"  HTTP Security Error     : "
            f"{http_security_result.get('error')}"
        )

    print()

    # 6D. V3.0 PHASE 4 - HTTP RESPONSE INTELLIGENCE
    http_response_result = analyze_http_response(url)
    http_response_score = http_response_result.get("risk_score", 0)

    risk_score = min(100, risk_score + http_response_score)

    for indicator in http_response_result.get("indicators", []):
        if indicator not in indicators:
            indicators.append(indicator)

    # 13D. V3.0 PHASE 4 - HTTP RESPONSE INTELLIGENCE
    print("HTTP RESPONSE INTELLIGENCE")
    print("-" * 55)

    print(
        f"  HTTP Status             : "
        f"{http_response_result.get('status_code') or 'N/A'}"
    )

    print(
        f"  HTTP Reason             : "
        f"{http_response_result.get('reason') or 'N/A'}"
    )

    print(
        f"  Content Type            : "
        f"{http_response_result.get('content_type') or 'N/A'}"
    )

    print(
        f"  Response Size           : "
        f"{http_response_result.get('content_length', 0)} bytes"
    )

    status_analysis = http_response_result.get("status_analysis") or {}

    print(
        f"  Status Risk Score       : "
        f"{status_analysis.get('risk_score', 0)}"
    )

    print(
        f"  Status Risk Level       : "
        f"{status_analysis.get('risk_level', 'SAFE')}"
    )

    content_type_analysis = (
        http_response_result.get("content_type_analysis") or {}
    )

    print(
        f"  Content-Type Risk Score : "
        f"{content_type_analysis.get('risk_score', 0)}"
    )

    print(
        f"  Content-Type Risk Level : "
        f"{content_type_analysis.get('risk_level', 'SAFE')}"
    )

    server_analysis = (
        http_response_result.get("server_analysis") or {}
    )

    print(
        f"  Server Disclosures      : "
        f"{server_analysis.get('disclosure_count', 0)}"
    )

    if server_analysis.get("disclosures"):
        for header, value in server_analysis.get("disclosures", {}).items():
            print(
                f"    - {header}: {value}"
            )

    print(
        f"  Server Risk Score       : "
        f"{server_analysis.get('risk_score', 0)}"
    )

    print(
        f"  Server Risk Level       : "
        f"{server_analysis.get('risk_level', 'SAFE')}"
    )

    header_analysis = (
        http_response_result.get("header_analysis") or {}
    )

    print(
        f"  Response Header Score   : "
        f"{header_analysis.get('risk_score', 0)}"
    )

    print(
        f"  Response Header Risk    : "
        f"{header_analysis.get('risk_level', 'SAFE')}"
    )

    if http_response_result.get("indicators"):
        print()
        print("  HTTP Response Indicators:")
        for indicator in http_response_result.get("indicators", []):
            print(f"    - {indicator}")

    print(
        f"  HTTP Response Score     : "
        f"{http_response_result.get('risk_score', 0)}"
    )

    print(
        f"  HTTP Response Risk      : "
        f"{http_response_result.get('risk_level', 'SAFE')}"
    )

    if http_response_result.get("error"):
        print(
            f"  HTTP Response Error     : "
            f"{http_response_result.get('error')}"
        )

    print()

    # 6E. V3.0 PHASE 5 - WEB REPUTATION & INFRASTRUCTURE
    web_reputation_result = analyze_infrastructure(url)
    web_reputation_score = web_reputation_result.get("risk_score", 0)

    risk_score = min(100, risk_score + web_reputation_score)

    for indicator in web_reputation_result.get("indicators", []):
        if indicator not in indicators:
            indicators.append(indicator)

    # 13E. V3.0 PHASE 5 - WEB REPUTATION & INFRASTRUCTURE
    print("WEB REPUTATION & INFRASTRUCTURE")
    print("-" * 55)

    print(
        f"  Hostname                : "
        f"{web_reputation_result.get('hostname') or 'N/A'}"
    )

    print(
        f"  Reputation Score        : "
        f"{web_reputation_result.get('risk_score', 0)}"
    )

    print(
        f"  Reputation Risk         : "
        f"{web_reputation_result.get('risk_level', 'SAFE')}"
    )

    domain_analysis = (
        web_reputation_result.get("domain_analysis") or {}
    )

    print()
    print("  DOMAIN REPUTATION")

    print(
        f"    Registered Domain     : "
        f"{domain_analysis.get('registered_domain') or 'N/A'}"
    )

    print(
        f"    TLD                   : "
        f"{domain_analysis.get('tld') or 'N/A'}"
    )

    print(
        f"    IP Address Host       : "
        f"{'YES' if domain_analysis.get('is_ip') else 'NO'}"
    )

    print(
        f"    Domain Risk Score     : "
        f"{domain_analysis.get('risk_score', 0)}"
    )

    print(
        f"    Domain Risk Level     : "
        f"{domain_analysis.get('risk_level', 'SAFE')}"
    )

    hosting_analysis = (
        web_reputation_result.get("hosting_analysis") or {}
    )

    print()
    print("  HOSTING INTELLIGENCE")

    print(
        f"    Hosting Platform      : "
        f"{hosting_analysis.get('hosting_platform') or 'N/A'}"
    )

    print(
        f"    Hosting Risk Score    : "
        f"{hosting_analysis.get('risk_score', 0)}"
    )

    print(
        f"    Hosting Risk Level    : "
        f"{hosting_analysis.get('risk_level', 'SAFE')}"
    )

    label_analysis = (
        web_reputation_result.get("label_analysis") or {}
    )

    print()
    print("  DOMAIN LABEL INTELLIGENCE")

    print(
        f"    Suspicious Labels     : "
        f"{len(label_analysis.get('suspicious_labels', []))}"
    )

    if label_analysis.get("suspicious_labels"):
        print(
            f"    Labels                : "
            f"{', '.join(label_analysis.get('suspicious_labels', []))}"
        )

    print(
        f"    Label Risk Score      : "
        f"{label_analysis.get('risk_score', 0)}"
    )

    print(
        f"    Label Risk Level      : "
        f"{label_analysis.get('risk_level', 'SAFE')}"
    )

    if web_reputation_result.get("indicators"):
        print()
        print("  WEB REPUTATION INDICATORS:")

        for indicator in web_reputation_result.get("indicators", []):
            print(f"    - {indicator}")

    print(
        f"  Web Reputation Score   : "
        f"{web_reputation_result.get('risk_score', 0)}"
    )

    print(
        f"  Web Reputation Risk    : "
        f"{web_reputation_result.get('risk_level', 'SAFE')}"
    )

    if web_reputation_result.get("error"):
        print(
            f"  Web Reputation Error   : "
            f"{web_reputation_result.get('error')}"
        )

    print()

    # 6F. V3.0 PHASE 6 - RELATIONSHIP INTELLIGENCE
    relationship_result = analyze_relationships(
        url,
        redirect_result=redirect_analysis,
        dns_result=dns_result,
        tls_result=tls_result,
    )

    relationship_score = relationship_result.get("risk_score", 0)

    risk_score = min(100, risk_score + relationship_score)

    for indicator in relationship_result.get("indicators", []):
        if indicator not in indicators:
            indicators.append(indicator)

    # 13F. V3.0 PHASE 6 - RELATIONSHIP INTELLIGENCE
    print("RELATIONSHIP INTELLIGENCE")
    print("-" * 55)

    print(
        f"  Hostname                : "
        f"{relationship_result.get('hostname') or 'N/A'}"
    )

    print(
        f"  Relationship Score      : "
        f"{relationship_result.get('risk_score', 0)}"
    )

    print(
        f"  Relationship Risk       : "
        f"{relationship_result.get('risk_level', 'SAFE')}"
    )

    redirect_relationship = (
        relationship_result.get("redirect_relationship") or {}
    )

    print()
    print("  REDIRECT RELATIONSHIP")

    print(
        f"    Original Host         : "
        f"{redirect_relationship.get('original_hostname') or 'N/A'}"
    )

    print(
        f"    Final Host            : "
        f"{redirect_relationship.get('final_hostname') or 'N/A'}"
    )

    print(
        f"    Same Domain           : "
        f"{'YES' if redirect_relationship.get('same_domain') else 'NO'}"
    )

    print(
        f"    Cross Domain          : "
        f"{'YES' if redirect_relationship.get('cross_domain') else 'NO'}"
    )

    print(
        f"    Related Subdomain     : "
        f"{'YES' if redirect_relationship.get('subdomain_redirect') else 'NO'}"
    )

    print(
        f"    Redirect Risk Score   : "
        f"{redirect_relationship.get('risk_score', 0)}"
    )

    tls_relationship = (
        relationship_result.get("tls_relationship") or {}
    )

    print()
    print("  TLS HOSTNAME RELATIONSHIP")

    print(
        f"    Certificate Present   : "
        f"{'YES' if tls_relationship.get('certificate_present') else 'NO'}"
    )

    hostname_match = tls_relationship.get("hostname_match")

    print(
        f"    Hostname Match        : "
        f"{'YES' if hostname_match is True else 'NO' if hostname_match is False else 'N/A'}"
    )

    print(
        f"    TLS Relationship Score: "
        f"{tls_relationship.get('risk_score', 0)}"
    )

    dns_relationship = (
        relationship_result.get("dns_relationship") or {}
    )

    print()
    print("  DNS HOSTNAME RELATIONSHIP")

    print(
        f"    DNS Available         : "
        f"{'YES' if dns_relationship.get('dns_available') else 'NO'}"
    )

    print(
        f"    Resolved Addresses    : "
        f"{len(dns_relationship.get('resolved_addresses', []))}"
    )

    print(
        f"    DNS Relationship Score: "
        f"{dns_relationship.get('risk_score', 0)}"
    )

    https_consistency = (
        relationship_result.get("https_consistency") or {}
    )

    print()
    print("  HTTPS/TLS CONSISTENCY")

    print(
        f"    HTTPS URL             : "
        f"{'YES' if https_consistency.get('https') else 'NO'}"
    )

    print(
        f"    TLS Available         : "
        f"{'YES' if https_consistency.get('tls_available') else 'NO'}"
    )

    print(
        f"    Consistency Score     : "
        f"{https_consistency.get('risk_score', 0)}"
    )

    if relationship_result.get("indicators"):
        print()
        print("  RELATIONSHIP INDICATORS:")

        for indicator in relationship_result.get("indicators", []):
            print(f"    - {indicator}")

    print(
        f"  Relationship Score     : "
        f"{relationship_result.get('risk_score', 0)}"
    )

    print(
        f"  Relationship Risk      : "
        f"{relationship_result.get('risk_level', 'SAFE')}"
    )

    if relationship_result.get("error"):
        print(
            f"  Relationship Error     : "
            f"{relationship_result.get('error')}"
        )

    print()

    # 6G. V3.0 PHASE 7 - IP & NETWORK INTELLIGENCE
    ip_network_result = analyze_ip_network(url)

    ip_network_score = ip_network_result.get("risk_score", 0)

    risk_score = min(100, risk_score + ip_network_score)

    for indicator in ip_network_result.get("indicators", []):
        if indicator not in indicators:
            indicators.append(indicator)

    # 13G. V3.0 PHASE 7 - IP & NETWORK INTELLIGENCE
    print("IP & NETWORK INTELLIGENCE")
    print("-" * 55)

    print(
        f"  Hostname                : "
        f"{ip_network_result.get('hostname') or 'N/A'}"
    )

    print(
        f"  Direct IP URL           : "
        f"{'YES' if ip_network_result.get('direct_ip') else 'NO'}"
    )

    resolution = ip_network_result.get("resolution") or {}

    print()
    print("  DNS / NETWORK RESOLUTION")

    print(
        f"    Resolution Successful : "
        f"{'YES' if resolution.get('success') else 'NO'}"
    )

    addresses = resolution.get("addresses", [])

    print(
        f"    Resolved IP Count     : "
        f"{len(addresses)}"
    )

    if addresses:
        print(
            f"    Resolved IPs          : "
            f"{', '.join(addresses)}"
        )

    ipv4_addresses = resolution.get("ipv4_addresses", [])
    ipv6_addresses = resolution.get("ipv6_addresses", [])

    print(
        f"    IPv4 Addresses        : "
        f"{len(ipv4_addresses)}"
    )

    print(
        f"    IPv6 Addresses        : "
        f"{len(ipv6_addresses)}"
    )

    ip_analysis = ip_network_result.get("ip_analysis") or {}

    print()
    print("  IP CLASSIFICATION")

    print(
        f"    Private IPs           : "
        f"{len(ip_analysis.get('private_addresses', []))}"
    )

    print(
        f"    Loopback IPs           : "
        f"{len(ip_analysis.get('loopback_addresses', []))}"
    )

    print(
        f"    Reserved IPs          : "
        f"{len(ip_analysis.get('reserved_addresses', []))}"
    )

    print(
        f"    Link-local IPs        : "
        f"{len(ip_analysis.get('link_local_addresses', []))}"
    )

    print(
        f"    Multicast IPs         : "
        f"{len(ip_analysis.get('multicast_addresses', []))}"
    )

    print(
        f"    Global IPs            : "
        f"{sum(1 for item in ip_analysis.get('classifications', []) if item.get('global'))}"
    )

    relationship = ip_network_result.get("relationship") or {}

    print()
    print("  IP / HOSTNAME RELATIONSHIP")

    print(
        f"    Direct IP             : "
        f"{'YES' if relationship.get('direct_ip') else 'NO'}"
    )

    print(
        f"    IP Version            : "
        f"{relationship.get('ip_version') or 'N/A'}"
    )

    resolved_match = relationship.get("resolved_match")

    print(
        f"    Resolution Match      : "
        f"{'YES' if resolved_match is True else 'NO' if resolved_match is False else 'N/A'}"
    )

    print(
        f"    Relationship Score    : "
        f"{relationship.get('risk_score', 0)}"
    )

    print()
    print(
        f"  IP Analysis Score       : "
        f"{ip_analysis.get('risk_score', 0)}"
    )

    print(
        f"  IP Analysis Risk        : "
        f"{ip_analysis.get('risk_level', 'SAFE')}"
    )

    if ip_network_result.get("indicators"):
        print()
        print("  IP / NETWORK INDICATORS:")

        for indicator in ip_network_result.get("indicators", []):
            print(f"    - {indicator}")

    print()
    print(
        f"  IP & Network Score      : "
        f"{ip_network_result.get('risk_score', 0)}"
    )

    print(
        f"  IP & Network Risk       : "
        f"{ip_network_result.get('risk_level', 'SAFE')}"
    )

    if ip_network_result.get("error"):
        print(
            f"  IP & Network Error      : "
            f"{ip_network_result.get('error')}"
        )

    print()

    # 6H. V3.0 PHASE 8 - THREAT CORRELATION
    threat_modules = {
        "url": {
            **analysis,
            "indicators": [],
        },
        "redirect": redirect_analysis,
        "redirect_chain": redirect_chain,
        "content": content_result,
        "dns": dns_result,
        "tls": tls_result,
        "tls_security": tls_security_result,
        "http_security": http_security_result,
        "http_response": http_response_result,
        "web_reputation": web_reputation_result,
        "relationship": relationship_result,
        "ip_network": ip_network_result,
    }

    threat_correlation_result = analyze_threat(threat_modules)

    # 13H. V3.0 PHASE 8 - THREAT CORRELATION
    # =========================================================

    print("[V3.0 PHASE 8 - THREAT CORRELATION]")
    print()

    print(
        f"  Classification        : "
        f"{threat_correlation_result.get('classification', 'UNKNOWN')}"
    )
    print(
        f"  Correlated Risk Score : "
        f"{threat_correlation_result.get('risk_score', 0)}/100"
    )
    print(
        f"  Security Posture Score: "
        f"{threat_correlation_result.get('posture_score', 0)}/100"
    )
    print(
        f"  Confidence            : "
        f"{threat_correlation_result.get('confidence', 0)}/100"
    )
    print(
        f"  Evidence Count        : "
        f"{threat_correlation_result.get('evidence_count', 0)}"
    )
    print(
        f"  Threat Evidence Count : "
        f"{threat_correlation_result.get('threat_evidence_count', 0)}"
    )
    print(
        f"  Posture Evidence Count: "
        f"{threat_correlation_result.get('posture_evidence_count', 0)}"
    )
    print(
        f"  Diagnostic Count      : "
        f"{threat_correlation_result.get('diagnostic_evidence_count', 0)}"
    )
    print(
        f"  Pattern Count         : "
        f"{threat_correlation_result.get('pattern_count', 0)}"
    )

    threat_evidence = threat_correlation_result.get(
        "threat_evidence",
        []
    )

    if threat_evidence:
        print()
        print("  THREAT EVIDENCE:")
        for item in threat_evidence:
            print(
                f"    - [{item.get('severity', 'LOW').upper()}] "
                f"{item.get('indicator', 'Unknown indicator')}"
            )
            modules = item.get("modules", [])
            if modules:
                print(
                    f"      Modules: "
                    f"{', '.join(modules)}"
                )

    posture_evidence = threat_correlation_result.get(
        "posture_evidence",
        []
    )

    if posture_evidence:
        print()
        print("  SECURITY POSTURE:")
        for item in posture_evidence:
            print(
                f"    - {item.get('indicator', 'Unknown observation')}"
            )
            modules = item.get("modules", [])
            if modules:
                print(
                    f"      Modules: "
                    f"{', '.join(modules)}"
                )

    diagnostic_evidence = threat_correlation_result.get(
        "diagnostic_evidence",
        []
    )

    if diagnostic_evidence:
        print()
        print("  DIAGNOSTIC OBSERVATIONS:")
        for item in diagnostic_evidence:
            print(
                f"    - {item.get('indicator', 'Unknown observation')}"
            )
            modules = item.get("modules", [])
            if modules:
                print(
                    f"      Modules: "
                    f"{', '.join(modules)}"
                )

    patterns = threat_correlation_result.get("patterns", [])

    if patterns:
        print()
        print("  DETECTED THREAT PATTERNS:")
        for pattern in patterns:
            print(
                f"    - [{pattern.get('severity', 'LOW').upper()}] "
                f"{pattern.get('name', 'Unknown pattern')}"
            )
            description = pattern.get("description")
            if description:
                print(
                    f"      {description}"
                )

    print()

    # 14. THREAT ASSESSMENT
    # =========================================================

    final_classification = threat_correlation_result.get(
        "classification",
        "UNKNOWN"
    )

    correlated_risk_score = threat_correlation_result.get(
        "risk_score",
        0
    )

    posture_score = threat_correlation_result.get(
        "posture_score",
        0
    )

    confidence = threat_correlation_result.get(
        "confidence",
        0
    )

    threat_evidence_count = threat_correlation_result.get(
        "threat_evidence_count",
        0
    )

    print("[THREAT ASSESSMENT]")
    print()

    print(
        f"  Threat Classification : "
        f"{final_classification}"
    )

    print(
        f"  Threat Risk Score     : "
        f"{correlated_risk_score}/100"
    )

    print(
        f"  Security Posture Score: "
        f"{posture_score}/100"
    )

    print(
        f"  Confidence            : "
        f"{confidence}/100"
    )

    print(
        f"  Threat Evidence Count : "
        f"{threat_evidence_count}"
    )

    print(
        f"  Legacy Module Score   : "
        f"{risk_score}/100"
    )

    threat_indicators = threat_correlation_result.get(
        "threat_indicators",
        []
    )

    diagnostic_indicators = threat_correlation_result.get(
        "diagnostic_indicators",
        []
    )

    print()

    if threat_indicators:
        print("  Threat Evidence:")
        for indicator in threat_indicators:
            print(
                f"    - {indicator}"
            )
    else:
        print("  Threat Evidence             : None")

    if diagnostic_indicators:
        print(
            f"  Diagnostic Observations     : "
            f"{len(diagnostic_indicators)}"
        )
    else:
        print("  Diagnostic Observations     : None")

    print()

    # =========================================================
    # 15. FINAL RESULT
    # =========================================================

    print("=" * 60)

    if final_classification == "MALICIOUS":
        print("  RESULT: MALICIOUS THREAT DETECTED")
    elif final_classification == "SUSPICIOUS":
        print("  RESULT: SUSPICIOUS — REVIEW REQUIRED")
    elif final_classification == "SAFE":
        print("  RESULT: NO SIGNIFICANT THREATS DETECTED")
    else:
        print("  RESULT: ANALYSIS INCONCLUSIVE")

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
