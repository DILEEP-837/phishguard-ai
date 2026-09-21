import sys

from phishguard.core.input_normalizer import normalize_url
from phishguard.core.url_analyzer import analyze_url


def scan_url(raw_url):
    """
    Normalize, analyze, and display URL threat assessment.
    """

    # =========================================================
    # 1. NORMALIZE INPUT
    # =========================================================

    url = normalize_url(raw_url)

    # =========================================================
    # 2. ANALYZE URL
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

    indicators = analysis.get(
        "indicators",
        []
    )

    # =========================================================
    # 3. HEADER
    # =========================================================

    print()
    print("=" * 60)
    print("                 PHISHGUARD AI")
    print("                  URL SCANNER")
    print("                     V2.5")
    print("=" * 60)
    print()

    # =========================================================
    # 4. URL INFORMATION
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
    # 5. THREAT ASSESSMENT
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
        f"{'YES' if analysis['suspicious'] else 'NO'}"
    )

    print()

    # =========================================================
    # 6. DETECTED INDICATORS
    # =========================================================

    print("[DETECTED INDICATORS]")
    print()

    if indicators:

        for indicator in indicators:
            print(f"  [!] {indicator}")

    else:

        print("  None detected")

    print()

    # =========================================================
    # 7. FINAL RESULT
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
        print("PHISHGUARD AI V2.3")
        print()

        print("Usage:")
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

        scan_url(raw_url)

    else:

        print()
        print(
            f"Unknown command: {command}"
        )

        print()
        print("Available commands:")

        print(
            "  scan-url <URL>"
        )

        print()


if __name__ == "__main__":
    main()
