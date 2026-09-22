# PhishGuard AI V3.0

PhishGuard AI is a Python-based URL threat detection and analysis system designed to identify phishing, malicious URLs, suspicious domains, dangerous payloads, and related web threats.

## Key Features

- URL structure and obfuscation analysis
- Redirect intelligence
- Web content and credential-form analysis
- DNS and domain intelligence
- TLS certificate analysis
- TLS security configuration analysis
- HTTP security-header analysis
- HTTP response intelligence
- Web reputation and infrastructure analysis
- Domain relationship intelligence
- IP and network intelligence
- Credential phishing detection
- Brand impersonation and typosquatting detection
- Malware and payload detection
- Threat correlation and final threat classification

## Threat Classification

PhishGuard correlates evidence from multiple analysis modules before producing a final classification:

- SAFE — no significant threat evidence detected
- SUSPICIOUS — indicators require further review
- MALICIOUS — strong evidence of malicious activity

## Detection Pipeline

URL Input
    |
    v
URL Analysis
    |
    +--> Redirect Intelligence
    +--> Content Intelligence
    +--> DNS & Domain Intelligence
    +--> TLS Certificate Intelligence
    +--> TLS Security Intelligence
    +--> HTTP Security Intelligence
    +--> HTTP Response Intelligence
    +--> Web Reputation
    +--> Relationship Intelligence
    +--> IP & Network Intelligence
    +--> Phishing Intelligence
    +--> Brand & Typosquatting Intelligence
    +--> Malware & Payload Intelligence
    |
    v
Threat Correlation Engine
    |
    v
Threat Classification
    |
    +--> SAFE
    +--> SUSPICIOUS
    +--> MALICIOUS

## Usage

Activate the virtual environment:

    source venv/bin/activate

Scan a URL:

    python -m phishguard.cli.main scan-url https://example.com

## Validation

The final V3.0 test suite contains:

    354 passed

Validated scenarios include:

### Safe Website

    https://example.com

Result:

    SAFE

### Typosquatting

    https://g00gle.com

Detected:

    Possible typosquatting of google

Result:

    SUSPICIOUS

### Dangerous Payload

    https://example.com/invoice.pdf.exe

Detected:

    Potentially dangerous file extension: .exe
    Suspicious double file extension detected

Result:

    SUSPICIOUS

### Credential Phishing

A controlled test page containing a login form, username field, password field, and external credential submission was detected.

Detected evidence included:

    Login form detected
    Password field detected
    Credential form submits to an external domain
    Credential collection combined with an external form

Threat pattern:

    Credential Phishing

Final result:

    MALICIOUS THREAT DETECTED
    Risk Score: 100/100
    Confidence: 80/100

## Testing

Run the complete test suite:

    pytest -q

Expected result:

    354 passed

## Project Status

Version: V3.0
Status: Final threat detection build
Final commit: 494a63a
Test status: 354 tests passing

## Disclaimer

PhishGuard AI is intended for cybersecurity research, defensive security analysis, education, and authorized testing. Detection results should be treated as security analysis rather than absolute proof of maliciousness.
