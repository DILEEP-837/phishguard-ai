# PhishGuard AI V3.0

PhishGuard AI is a Python-based URL threat detection and analysis system designed to identify phishing, malicious URLs, suspicious domains, dangerous payloads, and related web threats.

It is a command-line cybersecurity tool that can be installed directly from GitHub.

============================================================
INSTALLATION
============================================================

SUPPORTED SYSTEMS

PhishGuard AI can be installed on:

- Kali Linux
- Debian
- Ubuntu
- macOS

REQUIREMENTS

- Python 3.10 or newer
- Git
- pipx
- Internet connection

The required Python libraries are installed automatically:

- requests
- dnspython
- tldextract
- beautifulsoup4


============================================================
KALI LINUX / DEBIAN / UBUNTU INSTALLATION
============================================================

STEP 1 - Update the package list

Run:

sudo apt update


STEP 2 - Install Python, pip, pipx and Git

Run:

sudo apt install -y python3 python3-pip pipx git


STEP 3 - Configure pipx

Run:

pipx ensurepath

After running this command, close and reopen your terminal.


STEP 4 - Install PhishGuard AI

Run:

pipx install git+https://github.com/DILEEP-837/phishguard-ai.git


STEP 5 - Verify the installation

Run:

phishguard --help

If the installation was successful, PhishGuard AI command-line help will be displayed.


STEP 6 - Scan a URL

Run:

phishguard scan-url https://example.com

Example:

phishguard scan-url https://g00gle.com


============================================================
macOS INSTALLATION
============================================================

STEP 1 - Check Python

Run:

python3 --version

PhishGuard AI requires Python 3.10 or newer.

If Python is not installed, install it using Homebrew:

brew install python


STEP 2 - Check Git

Run:

git --version

If Git is not installed:

brew install git


STEP 3 - Install pipx

Run:

brew install pipx


STEP 4 - Configure pipx

Run:

pipx ensurepath

After running this command, close and reopen your terminal.


STEP 5 - Install PhishGuard AI

Run:

pipx install git+https://github.com/DILEEP-837/phishguard-ai.git


STEP 6 - Verify the installation

Run:

phishguard --help


STEP 7 - Scan a URL

Run:

phishguard scan-url https://example.com

Example:

phishguard scan-url https://g00gle.com


============================================================
UNIVERSAL INSTALLATION PROCESS
============================================================

For any supported operating system, the overall process is:

1. Install Python 3.10+
2. Install Git
3. Install pipx
4. Run pipx ensurepath
5. Restart the terminal
6. Install PhishGuard from GitHub
7. Verify PhishGuard
8. Scan a URL

The main installation command is:

pipx install git+https://github.com/DILEEP-837/phishguard-ai.git

The main scanning command is:

phishguard scan-url <URL>


============================================================
QUICK START
============================================================

If Python, Git and pipx are already installed:

pipx install git+https://github.com/DILEEP-837/phishguard-ai.git

Then:

phishguard --help

Then scan a URL:

phishguard scan-url https://example.com


============================================================
HOW TO USE
============================================================

Display help:

phishguard --help


Scan a URL:

phishguard scan-url https://example.com


Scan a suspicious-looking domain:

phishguard scan-url https://g00gle.com


Scan a URL containing a potentially dangerous payload:

phishguard scan-url https://example.com/invoice.pdf.exe


IMPORTANT:

Always enter a normal URL.

Correct:

phishguard scan-url https://example.com

Incorrect:

phishguard scan-url [https://example.com](https://example.com)

Do not use Markdown-formatted links in the command.


============================================================
WHAT PHISHGUARD AI ANALYZES
============================================================

PhishGuard AI analyzes multiple security signals:

- URL structure
- URL obfuscation
- Redirect behavior
- Web page content
- Login forms
- Password fields
- Credential collection
- External form submissions
- JavaScript behavior
- iframe behavior
- Meta refresh behavior
- DNS records
- Domain structure
- Punycode and IDN indicators
- TLS certificates
- TLS security configuration
- HTTP security headers
- HTTP responses
- Web reputation
- Hosting and infrastructure indicators
- Domain relationships
- IP and network information
- Credential phishing
- Brand impersonation
- Typosquatting
- Malware indicators
- Dangerous payload indicators
- Web behavior
- Cross-module threat correlation


============================================================
DETECTION PIPELINE
============================================================

URL Input
    |
    v
URL Analysis
    |
    +--> Obfuscation Intelligence
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
    +--> Web Behavior Intelligence
    |
    v
Threat Correlation Engine
    |
    v
Final Threat Classification
    |
    +--> SAFE
    +--> SUSPICIOUS
    +--> MALICIOUS


============================================================
THREAT CLASSIFICATION
============================================================

SAFE

No significant threat evidence was detected.


SUSPICIOUS

Suspicious indicators were detected and the URL requires further investigation.


MALICIOUS

Strong correlated evidence of malicious activity was detected.


============================================================
THREAT ASSESSMENT
============================================================

PhishGuard AI can provide:

- Threat Classification
- Threat Risk Score
- Security Posture
- Confidence
- Threat Evidence
- Diagnostic Observations
- Detected Threat Patterns

Evidence from multiple analysis modules is correlated before the final threat classification is produced.


============================================================
EXAMPLE 1 - SAFE WEBSITE
============================================================

Command:

phishguard scan-url https://example.com

Example result:

Threat Classification : SAFE
Threat Risk Score     : 0/100


============================================================
EXAMPLE 2 - TYPOSQUATTING
============================================================

Command:

phishguard scan-url https://g00gle.com

Detected:

Possible typosquatting of google

Result:

SUSPICIOUS


============================================================
EXAMPLE 3 - DANGEROUS PAYLOAD
============================================================

Command:

phishguard scan-url https://example.com/invoice.pdf.exe

Detected:

Potentially dangerous file extension: .exe
Suspicious double file extension detected

Result:

SUSPICIOUS


============================================================
EXAMPLE 4 - CREDENTIAL PHISHING
============================================================

A controlled test page containing a login form, username field, password field, and external credential submission was detected.

Detected evidence:

Login form detected
Password field detected
Credential form submits to an external domain
Credential collection combined with an external form

Threat pattern:

Credential Phishing

Example result:

MALICIOUS THREAT DETECTED
Risk Score: 100/100
Confidence: 80/100


============================================================
UPDATING PHISHGUARD AI
============================================================

To install the latest version from GitHub:

pipx install --force git+https://github.com/DILEEP-837/phishguard-ai.git

Then verify:

phishguard --help


============================================================
UNINSTALLING PHISHGUARD AI
============================================================

To uninstall PhishGuard AI:

pipx uninstall phishguard-ai


============================================================
CHECKING THE INSTALLATION
============================================================

Check PhishGuard:

phishguard --help

Check where PhishGuard is installed:

which phishguard

Check pipx:

pipx --version

Check Python:

python3 --version

Check Git:

git --version

Check installed pipx applications:

pipx list


============================================================
TROUBLESHOOTING
============================================================

PROBLEM: phishguard: command not found

Run:

pipx ensurepath

Then close and reopen the terminal.

Check:

which phishguard


PROBLEM: pipx: command not found

Kali Linux / Debian / Ubuntu:

sudo apt update
sudo apt install -y pipx

Then:

pipx ensurepath

Restart the terminal.


macOS:

brew install pipx

Then:

pipx ensurepath

Restart the terminal.


PROBLEM: Python version is too old

Check:

python3 --version

PhishGuard AI requires Python 3.10 or newer.


PROBLEM: Installation is corrupted

Uninstall:

pipx uninstall phishguard-ai

Reinstall:

pipx install git+https://github.com/DILEEP-837/phishguard-ai.git


============================================================
DEVELOPMENT INSTALLATION
============================================================

Developers can clone the source code.

STEP 1 - Clone the repository:

git clone https://github.com/DILEEP-837/phishguard-ai.git


STEP 2 - Enter the project:

cd phishguard-ai


STEP 3 - Create a virtual environment:

python3 -m venv venv


STEP 4 - Activate the virtual environment:

source venv/bin/activate


STEP 5 - Install the project:

python3 -m pip install -e .


STEP 6 - Run PhishGuard:

python3 -m phishguard.cli.main scan-url https://example.com


============================================================
TESTING
============================================================

From the project directory:

pytest -q

V3.0 validation result:

354 passed


============================================================
PROJECT STATUS
============================================================

Project:        PhishGuard AI
Version:        V3.0
Status:         Final threat detection build
Test Status:    354 tests passing


============================================================
REPOSITORY
============================================================

GitHub:

https://github.com/DILEEP-837/phishguard-ai


============================================================
SECURITY NOTICE
============================================================

PhishGuard AI is intended for:

- Cybersecurity research
- Defensive security analysis
- Education
- Authorized security testing

Only scan URLs, websites, and systems that you are authorized to analyze.


============================================================
DISCLAIMER
============================================================

PhishGuard AI is a defensive cybersecurity research project.

No automated detection system can guarantee that every malicious or benign URL will be classified correctly.

Detection results should be treated as security analysis rather than absolute proof of maliciousness.

Always perform additional investigation when making security decisions based on automated results.

