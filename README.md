<div align="center">

```
   ______    __     _____ _________    _   ___   ____________
  / ____/   / /    / ___// ____/   |  / | / / | / / ____/ __ \
 / /   __  / /_____\__ \/ /   / /| | /  |/ /  |/ / __/ / /_/ /
/ /___/ /_/ /_____/__/ / /___/ ___ |/ /|  / /|  / /___/ _, _/
\____/\____/     /____/\____/_/  |_/_/ |_/_/ |_/_____/_/ |_|
```

# CJ-SCANNER v2.0

**A professional, multi-threaded Clickjacking (UI Redressing) vulnerability scanner**  
**built for penetration testers and security researchers.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=flat-square)](https://github.com/alisalive/cj-scanner)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.0-red?style=flat-square)](https://github.com/alisalive/cj-scanner)
[![Author](https://img.shields.io/badge/Author-alisalive-orange?style=flat-square)](https://github.com/alisalive)

</div>

---

## Overview

Clickjacking (also known as UI Redressing) is a web attack in which a malicious page tricks users into clicking on invisible or disguised elements from another website — potentially leading to unauthorized actions, credential theft, or account takeover.

**CJ-SCANNER** automates the detection of missing or misconfigured clickjacking protections across single targets or large domain lists. It performs dual-layer HTTP header analysis, HTML body inspection, and cookie attribute checks — all in parallel — and generates color-coded terminal output, professional HTML reports, and machine-readable JSON exports.

---

## Demo

```
  Scanning 3 target(s) with 10 thread(s)...

  Target  : https://github.com/
  Status  : 200  (0.849s)
  XFO     : deny
  CSP FA  : frame-ancestors 'none'
  RESULT  : Protected

  Target  : https://dtx.gov.az/az/
  Status  : 200  (0.414s)
  XFO     : NOT SET
  CSP FA  : NOT SET
  RESULT  : *** VULNERABLE TO CLICKJACKING ***

  ==================================================
  Scan complete — 3 target(s)
  Vulnerable : 1  |  Protected : 2  |  Errors : 0
  ==================================================
```

---

## Features

| Feature | Description |
|---|---|
| **Dual-Layer Detection** | Checks both `X-Frame-Options` and `CSP: frame-ancestors` headers independently |
| **Multi-Threaded Engine** | Concurrent scanning with configurable thread count (default: 10) |
| **HTML Body Inspection** | Detects meta-tag based `X-Frame-Options` (ignored by browsers but flagged) |
| **Cookie SameSite Analysis** | Inspects `SameSite` cookie attributes as an additional security signal |
| **SSL Fallback** | Automatically retries over HTTP if HTTPS connection fails |
| **Retry Logic** | 2x automatic retries on connection errors before marking a domain as failed |
| **HTML Report** | Dark-themed professional report with statistics dashboard and color-coded verdicts |
| **JSON Export** | Machine-readable structured output for pipeline integration |
| **Redirect Tracking** | Follows and logs redirect chains, reporting the final destination URL |
| **Global Command** | Installable as a system-wide `cj-scanner` command on Linux and Windows |
| **Cross-Platform** | Kali Linux, Ubuntu, Windows, macOS |

---

## Detection Logic

CJ-SCANNER evaluates each target across four independent checks:

| Check | Secure Values | Misconfigured / Absent |
|---|---|---|
| `X-Frame-Options` header | `DENY`, `SAMEORIGIN` | Missing or `ALLOW-FROM` (deprecated) |
| `CSP: frame-ancestors` directive | `'none'`, `'self'` | Missing, `*`, or overly permissive origin |
| HTML `<meta>` X-Frame-Options | — | Present but ignored by browsers (flagged) |
| Cookie `SameSite` attribute | `Strict`, `Lax` | `None` or absent (informational) |

**Verdict:**
- **VULNERABLE** — Both `X-Frame-Options` and `CSP: frame-ancestors` are absent or misconfigured
- **Protected** — At least one header-based protection is correctly configured

> Modern browsers prioritize `frame-ancestors` over `X-Frame-Options`. CJ-SCANNER evaluates both independently and reports each one's state clearly.

---

## Installation

### Kali Linux (Recommended)

```bash
git clone https://github.com/alisalive/cj-scanner.git
cd cj-scanner
chmod +x setup_kali.sh
sudo ./setup_kali.sh
```

After setup, `cj-scanner` is available as a global command from any directory.

### Windows

```cmd
git clone https://github.com/alisalive/cj-scanner.git
cd cj-scanner
pip install -r requirements.txt
python cj_scanner.py -u target.com
```

### Any OS (Manual)

```bash
git clone https://github.com/alisalive/cj-scanner.git
cd cj-scanner
pip install -r requirements.txt --break-system-packages
python cj_scanner.py -u target.com
```

**Requirements:** Python 3.10+

---

## Usage

### Single URL

```bash
cj-scanner -u https://example.com
```

### Scan from file

```bash
cj-scanner -f domains.txt
```

### Full scan with HTML and JSON reports

```bash
cj-scanner -f domains.txt -t 20 --html report.html --json results.json
```

### Domains file format

```
# One domain per line. Lines starting with # are ignored.
google.com
https://example.com
subdomain.target.org
```

---

## Options

```
  -u, --url URL         Single target URL or domain
  -f, --file FILE       Path to .txt file with one domain per line
  -t, --threads N       Number of concurrent threads (default: 10)
  --html [FILE]         Save HTML report (default: cj_scanner_report.html)
  --json FILE           Save JSON report
  --timeout SEC         Request timeout in seconds (default: 10)
  --no-meta             Skip HTML body meta-tag inspection
  -v, --verbose         Show all results including protected domains
  -h, --help            Show help message
```

---

## Output Files

| File | Location | Description |
|---|---|---|
| `vulnerable_report.txt` | `~/cj-scanner-reports/` | Auto-generated list of vulnerable URLs. Deleted if no vulnerabilities found. |
| `cj_scanner_report.html` | `~/cj-scanner-reports/` | Dark-themed HTML report with full statistics and per-domain details |
| `results.json` | `~/cj-scanner-reports/` | Structured JSON export for programmatic use |

---

## Project Structure

```
cj-scanner/
├── cj_scanner.py        # Main scanner — all logic in a single portable script
├── setup_kali.sh        # One-shot installer for Kali Linux / Debian
├── requirements.txt     # Python dependencies
├── domains.txt          # Example target list
└── README.md
```

---

## Security Notice

> This tool is developed **strictly for authorized security testing and educational purposes.**  
> Always obtain **explicit written permission** from the target system owner before scanning.  
> The author assumes no responsibility for misuse or any legal consequences arising from unauthorized use.  
> Unauthorized use may violate local, national, or international cybersecurity laws.

---

## Author

**Shikhali Jamalzade**  
Offensive Security Researcher · Penetration Tester · Red Team Instructor

- GitHub: [@alisalive](https://github.com/alisalive)
- Instagram: [@alisalive.exe](https://instagram.com/alisalive.exe)
- Certifications: eJPTv2 · CRTA · Web-RTA

---

<div align="center">

*Built for authorized security research. Use responsibly.*

</div>
