# CJ-SCANNER v2.0

Clickjacking vulnerability scanner with dual-layer detection, multi-threading, and professional reporting.

**Author:** Shikhali Jamalzade  
**GitHub:** [alisalive](https://github.com/alisalive)

---

## Features

| Feature | Details |
|---|---|
| Dual-layer detection | `X-Frame-Options` header + `CSP frame-ancestors` directive |
| Meta tag fallback | Parses HTML body for `<meta http-equiv="X-Frame-Options">` |
| Multi-threading | `ThreadPoolExecutor`, default 10 threads (`-t` flag) |
| SSL fallback | Automatically retries over HTTP if HTTPS fails |
| Retry logic | 2 retries on connection/timeout errors with backoff |
| Redirect tracking | Follows redirects, records final URL |
| Response timing | Per-domain elapsed time in seconds |
| Cookie analysis | Flags cookies missing `SameSite` or set to `SameSite=None` |
| HTML report | Dark-themed, professional, self-contained file |
| JSON export | Machine-readable results |
| Vulnerable report | `vulnerable_report.txt` auto-created; deleted if no vulns found |
| Interactive mode | Prompts for input when no CLI flags are provided |
| Browser UA | Mimics Chrome 124 to reduce bot-blocking |

---

## Installation

### Standard (run with `python cj_scanner.py`)
```bash
git clone https://github.com/alisalive/cj-scanner.git
cd cj-scanner
pip install -r requirements.txt
```

### Global command (run as `cj-scanner` from anywhere)
```bash
pip install -e .
cj-scanner -u github.com
```

Python 3.11+ required (`datetime.UTC`, `X | Y` union type hints).

---

## Usage

### Single target
```bash
python cj_scanner.py -u example.com
python cj_scanner.py -u https://example.com
```

### Scan a list of domains
```bash
python cj_scanner.py -f domains.txt
```

### Full options
```bash
python cj_scanner.py -f domains.txt -t 20 --timeout 15 --html --json
python cj_scanner.py -f domains.txt --html report.html
```

### Interactive mode (no arguments)
```bash
python cj_scanner.py
```
The scanner will prompt for target, threads, timeout, and output format.

---

## CLI Reference

| Flag | Default | Description |
|---|---|---|
| `-u URL` | — | Single target URL or domain |
| `-f FILE` | — | File with one target per line (comments with `#` ignored) |
| `-t N` | `10` | Number of concurrent threads |
| `--timeout N` | `10` | Per-request timeout in seconds |
| `--html [FILE]` | off | Generate HTML report; default name `cj_scanner_report.html` |
| `--json` | off | Export results as a JSON file |
| `--no-meta` | off | Skip meta tag detection (faster on large lists) |

---

## Output Files

| File | Created when |
|---|---|
| `vulnerable_report.txt` | At least one vulnerable target found (auto-deleted if none) |
| `cj_scanner_report.html` (or custom name) | `--html` / `--html out.html` |
| `cj_results_<timestamp>.json` | `--json` flag is set |

---

## Detection Logic

A target is marked **VULNERABLE** only when **all three** of the following are absent:

1. `X-Frame-Options` response header (`DENY` / `SAMEORIGIN` / `ALLOW-FROM`)
2. `frame-ancestors` directive inside the `Content-Security-Policy` header
3. `<meta http-equiv="X-Frame-Options">` tag in the HTML body

---

## domains.txt format

```
# Comments are ignored
example.com
https://target2.com
target3.org
```

---

## Legal

For authorized security testing only. You are responsible for obtaining proper permission before scanning any target. The author assumes no liability for misuse.
