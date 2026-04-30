#!/usr/bin/env python3
"""
CJ-SCANNER v2.0
Clickjacking vulnerability scanner with dual-layer detection.
Author: Shikhali Jamalzade
GitHub: alisalive
"""

import argparse
import json
import os
import ssl
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse

import urllib3
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init as colorama_init
import pyfiglet

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
colorama_init(autoreset=True)

SCRIPT_DIR = os.path.join(os.path.expanduser("~"), "cj-scanner-reports")
os.makedirs(SCRIPT_DIR, exist_ok=True)

VERSION = "v2.0"
AUTHOR = "Shikhali Jamalzade"
GITHUB = "alisalive"

DEFAULT_THREADS = 10
DEFAULT_TIMEOUT = 10
MAX_RETRIES = 2

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xhtml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

print_lock = threading.Lock()


def print_banner():
    banner = pyfiglet.figlet_format("CJ-SCANNER", font="slant")
    print(Fore.RED + banner)
    print(Fore.YELLOW + f"  Version : {VERSION}")
    print(Fore.YELLOW + f"  Author  : {AUTHOR}")
    print(Fore.YELLOW + f"  GitHub  : github.com/{GITHUB}")
    print(Fore.WHITE + "  " + "-" * 50)
    print()


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def fetch(url: str, timeout: int) -> tuple[requests.Response | None, float, str | None]:
    """
    Fetch URL with three-stage fallback:
      1. HTTPS with verify=True  (retried up to MAX_RETRIES)
      2. HTTPS with verify=False  (catches broken/self-signed certs)
      3. HTTP fallback            (when the host refuses HTTPS entirely)
    Returns (response, elapsed_seconds, error_message).
    """
    parsed = urlparse(url)
    is_https = parsed.scheme == "https"

    http_url: str | None = None
    if is_https:
        http_url = "http://" + parsed.netloc + parsed.path
        if parsed.query:
            http_url += "?" + parsed.query

    last_err = "Unknown error"

    def _get(target: str, verify: bool) -> tuple[requests.Response | None, float, str | None]:
        nonlocal last_err
        for attempt in range(MAX_RETRIES + 1):
            try:
                start = time.time()
                resp = requests.get(
                    target,
                    headers=HEADERS,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=verify,
                )
                return resp, time.time() - start, None
            except (requests.exceptions.SSLError, ssl.SSLError) as exc:
                last_err = str(exc)
                return None, 0.0, last_err  # SSL errors don't benefit from retrying
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout) as exc:
                last_err = str(exc)
                if attempt < MAX_RETRIES:
                    time.sleep(0.5)
            except requests.exceptions.RequestException as exc:
                last_err = str(exc)
                return None, 0.0, last_err
        return None, 0.0, last_err

    # Stage 1: verified HTTPS
    resp, elapsed, err = _get(url, verify=True)
    if resp is not None:
        return resp, elapsed, None

    # Stage 2: unverified HTTPS (self-signed / broken cert)
    if is_https:
        resp, elapsed, err = _get(url, verify=False)
        if resp is not None:
            return resp, elapsed, None

    # Stage 3: plain HTTP fallback
    if http_url:
        resp, elapsed, err = _get(http_url, verify=False)
        if resp is not None:
            return resp, elapsed, None

    return None, 0.0, last_err


def parse_csp_frame_ancestors(csp_header: str) -> str | None:
    """Extract frame-ancestors directive value from a CSP header string."""
    for directive in csp_header.split(";"):
        directive = directive.strip()
        if directive.lower().startswith("frame-ancestors"):
            return directive
    return None


def check_meta_tag(html: str) -> bool:
    """Return True if an X-Frame-Options meta tag exists in the HTML body."""
    try:
        soup = BeautifulSoup(html, "html.parser")
        for meta in soup.find_all("meta"):
            http_equiv = meta.get("http-equiv", "").lower()
            if http_equiv == "x-frame-options":
                return True
    except Exception:
        pass
    return False


def check_samesite_cookies(response: requests.Response) -> list[str]:
    """Return cookie names that are missing SameSite or set to None."""
    flagged = []
    for cookie in response.cookies:
        samesite = cookie._rest.get("SameSite", None) if hasattr(cookie, "_rest") else None
        if samesite is None or samesite.lower() == "none":
            flagged.append(cookie.name)
    return flagged


def scan_target(url: str, timeout: int, check_meta: bool) -> dict:
    url = normalize_url(url)
    result = {
        "url": url,
        "final_url": None,
        "status_code": None,
        "response_time": None,
        "x_frame_options": None,
        "csp_frame_ancestors": None,
        "meta_xfo": False,
        "samesite_issues": [],
        "vulnerable": False,
        "error": None,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }

    resp, elapsed, error = fetch(url, timeout)

    if error or resp is None:
        result["error"] = error or "No response"
        return result

    result["final_url"] = resp.url
    result["status_code"] = resp.status_code
    result["response_time"] = round(elapsed, 3)

    # --- Header checks ---
    xfo = resp.headers.get("X-Frame-Options", "").strip()
    csp_raw = resp.headers.get("Content-Security-Policy", "").strip()
    csp_fa = parse_csp_frame_ancestors(csp_raw) if csp_raw else None

    result["x_frame_options"] = xfo if xfo else None
    result["csp_frame_ancestors"] = csp_fa

    # --- Meta tag check ---
    if check_meta and resp.text:
        result["meta_xfo"] = check_meta_tag(resp.text)

    # --- Cookie SameSite check ---
    result["samesite_issues"] = check_samesite_cookies(resp)

    # --- Vulnerability determination ---
    has_xfo = bool(xfo)
    has_csp_fa = bool(csp_fa)
    has_meta = result["meta_xfo"]

    if not has_xfo and not has_csp_fa and not has_meta:
        result["vulnerable"] = True

    return result


def format_result_console(r: dict) -> str:
    lines = []
    url_display = r["final_url"] or r["url"]

    if r["error"]:
        lines.append(Fore.RED + f"  [ERROR] {r['url']} — {r['error']}")
        return "\n".join(lines)

    status_color = Fore.GREEN if r["status_code"] and r["status_code"] < 400 else Fore.YELLOW
    lines.append(
        Fore.CYAN + f"\n  Target  : " + Style.BRIGHT + url_display
    )
    lines.append(status_color + f"  Status  : {r['status_code']}  ({r['response_time']}s)")

    if r["x_frame_options"]:
        lines.append(Fore.GREEN + f"  XFO     : {r['x_frame_options']}")
    else:
        lines.append(Fore.RED + "  XFO     : NOT SET")

    if r["csp_frame_ancestors"]:
        lines.append(Fore.GREEN + f"  CSP FA  : {r['csp_frame_ancestors']}")
    else:
        lines.append(Fore.RED + "  CSP FA  : NOT SET")

    if r["meta_xfo"]:
        lines.append(Fore.YELLOW + "  Meta XFO: FOUND (partial protection)")
    else:
        lines.append(Fore.WHITE + "  Meta XFO: not detected")

    if r["samesite_issues"]:
        names = ", ".join(r["samesite_issues"])
        lines.append(Fore.YELLOW + f"  Cookies : SameSite missing/None → {names}")

    if r["vulnerable"]:
        lines.append(Fore.RED + Style.BRIGHT + "  RESULT  : *** VULNERABLE TO CLICKJACKING ***")
    else:
        lines.append(Fore.GREEN + Style.BRIGHT + "  RESULT  : Protected")

    return "\n".join(lines)


def generate_html_report(results: list[dict], output_path: str):
    vuln_count = sum(1 for r in results if r["vulnerable"])
    safe_count = sum(1 for r in results if not r["vulnerable"] and not r["error"])
    error_count = sum(1 for r in results if r["error"])

    rows = ""
    for r in results:
        if r["error"]:
            badge = '<span class="badge err">ERROR</span>'
            status_cell = f'<td colspan="4" class="err-msg">{r["error"]}</td>'
        else:
            badge = (
                '<span class="badge vuln">VULNERABLE</span>'
                if r["vulnerable"]
                else '<span class="badge safe">PROTECTED</span>'
            )
            xfo_cell = (
                f'<td class="good">{r["x_frame_options"]}</td>'
                if r["x_frame_options"]
                else '<td class="bad">Not Set</td>'
            )
            csp_cell = (
                f'<td class="good">{r["csp_frame_ancestors"]}</td>'
                if r["csp_frame_ancestors"]
                else '<td class="bad">Not Set</td>'
            )
            meta_cell = (
                '<td class="warn">Found</td>'
                if r["meta_xfo"]
                else '<td class="neutral">—</td>'
            )
            cookie_cell = (
                f'<td class="warn">{", ".join(r["samesite_issues"])}</td>'
                if r["samesite_issues"]
                else '<td class="neutral">OK</td>'
            )
            status_cell = xfo_cell + csp_cell + meta_cell + cookie_cell

        rows += f"""
        <tr>
            <td><a href="{r['final_url'] or r['url']}" target="_blank">{r['url']}</a></td>
            <td>{r['status_code'] or '—'}</td>
            <td>{r['response_time'] or '—'}s</td>
            <td>{badge}</td>
            {status_cell}
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>CJ-SCANNER {VERSION} — Report</title>
  <style>
    :root {{
      --bg: #0d1117; --surface: #161b22; --border: #30363d;
      --text: #c9d1d9; --muted: #8b949e;
      --red: #f85149; --green: #3fb950; --yellow: #e3b341;
      --blue: #58a6ff; --accent: #ff4c4c;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; }}
    h1 {{ color: var(--accent); font-size: 2rem; letter-spacing: 2px; margin-bottom: .25rem; }}
    .subtitle {{ color: var(--muted); margin-bottom: 2rem; font-size: .9rem; }}
    .stats {{ display: flex; gap: 1.5rem; margin-bottom: 2rem; flex-wrap: wrap; }}
    .stat {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
             padding: .75rem 1.5rem; text-align: center; min-width: 120px; }}
    .stat .num {{ font-size: 2rem; font-weight: 700; }}
    .stat .lbl {{ font-size: .75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; }}
    .stat.v .num {{ color: var(--red); }}
    .stat.s .num {{ color: var(--green); }}
    .stat.e .num {{ color: var(--yellow); }}
    .stat.t .num {{ color: var(--blue); }}
    table {{ width: 100%; border-collapse: collapse; background: var(--surface);
             border-radius: 8px; overflow: hidden; border: 1px solid var(--border); }}
    th {{ background: #21262d; padding: .6rem 1rem; text-align: left; font-size: .78rem;
          color: var(--muted); text-transform: uppercase; letter-spacing: .5px; border-bottom: 1px solid var(--border); }}
    td {{ padding: .55rem 1rem; border-bottom: 1px solid var(--border); font-size: .85rem; vertical-align: middle; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover {{ background: rgba(255,255,255,.03); }}
    a {{ color: var(--blue); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .badge {{ display: inline-block; padding: .2rem .55rem; border-radius: 4px; font-size: .75rem; font-weight: 700; }}
    .badge.vuln {{ background: rgba(248,81,73,.2); color: var(--red); border: 1px solid var(--red); }}
    .badge.safe {{ background: rgba(63,185,80,.15); color: var(--green); border: 1px solid var(--green); }}
    .badge.err  {{ background: rgba(227,179,65,.15); color: var(--yellow); border: 1px solid var(--yellow); }}
    .good  {{ color: var(--green); }}
    .bad   {{ color: var(--red); }}
    .warn  {{ color: var(--yellow); }}
    .neutral {{ color: var(--muted); }}
    .err-msg {{ color: var(--yellow); font-style: italic; }}
    footer {{ margin-top: 2rem; color: var(--muted); font-size: .8rem; text-align: center; }}
  </style>
</head>
<body>
  <h1>CJ-SCANNER {VERSION}</h1>
  <p class="subtitle">Clickjacking Vulnerability Report &mdash; Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC &mdash; by {AUTHOR} &bull; github.com/{GITHUB}</p>
  <div class="stats">
    <div class="stat t"><div class="num">{len(results)}</div><div class="lbl">Total</div></div>
    <div class="stat v"><div class="num">{vuln_count}</div><div class="lbl">Vulnerable</div></div>
    <div class="stat s"><div class="num">{safe_count}</div><div class="lbl">Protected</div></div>
    <div class="stat e"><div class="num">{error_count}</div><div class="lbl">Errors</div></div>
  </div>
  <table>
    <thead>
      <tr>
        <th>URL</th><th>Status</th><th>Time</th><th>Result</th>
        <th>X-Frame-Options</th><th>CSP frame-ancestors</th><th>Meta XFO</th><th>Cookies</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
  <footer>CJ-SCANNER {VERSION} &mdash; Authorized security testing only</footer>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)


def interactive_mode(args):
    print(Fore.CYAN + "  No arguments provided. Entering interactive mode.")
    print()
    target = input(Fore.WHITE + "  Enter target URL or domain: ").strip()
    if not target:
        print(Fore.RED + "  No target entered. Exiting.")
        sys.exit(1)
    args.url = target
    threads_input = input(Fore.WHITE + f"  Threads [{DEFAULT_THREADS}]: ").strip()
    args.threads = int(threads_input) if threads_input.isdigit() else DEFAULT_THREADS
    timeout_input = input(Fore.WHITE + f"  Timeout [{DEFAULT_TIMEOUT}s]: ").strip()
    args.timeout = int(timeout_input) if timeout_input.isdigit() else DEFAULT_TIMEOUT
    html_input = input(Fore.WHITE + "  Generate HTML report? [y/N]: ").strip().lower()
    args.html = os.path.join(SCRIPT_DIR, "cj_scanner_report.html") if html_input in ("y", "yes") else None
    json_input = input(Fore.WHITE + "  Export JSON? [y/N]: ").strip().lower()
    args.json = json_input in ("y", "yes")
    print()


def collect_targets(args) -> list[str]:
    targets = []
    if args.url:
        targets.append(args.url.strip())
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except FileNotFoundError:
            print(Fore.RED + f"  [!] File not found: {args.file}")
            sys.exit(1)
    return list(dict.fromkeys(targets))  # deduplicate preserving order


def write_vuln_report(results: list[dict], path: str | None = None):
    if path is None:
        path = os.path.join(SCRIPT_DIR, "vulnerable_report.txt")
    vulns = [r for r in results if r["vulnerable"]]
    if not vulns:
        if os.path.exists(path):
            os.remove(path)
        return
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"CJ-SCANNER {VERSION} — Vulnerable Targets\n")
        f.write(f"Generated: {datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}\n")
        f.write("=" * 60 + "\n\n")
        for r in vulns:
            f.write(f"URL        : {r['final_url'] or r['url']}\n")
            f.write(f"Status     : {r['status_code']}\n")
            f.write(f"XFO        : {r['x_frame_options'] or 'NOT SET'}\n")
            f.write(f"CSP FA     : {r['csp_frame_ancestors'] or 'NOT SET'}\n")
            f.write(f"Meta XFO   : {'Found' if r['meta_xfo'] else 'Not found'}\n")
            if r["samesite_issues"]:
                f.write(f"SameSite ! : {', '.join(r['samesite_issues'])}\n")
            f.write("\n")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description=f"CJ-SCANNER {VERSION} — Clickjacking vulnerability scanner",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-u", "--url", help="Single target URL or domain")
    parser.add_argument("-f", "--file", help="File with list of targets (one per line)")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS,
                        help=f"Number of threads (default: {DEFAULT_THREADS})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument(
        "--html",
        nargs="?",
        const=os.path.join(SCRIPT_DIR, "cj_scanner_report.html"),
        metavar="FILE",
        help="Generate HTML report (default name: cj_scanner_report.html)",
    )
    parser.add_argument("--json", action="store_true", help="Export results as JSON")
    parser.add_argument("--no-meta", action="store_true",
                        help="Skip meta tag detection (faster)")
    args = parser.parse_args()

    if not args.url and not args.file:
        interactive_mode(args)

    targets = collect_targets(args)
    if not targets:
        print(Fore.RED + "  [!] No valid targets found.")
        sys.exit(1)

    check_meta = not args.no_meta
    results = []
    completed = 0

    print(Fore.WHITE + f"  Scanning {len(targets)} target(s) with {args.threads} thread(s)...\n")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_map = {
            executor.submit(scan_target, t, args.timeout, check_meta): t
            for t in targets
        }
        for future in as_completed(future_map):
            result = future.result()
            results.append(result)
            completed += 1
            with print_lock:
                print(format_result_console(result))
                progress = f"  [{completed}/{len(targets)}]"
                print(Fore.WHITE + progress)

    # --- Summary ---
    vuln_count = sum(1 for r in results if r["vulnerable"])
    error_count = sum(1 for r in results if r["error"])
    safe_count = len(results) - vuln_count - error_count

    print(Fore.WHITE + "\n  " + "=" * 50)
    print(Fore.CYAN + f"  Scan complete — {len(results)} target(s)")
    print(Fore.RED   + f"  Vulnerable : {vuln_count}")
    print(Fore.GREEN + f"  Protected  : {safe_count}")
    print(Fore.YELLOW + f"  Errors     : {error_count}")
    print(Fore.WHITE + "  " + "=" * 50)

    # --- Outputs ---
    vuln_path = os.path.join(SCRIPT_DIR, "vulnerable_report.txt")
    write_vuln_report(results, vuln_path)
    if vuln_count:
        print(Fore.RED + f"  [+] vulnerable_report.txt saved.")
        print(Fore.RED + f"  Report saved → {vuln_path}")

    if args.html:
        generate_html_report(results, args.html)
        print(Fore.CYAN + f"  [+] HTML report saved: {args.html}")
        print(Fore.CYAN + f"  Report saved → {args.html}")

    if args.json:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join(SCRIPT_DIR, f"cj_results_{ts}.json")
        with open(json_path, "w", encoding="utf-8") as jf:
            json.dump(results, jf, indent=2, ensure_ascii=False)
        print(Fore.CYAN + f"  [+] JSON export saved: {json_path}")
        print(Fore.CYAN + f"  Report saved → {json_path}")

    print()


if __name__ == "__main__":
    main()
