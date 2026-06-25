#!/usr/bin/env python3
"""
web_filtering.py
----------------
Tests access to a curated list of global gambling websites and reports:
  - HTTP Status Code
  - Destination IP
  - Source Port (ephemeral, assigned by OS)
  - Destination Port (80 for HTTP, 443 for HTTPS)
  - Allow / Block reason

Usage:
    pip install requests pandas tabulate
    python web_filtering.py

Optional flags (edit constants below):
    TIMEOUT        – per-request timeout in seconds
    MAX_WORKERS    – concurrent threads
    OUTPUT_CSV     – set to a filename (e.g. "results.csv") to save output
"""

import concurrent.futures
import socket
import time
from urllib.parse import urlparse

import pandas as pd
import requests

# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────
TIMEOUT     = 10          # seconds per request
MAX_WORKERS = 10          # concurrent threads
OUTPUT_CSV  = ""          # e.g. "results.csv"  — leave empty to skip

# Browser-like User-Agent to reduce bot-blocking false positives
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

# ──────────────────────────────────────────────
#  TARGET SITES  (name → URL)
# ──────────────────────────────────────────────
GAMBLING_SITES = {
    # ── Sports Betting ──
    "bet365":           "https://www.bet365.com",
    "DraftKings":       "https://www.draftkings.com",
    "FanDuel":          "https://www.fanduel.com",
    "William Hill":     "https://www.williamhill.com",
    "Betfair":          "https://www.betfair.com",
    "Paddy Power":      "https://www.paddypower.com",
    "Ladbrokes":        "https://www.ladbrokes.com",
    "Coral":            "https://www.coral.co.uk",
    "PointsBet":        "https://www.pointsbet.com",
    "BetMGM":           "https://www.betmgm.com",

    # ── Online Casinos ──
    "PokerStars Casino":"https://www.pokerstars.com",
    "888 Casino":       "https://www.888casino.com",
    "LeoVegas":         "https://www.leovegas.com",
    "Betway Casino":    "https://www.betway.com",
    "Casumo":           "https://www.casumo.com",
    "Unibet":           "https://www.unibet.com",
    "Mr Green":         "https://www.mrgreen.com",
    "Rizk":             "https://www.rizk.com",
    "Royal Vegas":      "https://www.royalvegas.com",
    "Jackpot City":     "https://www.jackpotcitycasino.com",

    # ── Poker Platforms ──
    "GGPoker":          "https://www.ggpoker.com",
    "partypoker":       "https://www.partypoker.com",
    "WPT Global":       "https://www.wptglobal.com",

    # ── Lottery / Other ──
    "Lottoland":        "https://www.lottoland.com",
    "theLotter":        "https://www.thelotter.com",
    "Sportsbet (AU)":   "https://www.sportsbet.com.au",
    "TAB (AU)":         "https://www.tab.com.au",
    "Sky Bet":          "https://www.skybet.com",
    "Bwin":             "https://www.bwin.com",
    "Mansion Casino":   "https://www.mansioncasino.com",
}

# ──────────────────────────────────────────────
#  HTTP STATUS → human reason
# ──────────────────────────────────────────────
BLOCK_CODES = {
    400: "Bad Request",
    401: "Unauthorised",
    403: "Forbidden – likely blocked by firewall/proxy",
    404: "Not Found",
    407: "Proxy Authentication Required – proxy blocking",
    451: "Unavailable for Legal / Regulatory Reasons",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}

def classify(status_code, error_type=None):
    """Return (verdict, reason) based on HTTP status or exception type."""
    if error_type:
        reasons = {
            "ConnectionError":   ("BLOCK", "Connection refused / DNS blocked"),
            "Timeout":           ("BLOCK", "Request timed out – possible firewall drop"),
            "SSLError":          ("BLOCK", "SSL/TLS error – cert or inspection policy"),
            "ProxyError":        ("BLOCK", "Proxy explicitly blocked the connection"),
            "TooManyRedirects":  ("BLOCK", "Redirect loop – possible captive portal"),
        }
        for key, val in reasons.items():
            if key.lower() in error_type.lower():
                return val
        return ("BLOCK", f"Request exception: {error_type}")

    if status_code == 200:
        return ("ALLOW", "HTTP 200 OK – site reachable")
    if status_code in (301, 302, 303, 307, 308):
        return ("ALLOW", f"HTTP {status_code} Redirect – site reachable")
    if status_code in BLOCK_CODES:
        return ("BLOCK", f"HTTP {status_code} – {BLOCK_CODES[status_code]}")
    if 400 <= status_code < 500:
        return ("BLOCK", f"HTTP {status_code} Client Error")
    if 500 <= status_code < 600:
        return ("BLOCK", f"HTTP {status_code} Server Error")
    return ("ALLOW", f"HTTP {status_code} – Unexpected status")


def resolve_ip(hostname):
    """Return the first resolved IP for a hostname, or 'N/A'."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return "N/A (DNS failed)"


def get_dest_port(url):
    """Return standard destination port based on URL scheme."""
    scheme = urlparse(url).scheme.lower()
    return 443 if scheme == "https" else 80


def probe_site(name, url):
    """
    Probe a single URL and return a result dict with all required fields.
    Source port is captured from the live socket used by requests.
    """
    parsed   = urlparse(url)
    hostname = parsed.netloc or parsed.path
    dest_ip  = resolve_ip(hostname)
    dest_port = get_dest_port(url)
    src_port  = "N/A"
    http_code = "N/A"
    verdict   = "BLOCK"
    reason    = "Unknown"

    try:
        # We use a Session so we can hook into the underlying socket
        session = requests.Session()

        # Monkey-patch to capture ephemeral source port
        _orig_connect = socket.create_connection

        captured_src_port = [None]

        def patched_connect(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
            sock = _orig_connect(address, timeout=timeout, source_address=source_address)
            captured_src_port[0] = sock.getsockname()[1]   # (host, port)[1]
            return sock

        socket.create_connection = patched_connect

        response  = session.get(
            url,
            headers=HEADERS,
            timeout=TIMEOUT,
            allow_redirects=True,
        )

        socket.create_connection = _orig_connect   # restore

        http_code = response.status_code
        src_port  = captured_src_port[0] if captured_src_port[0] else "N/A"
        verdict, reason = classify(http_code)

    except requests.exceptions.RequestException as exc:
        socket.create_connection = _orig_connect   # always restore
        error_type = type(exc).__name__
        verdict, reason = classify(None, error_type=error_type)
        http_code = "ERR"

    return {
        "Site":         name,
        "URL":          url,
        "HTTP Code":    http_code,
        "Dest IP":      dest_ip,
        "Src Port":     src_port,
        "Dest Port":    dest_port,
        "Verdict":      verdict,
        "Reason":       reason,
    }


def main():
    total = len(GAMBLING_SITES)
    print(f"\n{'='*70}")
    print(f"  Web Filtering Test  –  {total} Gambling / Wagering Sites")
    print(f"  Timeout: {TIMEOUT}s  |  Workers: {MAX_WORKERS}")
    print(f"{'='*70}\n")

    results  = []
    start    = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {
            executor.submit(probe_site, name, url): name
            for name, url in GAMBLING_SITES.items()
        }
        done = 0
        for future in concurrent.futures.as_completed(future_map):
            done += 1
            result = future.result()
            results.append(result)
            verdict_icon = "✅" if result["Verdict"] == "ALLOW" else "❌"
            print(f"  [{done:>2}/{total}] {verdict_icon}  {result['Site']:<22} "
                  f"HTTP {result['HTTP Code']}")

    elapsed = time.time() - start

    # ── Build DataFrame ──────────────────────────────────────────────────
    df = pd.DataFrame(results, columns=[
        "Site", "URL", "HTTP Code", "Dest IP",
        "Src Port", "Dest Port", "Verdict", "Reason"
    ])
    df.sort_values("Site", inplace=True)
    df.reset_index(drop=True, inplace=True)

    # ── Summary stats ────────────────────────────────────────────────────
    allowed = (df["Verdict"] == "ALLOW").sum()
    blocked = (df["Verdict"] == "BLOCK").sum()

    print(f"\n{'='*70}")
    print(f"  Completed in {elapsed:.1f}s   |   "
          f"✅ Allowed: {allowed}   ❌ Blocked: {blocked}")
    print(f"{'='*70}\n")

    # ── Pretty-print table ───────────────────────────────────────────────
    try:
        from tabulate import tabulate
        display_cols = ["Site", "HTTP Code", "Dest IP", "Src Port",
                        "Dest Port", "Verdict", "Reason"]
        print(tabulate(df[display_cols], headers="keys",
                       tablefmt="rounded_outline", showindex=False))
    except ImportError:
        # Fallback if tabulate not installed
        pd.set_option("display.max_colwidth", 60)
        pd.set_option("display.width", 200)
        print(df[["Site", "HTTP Code", "Dest IP", "Src Port",
                  "Dest Port", "Verdict", "Reason"]].to_string(index=False))

    # ── Optional CSV export ──────────────────────────────────────────────
    if OUTPUT_CSV:
        df.to_csv(OUTPUT_CSV, index=False)
        print(f"\n  Results saved to: {OUTPUT_CSV}")

    print()


if __name__ == "__main__":
    main()
