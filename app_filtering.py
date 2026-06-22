#!/usr/bin/env python3
"""
Firewall App Filter Traffic Generator
Generates test traffic for: HTTP/S, DNS, FTP/SFTP, SMTP/IMAP, Streaming/Media
Run sequentially to test application filtering on firewall products.
"""

import socket
import ssl
import smtplib
import imaplib
import urllib.request
import urllib.error
import urllib3
import dns.resolver          # pip install dnspython
import time
import argparse
import sys
import warnings
from datetime import datetime

# Suppress SSL/certificate warnings (expected when using --no-verify or --cacert)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Global SSL config (set in main(), used everywhere) ───────────────────────
SSL_CAFILE   = None   # path to firewall CA bundle, or None = system default
SSL_VERIFY   = True   # set False with --no-verify

def make_ssl_ctx():
    """Return an SSL context that respects --cacert / --no-verify."""
    if not SSL_VERIFY:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        return ctx
    ctx = ssl.create_default_context(cafile=SSL_CAFILE)
    return ctx

# ── Colour helpers ────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def log(category, target, status, detail=""):
    ts   = datetime.now().strftime("%H:%M:%S")
    icon = f"{GREEN}✔{RESET}" if status == "OK" else f"{RED}✘{RESET}"
    cat  = f"{CYAN}{category:<12}{RESET}"
    tgt  = f"{BOLD}{target:<40}{RESET}"
    det  = f"  {YELLOW}{detail}{RESET}" if detail else ""
    print(f"[{ts}] {icon} {cat} {tgt}{det}")

def section(title):
    bar = "─" * 60
    print(f"\n{BOLD}{bar}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{bar}{RESET}")

# ── 1. HTTP / HTTPS ───────────────────────────────────────────────────────────
HTTP_TARGETS = [
    ("http",  "http://example.com"),
    ("http",  "http://httpbin.org/get"),
    ("https", "https://www.google.com"),
    ("https", "https://www.cloudflare.com"),
    ("https", "https://httpbin.org/get"),
    ("https", "https://api.ipify.org"),          # plain REST API
    ("https", "https://speed.cloudflare.com"),   # CDN / speed-test endpoint
]

def test_http(timeout=5):
    section("HTTP / HTTPS")
    for proto, url in HTTP_TARGETS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "AppFilterTest/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                log(proto.upper(), url, "OK", f"HTTP {r.status}")
        except urllib.error.HTTPError as e:
            log(proto.upper(), url, "OK", f"HTTP {e.code}")   # got a response = traffic passed
        except Exception as e:
            log(proto.upper(), url, "FAIL", str(e))
        time.sleep(0.3)

# ── 2. DNS ────────────────────────────────────────────────────────────────────
DNS_QUERIES = [
    ("A",    "www.google.com",    "8.8.8.8"),
    ("A",    "www.amazon.com",    "1.1.1.1"),
    ("AAAA", "www.facebook.com",  "8.8.8.8"),
    ("MX",   "gmail.com",         "1.1.1.1"),
    ("TXT",  "cloudflare.com",    "8.8.4.4"),
    ("NS",   "wikipedia.org",     "9.9.9.9"),
    ("A",    "example.com",       "208.67.222.222"),  # OpenDNS
]

def test_dns(timeout=5):
    section("DNS")
    resolver = dns.resolver.Resolver()
    resolver.timeout  = timeout
    resolver.lifetime = timeout
    for qtype, name, server in DNS_QUERIES:
        resolver.nameservers = [server]
        label = f"{name} [{qtype}] via {server}"
        try:
            answers = resolver.resolve(name, qtype)
            log("DNS", label, "OK", f"{len(answers)} record(s)")
        except Exception as e:
            log("DNS", label, "FAIL", str(e))
        time.sleep(0.2)

# ── 3. Email – SMTP (banner grab) & IMAP ─────────────────────────────────────
SMTP_TARGETS = [
    # (host, port, use_tls, label)
    ("smtp.gmail.com",      587, True,  "Gmail SMTP STARTTLS"),
    ("smtp.office365.com",  587, True,  "O365 SMTP STARTTLS"),
    ("smtp.mail.yahoo.com", 465, False, "Yahoo SMTP SSL"),
    ("aspmx.l.google.com",  25,  False, "Google MX (port 25)"),
]

IMAP_TARGETS = [
    ("imap.gmail.com",      993, "Gmail IMAP SSL"),
    ("imap.mail.yahoo.com", 993, "Yahoo IMAP SSL"),
    ("outlook.office365.com", 993, "O365 IMAP SSL"),
]

def test_email(timeout=6):
    section("Email – SMTP")
    for host, port, starttls, label in SMTP_TARGETS:
        try:
            if port == 465:
                # Implicit TLS — must use SMTP_SSL from the start
                ctx  = make_ssl_ctx()
                smtp = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx)
            else:
                smtp = smtplib.SMTP(host, port, timeout=timeout)

            code, raw = smtp.ehlo()
            banner = raw.decode(errors="replace").splitlines()[0]  # first line only

            if starttls and port != 465:
                smtp.starttls(context=make_ssl_ctx())
                code, raw = smtp.ehlo()   # re-identify after STARTTLS

            smtp.quit()
            log("SMTP", label, "OK", f"EHLO {code}  {banner[:50]}")
        except Exception as e:
            log("SMTP", label, "FAIL", str(e))
        time.sleep(0.4)

    section("Email – IMAP")
    for host, port, label in IMAP_TARGETS:
        try:
            ctx  = make_ssl_ctx()
            imap = imaplib.IMAP4_SSL(host, port, ssl_context=ctx)
            cap  = imap.capability()[1][0].decode(errors="replace")
            imap.logout()
            log("IMAP", label, "OK", cap[:60])
        except Exception as e:
            log("IMAP", label, "FAIL", str(e))
        time.sleep(0.4)

# ── 4. Streaming / Media ──────────────────────────────────────────────────────
STREAMING_TARGETS = [
    # (label, url, expected_content_type_prefix)
    ("YouTube CDN",          "https://www.youtube.com",                       "text"),
    ("Netflix (homepage)",   "https://www.netflix.com",                       "text"),
    ("Twitch",               "https://www.twitch.tv",                         "text"),
    ("Spotify Web",          "https://open.spotify.com",                      "text"),
    ("Apple Podcasts",       "https://podcasts.apple.com",                    "text"),
    ("HLS sample stream",    "https://test-streams.mux.dev/x36xhzz/x36xhzz.m3u8", "application"),
    ("DASH manifest",        "https://dash.akamaized.net/akamai/bbb_30fps/bbb_30fps.mpd", "application"),
    ("MP4 sample (partial)", "https://test-videos.co.uk/vids/bigbuckbunny/mp4/h264/360/Big_Buck_Bunny_360_10s_1MB.mp4", "video"),
]

def test_streaming(timeout=8):
    section("Streaming / Media")
    for label, url, expected_ct in STREAMING_TARGETS:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (AppFilterTest)",
                    "Range":      "bytes=0-1023",   # only grab 1 KB
                }
            )
            with urllib.request.urlopen(req, timeout=timeout) as r:
                ct   = r.headers.get("Content-Type", "unknown")
                code = r.status
                log("STREAM", label, "OK", f"HTTP {code}  {ct[:50]}")
        except urllib.error.HTTPError as e:
            # 206 Partial, 302 redirect, etc. – still means traffic reached the server
            log("STREAM", label, "OK", f"HTTP {e.code}")
        except Exception as e:
            log("STREAM", label, "FAIL", str(e))
        time.sleep(0.4)

# ── Entry point ───────────────────────────────────────────────────────────────
MODULES = {
    "http":      test_http,
    "dns":       test_dns,
    "email":     test_email,
    "streaming": test_streaming,
}

def main():
    global SSL_CAFILE, SSL_VERIFY

    parser = argparse.ArgumentParser(
        description="Firewall App-Filter Traffic Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join([
            "Examples:",
            "  python traffic_generator.py                          # run all modules",
            "  python traffic_generator.py --only http dns",
            "  python traffic_generator.py --skip ftp",
            "  python traffic_generator.py --timeout 10",
            "  python traffic_generator.py --cacert /path/fw-ca.pem  # SSL inspection CA",
            "  python traffic_generator.py --no-verify               # skip cert checks",
        ])
    )
    parser.add_argument("--only",      nargs="+", choices=MODULES.keys(),
                        help="Run only these modules")
    parser.add_argument("--skip",      nargs="+", choices=MODULES.keys(),
                        help="Skip these modules")
    parser.add_argument("--timeout",   type=int, default=6,
                        help="Socket timeout in seconds (default: 6)")
    parser.add_argument("--cacert",    metavar="FILE",
                        help="Path to firewall CA certificate bundle (.pem/.crt). "
                             "Required when the firewall performs SSL inspection.")
    parser.add_argument("--no-verify", action="store_true",
                        help="Disable SSL certificate verification entirely "
                             "(quick test — not for production use)")
    args = parser.parse_args()

    # Apply SSL settings globally
    SSL_CAFILE = args.cacert
    SSL_VERIFY = not args.no_verify

    # Install a global urllib opener so all urlopen() calls use the right SSL context.
    # This covers both --no-verify (skip cert checks) and --cacert (custom CA bundle).
    if not SSL_VERIFY:
        no_verify_ctx = ssl.create_default_context()
        no_verify_ctx.check_hostname = False
        no_verify_ctx.verify_mode    = ssl.CERT_NONE
        urllib.request.install_opener(
            urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=no_verify_ctx)
            )
        )
    elif SSL_CAFILE:
        ca_ctx = ssl.create_default_context(cafile=SSL_CAFILE)
        urllib.request.install_opener(
            urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ca_ctx)
            )
        )

    selected = list(MODULES.keys())
    if args.only:
        selected = [m for m in selected if m in args.only]
    if args.skip:
        selected = [m for m in selected if m not in args.skip]

    if not SSL_VERIFY:
        ssl_mode = f"{YELLOW}DISABLED (--no-verify){RESET}"
    elif SSL_CAFILE:
        ssl_mode = f"{GREEN}Custom CA: {SSL_CAFILE}{RESET}"
    else:
        ssl_mode = f"{GREEN}System default{RESET}"

    print(f"\n{BOLD}{'═'*60}{RESET}")
    print(f"{BOLD}  Firewall App-Filter Traffic Generator{RESET}")
    print(f"  Modules : {', '.join(selected)}")
    print(f"  Timeout : {args.timeout}s")
    print(f"  SSL     : {ssl_mode}")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{BOLD}{'═'*60}{RESET}")

    for name in selected:
        try:
            MODULES[name](timeout=args.timeout)
        except KeyboardInterrupt:
            print(f"\n{YELLOW}Interrupted – stopping.{RESET}")
            sys.exit(0)

    print(f"\n{BOLD}{'═'*60}{RESET}")
    print(f"{BOLD}  Done.{RESET}  Check your firewall logs for matched app signatures.")
    print(f"{BOLD}{'═'*60}{RESET}\n")

if __name__ == "__main__":
    main()
