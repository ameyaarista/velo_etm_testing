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
import urllib.parse
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
DIM    = "\033[2m"

def log(category, target, status, detail="", conn=None):
    """
    conn = (dst_ip, src_port, dst_port) or None
    Printed columns: timestamp | icon | category | target | conn info | detail
    """
    ts   = datetime.now().strftime("%H:%M:%S")
    icon = f"{GREEN}✔{RESET}" if status == "OK" else f"{RED}✘{RESET}"
    cat  = f"{CYAN}{category:<8}{RESET}"
    tgt  = f"{BOLD}{target:<38}{RESET}"

    if conn:
        dst_ip, src_port, dst_port = conn
        conn_str = (
            f"{DIM}dst={dst_ip:<15} sport={str(src_port):<6} dport={dst_port}{RESET}"
        )
    else:
        conn_str = f"{DIM}{'dst=?':<15} {'sport=?':<12} {'dport=?'}{RESET}"

    det = f"  {YELLOW}{detail}{RESET}" if detail else ""
    print(f"[{ts}] {icon} {cat} {tgt} {conn_str}{det}")

def section(title):
    bar = "─" * 80
    print(f"\n{BOLD}{bar}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{bar}{RESET}")

# ── Connection-info helpers ───────────────────────────────────────────────────

def resolve_ip(hostname):
    """Resolve hostname → first IPv4 address, or '?' on failure."""
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return "?"

def sock_conn_info(sock):
    """
    Given a connected socket (plain or SSL), return (dst_ip, src_port, dst_port).
    Handles: raw socket, ssl.SSLSocket, and imaplib/smtplib wrapped objects.
    Falls back to '?' values on any error.
    """
    try:
        # imaplib.IMAP4_SSL exposes the real SSL socket via .socket() method
        if hasattr(sock, "socket") and callable(sock.socket):
            raw = sock.socket()
        # smtplib stores plain socket as .sock; SSL wrapped via SMTP_SSL is SSLSocket
        elif isinstance(sock, ssl.SSLSocket):
            raw = sock  # SSLSocket itself supports getsockname/getpeername
        else:
            raw = sock
        local_port  = raw.getsockname()[1]
        remote_addr = raw.getpeername()
        return remote_addr[0], local_port, remote_addr[1]
    except Exception:
        return "?", "?", "?"

def tcp_probe(host, port, timeout=5):
    """
    Open a plain TCP connection to host:port and immediately capture socket info.
    Returns (dst_ip, src_port, dst_port, err_msg).
    err_msg is None on success, or a string describing the failure (blocked/refused/timeout).
    This is the ground-truth reachability check — if this fails, the firewall is blocking.
    """
    try:
        dst_ip = resolve_ip(host)
        raw = socket.create_connection((host, port), timeout=timeout)
        src_port = raw.getsockname()[1]
        dst_port = raw.getpeername()[1]
        raw.close()
        return dst_ip, src_port, dst_port, None
    except socket.timeout:
        return resolve_ip(host), "?", port, "TCP timeout (likely blocked — no RST received)"
    except ConnectionRefusedError:
        return resolve_ip(host), "?", port, "TCP connection refused"
    except OSError as e:
        return resolve_ip(host), "?", port, f"TCP error: {e}"

def http_conn_info(url, timeout=5):
    """
    Open a raw TCP connection to the URL host:port just to read the socket
    addresses, then close it immediately.  Returns (dst_ip, src_port, dst_port).
    Used as a lightweight complement to urllib (which doesn't expose its socket).
    """
    try:
        parsed   = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        port     = parsed.port or (443 if parsed.scheme == "https" else 80)
        dst_ip   = resolve_ip(hostname)

        raw = socket.create_connection((hostname, port), timeout=timeout)
        src_port = raw.getsockname()[1]
        dst_port = raw.getpeername()[1]
        raw.close()
        return dst_ip, src_port, dst_port
    except Exception:
        return "?", "?", "?"

# ── 1. HTTP / HTTPS ───────────────────────────────────────────────────────────
HTTP_TARGETS = [
    ("http",  "http://example.com"),
    ("http",  "http://httpbin.org/get"),
    ("https", "https://www.google.com"),
    ("https", "https://www.cloudflare.com"),
    ("https", "https://httpbin.org/get"),
    ("https", "https://api.ipify.org"),
    ("https", "https://speed.cloudflare.com"),
]

def test_http(timeout=5):
    section("HTTP / HTTPS")
    for proto, url in HTTP_TARGETS:
        # Grab connection info via a quick probe socket before the real request
        conn = http_conn_info(url, timeout=timeout)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "AppFilterTest/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                log(proto.upper(), url, "OK", f"HTTP {r.status}", conn)
        except urllib.error.HTTPError as e:
            log(proto.upper(), url, "OK", f"HTTP {e.code}", conn)
        except Exception as e:
            log(proto.upper(), url, "FAIL", str(e), conn)
        time.sleep(0.3)

# ── 2. DNS ────────────────────────────────────────────────────────────────────
DNS_QUERIES = [
    ("A",    "www.google.com",    "8.8.8.8"),
    ("A",    "www.amazon.com",    "1.1.1.1"),
    ("AAAA", "www.facebook.com",  "8.8.8.8"),
    ("MX",   "gmail.com",         "1.1.1.1"),
    ("TXT",  "cloudflare.com",    "8.8.4.4"),
    ("NS",   "wikipedia.org",     "9.9.9.9"),
    ("A",    "example.com",       "208.67.222.222"),
]

def test_dns(timeout=5):
    section("DNS")
    resolver = dns.resolver.Resolver()
    resolver.timeout  = timeout
    resolver.lifetime = timeout
    for qtype, name, server in DNS_QUERIES:
        resolver.nameservers = [server]
        label = f"{name} [{qtype}] via {server}"

        # DNS uses UDP port 53; source port is ephemeral — probe with a UDP socket
        src_port, dst_port = "?", 53
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.settimeout(1)
            probe.connect((server, 53))
            src_port = probe.getsockname()[1]
            probe.close()
        except Exception:
            pass
        conn = (server, src_port, dst_port)

        try:
            answers = resolver.resolve(name, qtype)
            log("DNS", label, "OK", f"{len(answers)} record(s)", conn)
        except Exception as e:
            log("DNS", label, "FAIL", str(e), conn)
        time.sleep(0.2)

# ── 3. Email – SMTP (banner grab) & IMAP ─────────────────────────────────────
SMTP_TARGETS = [
    ("smtp.gmail.com",      587, True,  "Gmail SMTP STARTTLS"),
    ("smtp.office365.com",  587, True,  "O365 SMTP STARTTLS"),
    ("smtp.mail.yahoo.com", 465, False, "Yahoo SMTP SSL"),
    ("aspmx.l.google.com",  25,  False, "Google MX (port 25)"),
]

IMAP_TARGETS = [
    ("imap.gmail.com",        993, "Gmail IMAP SSL"),
    ("imap.mail.yahoo.com",   993, "Yahoo IMAP SSL"),
    ("outlook.office365.com", 993, "O365 IMAP SSL"),
]

def test_email(timeout=6):
    section("Email – SMTP")
    for host, port, starttls, label in SMTP_TARGETS:
        dst_ip = resolve_ip(host)
        conn   = None
        try:
            if port == 465:
                ctx  = make_ssl_ctx()
                smtp = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx)
                conn = sock_conn_info(smtp.sock)
            else:
                smtp = smtplib.SMTP(host, port, timeout=timeout)
                conn = sock_conn_info(smtp.sock)

            code, raw = smtp.ehlo()
            banner = raw.decode(errors="replace").splitlines()[0]

            if starttls and port != 465:
                smtp.starttls(context=make_ssl_ctx())
                smtp.ehlo()

            smtp.quit()
            log("SMTP", label, "OK", f"EHLO {code}  {banner[:40]}", conn)
        except Exception as e:
            if conn is None:
                conn = (dst_ip, "?", port)
            log("SMTP", label, "FAIL", str(e), conn)
        time.sleep(0.4)

    section("Email – IMAP")
    for host, port, label in IMAP_TARGETS:
        # ── Step 1: TCP pre-flight ────────────────────────────────────────────
        # Connects bare TCP first so we can (a) capture real socket info and
        # (b) detect firewall blocks before attempting TLS/IMAP.
        dst_ip, src_port, dst_port, tcp_err = tcp_probe(host, port, timeout=timeout)
        conn = (dst_ip, src_port, dst_port)

        if tcp_err:
            # TCP itself was blocked or refused — no point trying IMAP
            log("IMAP", label, "FAIL", f"BLOCKED – {tcp_err}", conn)
            time.sleep(0.4)
            continue

        # ── Step 2: Full IMAP over TLS ────────────────────────────────────────
        try:
            ctx  = make_ssl_ctx()
            imap = imaplib.IMAP4_SSL(host, port, ssl_context=ctx)
            # imap.socket() returns the underlying ssl.SSLSocket
            conn = sock_conn_info(imap)          # pass the IMAP4_SSL object
            cap  = imap.capability()[1][0].decode(errors="replace")
            imap.logout()
            log("IMAP", label, "OK", cap[:50], conn)
        except ssl.SSLError as e:
            log("IMAP", label, "FAIL", f"TLS error (firewall intercept?): {e}", conn)
        except imaplib.IMAP4.error as e:
            log("IMAP", label, "FAIL", f"IMAP error: {e}", conn)
        except Exception as e:
            log("IMAP", label, "FAIL", str(e), conn)
        time.sleep(0.4)

# ── 4. Streaming / Media ──────────────────────────────────────────────────────
STREAMING_TARGETS = [
    ("YouTube CDN",          "https://www.youtube.com",                                                       "text"),
    ("Netflix (homepage)",   "https://www.netflix.com",                                                       "text"),
    ("Twitch",               "https://www.twitch.tv",                                                         "text"),
    ("Spotify Web",          "https://open.spotify.com",                                                      "text"),
    ("Apple Podcasts",       "https://podcasts.apple.com",                                                    "text"),
    ("HLS sample stream",    "https://test-streams.mux.dev/x36xhzz/x36xhzz.m3u8",                           "application"),
    ("DASH manifest",        "https://dash.akamaized.net/akamai/bbb_30fps/bbb_30fps.mpd",                    "application"),
    ("MP4 sample (partial)", "https://test-videos.co.uk/vids/bigbuckbunny/mp4/h264/360/Big_Buck_Bunny_360_10s_1MB.mp4", "video"),
]

def test_streaming(timeout=8):
    section("Streaming / Media")
    for label, url, expected_ct in STREAMING_TARGETS:
        conn = http_conn_info(url, timeout=timeout)
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (AppFilterTest)",
                    "Range":      "bytes=0-1023",
                }
            )
            with urllib.request.urlopen(req, timeout=timeout) as r:
                ct   = r.headers.get("Content-Type", "unknown")
                code = r.status
                log("STREAM", label, "OK", f"HTTP {code}  {ct[:40]}", conn)
        except urllib.error.HTTPError as e:
            log("STREAM", label, "OK", f"HTTP {e.code}", conn)
        except Exception as e:
            log("STREAM", label, "FAIL", str(e), conn)
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
            "  python traffic_generator.py --skip streaming",
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

    SSL_CAFILE = args.cacert
    SSL_VERIFY = not args.no_verify

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

    print(f"\n{BOLD}{'═'*80}{RESET}")
    print(f"{BOLD}  Firewall App-Filter Traffic Generator{RESET}")
    print(f"  Modules : {', '.join(selected)}")
    print(f"  Timeout : {args.timeout}s")
    print(f"  SSL     : {ssl_mode}")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{BOLD}{'═'*80}{RESET}")
    # Column header
    print(
        f"\n  {'':8}  {'':2}  {'PROTO':<8} {'TARGET':<38} "
        f"{'DST IP':<19} {'SPORT':<10} {'DPORT':<8} DETAIL"
    )
    print(f"  {'─'*76}")

    for name in selected:
        try:
            MODULES[name](timeout=args.timeout)
        except KeyboardInterrupt:
            print(f"\n{YELLOW}Interrupted – stopping.{RESET}")
            sys.exit(0)

    print(f"\n{BOLD}{'═'*80}{RESET}")
    print(f"{BOLD}  Done.{RESET}  Check your firewall logs for matched app signatures.")
    print(f"{BOLD}{'═'*80}{RESET}\n")

if __name__ == "__main__":
    main()
