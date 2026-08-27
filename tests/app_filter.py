#!/usr/bin/env python
"""
app_filter.py - Application Filtering test.
Tests multiple protocols: HTTP, HTTPS, DNS, SMTP, IMAP, streaming.
Python 3.5.2 compatible.
"""

import sys
import os
import time
import socket
import smtplib
import imaplib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import helpers

PRESETS = [
    ("http-example", "HTTP example.com", {"proto": "http", "url": "http://example.com"}),
    ("http-httpbin", "HTTP httpbin.org", {"proto": "http", "url": "http://httpbin.org/get"}),
    ("https-google", "HTTPS google.com", {"proto": "https", "url": "https://www.google.com"}),
    ("https-cloudflare", "HTTPS cloudflare.com", {"proto": "https", "url": "https://www.cloudflare.com"}),
    ("https-httpbin", "HTTPS httpbin.org", {"proto": "https", "url": "https://httpbin.org/get"}),
    ("dns-google-a", "DNS A google.com via 8.8.8.8", {"proto": "dns", "name": "www.google.com", "qtype": "A", "server": "8.8.8.8"}),
    ("dns-amazon-a", "DNS A amazon.com via 1.1.1.1", {"proto": "dns", "name": "www.amazon.com", "qtype": "A", "server": "1.1.1.1"}),
    ("dns-facebook-aaaa", "DNS AAAA facebook.com via 8.8.8.8", {"proto": "dns", "name": "www.facebook.com", "qtype": "AAAA", "server": "8.8.8.8"}),
    ("smtp-gmail", "SMTP Gmail STARTTLS", {"proto": "smtp", "host": "smtp.gmail.com", "port": 587, "starttls": True}),
    ("smtp-o365", "SMTP Office365 STARTTLS", {"proto": "smtp", "host": "smtp.office365.com", "port": 587, "starttls": True}),
    ("smtp-yahoo", "SMTP Yahoo SSL", {"proto": "smtp", "host": "smtp.mail.yahoo.com", "port": 465, "starttls": False}),
    ("imap-gmail", "IMAP Gmail SSL", {"proto": "imap", "host": "imap.gmail.com", "port": 993}),
    ("imap-yahoo", "IMAP Yahoo SSL", {"proto": "imap", "host": "imap.mail.yahoo.com", "port": 993}),
    ("stream-youtube", "YouTube", {"proto": "stream", "url": "https://www.youtube.com"}),
    ("stream-netflix", "Netflix", {"proto": "stream", "url": "https://www.netflix.com"}),
    ("stream-twitch", "Twitch", {"proto": "stream", "url": "https://www.twitch.tv"}),
    ("stream-spotify", "Spotify", {"proto": "stream", "url": "https://open.spotify.com"}),
]


def _test_http(config, timeout, no_verify):
    """Test HTTP/HTTPS/streaming target."""
    url = config["url"]
    status, body, err = helpers.http_get(url, timeout=timeout, no_verify=no_verify)
    if err is not None:
        err_lower = err.lower()
        if "timeout" in err_lower or "connectionreset" in err_lower or "connectionrefused" in err_lower:
            return ("BLOCKED", "Connection failed: %s" % err)
        return ("INCONCLUSIVE", "Request error: %s" % err)
    if status is not None and 200 <= status < 400:
        return ("ALLOWED", "HTTP %d - accessible" % status)
    if status is not None:
        return ("INCONCLUSIVE", "HTTP %d" % status)
    return ("INCONCLUSIVE", "No response received")


def _test_dns(config, timeout):
    """Test DNS resolution via specific server using dnspython."""
    try:
        import dns.resolver
        import dns.rdatatype
    except ImportError:
        return ("INCONCLUSIVE", "dnspython not installed - cannot test DNS")

    name = config["name"]
    qtype = config.get("qtype", "A")
    server = config["server"]

    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [server]
        resolver.lifetime = timeout
        answers = resolver.resolve(name, qtype)
        records = [str(r) for r in answers]
        return ("ALLOWED", "Resolved %s %s: %s" % (qtype, name, ", ".join(records[:3])))
    except dns.resolver.NXDOMAIN:
        return ("BLOCKED", "NXDOMAIN for %s - domain blocked" % name)
    except dns.resolver.NoAnswer:
        return ("INCONCLUSIVE", "No %s records for %s" % (qtype, name))
    except dns.resolver.Timeout:
        return ("BLOCKED", "DNS query timed out - likely blocked")
    except Exception as e:
        return ("BLOCKED", "DNS query failed: %s" % type(e).__name__)


def _test_smtp(config, timeout, no_verify):
    """Test SMTP connection."""
    host = config["host"]
    port = config["port"]
    starttls = config.get("starttls", False)

    try:
        if not starttls and port == 465:
            ctx = helpers.make_ssl_context(no_verify)
            server = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx)
        else:
            server = smtplib.SMTP(host, port, timeout=timeout)
        server.ehlo()
        if starttls:
            ctx = helpers.make_ssl_context(no_verify)
            server.starttls(context=ctx)
            server.ehlo()
        server.quit()
        return ("ALLOWED", "SMTP %s:%d - banner received" % (host, port))
    except (socket.timeout, socket.error):
        return ("BLOCKED", "SMTP %s:%d - connection failed" % (host, port))
    except smtplib.SMTPException as e:
        return ("BLOCKED", "SMTP %s:%d - error: %s" % (host, port, type(e).__name__))
    except Exception as e:
        return ("BLOCKED", "SMTP %s:%d - %s" % (host, port, type(e).__name__))


def _test_imap(config, timeout, no_verify):
    """Test IMAP connection."""
    host = config["host"]
    port = config["port"]

    # First do a TCP probe
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
    except (socket.timeout, socket.error):
        return ("BLOCKED", "IMAP %s:%d - TCP connection failed" % (host, port))
    except Exception as e:
        return ("BLOCKED", "IMAP %s:%d - %s" % (host, port, type(e).__name__))

    # Then try IMAP SSL
    try:
        ctx = helpers.make_ssl_context(no_verify)
        mail = imaplib.IMAP4_SSL(host, port, ssl_context=ctx)
        caps = mail.capability()
        mail.logout()
        return ("ALLOWED", "IMAP %s:%d - capability received" % (host, port))
    except (socket.timeout, socket.error):
        return ("BLOCKED", "IMAP %s:%d - SSL connection failed" % (host, port))
    except imaplib.IMAP4.error as e:
        return ("BLOCKED", "IMAP %s:%d - error: %s" % (host, port, str(e)))
    except Exception as e:
        return ("BLOCKED", "IMAP %s:%d - %s" % (host, port, type(e).__name__))


def main():
    parser = helpers.base_parser("Application Filtering Test")
    args = parser.parse_args()

    helpers.emit_header("Application Filtering Test")

    targets, custom = helpers.filter_targets(PRESETS, args.target)

    total = 0
    blocked = 0
    allowed = 0
    inconclusive = 0
    start = time.time()

    for key, label, config in targets:
        proto = config["proto"]

        if proto in ("http", "https", "stream"):
            verdict, detail = _test_http(config, args.timeout, args.no_verify)
        elif proto == "dns":
            verdict, detail = _test_dns(config, args.timeout)
        elif proto == "smtp":
            verdict, detail = _test_smtp(config, args.timeout, args.no_verify)
        elif proto == "imap":
            verdict, detail = _test_imap(config, args.timeout, args.no_verify)
        else:
            verdict, detail = ("INCONCLUSIVE", "Unknown protocol: %s" % proto)

        helpers.emit_result(verdict, label, detail)
        total += 1
        if verdict == "BLOCKED":
            blocked += 1
        elif verdict == "ALLOWED":
            allowed += 1
        else:
            inconclusive += 1
        time.sleep(0.3)

    for entry in custom:
        label = "[custom] %s" % entry
        if entry.startswith("http://") or entry.startswith("https://"):
            config = {"proto": "http", "url": entry}
            verdict, detail = _test_http(config, args.timeout, args.no_verify)
        else:
            config = {"proto": "http", "url": "https://%s" % entry}
            verdict, detail = _test_http(config, args.timeout, args.no_verify)
        helpers.emit_result(verdict, label, detail)
        total += 1
        if verdict == "BLOCKED":
            blocked += 1
        elif verdict == "ALLOWED":
            allowed += 1
        else:
            inconclusive += 1
        time.sleep(0.3)

    elapsed = time.time() - start
    helpers.emit_done(total, blocked, allowed, inconclusive, elapsed)


if __name__ == "__main__":
    main()
