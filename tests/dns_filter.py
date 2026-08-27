#!/usr/bin/env python
"""
dns_filter.py - DNS Filter test.
Tests DNS resolution of known bad domains.
Python 3.5.2 compatible.
"""

import sys
import os
import time
import socket
import signal

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import helpers

PRESETS = [
    ("avsvmcloud.com", "SUNBURST C2 Domain", "avsvmcloud.com"),
    ("websitetheme.com", "Known Malicious Domain", "websitetheme.com"),
    ("malwaredomainlist.com", "Malware Domain List", "malwaredomainlist.com"),
    ("urlhaus.abuse.ch", "URLhaus Threat Feed", "urlhaus.abuse.ch"),
    ("phishtank.org", "PhishTank Phishing DB", "phishtank.org"),
    ("openphish.com", "OpenPhish Feed", "openphish.com"),
    ("feodotracker.abuse.ch", "Feodo Tracker (Banking Trojan)", "feodotracker.abuse.ch"),
    ("sslbl.abuse.ch", "SSL Blacklist (abuse.ch)", "sslbl.abuse.ch"),
]


class _DnsTimeout(Exception):
    pass


def _timeout_handler(signum, frame):
    raise _DnsTimeout("DNS lookup timed out")


def _resolve_with_timeout(domain, timeout):
    """Resolve a domain with a timeout. Returns (ip, error)."""
    # Use signal-based timeout on Unix; fallback to plain resolve on Windows
    use_signal = hasattr(signal, "SIGALRM")
    if use_signal:
        old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(timeout)
    try:
        addr = socket.gethostbyname(domain)
        if use_signal:
            signal.alarm(0)
        return (addr, None)
    except _DnsTimeout:
        return (None, "timeout")
    except socket.gaierror:
        if use_signal:
            signal.alarm(0)
        return (None, "gaierror")
    except Exception as e:
        if use_signal:
            signal.alarm(0)
        return (None, type(e).__name__)
    finally:
        if use_signal:
            signal.signal(signal.SIGALRM, old_handler)


def main():
    parser = helpers.base_parser("DNS Filter Test")
    args = parser.parse_args()

    helpers.emit_header("DNS Filter Test")

    targets, custom = helpers.filter_targets(PRESETS, args.target)

    total = 0
    blocked = 0
    allowed = 0
    inconclusive = 0
    start = time.time()

    all_domains = []
    for key, label, domain in targets:
        all_domains.append((label, domain))
    for custom_domain in custom:
        all_domains.append(("[custom] %s" % custom_domain, custom_domain))

    for label, domain in all_domains:
        addr, err = _resolve_with_timeout(domain, args.timeout)
        if addr is not None:
            verdict = "ALLOWED"
            detail = "Resolved to %s" % addr
        elif err == "timeout":
            verdict = "BLOCKED"
            detail = "DNS lookup timed out - likely blocked"
        else:
            verdict = "BLOCKED"
            detail = "DNS resolution failed - domain blocked"

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
