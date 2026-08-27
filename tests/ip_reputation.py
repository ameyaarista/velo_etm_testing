#!/usr/bin/env python
"""
ip_reputation.py - IP Reputation test.
Tests TCP connections to known bad IPs.
Python 3.5.2 compatible.
"""

import sys
import os
import time
import socket

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import helpers

PRESETS = [
    ("207.189.189.230", "Known Spyware C2 (207.189.189.230)", ("207.189.189.230", 80)),
    ("185.220.101.1", "Tor Exit Node (185.220.101.1)", ("185.220.101.1", 443)),
    ("45.33.32.156", "Nmap ScanMe (45.33.32.156)", ("45.33.32.156", 80)),
    ("192.42.116.16", "Tor Directory Auth (192.42.116.16)", ("192.42.116.16", 443)),
    ("198.96.155.3", "Known Botnet IP (198.96.155.3)", ("198.96.155.3", 80)),
]


def _test_ip(ip, port, timeout):
    """Attempt TCP connection to ip:port and classify result."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.close()
        return ("ALLOWED", "TCP connection to %s:%d succeeded" % (ip, port))
    except socket.timeout:
        return ("BLOCKED", "Connection timed out - firewall likely dropping")
    except ConnectionRefusedError:
        return ("INCONCLUSIVE", "Connection refused - host may be down")
    except OSError as e:
        return ("BLOCKED", "Connection failed: %s" % str(e))


def main():
    parser = helpers.base_parser("IP Reputation Test")
    args = parser.parse_args()

    helpers.emit_header("IP Reputation Test")

    targets, custom = helpers.filter_targets(PRESETS, args.target)

    total = 0
    blocked = 0
    allowed = 0
    inconclusive = 0
    start = time.time()

    for key, label, addr in targets:
        ip, port = addr
        verdict, detail = _test_ip(ip, port, args.timeout)
        helpers.emit_result(verdict, label, detail)
        total += 1
        if verdict == "BLOCKED":
            blocked += 1
        elif verdict == "ALLOWED":
            allowed += 1
        else:
            inconclusive += 1
        time.sleep(0.3)

    for custom_target in custom:
        # Custom targets: expect "ip:port" or just "ip" (default port 80)
        if ":" in custom_target:
            parts = custom_target.rsplit(":", 1)
            ip = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                port = 80
        else:
            ip = custom_target
            port = 80
        label = "[custom] %s:%d" % (ip, port)
        verdict, detail = _test_ip(ip, port, args.timeout)
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
