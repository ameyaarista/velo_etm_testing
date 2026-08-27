#!/usr/bin/env python
"""
url_reputation.py - URL Reputation test.
Tests access to known bad/malicious URLs.
Python 3.5.2 compatible.
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import helpers

PRESETS = [
    ("safebrowsing-malware", "Google Safe Browsing Malware Test", "http://testsafebrowsing.appspot.com/s/malware.html"),
    ("safebrowsing-phish", "Google Safe Browsing Phishing Test", "http://testsafebrowsing.appspot.com/s/phishing.html"),
    ("wicar-malware", "WICAR Malware Test File", "http://malware.wicar.org/data/eicar.com"),
    ("wicar-site", "WICAR Test Site", "http://www.wicar.org"),
    ("wicar-cryptominer", "WICAR Cryptominer Page", "http://malware.wicar.org/data/js_crypto_miner.html"),
    ("amtso-phishing", "AMTSO Phishing Test Page", "https://www.amtso.org/feature-settings-check-phishing-page/"),
    ("amtso-pua", "AMTSO PUA Test Page", "https://www.amtso.org/feature-settings-check-potentially-unwanted-applications/"),
    ("amtso-site", "AMTSO Security Org", "http://amtso.org"),
]


def main():
    parser = helpers.base_parser("URL Reputation Test")
    args = parser.parse_args()

    helpers.emit_header("URL Reputation Test")

    targets, custom = helpers.filter_targets(PRESETS, args.target)

    total = 0
    blocked = 0
    allowed = 0
    inconclusive = 0
    start = time.time()

    for key, label, url in targets:
        status, body, err = helpers.http_get(url, timeout=args.timeout,
                                             no_verify=args.no_verify)
        verdict, detail = helpers.classify_web_response(status, body, err)
        helpers.emit_result(verdict, label, detail)
        total += 1
        if verdict == "BLOCKED":
            blocked += 1
        elif verdict == "ALLOWED":
            allowed += 1
        else:
            inconclusive += 1
        time.sleep(0.5)

    for custom_url in custom:
        label = "[custom] %s" % custom_url
        status, body, err = helpers.http_get(custom_url, timeout=args.timeout,
                                             no_verify=args.no_verify)
        verdict, detail = helpers.classify_web_response(status, body, err)
        helpers.emit_result(verdict, label, detail)
        total += 1
        if verdict == "BLOCKED":
            blocked += 1
        elif verdict == "ALLOWED":
            allowed += 1
        else:
            inconclusive += 1
        time.sleep(0.5)

    elapsed = time.time() - start
    helpers.emit_done(total, blocked, allowed, inconclusive, elapsed)


if __name__ == "__main__":
    main()
