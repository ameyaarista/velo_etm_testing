#!/usr/bin/env python
"""
dynamic_blocklist.py - Dynamic Blocklist test.
Fetches URLs from external threat feeds and tests each one.
Python 3.5.2 compatible.
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import helpers

PRESETS = [
    ("abuse-ch-urlhaus", "URLhaus Threat Feed (abuse.ch)", "https://urlhaus.abuse.ch/downloads/text_online/"),
    ("openphish", "OpenPhish Feed", "https://openphish.com/feed.txt"),
]


def _classify_blocklist_response(status, body, err):
    """Like classify_web_response but treats timeouts as INCONCLUSIVE
    since malware servers go offline frequently."""
    if err is not None:
        err_lower = err.lower()
        if "timeout" in err_lower:
            return ("INCONCLUSIVE", "Request timed out - host may be offline")
        if "connectionreset" in err_lower or "connectionrefused" in err_lower:
            return ("INCONCLUSIVE", "%s - host may be offline" % err)
    return helpers.classify_web_response(status, body, err)

MAX_URLS_PER_FEED = 10


def _parse_feed(body):
    """Parse a feed body into a list of URLs, skipping comments."""
    urls = []
    if not body:
        return urls
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("http://") or line.startswith("https://"):
            urls.append(line)
    return urls


def _test_feed(feed_label, feed_url, timeout, no_verify):
    """Fetch a feed and test its URLs. Returns list of (verdict, label, detail)."""
    results = []

    helpers.emit_info("Fetching feed from %s ..." % feed_url)
    status, body, err = helpers.http_get(feed_url, timeout=timeout,
                                         no_verify=no_verify)
    if status is None or err is not None:
        results.append(("INCONCLUSIVE", feed_label,
                        "Could not fetch feed: %s" % (err or "no response")))
        return results

    if status != 200:
        results.append(("INCONCLUSIVE", feed_label,
                        "Feed returned HTTP %d" % status))
        return results

    urls = _parse_feed(body)
    if not urls:
        results.append(("INCONCLUSIVE", feed_label, "No URLs found in feed"))
        return results

    helpers.emit_info("Found %d URLs in feed, testing first %d" % (
        len(urls), min(len(urls), MAX_URLS_PER_FEED)))

    for url in urls[:MAX_URLS_PER_FEED]:
        test_status, test_body, test_err = helpers.http_get(
            url, timeout=timeout, no_verify=no_verify)
        verdict, detail = _classify_blocklist_response(
            test_status, test_body, test_err)
        label = "%s: %s" % (feed_label, url)
        results.append((verdict, label, detail))
        time.sleep(0.3)

    return results


def main():
    parser = helpers.base_parser("Dynamic Blocklist Test")
    args = parser.parse_args()

    helpers.emit_header("Dynamic Blocklist Test")

    targets, custom = helpers.filter_targets(PRESETS, args.target)

    total = 0
    blocked = 0
    allowed = 0
    inconclusive = 0
    start = time.time()

    for key, label, feed_url in targets:
        results = _test_feed(label, feed_url, args.timeout, args.no_verify)
        for verdict, res_label, detail in results:
            helpers.emit_result(verdict, res_label, detail)
            total += 1
            if verdict == "BLOCKED":
                blocked += 1
            elif verdict == "ALLOWED":
                allowed += 1
            else:
                inconclusive += 1

    # Custom targets treated as feed URLs
    for custom_url in custom:
        label = "[custom] %s" % custom_url
        results = _test_feed(label, custom_url, args.timeout, args.no_verify)
        for verdict, res_label, detail in results:
            helpers.emit_result(verdict, res_label, detail)
            total += 1
            if verdict == "BLOCKED":
                blocked += 1
            elif verdict == "ALLOWED":
                allowed += 1
            else:
                inconclusive += 1

    elapsed = time.time() - start
    helpers.emit_done(total, blocked, allowed, inconclusive, elapsed)


if __name__ == "__main__":
    main()
