"""
helpers.py - Shared utilities for VeloCloud ETM demo test scripts.
Python 3.5.2 compatible.
"""

import sys
import os
import json
import time
import socket
import ssl
import argparse


# -- Output Protocol ----------------------------------------------------------

def emit_header(text):
    sys.stdout.write("@@HEADER@@ %s\n" % str(text))
    sys.stdout.flush()

def emit_result(verdict, target, detail):
    sys.stdout.write("@@RESULT@@ %s|%s|%s\n" % (verdict, target, detail))
    sys.stdout.flush()

def emit_info(text):
    sys.stdout.write("@@INFO@@ %s\n" % str(text))
    sys.stdout.flush()

def emit_done(total, blocked, allowed, inconclusive, elapsed):
    summary = json.dumps({
        "total": total,
        "blocked": blocked,
        "allowed": allowed,
        "inconclusive": inconclusive,
        "elapsed": round(elapsed, 1)
    })
    sys.stdout.write("@@DONE@@ %s\n" % summary)
    sys.stdout.flush()


# -- Common argparse setup ----------------------------------------------------

def base_parser(description):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--no-verify', action='store_true',
                        help='Disable SSL certificate verification')
    parser.add_argument('--timeout', type=int, default=5,
                        help='Request timeout in seconds (default: 5)')
    parser.add_argument('--target', action='append', default=[],
                        help='Targets to test (can be repeated). If omitted, all presets run.')
    return parser


# -- SSL helpers ---------------------------------------------------------------

def make_ssl_context(no_verify=False):
    ctx = ssl.create_default_context()
    if no_verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx

def install_no_verify_opener():
    import urllib.request
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx)
    )
    urllib.request.install_opener(opener)


# -- Network helpers -----------------------------------------------------------

def resolve_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return "N/A"

def http_get(url, timeout=5, no_verify=False, headers=None):
    """
    Perform HTTP GET. Returns (status_code, response_body, error_type).
    status_code is int or None on error.
    response_body is first 4KB as string, or None.
    error_type is None on success, or exception class name.
    """
    import urllib.request
    import urllib.error

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    req = urllib.request.Request(url)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    else:
        req.add_header("User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36")

    ctx = make_ssl_context(no_verify)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(4096).decode("utf-8", errors="replace")
        return (resp.getcode(), body, None)
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(4096).decode("utf-8", errors="replace")
        except Exception:
            pass
        return (e.code, body, None)
    except Exception as e:
        return (None, None, type(e).__name__)


# -- Block page detection -----------------------------------------------------

VELOCLOUD_BLOCK_SIGNATURES = [
    "access denied",
    "this site is blocked",
    "web policy violation",
    "velocloud",
    "edge threat management",
    "security policy",
    "url filtering",
    "blocked by your organization",
    "content filtering",
    "blocked by policy",
]

def detect_block_page(response_body):
    if not response_body:
        return False
    body_lower = response_body.lower()
    matches = 0
    for sig in VELOCLOUD_BLOCK_SIGNATURES:
        if sig in body_lower:
            matches += 1
    return matches >= 2


def classify_web_response(status_code, response_body, error_type):
    """
    Classify a web request into BLOCKED, ALLOWED, or INCONCLUSIVE.
    Returns (verdict, detail_string).
    """
    if error_type is not None:
        err_lower = error_type.lower()
        if "connectionreset" in err_lower or "connectionrefused" in err_lower:
            return ("BLOCKED", "%s - connection terminated (likely firewall)" % error_type)
        if "timeout" in err_lower:
            return ("BLOCKED", "Request timed out - likely firewall drop")
        if "ssl" in err_lower:
            return ("INCONCLUSIVE", "%s - could be SSL inspection or site issue" % error_type)
        if "gaierror" in err_lower or "dns" in err_lower or "resolve" in err_lower:
            return ("BLOCKED", "DNS resolution failed - likely DNS-level block")
        return ("INCONCLUSIVE", "Request error: %s" % error_type)

    if response_body and detect_block_page(response_body):
        return ("BLOCKED",
                "HTTP %d but block page detected in response" % status_code)

    if status_code == 200:
        return ("ALLOWED", "HTTP 200 OK")

    if status_code in (301, 302, 303, 307, 308):
        return ("ALLOWED", "HTTP %d redirect - site reachable" % status_code)

    if status_code in (403, 503):
        return ("INCONCLUSIVE",
                "HTTP %d - site may be rejecting bot UA (not necessarily firewall)" % status_code)

    if status_code == 407:
        return ("BLOCKED", "HTTP 407 Proxy Authentication Required")

    if status_code == 451:
        return ("BLOCKED", "HTTP 451 Unavailable for Legal Reasons")

    if status_code is not None and 400 <= status_code < 500:
        return ("INCONCLUSIVE",
                "HTTP %d client error - likely site-side" % status_code)

    if status_code is not None and 500 <= status_code < 600:
        return ("INCONCLUSIVE",
                "HTTP %d server error - could be site issue or proxy" % status_code)

    return ("ALLOWED", "HTTP %s" % status_code)


# -- Target filtering helper --------------------------------------------------

def filter_targets(preset_targets, target_args):
    """
    Filter preset targets by --target CLI args.
    preset_targets: list of (key, ...) tuples or dict {key: ...}.
    target_args: list of keys from CLI. If empty, return all presets.

    For dicts: returns filtered dict.
    For list of tuples: returns filtered list where first element matches.
    Also returns any target_args that didn't match a preset (custom entries).
    """
    if not target_args:
        if isinstance(preset_targets, dict):
            return preset_targets, []
        return list(preset_targets), []

    target_set = set(target_args)
    custom = []

    if isinstance(preset_targets, dict):
        filtered = {}
        matched_keys = set()
        for key in preset_targets:
            if key in target_set:
                filtered[key] = preset_targets[key]
                matched_keys.add(key)
        custom = [t for t in target_args if t not in matched_keys]
        return filtered, custom

    filtered = []
    matched_keys = set()
    for entry in preset_targets:
        key = entry[0]
        if key in target_set:
            filtered.append(entry)
            matched_keys.add(key)
    custom = [t for t in target_args if t not in matched_keys]
    return filtered, custom
