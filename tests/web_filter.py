#!/usr/bin/env python
"""
web_filter.py - Web/URL Filter test.
Tests access to known gambling, social media, and news sites.
Python 3.5.2 compatible.
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import helpers

PRESETS = [
    # Social Media
    ("https://www.instagram.com", "Instagram (Social)", "https://www.instagram.com"),
    ("https://www.tiktok.com", "TikTok (Social)", "https://www.tiktok.com"),
    ("https://www.twitter.com", "Twitter/X (Social)", "https://www.twitter.com"),
    ("https://www.snapchat.com", "Snapchat (Social)", "https://www.snapchat.com"),
    # Streaming
    ("https://www.netflix.com", "Netflix (Streaming)", "https://www.netflix.com"),
    ("https://www.twitch.tv", "Twitch (Streaming)", "https://www.twitch.tv"),
    ("https://www.youtube.com", "YouTube (Streaming)", "https://www.youtube.com"),
    # Gambling
    ("https://www.bet365.com", "bet365 (Gambling)", "https://www.bet365.com"),
    ("https://www.draftkings.com", "DraftKings (Gambling)", "https://www.draftkings.com"),
    ("https://www.fanduel.com", "FanDuel (Gambling)", "https://www.fanduel.com"),
    # Adult
    ("https://www.pornhub.com", "Pornhub (Adult)", "https://www.pornhub.com"),
    ("https://www.xvideos.com", "XVideos (Adult)", "https://www.xvideos.com"),
    # News
    ("https://www.cnn.com", "CNN (News)", "https://www.cnn.com"),
    ("https://www.bbc.co.uk", "BBC News (News)", "https://www.bbc.co.uk"),
    ("https://www.foxnews.com", "Fox News (News)", "https://www.foxnews.com"),
    # Shopping
    ("https://www.amazon.com", "Amazon (Shopping)", "https://www.amazon.com"),
    ("https://www.walmart.com", "Walmart (Shopping)", "https://www.walmart.com"),
    # Gaming
    ("https://store.steampowered.com", "Steam (Gaming)", "https://store.steampowered.com"),
    ("https://www.roblox.com", "Roblox (Gaming)", "https://www.roblox.com"),
    # General
    ("https://www.reddit.com", "Reddit (Forum)", "https://www.reddit.com"),
]


def main():
    parser = helpers.base_parser("Web/URL Filter Test")
    args = parser.parse_args()

    helpers.emit_header("Web/URL Filter Test")

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
        time.sleep(0.3)

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
        time.sleep(0.3)

    elapsed = time.time() - start
    helpers.emit_done(total, blocked, allowed, inconclusive, elapsed)


if __name__ == "__main__":
    main()
