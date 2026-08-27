"""
server.py - Flask server for the VeloCloud ETM Demo tool.
Serves the web UI and launches test scripts via SSE.
Python 3.5.2 compatible (no f-strings).
"""

import os
import re
import sys
import subprocess
from flask import Flask, send_from_directory, jsonify, request, Response
from flask_cors import CORS

app = Flask(__name__, static_folder='.')
CORS(app)

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Script registry — 8 test modules with preset targets
# ---------------------------------------------------------------------------

SCRIPTS = [
    # 0 - Web/URL Filter
    {
        "id": 0,
        "file": "web_filter.py",
        "name": "Web/URL Filter",
        "targets": [
            {"key": "https://www.instagram.com",       "label": "Instagram (Social)"},
            {"key": "https://www.tiktok.com",          "label": "TikTok (Social)"},
            {"key": "https://www.twitter.com",         "label": "Twitter/X (Social)"},
            {"key": "https://www.snapchat.com",        "label": "Snapchat (Social)"},
            {"key": "https://www.netflix.com",         "label": "Netflix (Streaming)"},
            {"key": "https://www.twitch.tv",           "label": "Twitch (Streaming)"},
            {"key": "https://www.youtube.com",         "label": "YouTube (Streaming)"},
            {"key": "https://www.bet365.com",          "label": "bet365 (Gambling)"},
            {"key": "https://www.draftkings.com",      "label": "DraftKings (Gambling)"},
            {"key": "https://www.fanduel.com",         "label": "FanDuel (Gambling)"},
            {"key": "https://www.pornhub.com",         "label": "Pornhub (Adult)", "defaultOff": True},
            {"key": "https://www.xvideos.com",         "label": "XVideos (Adult)", "defaultOff": True},
            {"key": "https://www.cnn.com",             "label": "CNN (News)"},
            {"key": "https://www.bbc.co.uk",           "label": "BBC News (News)"},
            {"key": "https://www.foxnews.com",         "label": "Fox News (News)"},
            {"key": "https://www.amazon.com",          "label": "Amazon (Shopping)"},
            {"key": "https://www.walmart.com",         "label": "Walmart (Shopping)"},
            {"key": "https://store.steampowered.com",  "label": "Steam (Gaming)"},
            {"key": "https://www.roblox.com",          "label": "Roblox (Gaming)"},
            {"key": "https://www.reddit.com",          "label": "Reddit (Forum)"},
        ],
    },
    # 1 - IDPS
    {
        "id": 1,
        "file": "idps.py",
        "name": "IDPS",
        "targets": [
            {"key": "sunburst-http",   "label": "SUNBURST Malware HTTP"},
            {"key": "sunburst-dns",    "label": "SUNBURST Malware DNS"},
            {"key": "cobalt-c2",       "label": "CobaltStrike C2"},
            {"key": "log4j",           "label": "Log4j Exploit"},
            {"key": "xanthe-miner",    "label": "Xanthe Crypto Miner"},
            {"key": "erbium",          "label": "Erbium Stealer"},
            {"key": "lilith",          "label": "Lilith Stealer"},
            {"key": "trickbot",        "label": "Trickbot C2"},
            {"key": "sap-netweaver",   "label": "SAP NetWeaver Exploit"},
            {"key": "apache-struts",   "label": "Apache Struts OGNL"},
            {"key": "template-inject", "label": "Template Injection"},
            {"key": "phishing-dns",    "label": "Phishing Domain DNS"},
            {"key": "malware-dns",     "label": "Malware Delivery DNS"},
            {"key": "malware-exfil",   "label": "Data Exfiltration DNS"},
            {"key": "spyware-fh",      "label": "Spyware FH Variant"},
        ],
    },
    # 2 - URL Reputation
    {
        "id": 2,
        "file": "url_reputation.py",
        "name": "URL Reputation",
        "targets": [
            {"key": "safebrowsing-malware", "label": "Google Safe Browsing Malware Test"},
            {"key": "safebrowsing-phish",   "label": "Google Safe Browsing Phishing Test"},
            {"key": "wicar-malware",        "label": "WICAR Malware Test File"},
            {"key": "wicar-site",           "label": "WICAR Test Site"},
            {"key": "wicar-cryptominer",    "label": "WICAR Cryptominer Page"},
            {"key": "amtso-phishing",       "label": "AMTSO Phishing Test Page"},
            {"key": "amtso-pua",            "label": "AMTSO PUA Test Page"},
            {"key": "amtso-site",           "label": "AMTSO Security Org"},
        ],
    },
    # 3 - IP Reputation
    {
        "id": 3,
        "file": "ip_reputation.py",
        "name": "IP Reputation",
        "targets": [
            {"key": "207.189.189.230", "label": "Known Spyware C2 IP"},
            {"key": "185.220.101.1",   "label": "Tor Exit Node"},
            {"key": "45.33.32.156",    "label": "ScanMe (Nmap Test)"},
            {"key": "192.42.116.16",   "label": "Tor Directory Authority"},
            {"key": "198.96.155.3",    "label": "Known Botnet IP"},
        ],
    },
    # 4 - GEO/IP Filter
    {
        "id": 4,
        "file": "geo_ip.py",
        "name": "GEO/IP Filter",
        "targets": [
            {"key": "US", "label": "United States (US)"},
            {"key": "DE", "label": "Germany (DE)"},
            {"key": "JP", "label": "Japan (JP)"},
            {"key": "IN", "label": "India (IN)"},
            {"key": "GB", "label": "United Kingdom (GB)"},
            {"key": "FR", "label": "France (FR)"},
            {"key": "IT", "label": "Italy (IT)"},
            {"key": "BR", "label": "Brazil (BR)"},
            {"key": "KR", "label": "South Korea (KR)"},
            {"key": "AU", "label": "Australia (AU)"},
            {"key": "MX", "label": "Mexico (MX)"},
            {"key": "ES", "label": "Spain (ES)"},
            {"key": "ID", "label": "Indonesia (ID)"},
            {"key": "NL", "label": "Netherlands (NL)"},
            {"key": "SA", "label": "Saudi Arabia (SA)"},
            {"key": "TR", "label": "Turkey (TR)"},
            {"key": "CH", "label": "Switzerland (CH)"},
            {"key": "TW", "label": "Taiwan (TW)"},
            {"key": "PL", "label": "Poland (PL)"},
            {"key": "AR", "label": "Argentina (AR)"},
            {"key": "SE", "label": "Sweden (SE)"},
            {"key": "BE", "label": "Belgium (BE)"},
            {"key": "NO", "label": "Norway (NO)"},
            {"key": "IL", "label": "Israel (IL)"},
            {"key": "IE", "label": "Ireland (IE)"},
            {"key": "NG", "label": "Nigeria (NG)"},
            {"key": "SG", "label": "Singapore (SG)"},
            {"key": "ZA", "label": "South Africa (ZA)"},
            {"key": "MY", "label": "Malaysia (MY)"},
            {"key": "DK", "label": "Denmark (DK)"},
            {"key": "PH", "label": "Philippines (PH)"},
            {"key": "BD", "label": "Bangladesh (BD)"},
            {"key": "EG", "label": "Egypt (EG)"},
            {"key": "VN", "label": "Vietnam (VN)"},
            {"key": "TH", "label": "Thailand (TH)"},
            {"key": "AT", "label": "Austria (AT)"},
            {"key": "CL", "label": "Chile (CL)"},
            {"key": "CZ", "label": "Czech Republic (CZ)"},
            {"key": "FI", "label": "Finland (FI)"},
            {"key": "PT", "label": "Portugal (PT)"},
            {"key": "NZ", "label": "New Zealand (NZ)"},
            {"key": "GR", "label": "Greece (GR)"},
            {"key": "PE", "label": "Peru (PE)"},
            {"key": "CO", "label": "Colombia (CO)"},
            {"key": "KZ", "label": "Kazakhstan (KZ)"},
            {"key": "IQ", "label": "Iraq (IQ)"},
            {"key": "DZ", "label": "Algeria (DZ)"},
            {"key": "QA", "label": "Qatar (QA)"},
            {"key": "HU", "label": "Hungary (HU)"},
            {"key": "KW", "label": "Kuwait (KW)"},
            {"key": "UA", "label": "Ukraine (UA)"},
            {"key": "MA", "label": "Morocco (MA)"},
            {"key": "EC", "label": "Ecuador (EC)"},
            {"key": "PR", "label": "Puerto Rico (PR)"},
            {"key": "ET", "label": "Ethiopia (ET)"},
            {"key": "GT", "label": "Guatemala (GT)"},
            {"key": "BG", "label": "Bulgaria (BG)"},
            {"key": "DO", "label": "Dominican Republic (DO)"},
            {"key": "OM", "label": "Oman (OM)"},
            {"key": "TZ", "label": "Tanzania (TZ)"},
            {"key": "LT", "label": "Lithuania (LT)"},
            {"key": "GH", "label": "Ghana (GH)"},
            {"key": "PA", "label": "Panama (PA)"},
            {"key": "LK", "label": "Sri Lanka (LK)"},
            {"key": "HR", "label": "Croatia (HR)"},
            {"key": "BY", "label": "Belarus (BY)"},
            {"key": "UZ", "label": "Uzbekistan (UZ)"},
            {"key": "CR", "label": "Costa Rica (CR)"},
            {"key": "BO", "label": "Bolivia (BO)"},
            {"key": "UY", "label": "Uruguay (UY)"},
            {"key": "CI", "label": "Ivory Coast (CI)"},
            {"key": "RS", "label": "Serbia (RS)"},
            {"key": "AZ", "label": "Azerbaijan (AZ)"},
            {"key": "TN", "label": "Tunisia (TN)"},
            {"key": "SI", "label": "Slovenia (SI)"},
            {"key": "HN", "label": "Honduras (HN)"},
            {"key": "BH", "label": "Bahrain (BH)"},
            {"key": "LV", "label": "Latvia (LV)"},
            {"key": "CM", "label": "Cameroon (CM)"},
            {"key": "LY", "label": "Libya (LY)"},
            {"key": "PY", "label": "Paraguay (PY)"},
            {"key": "JO", "label": "Jordan (JO)"},
            {"key": "EE", "label": "Estonia (EE)"},
            {"key": "SV", "label": "El Salvador (SV)"},
            {"key": "NP", "label": "Nepal (NP)"},
            {"key": "IS", "label": "Iceland (IS)"},
            {"key": "ZM", "label": "Zambia (ZM)"},
            {"key": "KH", "label": "Cambodia (KH)"},
            {"key": "CY", "label": "Cyprus (CY)"},
            {"key": "PG", "label": "Papua New Guinea (PG)"},
            {"key": "MM", "label": "Myanmar (MM)"},
        ],
    },
    # 5 - DNS Filter
    {
        "id": 5,
        "file": "dns_filter.py",
        "name": "DNS Filter",
        "targets": [
            {"key": "avsvmcloud.com",             "label": "SUNBURST C2 Domain"},
            {"key": "websitetheme.com",            "label": "Known Malicious Domain"},
            {"key": "malwaredomainlist.com",         "label": "Malware Domain List"},
            {"key": "urlhaus.abuse.ch",            "label": "URLhaus Threat Feed"},
            {"key": "phishtank.org",               "label": "PhishTank Phishing DB"},
            {"key": "openphish.com",               "label": "OpenPhish Feed"},
            {"key": "feodotracker.abuse.ch",       "label": "Feodo Tracker (Banking Trojan)"},
            {"key": "sslbl.abuse.ch",              "label": "SSL Blacklist (abuse.ch)"},
        ],
    },
    # 6 - App Filter
    {
        "id": 6,
        "file": "app_filter.py",
        "name": "App Filter",
        "targets": [
            {"key": "http-example",      "label": "HTTP example.com"},
            {"key": "http-httpbin",      "label": "HTTP httpbin.org"},
            {"key": "https-google",      "label": "HTTPS google.com"},
            {"key": "https-cloudflare",  "label": "HTTPS cloudflare.com"},
            {"key": "https-httpbin",     "label": "HTTPS httpbin.org"},
            {"key": "dns-google-a",      "label": "DNS A record via 8.8.8.8"},
            {"key": "dns-amazon-a",      "label": "DNS A record via 1.1.1.1"},
            {"key": "dns-facebook-aaaa", "label": "DNS AAAA record via 8.8.8.8"},
            {"key": "smtp-gmail",        "label": "SMTP Gmail STARTTLS"},
            {"key": "smtp-o365",         "label": "SMTP Office365 STARTTLS"},
            {"key": "smtp-yahoo",        "label": "SMTP Yahoo SSL"},
            {"key": "imap-gmail",        "label": "IMAP Gmail SSL"},
            {"key": "imap-yahoo",        "label": "IMAP Yahoo SSL"},
            {"key": "stream-youtube",    "label": "YouTube"},
            {"key": "stream-netflix",    "label": "Netflix"},
            {"key": "stream-twitch",     "label": "Twitch"},
            {"key": "stream-spotify",    "label": "Spotify"},
        ],
    },
    # 7 - Dynamic Blocklist
    {
        "id": 7,
        "file": "dynamic_blocklist.py",
        "name": "Dynamic Blocklist",
        "targets": [
            {"key": "abuse-ch-urlhaus",  "label": "URLhaus Threat Feed (abuse.ch)"},
            {"key": "openphish",         "label": "OpenPhish Feed"},
        ],
    },
]

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')


def strip_ansi(text):
    """Remove ANSI escape codes from a string."""
    return _ANSI_RE.sub('', text)


_SHELL_META = set([';', '&', '|', '`', '$', '\n', '\r'])


def _validate_targets(targets):
    """Return an error string if any target contains shell metacharacters,
    or None if all targets are clean."""
    for t in targets:
        for ch in _SHELL_META:
            if ch in t:
                return "Invalid target value: contains forbidden character %r" % ch
    return None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    return send_from_directory(PROJECT_ROOT, 'etmdemo.html')


@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory(PROJECT_ROOT, filename)


@app.route('/targets/<int:idx>')
def get_targets(idx):
    if idx < 0 or idx >= len(SCRIPTS):
        return jsonify({"error": "Invalid module index: %d" % idx}), 404
    return jsonify(SCRIPTS[idx]["targets"])


@app.route('/run/<int:idx>')
def run_script(idx):
    if idx < 0 or idx >= len(SCRIPTS):
        return "Unknown script", 404

    script_info = SCRIPTS[idx]
    script_path = os.path.join(PROJECT_ROOT, "tests", script_info["file"])

    # Build command
    cmd = [sys.executable, '-u', script_path, '--no-verify']

    # Parse selected targets from query string
    targets = request.args.getlist('targets')

    # Input sanitization
    error = _validate_targets(targets)
    if error is not None:
        return error, 400

    for t in targets:
        cmd.append('--target')
        cmd.append(t)

    def generate():
        env = os.environ.copy()
        env['PYTHONPATH'] = PROJECT_ROOT

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                cwd=PROJECT_ROOT,
            )

            for raw_line in iter(proc.stdout.readline, b''):
                line = raw_line.decode('utf-8', errors='replace').rstrip('\n').rstrip('\r')
                line = strip_ansi(line)
                if line:
                    yield "data: %s\n\n" % line

            proc.wait()
            yield "data: __DONE__\n\n"

        except Exception as exc:
            yield "data: @@INFO@@ Error: %s\n\n" % str(exc)
            yield "data: __DONE__\n\n"

    return Response(generate(), mimetype='text/event-stream')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, threaded=True)
