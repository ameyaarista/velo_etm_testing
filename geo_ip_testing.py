#!/usr/bin/env python3
"""
GeoIP Firewall Test - Government Websites for Top 100 Countries by GDP
Tests HTTP accessibility and reports OK (green) or BLOCK (red).
"""

import urllib.request
import urllib.error
import ssl
import concurrent.futures
import time
from datetime import datetime

# Top 100 countries by GDP (nominal, IMF) with official government websites
GOVERNMENT_SITES = [
    ("United States",       "US", "https://www.usa.gov"),
    ("Germany",             "DE", "https://www.bundesregierung.de"),
    ("Japan",               "JP", "https://www.japan.go.jp"),
    ("India",               "IN", "https://www.india.gov.in"),
    ("United Kingdom",      "GB", "https://www.gov.uk"),
    ("France",              "FR", "https://www.gouvernement.fr"),
    ("Italy",               "IT", "https://www.governo.it"),
    ("Brazil",              "BR", "https://www.gov.br"),
    ("Russia",              "RU", "https://mid.ru/en"),
    ("South Korea",         "KR", "https://www.korea.net/main"),         # fixed: korea.go.kr → korea.net
    ("Australia",           "AU", "https://www.australia.gov.au"),
    ("Mexico",              "MX", "https://www.gob.mx"),
    ("Spain",               "ES", "https://www.exteriores.gob.es"),
    ("Indonesia",           "ID", "https://indonesia.go.id"),            # fixed: removed www. prefix
    ("Netherlands",         "NL", "https://www.government.nl"),
    ("Saudi Arabia",        "SA", "https://www.my.gov.sa"),
    ("Turkey",              "TR", "https://www.turkiye.gov.tr"),
    ("Switzerland",         "CH", "https://www.admin.ch"),
    ("Taiwan",              "TW", "https://www.gov.tw"),
    ("Poland",              "PL", "https://www.gov.pl"),
    ("Argentina",           "AR", "https://www.argentina.gob.ar"),
    ("Sweden",              "SE", "https://www.government.se"),
    ("Belgium",             "BE", "https://www.belgium.be"),
    ("Norway",              "NO", "https://www.regjeringen.no"),
    ("Israel",              "IL", "https://www.gov.il"),
    ("Ireland",             "IE", "https://www.gov.ie"),
    ("Nigeria",             "NG", "https://services.gov.ng"),            # fixed: nigeria.gov.ng → services.gov.ng
    ("Singapore",           "SG", "https://www.gov.sg"),
    ("South Africa",        "ZA", "https://www.gov.za"),
    ("Malaysia",            "MY", "https://www.malaysia.gov.my"),
    ("Denmark",             "DK", "https://www.denmark.dk"),
    ("Philippines",         "PH", "https://www.gov.ph"),
    ("Bangladesh",          "BD", "https://www.bangladesh.gov.bd"),
    ("Egypt",               "EG", "https://www.presidency.eg/en"),       # fixed: egypt.gov.eg → presidency.eg
    ("Vietnam",             "VN", "https://en.baochinhphu.vn"),          # fixed: chinhphu.vn → en.baochinhphu.vn
    ("Thailand",            "TH", "https://www.thaigov.go.th"),
    ("Austria",             "AT", "https://www.oesterreich.gv.at"),
    ("Chile",               "CL", "https://www.gob.cl"),
    ("Czech Republic",      "CZ", "https://www.vlada.cz"),
    ("Finland",             "FI", "https://www.government.fi"),
    ("Portugal",            "PT", "https://www.portugal.gov.pt"),
    ("New Zealand",         "NZ", "https://www.govt.nz"),
    ("Greece",              "GR", "https://www.primeminister.gr"),
    ("Peru",                "PE", "https://www.gob.pe"),
    ("Colombia",            "CO", "https://www.gov.co"),
    ("Kazakhstan",          "KZ", "https://www.gov.kz"),
    ("Iraq",                "IQ", "https://www.cabinet.iq"),
    ("Algeria",             "DZ", "https://www.premier-ministre.gov.dz"),
    ("Qatar",               "QA", "https://www.hukoomi.gov.qa"),
    ("Hungary",             "HU", "https://www.kormany.hu"),
    ("Kuwait",              "KW", "https://www.e.gov.kw"),
    ("Ukraine",             "UA", "https://www.kmu.gov.ua"),
    ("Morocco",             "MA", "https://www.maroc.ma"),
    ("Ecuador",             "EC", "https://www.gob.ec"),
    ("Puerto Rico",         "PR", "https://www.estado.pr.gov"),
    ("Ethiopia",            "ET", "https://www.pmo.gov.et"),             # fixed: ethiopia.gov.et → pmo.gov.et
    ("Guatemala",           "GT", "https://www.guatemala.gob.gt"),
    ("Bulgaria",            "BG", "https://www.government.bg"),
    ("Dominican Republic",  "DO", "https://www.gob.do"),
    ("Oman",                "OM", "https://www.oman.om"),
    ("Tanzania",            "TZ", "https://www.mof.go.tz"),             # fixed: utumishi.go.tz → mof.go.tz
    ("Lithuania",           "LT", "https://www.lrv.lt"),
    ("Ghana",               "GH", "https://www.ghana.gov.gh"),
    ("Panama",              "PA", "https://www.presidencia.gob.pa"),
    ("Sri Lanka",           "LK", "https://www.gov.lk"),
    ("Croatia",             "HR", "https://vlada.gov.hr"),
    ("Belarus",             "BY", "https://president.gov.by/en"),        # fixed: gov.by → president.gov.by
    ("Uzbekistan",          "UZ", "https://www.gov.uz"),
    ("Costa Rica",          "CR", "https://www.presidencia.go.cr"),
    ("Bolivia",             "BO", "https://www.gob.bo"),
    ("Uruguay",             "UY", "https://www.gub.uy"),
    ("Ivory Coast",         "CI", "https://www.gouv.ci"),                # fixed: gouvernement.ci → gouv.ci
    ("Serbia",              "RS", "https://www.srbija.gov.rs"),
    ("Azerbaijan",          "AZ", "https://www.president.az"),
    ("Tunisia",             "TN", "https://www.tap.info.tn"),
    ("Slovenia",            "SI", "https://www.gov.si"),
    ("Honduras",            "HN", "https://www.presidencia.gob.hn"),
    ("Bahrain",             "BH", "https://www.bahrain.bh"),
    ("Latvia",              "LV", "https://www.mk.gov.lv"),
    ("Cameroon",            "CM", "https://www.spm.gov.cm"),
    ("Libya",               "LY", "https://www.pm.gov.ly"),
    ("Paraguay",            "PY", "https://www.presidencia.gov.py"),
    ("Jordan",              "JO", "https://jordan.gov.jo"),              # fixed: pm.gov.jo → jordan.gov.jo
    ("Estonia",             "EE", "https://www.valitsus.ee"),
    ("El Salvador",         "SV", "https://www.presidencia.gob.sv"),
    ("Nepal",               "NP", "https://www.opmcm.gov.np"),
    ("Iceland",             "IS", "https://www.government.is"),
    ("Zambia",              "ZM", "https://www.cabinet.gov.zm"),         # fixed: statehouse.gov.zm → cabinet.gov.zm
    ("Cambodia",            "KH", "https://www.pressocm.gov.kh"),
    ("Cyprus",              "CY", "https://www.presidency.gov.cy"),
    ("Papua New Guinea",    "PG", "https://www.pm.gov.pg"),
    ("Myanmar",             "MM", "https://www.myanmar.gov.mm/en"),      # fixed: president-office.gov.mm → myanmar.gov.mm
]

# ANSI color codes
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
DIM    = "\033[2m"

TIMEOUT = 10  # seconds per request
MAX_WORKERS = 20  # parallel threads

def check_site(entry):
    country, code, url = entry
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (GeoIP-Firewall-Tester/1.0)"}
    )
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
            status = resp.status
            elapsed = time.time() - start
            if status == 200:
                return (country, code, url, "OK", status, elapsed)
            else:
                return (country, code, url, "REDIRECT", status, elapsed)
    except urllib.error.HTTPError as e:
        elapsed = time.time() - start
        return (country, code, url, "HTTP_ERR", e.code, elapsed)
    except Exception as e:
        elapsed = time.time() - start
        short = str(e)[:40]
        return (country, code, url, "BLOCK", short, elapsed)

def status_label(status_type, code):
    if status_type == "OK":
        return f"{GREEN}{BOLD} OK ✔  {RESET}"
    elif status_type in ("HTTP_ERR", "REDIRECT"):
        return f"{YELLOW}{BOLD} {code:<5}{RESET}"
    else:
        return f"{RED}{BOLD} BLOCK ✘{RESET}"

def main():
    print(f"\n{BOLD}{CYAN}{'═'*72}{RESET}")
    print(f"{BOLD}{CYAN}  GeoIP Firewall Test — Government Websites {RESET}")
    print(f"{BOLD}{CYAN}  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  Timeout: {TIMEOUT}s  |  Threads: {MAX_WORKERS}{RESET}")
    print(f"{BOLD}{CYAN}{'═'*72}{RESET}\n")

    col_country = 24
    col_code    = 5
    col_status  = 12
    col_http    = 6
    col_time    = 8
    col_url     = 44

    header = (
        f"  {'#':>3}  "
        f"{'Country':<{col_country}}  "
        f"{'CC':<{col_code}}"
        f"{'Status':<{col_status}}"
        f"{'HTTP':>{col_http}}  "
        f"{'Time(s)':>{col_time}}  "
        f"{'URL':<{col_url}}"
    )
    print(f"{BOLD}{DIM}{header}{RESET}")
    print(f"{DIM}{'─'*104}{RESET}")

    results = []
    ok_count = block_count = other_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_site, entry): i for i, entry in enumerate(GOVERNMENT_SITES)}
        completed = {}
        for future in concurrent.futures.as_completed(futures):
            idx = futures[future]
            completed[idx] = future.result()

    for i, entry in enumerate(GOVERNMENT_SITES):
        result = completed[i]
        country, code, url, status_type, code_or_err, elapsed = result
        results.append(result)

        label = status_label(status_type, code_or_err)

        if status_type == "OK":
            ok_count += 1
            http_str = f"{GREEN}{code_or_err}{RESET}"
        elif status_type in ("HTTP_ERR", "REDIRECT"):
            other_count += 1
            http_str = f"{YELLOW}{code_or_err}{RESET}"
        else:
            block_count += 1
            http_str = f"{RED}---{RESET}"

        time_str = f"{elapsed:.2f}s"
        url_display = url[:col_url]

        print(
            f"  {i+1:>3}  "
            f"{country:<{col_country}}  "
            f"{code:<{col_code}}"
            f"{label:<{col_status}}"
            f"  {http_str:>10}  "
            f"{DIM}{time_str:>{col_time}}{RESET}  "
            f"{DIM}{url_display}{RESET}"
        )

    # Summary
    total = len(results)
    print(f"\n{BOLD}{CYAN}{'═'*72}{RESET}")
    print(f"{BOLD}  SUMMARY{RESET}")
    print(f"{'─'*40}")
    print(f"  Total tested : {total}")
    print(f"  {GREEN}{BOLD}OK (200)     : {ok_count}{RESET}")
    print(f"  {YELLOW}{BOLD}Other HTTP   : {other_count}{RESET}  (redirects, 4xx, 5xx — reachable)")
    print(f"  {RED}{BOLD}BLOCKED      : {block_count}{RESET}  (timeout / connection refused / DNS fail)")
    print(f"{BOLD}{CYAN}{'═'*72}{RESET}\n")

    # Blocked list
    blocked = [r for r in results if r[3] == "BLOCK"]
    if blocked:
        print(f"{RED}{BOLD}  Blocked sites:{RESET}")
        for r in blocked:
            print(f"    {RED}✘{RESET}  {r[0]:<24} ({r[1]})  {DIM}{r[2]}{RESET}")
        print()


def check_my_ip():
    """Fetch public IP and POP/geo details via ipinfo.io"""
    print(f"\n{BOLD}{CYAN}{'═' * 72}{RESET}")
    print(f"{BOLD}{CYAN}  YOUR EGRESS IP & POP INFORMATION{RESET}")
    print(f"{BOLD}{CYAN}{'═' * 72}{RESET}")

    try:
        req = urllib.request.Request(
            "https://ipinfo.io/json",
            headers={"User-Agent": "Mozilla/5.0 (GeoIP-Firewall-Tester/1.0)",
                     "Accept": "application/json"}
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            import json
            data = json.loads(resp.read().decode())

        fields = [
            ("IP Address", data.get("ip", "N/A")),
            ("Hostname", data.get("hostname", "N/A")),
            ("City", data.get("city", "N/A")),
            ("Region", data.get("region", "N/A")),
            ("Country", data.get("country", "N/A")),
            ("Location", data.get("loc", "N/A")),
            ("Organisation", data.get("org", "N/A")),
            ("Postal", data.get("postal", "N/A")),
            ("Timezone", data.get("timezone", "N/A")),
        ]

        print()
        for label, value in fields:
            # Highlight IP in green, rest in normal
            if label == "IP Address":
                print(f"  {BOLD}{label:<14}{RESET}  {GREEN}{BOLD}{value}{RESET}")
            elif label == "Organisation":
                print(f"  {BOLD}{label:<14}{RESET}  {CYAN}{value}{RESET}")
            else:
                print(f"  {BOLD}{label:<14}{RESET}  {value}")
        print()

        # Derive POP hint from org/ASN
        org = data.get("org", "")
        city = data.get("city", "N/A")
        country = data.get("country", "N/A")
        print(f"  {BOLD}POP Estimate :{RESET}  Traffic exits via {CYAN}{city}, {country}{RESET}  [{DIM}{org}{RESET}]")
        print(f"  {DIM}(POP = the firewall/proxy egress node seen by remote servers){RESET}")

    except Exception as e:
        print(f"  {RED}Could not retrieve IP info: {e}{RESET}")

    print(f"\n{BOLD}{CYAN}{'═' * 72}{RESET}\n")

if __name__ == "__main__":
    main()
    check_my_ip()
