#!/usr/bin/env python
"""
geo_ip.py - GEO/IP Filter test.
Tests access to government websites from ~95 countries.
Python 3.5.2 compatible.
"""

import sys
import os
import time
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import helpers

try:
    from concurrent.futures import ThreadPoolExecutor, as_completed
except ImportError:
    ThreadPoolExecutor = None

PRESETS = [
    ("US", "United States (US)", "https://www.usa.gov"),
    ("DE", "Germany (DE)", "https://www.deutschland.de/en"),
    ("JP", "Japan (JP)", "https://www.japan.go.jp"),
    ("IN", "India (IN)", "https://www.india.gov.in"),
    ("GB", "United Kingdom (GB)", "https://www.gov.uk"),
    ("FR", "France (FR)", "https://www.france.fr/en"),
    ("IT", "Italy (IT)", "https://www.governo.it"),
    ("BR", "Brazil (BR)", "https://www.gov.br/en"),
    ("KR", "South Korea (KR)", "https://www.korea.net"),
    ("AU", "Australia (AU)", "https://www.australia.gov.au"),
    ("MX", "Mexico (MX)", "https://www.gob.mx"),
    ("ES", "Spain (ES)", "https://www.exteriores.gob.es"),
    ("ID", "Indonesia (ID)", "https://indonesia.go.id"),
    ("NL", "Netherlands (NL)", "https://www.netherlandsandyou.nl"),
    ("SA", "Saudi Arabia (SA)", "https://www.vision2030.gov.sa"),
    ("TR", "Turkey (TR)", "https://www.turkiye.gov.tr"),
    ("CH", "Switzerland (CH)", "https://www.swissinfo.ch"),
    ("TW", "Taiwan (TW)", "https://www.gov.tw"),
    ("PL", "Poland (PL)", "https://www.gov.pl"),
    ("AR", "Argentina (AR)", "https://www.argentina.gob.ar"),
    ("SE", "Sweden (SE)", "https://www.government.se"),
    ("BE", "Belgium (BE)", "https://www.belgium.be"),
    ("NO", "Norway (NO)", "https://www.norway.no"),
    ("IL", "Israel (IL)", "https://www.gov.il"),
    ("IE", "Ireland (IE)", "https://www.gov.ie"),
    ("NG", "Nigeria (NG)", "https://statehouse.gov.ng"),
    ("SG", "Singapore (SG)", "https://www.gov.sg"),
    ("ZA", "South Africa (ZA)", "https://www.gov.za"),
    ("MY", "Malaysia (MY)", "https://www.malaysia.gov.my"),
    ("DK", "Denmark (DK)", "https://www.denmark.dk"),
    ("PH", "Philippines (PH)", "https://www.tourism.gov.ph"),
    ("BD", "Bangladesh (BD)", "https://www.bangladesh.gov.bd"),
    ("EG", "Egypt (EG)", "https://www.presidency.eg/en"),
    ("VN", "Vietnam (VN)", "https://vietnam.vn"),
    ("TH", "Thailand (TH)", "https://www.mfa.go.th"),
    ("AT", "Austria (AT)", "https://www.oesterreich.gv.at"),
    ("CL", "Chile (CL)", "https://www.chile.gob.cl"),
    ("CZ", "Czech Republic (CZ)", "https://www.vlada.cz"),
    ("FI", "Finland (FI)", "https://finland.fi"),
    ("PT", "Portugal (PT)", "https://www.portugal.gov.pt"),
    ("NZ", "New Zealand (NZ)", "https://www.beehive.govt.nz"),
    ("GR", "Greece (GR)", "https://www.visitgreece.gr"),
    ("PE", "Peru (PE)", "https://www.gob.pe"),
    ("CO", "Colombia (CO)", "https://www.gov.co"),
    ("KZ", "Kazakhstan (KZ)", "https://www.gov.kz"),
    ("IQ", "Iraq (IQ)", "https://www.cabinet.iq"),
    ("DZ", "Algeria (DZ)", "https://www.premier-ministre.gov.dz"),
    ("QA", "Qatar (QA)", "https://www.hukoomi.gov.qa"),
    ("HU", "Hungary (HU)", "https://www.parlament.hu"),
    ("KW", "Kuwait (KW)", "https://www.kuwaitchamber.org.kw"),
    ("UA", "Ukraine (UA)", "https://www.kmu.gov.ua"),
    ("MA", "Morocco (MA)", "https://www.maroc.ma"),
    ("EC", "Ecuador (EC)", "https://www.gob.ec"),
    ("PR", "Puerto Rico (PR)", "https://www.estado.pr.gov"),
    ("ET", "Ethiopia (ET)", "https://www.pmo.gov.et"),
    ("GT", "Guatemala (GT)", "https://www.banguat.gob.gt"),
    ("BG", "Bulgaria (BG)", "https://www.government.bg"),
    ("DO", "Dominican Republic (DO)", "https://www.gob.do"),
    ("OM", "Oman (OM)", "https://www.oman.om"),
    ("TZ", "Tanzania (TZ)", "https://www.mof.go.tz"),
    ("LT", "Lithuania (LT)", "https://www.lrs.lt"),
    ("GH", "Ghana (GH)", "https://www.ghana.gov.gh"),
    ("PA", "Panama (PA)", "https://www.presidencia.gob.pa"),
    ("LK", "Sri Lanka (LK)", "https://www.gov.lk"),
    ("HR", "Croatia (HR)", "https://vlada.gov.hr"),
    ("BY", "Belarus (BY)", "https://www.mfa.gov.by/en"),
    ("UZ", "Uzbekistan (UZ)", "https://www.gov.uz"),
    ("CR", "Costa Rica (CR)", "https://www.visitcostarica.com"),
    ("BO", "Bolivia (BO)", "https://www.gob.bo"),
    ("UY", "Uruguay (UY)", "https://www.gub.uy"),
    ("CI", "Ivory Coast (CI)", "https://www.gouv.ci"),
    ("RS", "Serbia (RS)", "https://www.mfa.gov.rs"),
    ("AZ", "Azerbaijan (AZ)", "https://www.president.az"),
    ("TN", "Tunisia (TN)", "https://www.tap.info.tn"),
    ("SI", "Slovenia (SI)", "https://www.gov.si"),
    ("HN", "Honduras (HN)", "https://www.bch.hn"),
    ("BH", "Bahrain (BH)", "https://www.bahrain.bh"),
    ("LV", "Latvia (LV)", "https://www.mk.gov.lv"),
    ("CM", "Cameroon (CM)", "https://www.spm.gov.cm"),
    ("LY", "Libya (LY)", "https://www.hnec.ly"),
    ("PY", "Paraguay (PY)", "https://www.mre.gov.py"),
    ("JO", "Jordan (JO)", "https://jordan.gov.jo"),
    ("EE", "Estonia (EE)", "https://www.valitsus.ee"),
    ("SV", "El Salvador (SV)", "https://www.presidencia.gob.sv"),
    ("NP", "Nepal (NP)", "https://www.opmcm.gov.np"),
    ("IS", "Iceland (IS)", "https://www.government.is"),
    ("ZM", "Zambia (ZM)", "https://www.cabinet.gov.zm"),
    ("KH", "Cambodia (KH)", "https://www.pressocm.gov.kh"),
    ("CY", "Cyprus (CY)", "https://www.presidency.gov.cy"),
    ("PG", "Papua New Guinea (PG)", "https://www.papuanewguinea.travel"),
    ("MM", "Myanmar (MM)", "https://www.moi.gov.mm"),
    ("CN", "China (CN)", "https://english.www.gov.cn"),
    ("IR", "Iran (IR)", "https://www.president.ir/en"),
    ("CU", "Cuba (CU)", "https://www.presidencia.gob.cu"),
    ("SY", "Syria (SY)", "https://www.sana.sy/en"),
    ("KP", "North Korea (KP)", "http://www.korean-books.com.kp"),
]


def _test_target(key, label, url, timeout, no_verify):
    """Test a single target and return (key, label, verdict, detail)."""
    status, body, err = helpers.http_get(url, timeout=timeout,
                                         no_verify=no_verify)
    verdict, detail = helpers.classify_web_response(status, body, err)
    return (key, label, verdict, detail)


def main():
    parser = helpers.base_parser("GEO/IP Filter Test")
    args = parser.parse_args()

    helpers.emit_header("GEO/IP Filter Test")

    targets, custom = helpers.filter_targets(PRESETS, args.target)

    total = 0
    blocked = 0
    allowed = 0
    inconclusive = 0
    start = time.time()

    if ThreadPoolExecutor is not None and len(targets) > 1:
        # Run tests in parallel, emit results in order
        results = [None] * len(targets)
        with ThreadPoolExecutor(max_workers=15) as executor:
            future_to_idx = {}
            for idx, entry in enumerate(targets):
                key, label, url = entry
                fut = executor.submit(_test_target, key, label, url,
                                      args.timeout, args.no_verify)
                future_to_idx[fut] = idx

            for fut in as_completed(future_to_idx):
                idx = future_to_idx[fut]
                results[idx] = fut.result()

        for key, label, verdict, detail in results:
            helpers.emit_result(verdict, label, detail)
            total += 1
            if verdict == "BLOCKED":
                blocked += 1
            elif verdict == "ALLOWED":
                allowed += 1
            else:
                inconclusive += 1
    else:
        # Sequential fallback
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

    # Custom targets (sequential)
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

    elapsed = time.time() - start

    # Egress IP info
    try:
        ip_status, ip_body, ip_err = helpers.http_get(
            "https://ipinfo.io/json", timeout=args.timeout,
            no_verify=args.no_verify)
        if ip_status == 200 and ip_body:
            info = json.loads(ip_body)
            helpers.emit_info("Egress IP: %s" % info.get("ip", "unknown"))
            helpers.emit_info("City: %s" % info.get("city", "unknown"))
            helpers.emit_info("Country: %s" % info.get("country", "unknown"))
            helpers.emit_info("Org: %s" % info.get("org", "unknown"))
    except Exception:
        helpers.emit_info("Could not retrieve egress IP info")

    helpers.emit_done(total, blocked, allowed, inconclusive, elapsed)


if __name__ == "__main__":
    main()
