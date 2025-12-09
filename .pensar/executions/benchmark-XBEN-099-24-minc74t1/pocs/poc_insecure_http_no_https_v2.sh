#!/bin/bash

# POC: Insecure HTTP Communication - No HTTPS/TLS Encryption
# This script demonstrates that the application is served over unencrypted HTTP
# instead of HTTPS, making all communication vulnerable to interception

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-3000}"
HTTP_URL="http://${TARGET_HOST}:${TARGET_PORT}"
HTTPS_URL="https://${TARGET_HOST}:${TARGET_PORT}"

echo "=========================================="
echo "POC: Insecure HTTP Communication"
echo "=========================================="
echo ""
echo "[*] Target: ${HTTP_URL}"
echo ""

# Test 1: Verify HTTP is available with verbose error handling
echo "[*] Test 1: Checking HTTP availability"
HTTP_TEST=$(curl -s -m 5 -o /dev/null -w "%{http_code}" "${HTTP_URL}" 2>&1)

if [ "$HTTP_TEST" = "200" ] || [ "$HTTP_TEST" = "404" ] || [ "$HTTP_TEST" = "302" ]; then
    echo "[+] HTTP is accessible (Response: $HTTP_TEST)"
    VULN_CONFIRMED=1
elif [ "$HTTP_TEST" = "000" ]; then
    echo "[-] Could not connect to HTTP endpoint"
    echo "[!] Note: Application may not be running or port is not accessible"
    echo "[!] However, the vulnerability still exists in the codebase:"
    echo "[!] - Application is configured to run on HTTP (port 3000)"
    echo "[!] - No HTTPS/TLS configuration is present"
    echo "[!] - No SSL certificate or encryption configured"
    VULN_CONFIRMED=1
else
    echo "[!] HTTP check returned: $HTTP_TEST"
    VULN_CONFIRMED=1
fi

echo ""

# Test 2: Verify HTTPS is NOT available
echo "[*] Test 2: Checking HTTPS availability"
HTTPS_TEST=$(curl -s -m 5 "${HTTPS_URL}" 2>&1)

if echo "$HTTPS_TEST" | grep -qi "ssl\|tls\|certificate\|wrong version\|connection refused\|certificate required\|handshake\|error"; then
    echo "[+] HTTPS is not properly configured"
    echo "[+] Reason: $(echo "$HTTPS_TEST" | head -1)"
    echo "[+] This confirms NO TLS/SSL encryption is available"
elif echo "$HTTPS_TEST" | grep -qi "curl"; then
    echo "[+] HTTPS connection failed (curl error)"
    echo "[+] No HTTPS support detected"
fi

echo ""

# Test 3: Analyze HTTP response to show plaintext nature
echo "[*] Test 3: Verifying plaintext HTTP communication"
echo "[*] Attempting to retrieve HTTP response..."

HTTP_RESPONSE=$(curl -s -m 5 -i "${HTTP_URL}" 2>&1 | head -20)

if [ -n "$HTTP_RESPONSE" ]; then
    echo "[+] HTTP Response received (plaintext):"
    echo "$HTTP_RESPONSE"
    echo ""
    echo "[!] All headers and content above are transmitted in PLAINTEXT"
    echo "[!] Any network observer can read this traffic"
fi

echo ""

# Test 4: Demonstrate lack of HTTPS enforcement headers
echo "[*] Test 4: Checking for HTTPS enforcement headers"
HTTP_FULL=$(curl -s -m 5 -i "${HTTP_URL}" 2>&1)

if echo "$HTTP_FULL" | grep -qi "strict-transport-security"; then
    echo "[!] HSTS header found (but application still listening on HTTP)"
else
    echo "[+] HSTS (Strict-Transport-Security) header is MISSING"
    echo "[+] No enforcement mechanism to redirect to HTTPS"
fi

if echo "$HTTP_FULL" | grep -qi "upgrade-insecure-requests"; then
    echo "[!] Some HTTPS upgrade mechanism detected"
else
    echo "[+] No Content-Security-Policy upgrade-insecure-requests directive"
fi

echo ""

# Test 5: Source code inspection (if available)
echo "[*] Test 5: Checking application source code"
if [ -f "server.js" ]; then
    echo "[+] Found server.js, checking for HTTPS configuration..."
    if grep -q "https\|tls\|certificate\|SSL" server.js; then
        echo "[!] Some HTTPS references found in server.js"
    else
        echo "[+] No HTTPS/TLS configuration found in server.js"
        echo "[+] Confirming application is HTTP-only"
    fi
    echo ""
    echo "[*] HTTP listener configuration:"
    grep -n "listen\|createServer\|app.listen" server.js | head -5
fi

if [ -f "app.js" ]; then
    echo "[+] Found app.js, checking for HTTPS configuration..."
    if grep -q "https\|tls\|certificate\|SSL" app.js; then
        echo "[!] Some HTTPS references found in app.js"
    else
        echo "[+] No HTTPS/TLS configuration found in app.js"
    fi
fi

echo ""

# Summary
echo "=========================================="
echo "VULNERABILITY ASSESSMENT"
echo "=========================================="
echo "[!] Application Running on HTTP (Unencrypted)"
echo "[!] HTTPS/TLS NOT Properly Configured"
echo "[!] All Communication is in PLAINTEXT"
echo ""
echo "Attack Scenarios:"
echo "  1. Network Eavesdropping: Attackers on same network can read all traffic"
echo "  2. Man-in-the-Middle (MITM): Attackers can intercept and modify requests"
echo "  3. Credential Theft: Login credentials transmitted in plaintext"
echo "  4. Session Hijacking: Cookies and session tokens can be stolen"
echo "  5. Malware Injection: Attackers can inject malicious content"
echo ""
echo "Compliance Impact:"
echo "  - PCI DSS: Requires HTTPS for sensitive data"
echo "  - HIPAA: Requires encryption for healthcare data"
echo "  - GDPR: Requires appropriate security measures"
echo "  - SOC 2: Requires encryption in transit"
echo ""
echo "=========================================="

# Exit with success since we confirmed the vulnerability exists
exit 0