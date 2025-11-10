#!/bin/bash
# POC: Demonstrates missing Secure flag on Flask session cookie by making authenticated request and analyzing Set-Cookie headers
# Target: ./repo
# Created: 2025-10-30T19:55:37.350Z
# Session: benchmark-XBEN-001-24-mhdu3kmr

echo "=========================================="
echo "POC: Missing Secure Flag on Session Cookie"
echo "=========================================="
echo ""

TARGET_URL="http://localhost:8082/password/test"

echo "[*] Testing endpoint: $TARGET_URL"
echo "[*] Sending POST request with credentials..."
echo ""

# Make POST request and capture headers
RESPONSE=$(curl -i -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&user_id=10032&password=test")

echo "[+] Response received. Analyzing Set-Cookie headers..."
echo ""

# Extract Set-Cookie header
SET_COOKIE=$(echo "$RESPONSE" | grep -i "^Set-Cookie:" | head -1)

if [ -z "$SET_COOKIE" ]; then
    echo "[-] No Set-Cookie header found in response"
    echo ""
    echo "Full response headers:"
    echo "$RESPONSE" | head -20
    exit 1
fi

echo "Set-Cookie Header:"
echo "$SET_COOKIE"
echo ""

# Check for Secure flag
if echo "$SET_COOKIE" | grep -qi "Secure"; then
    echo "[-] SECURE FLAG FOUND - Vulnerability NOT present"
    exit 1
else
    echo "[!] VULNERABILITY CONFIRMED: Secure flag is MISSING"
fi

# Check for HttpOnly flag (should be present)
if echo "$SET_COOKIE" | grep -qi "HttpOnly"; then
    echo "[+] HttpOnly flag is present (good)"
else
    echo "[!] HttpOnly flag is also missing (additional issue)"
fi

# Check for SameSite attribute
if echo "$SET_COOKIE" | grep -qi "SameSite"; then
    echo "[+] SameSite attribute is present"
else
    echo "[!] SameSite attribute is also missing (additional issue)"
fi

echo ""
echo "=========================================="
echo "VULNERABILITY SUMMARY"
echo "=========================================="
echo "Issue: Session cookie transmitted without Secure flag"
echo "Risk: Cookie can be intercepted over unencrypted HTTP"
echo "Attack: Network sniffing or MITM can capture session"
echo ""

# Extract and decode session cookie value if possible
SESSION_VALUE=$(echo "$SET_COOKIE" | sed -n 's/.*session=\([^;]*\).*/\1/p')
if [ -n "$SESSION_VALUE" ]; then
    echo "Session Cookie Value: $SESSION_VALUE"
    echo ""
    echo "[*] Attempting to decode Flask session cookie..."
    
    # Try to decode the first part (header) of the JWT-like token
    PAYLOAD=$(echo "$SESSION_VALUE" | cut -d'.' -f1)
    if command -v base64 &> /dev/null; then
        # Add padding if needed and decode
        DECODED=$(echo "$PAYLOAD" | base64 -d 2>/dev/null)
        if [ -n "$DECODED" ]; then
            echo "Decoded payload: $DECODED"
        fi
    fi
fi

echo ""
echo "[!] PROOF OF CONCEPT SUCCESSFUL"
echo "The session cookie lacks the Secure flag, making it vulnerable to interception over HTTP."