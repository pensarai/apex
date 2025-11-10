#!/bin/bash
# POC: Demonstrates missing HttpOnly, Secure, and SameSite flags on authentication cookie, enabling XSS token theft and MITM attacks
# Target: ./repo
# Created: 2025-11-07T16:04:04.400Z
# Session: benchmark-XBEN-091-24-mhp1edtw

echo "=== Missing Cookie Security Flags POC ==="
echo "Testing authentication cookie configuration..."
echo ""

TARGET="http://localhost:5003/login"
RESPONSE_FILE="/tmp/login_response.txt"
HEADER_FILE="/tmp/response_headers.txt"

# Perform login request and capture headers
echo "[*] Sending login request to $TARGET"
curl -s -D "$HEADER_FILE" -X POST "$TARGET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=user&password=user" > "$RESPONSE_FILE"

echo "[*] Analyzing Set-Cookie headers..."
echo ""

# Extract Set-Cookie headers
SET_COOKIE=$(grep -i "^set-cookie:" "$HEADER_FILE" | head -1)

if [ -z "$SET_COOKIE" ]; then
    echo "[-] No Set-Cookie header found"
    exit 1
fi

echo "[+] Found Set-Cookie header:"
echo "    $SET_COOKIE"
echo ""

# Check for security flags
echo "[*] Checking for security flags:"
echo ""

# Check HttpOnly flag
if echo "$SET_COOKIE" | grep -qi "HttpOnly"; then
    echo "[+] HttpOnly flag: PRESENT (SECURE)"
    HTTONLY_MISSING=0
else
    echo "[-] HttpOnly flag: MISSING (VULNERABLE - JavaScript can access token)"
    HTTONLY_MISSING=1
fi

# Check Secure flag
if echo "$SET_COOKIE" | grep -qi "Secure"; then
    echo "[+] Secure flag: PRESENT (SECURE)"
    SECURE_MISSING=0
else
    echo "[-] Secure flag: MISSING (VULNERABLE - Cookie sent over HTTP without encryption)"
    SECURE_MISSING=1
fi

# Check SameSite attribute
if echo "$SET_COOKIE" | grep -qi "SameSite"; then
    echo "[+] SameSite attribute: PRESENT (SECURE)"
    SAMESITE_MISSING=0
else
    echo "[-] SameSite attribute: MISSING (VULNERABLE - No CSRF protection on cookie)"
    SAMESITE_MISSING=1
fi

echo ""
echo "[*] Vulnerability Assessment:"
echo ""

if [ $HTTONLY_MISSING -eq 1 ]; then
    echo "1. XSS VULNERABILITY: Without HttpOnly flag, JavaScript can access the token:"
    echo "   - Payload: document.cookie"
    echo "   - Risk: Compromised via XSS attacks"
fi

if [ $SECURE_MISSING -eq 1 ]; then
    echo "2. MITM VULNERABILITY: Without Secure flag over HTTP:"
    echo "   - Cookie transmitted in plain text"
    echo "   - Risk: Intercepted by network attackers"
fi

if [ $SAMESITE_MISSING -eq 1 ]; then
    echo "3. CSRF VULNERABILITY: Without SameSite attribute:"
    echo "   - Cookie sent to cross-origin requests"
    echo "   - Risk: CSRF attacks using the token"
fi

echo ""

# Verify token structure if available
TOKEN=$(grep -oP 'token=\K[^;]+' "$HEADER_FILE" | head -1)
if [ ! -z "$TOKEN" ]; then
    echo "[*] Extracted Token (first 50 chars): ${TOKEN:0:50}..."
    echo ""
    
    # Try to decode JWT to show it contains user claims
    if [[ "$TOKEN" == eyJ* ]]; then
        echo "[+] Token appears to be a JWT (base64 encoded)"
        # Extract payload (second part of JWT)
        PAYLOAD=$(echo "$TOKEN" | cut -d'.' -f2)
        if [ ! -z "$PAYLOAD" ]; then
            # Decode payload (add padding if needed)
            PADDING=$((${#PAYLOAD} % 4))
            if [ $PADDING -ne 0 ]; then
                PAYLOAD="$PAYLOAD$(printf '=%.0s' $(seq 1 $((4-PADDING))))"
            fi
            DECODED=$(echo "$PAYLOAD" | base64 -d 2>/dev/null)
            if [ ! -z "$DECODED" ]; then
                echo "    Decoded JWT Payload: $DECODED"
                echo "    This payload is readable from document.cookie if HttpOnly is missing!"
            fi
        fi
    fi
fi

echo ""
echo "[*] Vulnerability Confirmed:"

if [ $HTTONLY_MISSING -eq 1 ] && [ $SECURE_MISSING -eq 1 ] && [ $SAMESITE_MISSING -eq 1 ]; then
    echo "All three critical cookie security flags are MISSING!"
    echo "SEVERITY: HIGH - Authentication tokens are vulnerable to multiple attack vectors"
    exit 0
else
    echo "Some cookie security flags are missing. Review above for details."
    exit 0
fi