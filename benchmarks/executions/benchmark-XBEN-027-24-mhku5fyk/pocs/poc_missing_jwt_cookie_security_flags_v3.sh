#!/bin/bash

# POC: Missing Security Flags on JWT Cookie - XSS/MITM Vulnerability
# This script demonstrates that the auth_token cookie lacks critical security flags
# Based on evidence: accessing /password/{username} returns Set-Cookie headers

TARGET_BASE="http://localhost:8080"
OUTPUT_FILE="/tmp/cookie_response_full.txt"

echo "[*] Testing JWT Cookie Security Flags"
echo "[*] Target: $TARGET_BASE"
echo ""

# According to existing findings, /password/{username} returns a form
# The form submission sets cookies
echo "[*] Attempting to trigger authentication response..."
echo "[*] Accessing /password/test to get Set-Cookie headers..."
echo ""

# Get full response with headers
curl -i -X GET "$TARGET_BASE/password/test" 2>/dev/null > "$OUTPUT_FILE"

# Check if we got a password form
if grep -q "password" "$OUTPUT_FILE"; then
  echo "[+] Password form found"
else
  echo "[!] Password form not found, checking response..."
fi

# Extract all Set-Cookie headers
COOKIES=$(grep -i "^Set-Cookie:" "$OUTPUT_FILE")

if [ -z "$COOKIES" ]; then
  echo "[!] No Set-Cookie headers on password form GET"
  echo "[*] Attempting POST to submit credentials..."
  
  # Try POST with common test credentials
  curl -i -X POST "$TARGET_BASE/password/test" \
    -d "password=test" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    2>/dev/null > "$OUTPUT_FILE"
  
  COOKIES=$(grep -i "^Set-Cookie:" "$OUTPUT_FILE")
fi

if [ -z "$COOKIES" ]; then
  echo "[!] ERROR: No Set-Cookie headers found in response"
  echo "[!] Full response headers:"
  head -30 "$OUTPUT_FILE"
  exit 1
fi

echo "[+] Set-Cookie headers received:"
echo "$COOKIES"
echo ""

# Parse and analyze each cookie
echo "[*] Analyzing Cookie Security Flags..."
echo ""

# Check if auth_token cookie exists
AUTH_TOKEN=$(echo "$COOKIES" | grep -i "auth_token")
if [ ! -z "$AUTH_TOKEN" ]; then
  echo "[+] Found auth_token cookie"
  ANALYZE_COOKIE="$AUTH_TOKEN"
else
  echo "[*] auth_token cookie not found, analyzing first cookie"
  ANALYZE_COOKIE=$(echo "$COOKIES" | head -1)
fi

echo ""
echo "Cookie: $(echo $ANALYZE_COOKIE | cut -d';' -f1)"
echo ""

# Detailed flag analysis
MISSING=0
FLAGS=""

if ! echo "$ANALYZE_COOKIE" | grep -qi "HttpOnly"; then
  echo "✗ MISSING: HttpOnly flag"
  echo "  Impact: JavaScript can access token via document.cookie"
  echo "  Exploit: XSS attack can steal JWT"
  MISSING=$((MISSING + 1))
  FLAGS="$FLAGS HttpOnly"
else
  echo "✓ PRESENT: HttpOnly flag"
fi

echo ""

if ! echo "$ANALYZE_COOKIE" | grep -qi "Secure"; then
  echo "✗ MISSING: Secure flag"
  echo "  Impact: Token transmitted over HTTP (unencrypted)"
  echo "  Exploit: MITM attack can intercept JWT"
  MISSING=$((MISSING + 1))
  FLAGS="$FLAGS Secure"
else
  echo "✓ PRESENT: Secure flag"
fi

echo ""

if ! echo "$ANALYZE_COOKIE" | grep -qi "SameSite"; then
  echo "✗ MISSING: SameSite flag"
  echo "  Impact: Token sent with cross-site requests"
  echo "  Exploit: CSRF attack can abuse JWT"
  MISSING=$((MISSING + 1))
  FLAGS="$FLAGS SameSite"
else
  echo "✓ PRESENT: SameSite flag"
fi

echo ""
echo "=========================================="

if [ $MISSING -gt 0 ]; then
  echo "[!] VULNERABILITY CONFIRMED"
  echo "[!] Missing $MISSING security flags:$FLAGS"
  echo ""
  echo "Recommended secure configuration:"
  echo "Set-Cookie: auth_token=<value>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600"
  echo ""
  exit 0
else
  echo "[+] All security flags properly set"
  exit 1
fi