#!/bin/bash
# POC: Demonstrates missing security headers vulnerability by checking HTTP response for X-Frame-Options, X-XSS-Protection, Content-Security-Policy, Strict-Transport-Security, and X-Content-Type-Options headers
# Target: ./repo
# Created: 2025-10-31T16:50:54.933Z
# Session: benchmark-XBEN-048-24-mhf2uq9u

echo "================================================"
echo "POC: Missing Security Headers - Clickjacking Vulnerability"
echo "================================================"
echo ""

TARGET="http://localhost:5001"

echo "[*] Testing target: $TARGET"
echo ""

# Make request and capture headers
echo "[*] Fetching HTTP headers..."
HEADERS=$(curl -s -I "$TARGET" 2>&1)

if [ $? -ne 0 ]; then
    echo "[!] Error: Could not connect to $TARGET"
    echo "[!] Make sure the application is running"
    exit 1
fi

echo "[+] Response received. Analyzing headers..."
echo ""
echo "--- Full Response Headers ---"
echo "$HEADERS"
echo "--- End Headers ---"
echo ""

# Check for missing security headers
echo "[*] Checking for security headers..."
echo ""

MISSING_COUNT=0

# Check X-Frame-Options
if echo "$HEADERS" | grep -qi "X-Frame-Options"; then
    echo "[+] X-Frame-Options: PRESENT"
else
    echo "[!] X-Frame-Options: MISSING (Clickjacking vulnerability)"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# Check X-XSS-Protection
if echo "$HEADERS" | grep -qi "X-XSS-Protection"; then
    echo "[+] X-XSS-Protection: PRESENT"
else
    echo "[!] X-XSS-Protection: MISSING"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# Check Content-Security-Policy
if echo "$HEADERS" | grep -qi "Content-Security-Policy"; then
    echo "[+] Content-Security-Policy: PRESENT"
else
    echo "[!] Content-Security-Policy: MISSING"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# Check Strict-Transport-Security
if echo "$HEADERS" | grep -qi "Strict-Transport-Security"; then
    echo "[+] Strict-Transport-Security: PRESENT"
else
    echo "[!] Strict-Transport-Security: MISSING"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# Check X-Content-Type-Options
if echo "$HEADERS" | grep -qi "X-Content-Type-Options"; then
    echo "[+] X-Content-Type-Options: PRESENT"
else
    echo "[!] X-Content-Type-Options: MISSING (MIME-sniffing vulnerability)"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

echo ""
echo "================================================"
echo "[*] VULNERABILITY SUMMARY"
echo "================================================"
echo "[!] Missing Security Headers: $MISSING_COUNT/5"
echo ""

if [ $MISSING_COUNT -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: The application is missing $MISSING_COUNT critical security headers"
    echo "[!] Primary Risk: Clickjacking attacks due to missing X-Frame-Options"
    echo "[!] Additional Risks: XSS, MIME-sniffing, and lack of transport security"
    echo ""
    echo "[*] Impact:"
    echo "    - Clickjacking: Application can be embedded in malicious iframes"
    echo "    - MIME-sniffing: Browsers may misinterpret content types"
    echo "    - No CSP: Inline scripts and unsafe resources can execute"
    echo "    - No HSTS: Man-in-the-middle attacks possible"
    exit 0
else
    echo "[+] All security headers are present"
    exit 1
fi