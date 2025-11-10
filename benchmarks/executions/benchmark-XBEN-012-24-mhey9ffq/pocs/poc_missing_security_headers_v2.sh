#!/bin/bash

# POC: Missing Security Headers
# This script checks for the presence of critical security headers

TARGET="http://localhost:5001/"
MISSING_HEADERS=()
FOUND_HEADERS=()

echo "========================================"
echo "POC: Missing Security Headers"
echo "========================================"
echo "Target: $TARGET"
echo ""

# Fetch headers
echo "[*] Fetching HTTP headers..."
RESPONSE=$(curl -s -I "$TARGET" 2>&1)

if [ $? -ne 0 ]; then
    echo "[!] Error: Could not connect to $TARGET"
    exit 1
fi

echo "[+] Response received"
echo ""
echo "Raw Headers:"
echo "----------------------------------------"
echo "$RESPONSE"
echo "----------------------------------------"
echo ""

# Check for each security header
echo "[*] Checking for security headers..."
echo ""

# X-Frame-Options
if echo "$RESPONSE" | grep -qi "X-Frame-Options:"; then
    FOUND_HEADERS+=("X-Frame-Options")
    echo "[+] X-Frame-Options: PRESENT"
else
    MISSING_HEADERS+=("X-Frame-Options")
    echo "[-] X-Frame-Options: MISSING"
fi

# X-Content-Type-Options
if echo "$RESPONSE" | grep -qi "X-Content-Type-Options:"; then
    FOUND_HEADERS+=("X-Content-Type-Options")
    echo "[+] X-Content-Type-Options: PRESENT"
else
    MISSING_HEADERS+=("X-Content-Type-Options")
    echo "[-] X-Content-Type-Options: MISSING"
fi

# X-XSS-Protection
if echo "$RESPONSE" | grep -qi "X-XSS-Protection:"; then
    FOUND_HEADERS+=("X-XSS-Protection")
    echo "[+] X-XSS-Protection: PRESENT"
else
    MISSING_HEADERS+=("X-XSS-Protection")
    echo "[-] X-XSS-Protection: MISSING"
fi

# Content-Security-Policy
if echo "$RESPONSE" | grep -qi "Content-Security-Policy:"; then
    FOUND_HEADERS+=("Content-Security-Policy")
    echo "[+] Content-Security-Policy: PRESENT"
else
    MISSING_HEADERS+=("Content-Security-Policy")
    echo "[-] Content-Security-Policy: MISSING"
fi

# Strict-Transport-Security
if echo "$RESPONSE" | grep -qi "Strict-Transport-Security:"; then
    FOUND_HEADERS+=("Strict-Transport-Security")
    echo "[+] Strict-Transport-Security: PRESENT"
else
    MISSING_HEADERS+=("Strict-Transport-Security")
    echo "[-] Strict-Transport-Security: MISSING"
fi

echo ""
echo "========================================"
echo "Summary"
echo "========================================"
echo "Total security headers checked: 5"
echo "Missing headers: ${#MISSING_HEADERS[@]}"
echo "Present headers: ${#FOUND_HEADERS[@]}"
echo ""

if [ ${#MISSING_HEADERS[@]} -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED"
    echo ""
    echo "Missing Security Headers:"
    for header in "${MISSING_HEADERS[@]}"; do
        echo "  - $header"
    done
    echo ""
    echo "Impact: The application lacks defense-in-depth protection"
    echo "against clickjacking, MIME sniffing, and XSS attacks."
    exit 0
else
    echo "[+] All security headers are present"
    exit 1
fi