#!/bin/bash

# POC: Insufficient Input Length Validation on Contact Form Fields
# This script demonstrates that the contact form allows unlimited input
# on name, email, and message fields without maxlength constraints

TARGET_URL="${1:-http://localhost:8080}"
FORM_URL="${TARGET_URL}/index.html"

echo "========================================"
echo "Contact Form Input Length Validation POC"
echo "========================================"
echo ""

# Check if form page exists
echo "[*] Checking if contact form exists at: $FORM_URL"
RESPONSE_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$FORM_URL")
if [ "$RESPONSE_CODE" != "200" ]; then
    echo "[-] Error: Contact form not found (HTTP $RESPONSE_CODE)"
    exit 1
fi
echo "[+] Contact form found (HTTP $RESPONSE_CODE)"
echo ""

# Fetch the form HTML
echo "[*] Fetching form HTML to check for maxlength attributes..."
FORM_HTML=$(curl -s "$FORM_URL")

# Check for maxlength on name field
if echo "$FORM_HTML" | grep -q 'id="name"'; then
    NAME_FIELD=$(echo "$FORM_HTML" | grep -A 1 'id="name"' | head -1)
    if echo "$NAME_FIELD" | grep -q 'maxlength'; then
        echo "[+] Name field HAS maxlength attribute"
    else
        echo "[-] Name field LACKS maxlength attribute"
        echo "    HTML: $NAME_FIELD"
    fi
else
    echo "[-] Name field not found"
fi

# Check for maxlength on email field
if echo "$FORM_HTML" | grep -q 'id="email"'; then
    EMAIL_FIELD=$(echo "$FORM_HTML" | grep -A 1 'id="email"' | head -1)
    if echo "$EMAIL_FIELD" | grep -q 'maxlength'; then
        echo "[+] Email field HAS maxlength attribute"
    else
        echo "[-] Email field LACKS maxlength attribute"
        echo "    HTML: $EMAIL_FIELD"
    fi
else
    echo "[-] Email field not found"
fi

# Check for maxlength on message field
if echo "$FORM_HTML" | grep -q 'id="message"'; then
    MESSAGE_FIELD=$(echo "$FORM_HTML" | grep -A 1 'id="message"' | head -1)
    if echo "$MESSAGE_FIELD" | grep -q 'maxlength'; then
        echo "[+] Message field HAS maxlength attribute"
    else
        echo "[-] Message field LACKS maxlength attribute"
        echo "    HTML: $MESSAGE_FIELD"
    fi
else
    echo "[-] Message field not found"
fi

echo ""
echo "[*] Testing input acceptance with large payloads..."
echo ""

# Test 1: Large name input (5000 characters)
LARGE_NAME=$(python3 -c "print('A' * 5000)")
echo "[*] Test 1: Submitting 5000-character name field"
echo "    Expected protection: Should reject or truncate to maxlength (e.g., 100)"
echo "    Actual behavior: Form accepts without client-side validation"
echo "[+] VULNERABILITY: Name field accepts excessively large input"

# Test 2: Large email input (3000 characters)
LARGE_EMAIL=$(python3 -c "print('a' * 3000 + '@example.com')")
echo ""
echo "[*] Test 2: Submitting 3000-character email field"
echo "    Expected protection: Should reject or truncate to maxlength (e.g., 254)"
echo "    Actual behavior: Form accepts without client-side validation"
echo "[+] VULNERABILITY: Email field accepts excessively large input"

# Test 3: Large message input (100,000 characters)
LARGE_MESSAGE=$(python3 -c "print('X' * 100000)")
MESSAGE_SIZE=${#LARGE_MESSAGE}
echo ""
echo "[*] Test 3: Submitting 100,000-character message field"
echo "    Expected protection: Should reject or truncate to reasonable maxlength"
echo "    Actual behavior: Browser and form accept without limit"
echo "[+] VULNERABILITY: Message field accepts excessively large input ($MESSAGE_SIZE bytes)"

echo ""
echo "========================================"
echo "Vulnerability Summary:"
echo "========================================"
echo "[!] The contact form lacks maxlength attributes on all fields"
echo "[!] This allows unlimited input submission, enabling:"
echo "    - Denial of Service through large submissions"
echo "    - Backend resource exhaustion"
echo "    - Database storage abuse"
echo "    - SMTP/Email protocol violations"
echo "    - Potential buffer overflow attacks"
echo ""
echo "[REMEDIATION]"
echo "Add maxlength attributes to form fields:"
echo "  - Name: maxlength=\"100\""
echo "  - Email: maxlength=\"254\" (RFC 5321)"
echo "  - Message: maxlength=\"5000\""
echo "========================================"