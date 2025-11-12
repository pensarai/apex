#!/bin/bash

# POC: Broken Form Functionality - Missing Form Action and Method
# This script demonstrates the presence of a malformed form element on the homepage
# that lacks critical 'action' and 'method' attributes required for form submission

TARGET_URL="${1:-http://localhost:5000/}"
RESPONSE_FILE="/tmp/homepage_response.html"

echo "[*] Testing for broken form functionality at: $TARGET_URL"
echo "[*] Fetching homepage HTML..."

# Fetch the homepage
curl -s "$TARGET_URL" > "$RESPONSE_FILE"

if [ ! -s "$RESPONSE_FILE" ]; then
    echo "[-] Failed to fetch homepage"
    exit 1
fi

echo "[+] Homepage fetched successfully"
echo ""

# Check for form elements
echo "[*] Searching for form elements..."
FORM_COUNT=$(grep -c '<form' "$RESPONSE_FILE")
echo "[+] Found $FORM_COUNT form element(s)"
echo ""

# Extract and analyze the form element
echo "[*] Analyzing form element attributes..."
FORM_CONTENT=$(sed -n '/<form/,/<\/form>/p' "$RESPONSE_FILE" | head -20)

if [ -z "$FORM_CONTENT" ]; then
    echo "[-] Could not extract form content"
    exit 1
fi

echo "[+] Form element content:"
echo "---"
echo "$FORM_CONTENT"
echo "---"
echo ""

# Check for missing action attribute
if grep -q '<form[^>]*>' "$RESPONSE_FILE"; then
    FORM_TAG=$(grep '<form' "$RESPONSE_FILE" | head -1)
    
    echo "[*] Full form opening tag: $FORM_TAG"
    echo ""
    
    # Check for action attribute
    if echo "$FORM_TAG" | grep -q 'action='; then
        echo "[-] Form HAS action attribute"
        ACTION_FOUND=1
    else
        echo "[+] VULNERABILITY: Form is MISSING action attribute"
        ACTION_FOUND=0
    fi
    
    # Check for method attribute
    if echo "$FORM_TAG" | grep -q 'method='; then
        echo "[-] Form HAS method attribute"
        METHOD_FOUND=1
    else
        echo "[+] VULNERABILITY: Form is MISSING method attribute"
        METHOD_FOUND=0
    fi
    
    echo ""
    
    # Summary
    if [ "$ACTION_FOUND" -eq 0 ] && [ "$METHOD_FOUND" -eq 0 ]; then
        echo "[+] CONFIRMED: Form is missing BOTH action and method attributes"
        echo "[+] Impact: This form cannot submit data to any endpoint"
        echo "[+] The form is non-functional and indicates broken development"
        exit 0
    elif [ "$ACTION_FOUND" -eq 0 ]; then
        echo "[+] WARNING: Form is missing action attribute"
        exit 0
    elif [ "$METHOD_FOUND" -eq 0 ]; then
        echo "[+] WARNING: Form is missing method attribute"
        exit 0
    fi
fi

echo "[-] Could not verify form attributes"
exit 1