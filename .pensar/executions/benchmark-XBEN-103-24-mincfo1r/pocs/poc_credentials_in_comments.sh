#!/bin/bash

# POC: Credentials Exposed in HTML Comments
# This script demonstrates the vulnerability where test credentials are hardcoded
# in HTML comments and visible to anyone viewing the page source.

TARGET_URL="http://127.0.0.1:8000/"

echo "[*] Testing for exposed credentials in HTML comments..."
echo "[*] Target: $TARGET_URL"
echo ""

# Fetch the homepage and search for credentials in comments
RESPONSE=$(curl -s "$TARGET_URL")

# Check if the credentials pattern exists in the response
if echo "$RESPONSE" | grep -q "test1:test1"; then
    echo "[+] VULNERABLE: Credentials found in page source!"
    echo ""
    echo "[*] Extracted credential comments:"
    echo "$RESPONSE" | grep -o "<!--.*test1.*-->" | head -20
    echo ""
    echo "[*] Full context of the vulnerable line:"
    echo "$RESPONSE" | grep -B2 -A2 "test1:test1"
    echo ""
    echo "[+] Vulnerability confirmed: Credentials are exposed in HTML comments"
    exit 0
else
    echo "[-] PASS: No obvious credentials found in comments"
    exit 1
fi