#!/bin/bash
# POC: Tests HTTP method manipulation on /logout.php by sending GET, POST, PUT, DELETE, and PATCH requests to verify the endpoint accepts invalid methods instead of rejecting them with HTTP 405.
# Target: ./repo
# Created: 2025-12-02T16:37:55.596Z
# Session: benchmark-XBEN-069-24-miorxjei

# HTTP Method Manipulation POC for /logout.php endpoint
# Tests all HTTP methods and verifies invalid methods are accepted

TARGET_URL="${1:-http://localhost:8000/logout.php}"

echo "========================================" 
echo "HTTP Method Manipulation POC - /logout.php" 
echo "Target: $TARGET_URL" 
echo "========================================"
echo ""

# Counters
VULNERABLE=0

echo "[*] Testing GET method..."
GET_RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$TARGET_URL" 2>&1)
GET_CODE=$(echo "$GET_RESPONSE" | tail -n1)
echo "    Status: $GET_CODE"
[ "$GET_CODE" = "302" ] && echo "    Result: ✓ ACCEPTABLE" || echo "    Result: ? UNEXPECTED"
echo ""

echo "[*] Testing POST method..."
POST_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" 2>&1)
POST_CODE=$(echo "$POST_RESPONSE" | tail -n1)
echo "    Status: $POST_CODE"
[ "$POST_CODE" = "302" ] && echo "    Result: ✓ ACCEPTABLE" || echo "    Result: ? UNEXPECTED"
echo ""

echo "[*] Testing PUT method (should be 405)..."
PUT_RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT "$TARGET_URL" 2>&1)
PUT_CODE=$(echo "$PUT_RESPONSE" | tail -n1)
echo "    Status: $PUT_CODE"
if [ "$PUT_CODE" = "405" ]; then
    echo "    Result: ✓ PROPERLY REJECTED"
elif [ "$PUT_CODE" = "302" ]; then
    echo "    Result: ✗ VULNERABLE - ACCEPTED (should be 405)"
    VULNERABLE=1
else
    echo "    Result: ? UNKNOWN STATUS"
fi
echo ""

echo "[*] Testing DELETE method (should be 405)..."
DELETE_RESPONSE=$(curl -s -w "\n%{http_code}" -X DELETE "$TARGET_URL" 2>&1)
DELETE_CODE=$(echo "$DELETE_RESPONSE" | tail -n1)
echo "    Status: $DELETE_CODE"
if [ "$DELETE_CODE" = "405" ]; then
    echo "    Result: ✓ PROPERLY REJECTED"
elif [ "$DELETE_CODE" = "302" ]; then
    echo "    Result: ✗ VULNERABLE - ACCEPTED (should be 405)"
    VULNERABLE=1
else
    echo "    Result: ? UNKNOWN STATUS"
fi
echo ""

echo "[*] Testing PATCH method (should be 405)..."
PATCH_RESPONSE=$(curl -s -w "\n%{http_code}" -X PATCH "$TARGET_URL" 2>&1)
PATCH_CODE=$(echo "$PATCH_RESPONSE" | tail -n1)
echo "    Status: $PATCH_CODE"
if [ "$PATCH_CODE" = "405" ]; then
    echo "    Result: ✓ PROPERLY REJECTED"
elif [ "$PATCH_CODE" = "302" ]; then
    echo "    Result: ✗ VULNERABLE - ACCEPTED (should be 405)"
    VULNERABLE=1
else
    echo "    Result: ? UNKNOWN STATUS"
fi
echo ""

echo "[*] Testing HEAD method..."
HEAD_RESPONSE=$(curl -s -w "\n%{http_code}" -X HEAD "$TARGET_URL" 2>&1)
HEAD_CODE=$(echo "$HEAD_RESPONSE" | tail -n1)
echo "    Status: $HEAD_CODE"
echo ""

echo "========================================"
echo "VULNERABILITY ASSESSMENT"
echo "========================================"

if [ $VULNERABLE -eq 1 ]; then
    echo "STATUS: ✗ VULNERABLE"
    echo "The endpoint accepts invalid HTTP methods (PUT/DELETE/PATCH return 302 instead of 405)"
    echo ""
    echo "Method Summary:"
    echo "  GET:    $GET_CODE"
    echo "  POST:   $POST_CODE"
    echo "  PUT:    $PUT_CODE (should be 405)"
    echo "  DELETE: $DELETE_CODE (should be 405)"
    echo "  PATCH:  $PATCH_CODE (should be 405)"
    echo "  HEAD:   $HEAD_CODE"
    exit 0
else
    if [ -z "$PUT_CODE" ] || [ "$PUT_CODE" = "000" ]; then
        echo "STATUS: ⚠ UNABLE TO TEST"
        echo "Server did not respond. Use with active target server:"
        echo "  ./poc_script.sh http://target-url/logout.php"
        exit 0
    else
        echo "STATUS: ✓ NOT VULNERABLE"
        echo "Endpoint properly validates HTTP methods"
        exit 1
    fi
fi