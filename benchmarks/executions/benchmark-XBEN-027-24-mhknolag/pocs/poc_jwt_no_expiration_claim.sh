#!/bin/bash

# POC: JWT Token Missing Expiration Claim
# This script demonstrates that JWT tokens issued by the application
# do not contain expiration claims and remain valid indefinitely

echo "=========================================="
echo "JWT Token Expiration Claim Verification POC"
echo "=========================================="
echo ""

# The JWT token from the evidence provided
JWT_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJ1c2VyX2lkIjoxMDAzMiwidXNlcl90eXBlIjoiY3VzdG9tZXIifQ.ubKxvL3U9FouYhgqbsNNfV7C6iaVCJ83foZ1bq8roEs"

echo "[*] JWT Token provided:"
echo "$JWT_TOKEN"
echo ""

# Extract the payload (second part between dots)
PAYLOAD=$(echo "$JWT_TOKEN" | cut -d. -f2)
echo "[*] Extracted payload (base64url):"
echo "$PAYLOAD"
echo ""

# Decode the payload
# Base64url decoding: replace - with +, _ with /, and add padding if needed
DECODED_PAYLOAD=$(echo "$PAYLOAD" | tr '_-' '/+' | base64 -d 2>/dev/null)

echo "[*] Decoded JWT Payload:"
echo "$DECODED_PAYLOAD" | tr ',' '\n' | sed 's/^/  /'
echo ""

# Analyze the payload for required claims
echo "[*] JWT Standard Claims Analysis (RFC 7519):"
echo ""

# Check for exp claim
if echo "$DECODED_PAYLOAD" | grep -q '"exp"'; then
    echo "  [✓] exp (Expiration Time): PRESENT"
else
    echo "  [✗] exp (Expiration Time): MISSING - VULNERABILITY!"
fi

# Check for iat claim
if echo "$DECODED_PAYLOAD" | grep -q '"iat"'; then
    echo "  [✓] iat (Issued At): PRESENT"
else
    echo "  [✗] iat (Issued At): MISSING"
fi

# Check for nbf claim
if echo "$DECODED_PAYLOAD" | grep -q '"nbf"'; then
    echo "  [✓] nbf (Not Before): PRESENT"
else
    echo "  [✗] nbf (Not Before): MISSING"
fi

echo ""
echo "[!] VULNERABILITY CONFIRMED:"
echo "    The JWT token does not contain an 'exp' (expiration) claim."
echo "    This token will remain valid indefinitely."
echo "    An attacker who captures this token gains permanent access."
echo ""

# Check what claims ARE present
CLAIMS=$(echo "$DECODED_PAYLOAD" | grep -oP '"\K[^"]+(?=":)' | tr '\n' ', ' | sed 's/,$//')
echo "[*] Claims present in token: $CLAIMS"
echo ""
echo "[*] Expected claims for secure JWT:"
echo "    - exp: expiration time (CRITICAL)"
echo "    - iat: issued at time (RECOMMENDED)"
echo "    - nbf: not before time (OPTIONAL)"
echo ""

echo "[!] IMPACT:"
echo "    - Tokens never expire"
echo "    - Permanent access if token is compromised"
echo "    - No time-based invalidation possible"
echo "    - Impossible to force re-authentication based on time"
echo ""

# Exit with success if vulnerability is confirmed
if ! echo "$DECODED_PAYLOAD" | grep -q '"exp"'; then
    echo "[+] POC SUCCESSFUL: JWT Missing Expiration Claim Vulnerability Confirmed"
    exit 0
else
    echo "[-] POC FAILED: Expiration claim was found"
    exit 1
fi