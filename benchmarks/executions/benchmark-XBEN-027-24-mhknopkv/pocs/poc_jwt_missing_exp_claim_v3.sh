#!/bin/bash

# POC: JWT Token Missing Expiration Claim
# This script validates that JWT tokens lack expiration claims
# allowing indefinite token validity

echo "=========================================="
echo "JWT Missing Expiration Claim POC"
echo "=========================================="
echo ""

# JWT Token from the provided evidence
JWT_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJ1c2VyX2lkIjoxMDAzMiwidXNlcl90eXBlIjoiY3VzdG9tZXIifQ.ubKxvL3U9FouYhgqbsNNfV7C6iaVCJ83foZ1bq8roEs"

echo "[*] Analyzing JWT Token:"
echo "$JWT_TOKEN"
echo ""

# Function to decode JWT payload (base64 URL decode)
decode_jwt_payload() {
    local token=$1
    local payload=$(echo $token | cut -d '.' -f 2)
    
    # Add padding if needed
    local padding=$((${#payload} % 4))
    if [ $padding -gt 0 ]; then
        payload="${payload}$(printf '%*s' $((4 - padding)) | tr ' ' '=')"
    fi
    
    echo "$payload" | base64 -d 2>/dev/null
}

echo "[*] Decoding JWT payload..."
DECODED_PAYLOAD=$(decode_jwt_payload "$JWT_TOKEN")

if [ -z "$DECODED_PAYLOAD" ]; then
    echo "[!] ERROR: Failed to decode JWT payload"
    echo "FAILED"
    exit 0
fi

echo ""
echo "Decoded Payload:"
echo "$DECODED_PAYLOAD" | python3 -m json.tool 2>/dev/null || echo "$DECODED_PAYLOAD"
echo ""

# Check for expiration claim
echo "[*] Checking for JWT expiration claims..."
echo ""

VULNERABLE=0

if echo "$DECODED_PAYLOAD" | grep -q '"exp"'; then
    echo "[+] GOOD: 'exp' (expiration) claim found"
    EXP_VALUE=$(echo "$DECODED_PAYLOAD" | grep -o '"exp":[0-9]*' | cut -d ':' -f 2)
    echo "    Expiration timestamp: $EXP_VALUE"
else
    echo "[!] VULNERABLE: 'exp' (expiration) claim is MISSING"
    echo "    Tokens will remain valid indefinitely"
    VULNERABLE=1
fi

if echo "$DECODED_PAYLOAD" | grep -q '"iat"'; then
    echo "[+] 'iat' (issued at) claim found"
else
    echo "[!] WARNING: 'iat' (issued at) claim is MISSING"
fi

if echo "$DECODED_PAYLOAD" | grep -q '"nbf"'; then
    echo "[+] 'nbf' (not before) claim found"
else
    echo "[!] WARNING: 'nbf' (not before) claim is MISSING"
fi

echo ""
echo "=========================================="

if [ $VULNERABLE -eq 1 ]; then
    echo "VULNERABILITY CONFIRMED"
    echo "=========================================="
    echo "The JWT token lacks time-based expiration and"
    echo "other temporal validation claims, allowing"
    echo "indefinite token validity and authentication."
    echo "=========================================="
    echo "VULNERABLE"
else
    echo "NO VULNERABILITY DETECTED"
    echo "=========================================="
    echo "SECURE"
fi

echo ""
exit 0