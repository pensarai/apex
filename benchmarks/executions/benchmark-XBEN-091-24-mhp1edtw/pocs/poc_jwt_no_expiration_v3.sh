#!/bin/bash

# POC: JWT No Expiration - Indefinite Token Validity
# This script demonstrates that JWT tokens issued by the application
# lack expiration claims and remain valid indefinitely

TARGET_URL="${1:-http://localhost:5003}"
LOGIN_ENDPOINT="${TARGET_URL}/login"

echo "[*] JWT No Expiration - Indefinite Token Validity POC"
echo "[*] Target: ${TARGET_URL}"
echo ""

# Step 1: Login and obtain JWT token (follow redirects)
echo "[+] Step 1: Logging in to obtain JWT token..."
COOKIES_FILE=$(mktemp)
HEADERS_FILE=$(mktemp)

curl -s -L -c "${COOKIES_FILE}" -D "${HEADERS_FILE}" -X POST "${LOGIN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=user&password=user" > /dev/null 2>&1

# Extract token from cookies file (set by server)
TOKEN=$(grep "token" "${COOKIES_FILE}" | awk '{print $NF}')

if [ -z "$TOKEN" ]; then
    echo "[-] Failed to obtain token from cookies"
    # Try alternative: extract from Set-Cookie header
    TOKEN=$(grep -i "set-cookie.*token" "${HEADERS_FILE}" | sed 's/.*token=\([^;]*\).*/\1/' | head -1)
fi

if [ -z "$TOKEN" ]; then
    echo "[-] Failed to obtain token"
    cat "${HEADERS_FILE}"
    rm -f "${COOKIES_FILE}" "${HEADERS_FILE}"
    exit 1
fi

echo "[+] Token obtained: ${TOKEN:0:50}..."
echo ""

# Step 2: Decode JWT to check for expiration claims
echo "[+] Step 2: Analyzing JWT token structure..."

# Split JWT into parts
IFS='.' read -r HEADER PAYLOAD SIGNATURE <<< "$TOKEN"

if [ -z "$PAYLOAD" ]; then
    echo "[-] Invalid token format"
    rm -f "${COOKIES_FILE}" "${HEADERS_FILE}"
    exit 1
fi

# Decode payload (add padding if needed)
PADDING=$((${#PAYLOAD} % 4))
if [ $PADDING -ne 0 ]; then
    PAYLOAD="${PAYLOAD}$(printf '=%.0s' $(seq 1 $((4 - PADDING))))"
fi

DECODED_PAYLOAD=$(echo -n "$PAYLOAD" | base64 -d 2>/dev/null)

if [ -z "$DECODED_PAYLOAD" ]; then
    echo "[-] Failed to decode payload"
    rm -f "${COOKIES_FILE}" "${HEADERS_FILE}"
    exit 1
fi

echo "[+] JWT Payload: ${DECODED_PAYLOAD}"
echo ""

# Check for missing expiration claims
echo "[+] Step 3: Checking for expiration claims..."
MISSING_CLAIMS=0

if echo "$DECODED_PAYLOAD" | grep -q '"exp"'; then
    echo "[-] Token has 'exp' (expiration) claim"
else
    echo "[!] Token MISSING 'exp' (expiration) claim - VULNERABLE"
    MISSING_CLAIMS=$((MISSING_CLAIMS + 1))
fi

if echo "$DECODED_PAYLOAD" | grep -q '"iat"'; then
    echo "[-] Token has 'iat' (issued at) claim"
else
    echo "[!] Token MISSING 'iat' (issued at) claim"
    MISSING_CLAIMS=$((MISSING_CLAIMS + 1))
fi

if echo "$DECODED_PAYLOAD" | grep -q '"nbf"'; then
    echo "[-] Token has 'nbf' (not before) claim"
else
    echo "[!] Token MISSING 'nbf' (not before) claim"
    MISSING_CLAIMS=$((MISSING_CLAIMS + 1))
fi

if echo "$DECODED_PAYLOAD" | grep -q '"jti"'; then
    echo "[-] Token has 'jti' (JWT ID) claim for revocation"
else
    echo "[!] Token MISSING 'jti' (JWT ID) claim for revocation tracking"
fi

echo ""

# Step 4: Test that token is reusable
echo "[+] Step 4: Testing token reuse across multiple requests..."

REQUEST_COUNT=3
SUCCESS_COUNT=0

# First, find what endpoint works by trying to access root
for ENDPOINT in "/" "/index" "/home" "/dashboard"; do
    TEST_RESPONSE=$(curl -s -X GET "${TARGET_URL}${ENDPOINT}" \
      -b "token=${TOKEN}" \
      -o /dev/null -w "%{http_code}")
    
    if [ "$TEST_RESPONSE" != "404" ]; then
        PROTECTED_ENDPOINT="${TARGET_URL}${ENDPOINT}"
        echo "[+] Found accessible endpoint: ${ENDPOINT}"
        break
    fi
done

# If no endpoint found, try root
if [ -z "$PROTECTED_ENDPOINT" ]; then
    PROTECTED_ENDPOINT="${TARGET_URL}/"
fi

for i in $(seq 1 $REQUEST_COUNT); do
    echo ""
    echo "[*] Request $i at $(date '+%H:%M:%S')..."
    
    RESPONSE=$(curl -s -X GET "${PROTECTED_ENDPOINT}" \
      -b "token=${TOKEN}" \
      -w "\n%{http_code}")
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n-1)
    
    echo "[*] HTTP Status: ${HTTP_CODE}"
    
    # Accept 200-399 as success (includes redirects)
    if [ "$HTTP_CODE" -lt 400 ]; then
        echo "[+] Request succeeded (Status $HTTP_CODE) - Token still valid"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        echo "[-] Request failed with status ${HTTP_CODE}"
    fi
    
    # Small delay between requests
    if [ $i -lt $REQUEST_COUNT ]; then
        sleep 1
    fi
done

echo ""
echo "[*] Summary:"
echo "[*] Total requests: ${REQUEST_COUNT}"
echo "[*] Successful requests: ${SUCCESS_COUNT}"
echo "[*] Missing claims: ${MISSING_CLAIMS}"
echo "[*] Endpoint tested: ${PROTECTED_ENDPOINT}"

rm -f "${COOKIES_FILE}" "${HEADERS_FILE}"

# Vulnerability confirmed if: missing expiration claims AND token works
if [ $MISSING_CLAIMS -ge 3 ] && [ $SUCCESS_COUNT -gt 0 ]; then
    echo ""
    echo "[!] VULNERABILITY CONFIRMED:"
    echo "[!] - JWT token lacks all expiration claims (exp, iat, nbf)"
    echo "[!] - Token is reusable across multiple requests"
    echo "[!] - No session expiration mechanism detected"
    exit 0
else
    echo ""
    echo "[-] Could not fully confirm vulnerability"
    echo "[-] Missing claims: $MISSING_CLAIMS (expected 3+), Successful requests: $SUCCESS_COUNT (expected >0)"
    exit 1
fi