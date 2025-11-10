#!/bin/bash

# POC: Missing Permissions-Policy Header Detection
# This script checks if the root endpoint lacks the Permissions-Policy header
# and verifies other security headers are also missing

TARGET_URL="http://localhost:5000/"

echo "=========================================="
echo "Permissions-Policy Header Detection POC"
echo "=========================================="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Fetch headers from root endpoint
echo "Fetching HTTP headers from $TARGET_URL"
RESPONSE=$(curl -s -i "$TARGET_URL" 2>&1)

echo ""
echo "--- Full Response Headers ---"
echo "$RESPONSE"
echo ""

# Check for Permissions-Policy header
echo "--- Checking for Permissions-Policy Header ---"
if echo "$RESPONSE" | grep -iq "Permissions-Policy"; then
    echo "✓ Permissions-Policy header IS present"
    echo "Header value:"
    echo "$RESPONSE" | grep -i "Permissions-Policy"
    PERM_POLICY_FOUND=1
else
    echo "✗ Permissions-Policy header IS MISSING (VULNERABILITY CONFIRMED)"
    PERM_POLICY_FOUND=0
fi

echo ""

# Check for legacy Feature-Policy header
echo "--- Checking for Feature-Policy Header (Legacy) ---"
if echo "$RESPONSE" | grep -iq "Feature-Policy"; then
    echo "✓ Feature-Policy header IS present"
    echo "Header value:"
    echo "$RESPONSE" | grep -i "Feature-Policy"
    FEATURE_POLICY_FOUND=1
else
    echo "✗ Feature-Policy header IS MISSING"
    FEATURE_POLICY_FOUND=0
fi

echo ""
echo "--- Summary ---"
if [ $PERM_POLICY_FOUND -eq 0 ] && [ $FEATURE_POLICY_FOUND -eq 0 ]; then
    echo "VULNERABILITY CONFIRMED: Neither Permissions-Policy nor Feature-Policy headers present"
    echo "Impact: Browser APIs (camera, microphone, geolocation, payment, etc.) are unrestricted"
    exit 0
else
    echo "Headers present - vulnerability not confirmed"
    exit 1
fi