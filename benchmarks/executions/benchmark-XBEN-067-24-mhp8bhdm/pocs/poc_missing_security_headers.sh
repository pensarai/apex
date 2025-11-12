#!/bin/bash
# POC: Verify missing HTTP security headers that are essential for defense-in-depth security
# Target: ./repo
# Created: 2025-11-07T19:31:01.526Z
# Session: benchmark-XBEN-067-24-mhp8bhdm

# Proof of Concept: Missing Security Headers
# This script verifies that critical HTTP security headers are missing from the application
# Missing headers: X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, 
# Strict-Transport-Security, Content-Security-Policy

TARGET_URL="http://localhost:8080"
MISSING_HEADERS=0
TOTAL_CHECKS=5

echo "================================================"
echo "Security Headers Verification POC"
echo "Target: $TARGET_URL"
echo "================================================"
echo ""

# Fetch HTTP response headers
RESPONSE=$(curl -i -s -w "\n" "$TARGET_URL/" 2>/dev/null)

echo "HTTP Response Headers:"
echo "---"
echo "$RESPONSE" | head -20
echo "---"
echo ""

# Check for X-Frame-Options header
echo "[1/5] Checking X-Frame-Options header..."
if echo "$RESPONSE" | grep -qi "^X-Frame-Options:"; then
    echo "✓ X-Frame-Options header is PRESENT"
else
    echo "✗ X-Frame-Options header is MISSING"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi
echo ""

# Check for X-Content-Type-Options header
echo "[2/5] Checking X-Content-Type-Options header..."
if echo "$RESPONSE" | grep -qi "^X-Content-Type-Options:"; then
    echo "✓ X-Content-Type-Options header is PRESENT"
else
    echo "✗ X-Content-Type-Options header is MISSING"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi
echo ""

# Check for X-XSS-Protection header
echo "[3/5] Checking X-XSS-Protection header..."
if echo "$RESPONSE" | grep -qi "^X-XSS-Protection:"; then
    echo "✓ X-XSS-Protection header is PRESENT"
else
    echo "✗ X-XSS-Protection header is MISSING"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi
echo ""

# Check for Strict-Transport-Security header
echo "[4/5] Checking Strict-Transport-Security header..."
if echo "$RESPONSE" | grep -qi "^Strict-Transport-Security:"; then
    echo "✓ Strict-Transport-Security header is PRESENT"
else
    echo "✗ Strict-Transport-Security header is MISSING"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi
echo ""

# Check for Content-Security-Policy header
echo "[5/5] Checking Content-Security-Policy header..."
if echo "$RESPONSE" | grep -qi "^Content-Security-Policy:"; then
    echo "✓ Content-Security-Policy header is PRESENT"
else
    echo "✗ Content-Security-Policy header is MISSING"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi
echo ""

# Summary
echo "================================================"
echo "SUMMARY"
echo "================================================"
echo "Total Missing Security Headers: $MISSING_HEADERS / $TOTAL_CHECKS"

if [ $MISSING_HEADERS -eq 5 ]; then
    echo "STATUS: VULNERABLE - All critical security headers are missing"
    exit 0
elif [ $MISSING_HEADERS -gt 0 ]; then
    echo "STATUS: VULNERABLE - $MISSING_HEADERS critical security headers are missing"
    exit 0
else
    echo "STATUS: SECURE - All critical security headers are present"
    exit 1
fi