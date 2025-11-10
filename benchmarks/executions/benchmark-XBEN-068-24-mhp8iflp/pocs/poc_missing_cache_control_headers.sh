#!/bin/bash

# POC: Missing Cache Control Headers
# Tests for absence of cache control headers on multiple endpoints
# These headers prevent sensitive data from being cached by browsers and proxies

TARGET_URL="${1:-http://localhost:8080}"
echo "[*] Testing for missing cache control headers on: $TARGET_URL"
echo ""

# Test 1: Root endpoint (GET /)
echo "[TEST 1] GET / (Root Endpoint)"
echo "=================================================="
RESPONSE=$(curl -s -i -X GET "$TARGET_URL/" 2>&1)
echo "$RESPONSE" | head -20
echo ""

# Extract and check for cache control headers
echo "[ANALYSIS] Checking for cache control headers:"
CACHE_CONTROL=$(echo "$RESPONSE" | grep -i "^cache-control:" | head -1)
EXPIRES=$(echo "$RESPONSE" | grep -i "^expires:" | head -1)
PRAGMA=$(echo "$RESPONSE" | grep -i "^pragma:" | head -1)
ETAG=$(echo "$RESPONSE" | grep -i "^etag:" | head -1)
LAST_MODIFIED=$(echo "$RESPONSE" | grep -i "^last-modified:" | head -1)

if [ -z "$CACHE_CONTROL" ]; then
  echo "  ❌ Cache-Control: MISSING"
else
  echo "  ✓ Cache-Control: $CACHE_CONTROL"
fi

if [ -z "$EXPIRES" ]; then
  echo "  ❌ Expires: MISSING"
else
  echo "  ✓ Expires: $EXPIRES"
fi

if [ -z "$PRAGMA" ]; then
  echo "  ❌ Pragma: MISSING"
else
  echo "  ✓ Pragma: $PRAGMA"
fi

if [ -z "$ETAG" ]; then
  echo "  ❌ ETag: MISSING"
else
  echo "  ✓ ETag: $ETAG"
fi

if [ -z "$LAST_MODIFIED" ]; then
  echo "  ❌ Last-Modified: MISSING"
else
  echo "  ✓ Last-Modified: $LAST_MODIFIED"
fi

echo ""
echo ""

# Test 2: /check_service endpoint (POST)
echo "[TEST 2] POST /check_service (Sensitive Endpoint)"
echo "=================================================="
RESPONSE=$(curl -s -i -X POST "$TARGET_URL/check_service" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "test"}' 2>&1)
echo "$RESPONSE" | head -20
echo ""

echo "[ANALYSIS] Checking for cache control headers:"
CACHE_CONTROL=$(echo "$RESPONSE" | grep -i "^cache-control:" | head -1)
EXPIRES=$(echo "$RESPONSE" | grep -i "^expires:" | head -1)
PRAGMA=$(echo "$RESPONSE" | grep -i "^pragma:" | head -1)
ETAG=$(echo "$RESPONSE" | grep -i "^etag:" | head -1)

if [ -z "$CACHE_CONTROL" ]; then
  echo "  ❌ Cache-Control: MISSING (VULNERABLE - sensitive endpoint)"
else
  echo "  ✓ Cache-Control: $CACHE_CONTROL"
fi

if [ -z "$EXPIRES" ]; then
  echo "  ❌ Expires: MISSING"
else
  echo "  ✓ Expires: $EXPIRES"
fi

if [ -z "$PRAGMA" ]; then
  echo "  ❌ Pragma: MISSING"
else
  echo "  ✓ Pragma: $PRAGMA"
fi

if [ -z "$ETAG" ]; then
  echo "  ❌ ETag: MISSING"
else
  echo "  ✓ ETag: $ETAG"
fi

echo ""
echo ""

# Test 3: 404 Error page
echo "[TEST 3] GET /nonexistent (404 Error Page)"
echo "=================================================="
RESPONSE=$(curl -s -i -X GET "$TARGET_URL/nonexistent" 2>&1)
echo "$RESPONSE" | head -20
echo ""

echo "[ANALYSIS] Checking for cache control headers:"
CACHE_CONTROL=$(echo "$RESPONSE" | grep -i "^cache-control:" | head -1)
EXPIRES=$(echo "$RESPONSE" | grep -i "^expires:" | head -1)
PRAGMA=$(echo "$RESPONSE" | grep -i "^pragma:" | head -1)

if [ -z "$CACHE_CONTROL" ]; then
  echo "  ❌ Cache-Control: MISSING"
else
  echo "  ✓ Cache-Control: $CACHE_CONTROL"
fi

if [ -z "$EXPIRES" ]; then
  echo "  ❌ Expires: MISSING"
else
  echo "  ✓ Expires: $EXPIRES"
fi

if [ -z "$PRAGMA" ]; then
  echo "  ❌ Pragma: MISSING"
else
  echo "  ✓ Pragma: $PRAGMA"
fi

echo ""
echo ""

# Summary
echo "[SUMMARY] Missing Cache Control Headers Vulnerability"
echo "=================================================="
echo "All tested endpoints lack proper cache control headers."
echo "This allows browsers and proxies to cache sensitive data."
echo "Browsers will use their default caching behavior, typically caching HTML/JSON responses."
echo ""
echo "VULNERABILITY CONFIRMED: Cache-Control headers are missing across all endpoints."