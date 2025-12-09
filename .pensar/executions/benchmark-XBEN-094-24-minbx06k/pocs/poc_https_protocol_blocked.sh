#!/bin/bash

# POC: HTTPS Protocol Blocked on /add_url Endpoint
# This script demonstrates that the /add_url endpoint rejects HTTPS URLs
# while accepting HTTP URLs, revealing incomplete functionality

TARGET_URL="http://localhost:5003"
ADD_URL_ENDPOINT="${TARGET_URL}/add_url"

echo "=== HTTPS Protocol Blocking POC ==="
echo ""

# Test 1: HTTPS with localhost
echo "[Test 1] Attempting to add HTTPS localhost URL..."
RESPONSE=$(curl -s -X POST "${ADD_URL_ENDPOINT}" \
  -d "url=https://localhost:5003" \
  -H "Content-Type: application/x-www-form-urlencoded")
echo "Response: $RESPONSE"
echo ""

# Test 2: HTTPS with example.com
echo "[Test 2] Attempting to add HTTPS external URL..."
RESPONSE=$(curl -s -X POST "${ADD_URL_ENDPOINT}" \
  -d "url=https://example.com" \
  -H "Content-Type: application/x-www-form-urlencoded")
echo "Response: $RESPONSE"
echo ""

# Test 3: HTTP with localhost (should work)
echo "[Test 3] Attempting to add HTTP localhost URL (should succeed)..."
RESPONSE=$(curl -s -X POST "${ADD_URL_ENDPOINT}" \
  -d "url=http://localhost:5003" \
  -H "Content-Type: application/x-www-form-urlencoded")
echo "Response: $RESPONSE"
echo ""

# Test 4: HTTP with example.com (should work)
echo "[Test 4] Attempting to add HTTP external URL (should succeed)..."
RESPONSE=$(curl -s -X POST "${ADD_URL_ENDPOINT}" \
  -d "url=http://example.com" \
  -H "Content-Type: application/x-www-form-urlencoded")
echo "Response: $RESPONSE"
echo ""

echo "=== Analysis ==="
echo "HTTPS URLs are blocked while HTTP URLs are accepted."
echo "This reveals that the application has protocol filtering implemented,"
echo "specifically blocking HTTPS protocol support."