#!/bin/bash

# POC: Schema Accuracy Mismatch for /ping Endpoint
# This script demonstrates the discrepancy between the documented OpenAPI schema
# and the actual response from the /ping endpoint

TARGET_URL="${1:-http://localhost:8080}"

echo "=========================================="
echo "Schema Accuracy Mismatch POC"
echo "=========================================="
echo ""

# Step 1: Fetch the OpenAPI schema
echo "[*] Fetching OpenAPI schema from /openapi.json..."
SCHEMA=$(curl -s "${TARGET_URL}/openapi.json")

if [ -z "$SCHEMA" ]; then
    echo "[!] Failed to fetch OpenAPI schema"
    exit 1
fi

# Step 2: Extract the /ping endpoint response schema
echo "[*] Extracting /ping endpoint schema definition..."
PING_SCHEMA=$(echo "$SCHEMA" | jq -r '.paths["/ping"].get.responses["200"].content["application/json"].schema' 2>/dev/null)

if [ -z "$PING_SCHEMA" ] || [ "$PING_SCHEMA" = "null" ]; then
    echo "[!] Could not extract schema, trying alternative path..."
    PING_SCHEMA=$(echo "$SCHEMA" | jq -r '.paths["/ping"]' 2>/dev/null)
fi

echo "[+] Documented OpenAPI Schema for /ping:"
echo "$PING_SCHEMA" | jq '.' 2>/dev/null || echo "$PING_SCHEMA"
echo ""

# Step 3: Get actual response from /ping endpoint
echo "[*] Fetching actual response from /ping endpoint..."
ACTUAL_RESPONSE=$(curl -s "${TARGET_URL}/ping")

echo "[+] Actual /ping Response:"
echo "$ACTUAL_RESPONSE" | jq '.' 2>/dev/null || echo "$ACTUAL_RESPONSE"
echo ""

# Step 4: Compare
echo "[*] Comparison:"
echo "=========================================="

# Check if schema is empty object
if echo "$PING_SCHEMA" | grep -q '{}'; then
    echo "[!] DISCREPANCY FOUND:"
    echo "    - OpenAPI Schema: {} (empty object)"
    echo "    - Actual Response Properties: $(echo "$ACTUAL_RESPONSE" | jq 'keys' 2>/dev/null || echo 'unknown')"
    echo ""
    echo "[!] The schema fails to document the actual response structure."
    echo "[!] Expected schema should define properties: ping (string)"
    exit 0
elif echo "$PING_SCHEMA" | grep -q '"properties"'; then
    echo "[+] Schema includes property definitions"
    echo "[+] Checking if all response properties are documented..."
    ACTUAL_KEYS=$(echo "$ACTUAL_RESPONSE" | jq 'keys | .[]' 2>/dev/null | tr '\n' ',' | sed 's/,$//')
    echo "    Actual response keys: $ACTUAL_KEYS"
    SCHEMA_KEYS=$(echo "$PING_SCHEMA" | jq '.properties | keys | .[]' 2>/dev/null | tr '\n' ',' | sed 's/,$//')
    echo "    Schema documented keys: $SCHEMA_KEYS"
    if [ "$ACTUAL_KEYS" != "$SCHEMA_KEYS" ]; then
        echo "[!] Mismatch between actual and documented properties"
        exit 0
    else
        echo "[+] Schema matches actual response"
        exit 1
    fi
else
    echo "[*] Schema type: $PING_SCHEMA"
    echo "[!] Cannot determine if schema matches response"
    exit 1
fi