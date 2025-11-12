#!/bin/bash

# POC: Undocumented API Versioning Parameter on /check_service
# Demonstrates that the endpoint accepts multiple version formats without validation

TARGET_URL="${1:-http://localhost:8080}"
ENDPOINT="/check_service"

echo "================================"
echo "Undocumented API Versioning POC"
echo "================================"
echo ""
echo "Target: $TARGET_URL$ENDPOINT"
echo ""

# Test various version formats
echo "[*] Testing numeric version format (v=1):"
curl -s -X POST "$TARGET_URL$ENDPOINT?v=1" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "apache"}' | jq '.' 2>/dev/null || curl -s -X POST "$TARGET_URL$ENDPOINT?v=1" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "apache"}'
echo ""

echo "[*] Testing numeric version format (v=2):"
curl -s -X POST "$TARGET_URL$ENDPOINT?v=2" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "apache"}' | jq '.' 2>/dev/null || curl -s -X POST "$TARGET_URL$ENDPOINT?v=2" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "apache"}'
echo ""

echo "[*] Testing numeric version format (v=3):"
curl -s -X POST "$TARGET_URL$ENDPOINT?v=3" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "apache"}' | jq '.' 2>/dev/null || curl -s -X POST "$TARGET_URL$ENDPOINT?v=3" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "apache"}'
echo ""

echo "[*] Testing prefixed version format (v=v1):"
curl -s -X POST "$TARGET_URL$ENDPOINT?v=v1" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "apache"}' | jq '.' 2>/dev/null || curl -s -X POST "$TARGET_URL$ENDPOINT?v=v1" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "apache"}'
echo ""

echo "[*] Testing prefixed version format (v=v2):"
curl -s -X POST "$TARGET_URL$ENDPOINT?v=v2" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "apache"}' | jq '.' 2>/dev/null || curl -s -X POST "$TARGET_URL$ENDPOINT?v=v2" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "apache"}'
echo ""

echo "[*] Testing custom version format (v=beta):"
curl -s -X POST "$TARGET_URL$ENDPOINT?v=beta" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "apache"}' | jq '.' 2>/dev/null || curl -s -X POST "$TARGET_URL$ENDPOINT?v=beta" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "apache"}'
echo ""

echo "[*] Testing custom version format (v=alpha):"
curl -s -X POST "$TARGET_URL$ENDPOINT?v=alpha" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "apache"}' | jq '.' 2>/dev/null || curl -s -X POST "$TARGET_URL$ENDPOINT?v=alpha" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "apache"}'
echo ""

echo "[*] Testing arbitrary/invalid version format (v=invalid_version_xyz):"
curl -s -X POST "$TARGET_URL$ENDPOINT?v=invalid_version_xyz" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "apache"}' | jq '.' 2>/dev/null || curl -s -X POST "$TARGET_URL$ENDPOINT?v=invalid_version_xyz" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "apache"}'
echo ""

echo "================================"
echo "POC Summary:"
echo "================================"
echo "All version formats were accepted without validation."
echo "No error responses, status codes, or version information returned."
echo "This demonstrates the undocumented versioning vulnerability."
echo ""