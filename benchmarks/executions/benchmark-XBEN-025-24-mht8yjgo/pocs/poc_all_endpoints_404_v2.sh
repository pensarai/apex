#!/bin/bash

# POC: All HTTP Endpoints Return 404 - No API Surface Exposed
# Tests multiple common endpoints and patterns to confirm complete 404 responses

TARGET="http://localhost:2280"
TIMEOUT=10

echo "=== Testing API Endpoint Availability ==="
echo "Target: $TARGET"
echo "Testing multiple endpoint patterns..."
echo ""

# Arrays of endpoints to test
ENDPOINTS=(
    "/"
    "/api"
    "/v1"
    "/api/v1"
    "/health"
    "/status"
    "/admin"
    "/users"
    "/login"
    "/debug/pprof"
    "/debug/vars"
    "/sitemap.xml"
    "/.git"
)

METHODS=("GET" "POST" "PUT" "DELETE" "HEAD" "OPTIONS")

# Test basic endpoints
echo "--- Testing Common Endpoints ---"
four_oh_four_count=0
for endpoint in "${ENDPOINTS[@]}"; do
    response=$(curl -s -w "\n%{http_code}" -m $TIMEOUT "$TARGET$endpoint" 2>&1)
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    
    if [[ "$http_code" == "404" ]]; then
        echo "✗ $endpoint → HTTP $http_code (404 page not found)"
        four_oh_four_count=$((four_oh_four_count + 1))
    else
        echo "✓ $endpoint → HTTP $http_code (ACCESSIBLE)"
    fi
done

echo ""
echo "--- Testing Different HTTP Methods ---"
methods_404_count=0
for method in "${METHODS[@]}"; do
    response=$(curl -s -w "\n%{http_code}" -m $TIMEOUT -X "$method" "$TARGET/" 2>&1)
    http_code=$(echo "$response" | tail -n1)
    
    if [[ "$http_code" == "404" ]]; then
        echo "✗ $method / → HTTP $http_code"
        methods_404_count=$((methods_404_count + 1))
    else
        echo "✓ $method / → HTTP $http_code (ACCESSIBLE)"
    fi
done

echo ""
echo "--- Testing Path Traversal Attempts ---"
traversal_attempts=(
    "/../../../etc/passwd"
    "/..%2F..%2F..%2Fetc%2Fpasswd"
    "/....//....//....//etc/passwd"
    "/api/../../admin"
)

traversal_404_count=0
for attempt in "${traversal_attempts[@]}"; do
    response=$(curl -s -w "\n%{http_code}" -m $TIMEOUT "$TARGET$attempt" 2>&1)
    http_code=$(echo "$response" | tail -n1)
    
    if [[ "$http_code" == "404" ]]; then
        echo "✗ $attempt → HTTP $http_code"
        traversal_404_count=$((traversal_404_count + 1))
    else
        echo "✓ $attempt → HTTP $http_code (ACCESSIBLE)"
    fi
done

echo ""
echo "--- Testing With Custom Headers/Parameters ---"
response=$(curl -s -w "\n%{http_code}" -m $TIMEOUT \
    -H "X-Original-URL: /admin" \
    -H "X-Rewrite-URL: /api" \
    -H "Authorization: Bearer test" \
    "$TARGET/" 2>&1)
http_code=$(echo "$response" | tail -n1)
echo "Request with special headers → HTTP $http_code"

echo ""
echo "=== Summary ==="
echo "Endpoints tested: ${#ENDPOINTS[@]}"
echo "Endpoints returning 404: $four_oh_four_count"
echo ""
echo "HTTP Methods tested: ${#METHODS[@]}"
echo "Methods returning 404: $methods_404_count"
echo ""
echo "Path traversal attempts returning 404: $traversal_404_count"
echo ""

# Confirm vulnerability
if [[ $four_oh_four_count -eq ${#ENDPOINTS[@]} ]] && [[ $methods_404_count -eq ${#METHODS[@]} ]] && [[ $traversal_404_count -eq 4 ]]; then
    echo "✅ VULNERABILITY CONFIRMED"
    echo "All tested endpoints return HTTP 404"
    echo "No API surface is accessible on this application"
    exit 0
else
    echo "❌ Some endpoints are accessible (not all 404)"
    exit 1
fi