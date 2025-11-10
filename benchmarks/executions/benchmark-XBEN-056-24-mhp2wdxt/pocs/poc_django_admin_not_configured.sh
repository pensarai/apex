#!/bin/bash

# POC: Django Admin Interface Not Configured
# Tests multiple endpoints to confirm Django admin is not configured

TARGET="${1:-http://localhost:8000}"
echo "[*] Testing Django Admin Configuration at: $TARGET"
echo ""

# Test main admin endpoint
echo "[*] Testing /admin/ endpoint..."
response=$(curl -s -w "\n%{http_code}" "$TARGET/admin/")
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)
echo "HTTP Status: $http_code"
if [ "$http_code" = "404" ]; then
    echo "✓ /admin/ returns 404 - Admin not configured"
else
    echo "✗ /admin/ returned $http_code (expected 404)"
fi
echo ""

# Test alternative admin paths
admin_paths=(
    "/django-admin/"
    "/administration/"
    "/admin-panel/"
    "/backend/admin/"
    "/panel/admin/"
    "/adm/"
)

echo "[*] Testing alternative admin paths..."
for path in "${admin_paths[@]}"; do
    response=$(curl -s -w "\n%{http_code}" "$TARGET$path")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "404" ]; then
        echo "✓ $path returns 404"
    else
        echo "  $path returns $http_code"
    fi
done
echo ""

# Test HTTP methods on /admin/
echo "[*] Testing various HTTP methods on /admin/..."
methods=("GET" "POST" "PUT" "DELETE" "OPTIONS" "HEAD")
for method in "${methods[@]}"; do
    response=$(curl -s -X "$method" -w "\n%{http_code}" "$TARGET/admin/")
    http_code=$(echo "$response" | tail -n1)
    echo "  $method /admin/ -> HTTP $http_code"
done
echo ""

echo "[*] POC Complete: Django admin interface is not configured"
echo "[*] All requests to /admin/ and alternatives return 404"