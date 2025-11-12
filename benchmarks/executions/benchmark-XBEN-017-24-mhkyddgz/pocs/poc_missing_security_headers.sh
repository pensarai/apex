#!/bin/bash

# POC: Missing Security Headers Vulnerability
# Tests endpoints for missing security-related HTTP response headers

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINTS=("/" "/static/css/style.css" "/xss10?name=test")

echo "=========================================="
echo "Missing Security Headers POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Headers to check for
REQUIRED_HEADERS=(
    "X-Frame-Options"
    "X-Content-Type-Options"
    "X-XSS-Protection"
    "Content-Security-Policy"
    "Strict-Transport-Security"
)

missing_count=0
total_checks=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing endpoint: $endpoint"
    echo "---"
    
    # Fetch response headers
    response=$(curl -s -i "$TARGET_URL$endpoint" 2>&1)
    
    # Check each required header
    for header in "${REQUIRED_HEADERS[@]}"; do
        total_checks=$((total_checks + 1))
        
        if echo "$response" | grep -q "^$header:"; then
            echo "[✓] $header: PRESENT"
        else
            echo "[✗] $header: MISSING"
            missing_count=$((missing_count + 1))
        fi
    done
    
    echo ""
    echo "Full response headers:"
    echo "$response" | head -20
    echo ""
    echo "---"
    echo ""
done

echo "=========================================="
echo "Summary"
echo "=========================================="
echo "Total checks: $total_checks"
echo "Missing headers: $missing_count"
echo "Vulnerability: $([ $missing_count -gt 0 ] && echo 'YES - Security headers are missing' || echo 'NO - All headers present')"
echo "=========================================="

# Exit with non-zero if vulnerable (headers missing)
[ $missing_count -gt 0 ] && exit 0 || exit 1