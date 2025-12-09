#!/bin/bash

# POC: Missing Critical HTTP Security Headers
# Tests for absence of CSP, X-Frame-Options, X-Content-Type-Options, and HSTS headers
# Target: http://localhost:5000

TARGET_URL="http://localhost:5000"
ENDPOINTS=("/" "/list" "/about" "/add")
REQUIRED_HEADERS=("Content-Security-Policy" "X-Frame-Options" "X-Content-Type-Options" "Strict-Transport-Security")

echo "=========================================="
echo "Security Headers Vulnerability Scanner"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

MISSING_COUNT=0
TOTAL_CHECKS=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing endpoint: $endpoint"
    echo "---"
    
    # Fetch headers from the endpoint
    RESPONSE=$(curl -s -i "$TARGET_URL$endpoint" 2>/dev/null)
    
    if [ -z "$RESPONSE" ]; then
        echo "[ERROR] Failed to connect to $TARGET_URL$endpoint"
        echo ""
        continue
    fi
    
    # Extract headers (everything before the first blank line)
    HEADERS=$(echo "$RESPONSE" | head -n 100)
    
    # Check for each required header
    ENDPOINT_MISSING=0
    for header in "${REQUIRED_HEADERS[@]}"; do
        TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
        
        if echo "$HEADERS" | grep -qi "^$header:"; then
            echo "[PRESENT] $header: Found"
        else
            echo "[MISSING] $header: NOT FOUND"
            MISSING_COUNT=$((MISSING_COUNT + 1))
            ENDPOINT_MISSING=$((ENDPOINT_MISSING + 1))
        fi
    done
    
    echo ""
done

echo "=========================================="
echo "SUMMARY"
echo "=========================================="
echo "Total checks: $TOTAL_CHECKS"
echo "Missing headers: $MISSING_COUNT"
echo "Endpoints tested: ${#ENDPOINTS[@]}"
echo ""

if [ $MISSING_COUNT -gt 0 ]; then
    echo "[VULNERABLE] Critical security headers are missing!"
    echo "Percentage missing: $(( (MISSING_COUNT * 100) / TOTAL_CHECKS ))%"
    exit 0  # Exit 0 to indicate vulnerability confirmed
else
    echo "[SECURE] All security headers are present"
    exit 1
fi