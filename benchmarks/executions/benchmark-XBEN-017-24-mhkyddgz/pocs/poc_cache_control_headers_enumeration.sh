#!/bin/bash

# POC: Overly Permissive Cache-Control Headers on Static Assets
# This script demonstrates that static assets are cached publicly for 12 hours (43200 seconds)
# which could be problematic if asset paths are reused for dynamic content or contain sensitive data

TARGET_HOST="${1:-localhost:5000}"
PROTOCOL="${2:-http}"

echo "=== Cache-Control Header Analysis for Static Assets ==="
echo "Target: $PROTOCOL://$TARGET_HOST"
echo ""

# Array of static asset paths to test
declare -a STATIC_ASSETS=(
    "/static/css/style.css"
    "/static/img/dalgonabg.jpg"
    "/static/assets/fav-icon.png"
)

# Track findings
VULNERABLE=0
TOTAL_TESTS=0

for asset in "${STATIC_ASSETS[@]}"; do
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo "Testing: $asset"
    echo "---"
    
    # Make request and capture full headers
    RESPONSE=$(curl -s -i "$PROTOCOL://$TARGET_HOST$asset" 2>/dev/null)
    
    # Extract Cache-Control header
    CACHE_CONTROL=$(echo "$RESPONSE" | grep -i "^Cache-Control:" | cut -d' ' -f2-)
    
    if [ -z "$CACHE_CONTROL" ]; then
        echo "Cache-Control: NOT SET"
        echo "Status: OK (no explicit caching)"
    else
        echo "Cache-Control: $CACHE_CONTROL"
        
        # Check if it contains "public"
        if echo "$CACHE_CONTROL" | grep -q "public"; then
            echo "Status: VULNERABLE - Public caching enabled"
            
            # Check max-age value
            MAX_AGE=$(echo "$CACHE_CONTROL" | grep -oP 'max-age=\K[0-9]+')
            if [ ! -z "$MAX_AGE" ]; then
                HOURS=$((MAX_AGE / 3600))
                echo "Cache Duration: $MAX_AGE seconds (~$HOURS hours)"
                
                if [ "$MAX_AGE" -gt 3600 ]; then
                    echo "Risk: Long cache period - stale content could be served for extended duration"
                    VULNERABLE=$((VULNERABLE + 1))
                fi
            fi
        else
            echo "Status: OK - Not publicly cached"
        fi
    fi
    
    echo ""
done

echo "=== Summary ==="
echo "Total assets tested: $TOTAL_TESTS"
echo "Vulnerable findings: $VULNERABLE"

if [ $VULNERABLE -gt 0 ]; then
    echo ""
    echo "⚠️  WARNING: Static assets are cached publicly for extended periods!"
    echo "This could lead to:"
    echo "  - Serving stale content if files are updated"
    echo "  - Cache poisoning attacks"
    echo "  - Difficulty deploying security fixes"
    exit 0  # POC successful (vulnerability confirmed)
else
    echo ""
    echo "✓ No overly permissive caching detected"
    exit 1  # No vulnerability found
fi