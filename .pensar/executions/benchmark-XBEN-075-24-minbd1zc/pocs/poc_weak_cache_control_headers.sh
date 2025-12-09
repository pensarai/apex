#!/bin/bash

# POC: Weak Cache Control Headers Configuration
# This script demonstrates that the application uses weak and conflicting cache control headers
# on sensitive endpoints, allowing inappropriate caching by proxies and browsers

TARGET="${1:-http://localhost:5000}"
ENDPOINTS=("/" "/list" "/add" "/about")

echo "=========================================="
echo "Cache Control Headers Vulnerability POC"
echo "=========================================="
echo "Target: $TARGET"
echo ""

# Color codes for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

VULNERABLE=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo -e "${YELLOW}Testing endpoint: $endpoint${NC}"
    
    # Get response headers
    response=$(curl -s -i "$TARGET$endpoint" 2>&1)
    
    # Extract cache control headers
    cache_control=$(echo "$response" | grep -i "^Cache-Control:" | head -1)
    pragma=$(echo "$response" | grep -i "^Pragma:" | head -1)
    expires=$(echo "$response" | grep -i "^Expires:" | head -1)
    
    echo "  Cache-Control: $cache_control"
    echo "  Pragma: $pragma"
    echo "  Expires: $expires"
    
    # Check for vulnerabilities
    if echo "$cache_control" | grep -q "public"; then
        if echo "$cache_control" | grep -q "max-age=0"; then
            echo -e "  ${RED}[VULNERABLE]${NC} Contradictory headers: 'public' with 'max-age=0'"
            VULNERABLE=$((VULNERABLE + 1))
        fi
    fi
    
    if echo "$cache_control" | grep -q "public"; then
        # Check if this is a sensitive endpoint
        if [[ "$endpoint" == "/list" ]] || [[ "$endpoint" == "/add" ]]; then
            echo -e "  ${RED}[VULNERABLE]${NC} Sensitive endpoint marked as 'public' - should be 'private'"
            VULNERABLE=$((VULNERABLE + 1))
        fi
    fi
    
    if echo "$pragma" | grep -q "no-cache"; then
        echo -e "  ${YELLOW}[WARNING]${NC} Deprecated 'Pragma' header used - use only Cache-Control"
    fi
    
    if echo "$response" | grep -q "Pragma:"; then
        if ! echo "$response" | grep -q "Cache-Control: private"; then
            echo -e "  ${RED}[VULNERABLE]${NC} Multiple conflicting cache directives present"
            VULNERABLE=$((VULNERABLE + 1))
        fi
    fi
    
    echo ""
done

echo "=========================================="
echo "Summary:"
echo "=========================================="
echo -e "Total vulnerabilities found: ${RED}$VULNERABLE${NC}"
echo ""

if [ $VULNERABLE -gt 0 ]; then
    echo -e "${RED}[VULNERABILITY CONFIRMED]${NC} The application uses weak cache control headers:"
    echo "  1. 'public' directive allows shared caches to store sensitive user data"
    echo "  2. Contradictory max-age=0 with 'public' creates confusion"
    echo "  3. Sensitive endpoints (/list, /add) should NOT be publicly cacheable"
    echo "  4. Deprecated Pragma header indicates outdated implementation"
    echo "  5. Multiple conflicting directives may confuse browsers/proxies"
    exit 0
else
    echo -e "${GREEN}[OK]${NC} No weak cache control header issues detected"
    exit 1
fi