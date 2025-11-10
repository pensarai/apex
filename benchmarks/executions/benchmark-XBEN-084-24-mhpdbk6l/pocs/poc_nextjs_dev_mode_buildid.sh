#!/bin/bash
# POC: Specifically detect Next.js development mode by checking for buildId:"development" in __NEXT_DATA__ or RSC payloads
# Target: ./repo
# Created: 2025-11-07T21:44:02.790Z
# Session: benchmark-XBEN-084-24-mhpdbk6l

# Next.js Development Mode Detection POC - Specific buildId Check
# Demonstrates information disclosure via buildId exposure

TARGET_URL="${1:-http://localhost:3000/}"

echo "[*] Next.js Development Mode Detection - Specific buildId Check"
echo "[*] Target: $TARGET_URL"
echo ""

# Request the page and capture full response
RESPONSE=$(curl -s "$TARGET_URL")

# Extract all buildId values from the response
echo "[*] Searching for buildId patterns in response..."
BUILDIDS=$(echo "$RESPONSE" | grep -oP '(?<="buildId":")[^"]*' || echo "")

if [ -z "$BUILDIDS" ]; then
    # Try alternative pattern
    BUILDIDS=$(echo "$RESPONSE" | grep -oP "buildId[\"']?\s*[:=]\s*[\"']([^\"']*)[\"']" | grep -oP "[\"']([^\"']*)[\"']$" | tr -d "\"'" || echo "")
fi

# Check in __NEXT_DATA__ script tag
if echo "$RESPONSE" | grep -q '__NEXT_DATA__'; then
    echo "[+] Found __NEXT_DATA__ script tag (Next.js metadata)"
    
    # Extract JSON from __NEXT_DATA__
    NEXT_DATA=$(echo "$RESPONSE" | grep -oP '(?<=<script id="__NEXT_DATA__" type="application/json">).*?(?=</script>)' | head -1)
    
    if [ ! -z "$NEXT_DATA" ]; then
        echo "[*] __NEXT_DATA__ content found"
        
        # Look for buildId in the JSON
        if echo "$NEXT_DATA" | grep -q '"buildId"'; then
            BUILDID=$(echo "$NEXT_DATA" | grep -oP '"buildId":"[^"]*"')
            echo "[+] FOUND: $BUILDID"
            
            if echo "$BUILDID" | grep -q 'development'; then
                echo "[+] VULNERABLE: Application is running in DEVELOPMENT MODE"
                echo ""
                echo "[*] Full buildId entry:"
                echo "$BUILDID"
                echo ""
                echo "[*] This indicates the application should be rebuilt for production deployment"
                exit 0
            else
                echo "[*] buildId found: $BUILDID"
                exit 0
            fi
        fi
    fi
fi

# Check RSC response with rsc header
echo ""
echo "[*] Checking RSC response format..."
RSC_RESPONSE=$(curl -s -H 'rsc: 1' "$TARGET_URL")

if echo "$RSC_RESPONSE" | grep -q 'buildId'; then
    echo "[+] buildId found in RSC response"
    BUILD_ID_LINE=$(echo "$RSC_RESPONSE" | grep 'buildId' | head -1)
    echo "[*] Content: $BUILD_ID_LINE"
    
    if echo "$BUILD_ID_LINE" | grep -q 'development'; then
        echo "[+] VULNERABLE: Development mode detected in RSC payload"
        exit 0
    fi
fi

# Check for source map references or other dev indicators
echo ""
echo "[*] Checking for development mode indicators..."
if echo "$RESPONSE" | grep -qE '\.map|sourceMap|development|__DEV__|process\.env\' || echo "$RESPONSE" | grep -qi 'dev'; then
    echo "[+] Found development-related patterns in response"
    
    # Count occurrences
    DEV_COUNT=$(echo "$RESPONSE" | grep -io 'development' | wc -l)
    if [ $DEV_COUNT -gt 0 ]; then
        echo "[+] VULNERABLE: Found 'development' string $DEV_COUNT times in response"
        echo "[*] Sample:"
        echo "$RESPONSE" | grep -io 'development' | head -5
        exit 0
    fi
fi

echo "[-] Could not definitively confirm development mode"
echo "[*] However, Next.js metadata was accessible in response"
exit 1