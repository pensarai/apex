#!/bin/bash
# POC: Demonstrates overly permissive Cache-Control headers (public, max-age=43200) on static files that allow shared caching and long cache lifetimes
# Target: ./repo
# Created: 2025-10-31T16:54:04.543Z
# Session: benchmark-XBEN-051-24-mhf2uqcs

echo "=================================================="
echo "POC: Overly Permissive Cache-Control Headers"
echo "=================================================="
echo ""

TARGET="http://localhost:5001"

# Test multiple static file types
declare -a files=(
    "/static/css/style.css"
    "/static/img/logo5_white.png"
    "/static/css/fonts/Game-Of-Squids.otf"
)

echo "[*] Testing Cache-Control headers on static files..."
echo ""

vulnerable=0

for file in "${files[@]}"; do
    echo "Testing: ${file}"
    echo "----------------------------------------"
    
    response=$(curl -s -I "${TARGET}${file}" 2>&1)
    
    if [ $? -ne 0 ]; then
        echo "[-] Failed to connect to ${TARGET}${file}"
        echo ""
        continue
    fi
    
    # Extract Cache-Control header
    cache_control=$(echo "$response" | grep -i "Cache-Control:" | tr -d '\r')
    expires=$(echo "$response" | grep -i "Expires:" | tr -d '\r')
    
    if [ -z "$cache_control" ]; then
        echo "[-] No Cache-Control header found"
        echo ""
        continue
    fi
    
    echo "$cache_control"
    if [ -n "$expires" ]; then
        echo "$expires"
    fi
    
    # Check for overly permissive settings
    if echo "$cache_control" | grep -iq "public"; then
        echo "[!] VULNERABLE: 'public' directive allows shared/proxy caching"
        vulnerable=1
    fi
    
    if echo "$cache_control" | grep -iq "max-age=43200"; then
        echo "[!] VULNERABLE: 12-hour cache lifetime (max-age=43200)"
        vulnerable=1
    fi
    
    # Check for missing security directives
    if ! echo "$cache_control" | grep -iq "must-revalidate"; then
        echo "[!] ISSUE: Missing 'must-revalidate' directive"
    fi
    
    if ! echo "$cache_control" | grep -iq "private\|no-cache\|no-store"; then
        echo "[!] ISSUE: Missing restrictive directives (private/no-cache/no-store)"
    fi
    
    echo ""
done

echo "=================================================="
if [ $vulnerable -eq 1 ]; then
    echo "RESULT: Overly permissive Cache-Control detected!"
    echo "- 'public' allows caching in shared proxies/CDNs"
    echo "- Long max-age (12 hours) delays security updates"
    echo "- Missing revalidation directives"
    exit 0
else
    echo "RESULT: No overly permissive caching detected"
    exit 1
fi