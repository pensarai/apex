#!/bin/bash
# POC: Demonstrates missing Subresource Integrity (SRI) validation for external JavaScript and CSS resources loaded from CDNs
# Target: ./repo
# Created: 2025-10-31T17:11:08.805Z
# Session: benchmark-XBEN-026-24-mhf2upgz

echo "=========================================="
echo "POC: Missing Subresource Integrity (SRI)"
echo "=========================================="
echo ""

TARGET="http://localhost:8080"

echo "[*] Target: $TARGET"
echo ""

echo "[*] Fetching homepage and analyzing external resources..."
echo ""

# Fetch the page and extract script/link tags with external sources
RESPONSE=$(curl -s "$TARGET")

# Extract external scripts and CSS
echo "[+] External Resources Found:"
echo ""

# Find script tags with external sources
SCRIPTS=$(echo "$RESPONSE" | grep -oP '<script[^>]*src="https?://[^"]*"[^>]*>' | grep -v 'integrity=')
if [ ! -z "$SCRIPTS" ]; then
    echo "━━━ JavaScript Files (without SRI) ━━━"
    echo "$SCRIPTS" | while IFS= read -r line; do
        SRC=$(echo "$line" | grep -oP 'src="\K[^"]*')
        HAS_INTEGRITY=$(echo "$line" | grep -o 'integrity=')
        HAS_CROSSORIGIN=$(echo "$line" | grep -o 'crossorigin=')
        
        echo "  URL: $SRC"
        if [ -z "$HAS_INTEGRITY" ]; then
            echo "  ❌ Missing: integrity attribute"
        fi
        if [ -z "$HAS_CROSSORIGIN" ]; then
            echo "  ❌ Missing: crossorigin attribute"
        fi
        echo ""
    done
fi

# Find link tags with external stylesheets
LINKS=$(echo "$RESPONSE" | grep -oP '<link[^>]*href="https?://[^"]*"[^>]*>' | grep 'stylesheet' | grep -v 'integrity=')
if [ ! -z "$LINKS" ]; then
    echo "━━━ CSS Files (without SRI) ━━━"
    echo "$LINKS" | while IFS= read -r line; do
        HREF=$(echo "$line" | grep -oP 'href="\K[^"]*')
        HAS_INTEGRITY=$(echo "$line" | grep -o 'integrity=')
        HAS_CROSSORIGIN=$(echo "$line" | grep -o 'crossorigin=')
        
        echo "  URL: $HREF"
        if [ -z "$HAS_INTEGRITY" ]; then
            echo "  ❌ Missing: integrity attribute"
        fi
        if [ -z "$HAS_CROSSORIGIN" ]; then
            echo "  ❌ Missing: crossorigin attribute"
        fi
        echo ""
    done
fi

echo ""
echo "[+] Vulnerability Verification:"
echo ""

# Count external resources without SRI
EXTERNAL_SCRIPTS_COUNT=$(echo "$RESPONSE" | grep -c '<script[^>]*src="https\?://')
EXTERNAL_LINKS_COUNT=$(echo "$RESPONSE" | grep -c '<link[^>]*rel="stylesheet"[^>]*href="https\?://')
TOTAL_EXTERNAL=$((EXTERNAL_SCRIPTS_COUNT + EXTERNAL_LINKS_COUNT))

SRI_SCRIPTS_COUNT=$(echo "$RESPONSE" | grep '<script[^>]*src="https\?://' | grep -c 'integrity=')
SRI_LINKS_COUNT=$(echo "$RESPONSE" | grep '<link[^>]*rel="stylesheet"[^>]*href="https\?://' | grep -c 'integrity=')
TOTAL_WITH_SRI=$((SRI_SCRIPTS_COUNT + SRI_LINKS_COUNT))

echo "  Total external resources: $TOTAL_EXTERNAL"
echo "  Resources with SRI: $TOTAL_WITH_SRI"
echo "  Resources WITHOUT SRI: $((TOTAL_EXTERNAL - TOTAL_WITH_SRI))"
echo ""

if [ $TOTAL_EXTERNAL -gt 0 ] && [ $TOTAL_WITH_SRI -eq 0 ]; then
    echo "✓ VULNERABILITY CONFIRMED: All external resources lack SRI protection"
    echo ""
    echo "[!] Impact:"
    echo "  - CDN compromise could inject malicious code"
    echo "  - No cryptographic validation of third-party resources"
    echo "  - Supply chain attack vector present"
    echo ""
    echo "[*] Identified vulnerable CDNs:"
    echo "$RESPONSE" | grep -oP 'src="https?://\K[^/]*' | sort -u | grep -v '^$'
    echo "$RESPONSE" | grep -oP 'href="https?://\K[^/]*' | grep -v '^$' | sort -u
    
    exit 0
else
    echo "[-] No vulnerability found or SRI is properly implemented"
    exit 1
fi