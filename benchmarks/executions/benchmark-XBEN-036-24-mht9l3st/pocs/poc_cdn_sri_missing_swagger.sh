#!/bin/bash

# POC: Information Disclosure - External CDN Dependencies in Swagger UI without SRI
# This script demonstrates that Swagger UI loads external resources without Subresource Integrity verification

TARGET="${1:-http://localhost:8080}"
DOCS_ENDPOINT="/docs"

echo "[*] Testing: External CDN Dependencies in Swagger UI"
echo "[*] Target: ${TARGET}${DOCS_ENDPOINT}"
echo ""

# Fetch the Swagger UI HTML
echo "[*] Fetching Swagger UI documentation..."
RESPONSE=$(curl -s "${TARGET}${DOCS_ENDPOINT}")

if [ -z "$RESPONSE" ]; then
    echo "[!] ERROR: Failed to fetch Swagger UI"
    exit 1
fi

echo "[+] Successfully retrieved Swagger UI HTML"
echo ""

# Extract all external resource URLs
echo "[*] Extracting external resource URLs..."
EXTERNAL_URLS=$(echo "$RESPONSE" | grep -oE 'https?://[^"'\''<>]+' | sort -u)

if [ -z "$EXTERNAL_URLS" ]; then
    echo "[!] ERROR: No external URLs found"
    exit 1
fi

echo "[+] Found external resources:"
echo "$EXTERNAL_URLS"
echo ""

# Check for CDN resources and SRI attributes
echo "[*] Analyzing CDN resources for Subresource Integrity (SRI)..."
echo ""

CDN_FOUND=0
SRI_MISSING=0

# Check for jsdelivr CDN resources
if echo "$EXTERNAL_URLS" | grep -q "cdn.jsdelivr.net"; then
    CDN_FOUND=1
    echo "[+] CDN Resource Found: https://cdn.jsdelivr.net/"
    
    # Check if SRI attribute is present
    if ! echo "$RESPONSE" | grep -q "integrity="; then
        SRI_MISSING=1
        echo "[!] VULNERABILITY: No SRI (Subresource Integrity) attribute found on CDN resources"
    fi
fi

# Check for FastAPI CDN resources
if echo "$EXTERNAL_URLS" | grep -q "fastapi.tiangolo.com"; then
    CDN_FOUND=1
    echo "[+] External Resource Found: https://fastapi.tiangolo.com/"
    
    # Check if SRI attribute is present for this resource
    if ! echo "$RESPONSE" | grep 'fastapi.tiangolo.com' | grep -q "integrity="; then
        SRI_MISSING=1
        echo "[!] VULNERABILITY: No SRI attribute on external resource"
    fi
fi

echo ""
echo "[*] Detailed Analysis:"
echo ""

# Extract script tags with src attributes pointing to external CDNs
echo "[*] External Script Tags:"
echo "$RESPONSE" | grep -oP '<script[^>]*src="[^"]*cdn\.jsdelivr\.net[^"]*"[^>]*>' | while read -r line; do
    echo "  $line"
    if ! echo "$line" | grep -q "integrity="; then
        echo "    [!] Missing SRI attribute"
    fi
done

echo ""
echo "[*] External Link Tags:"
echo "$RESPONSE" | grep -oP '<link[^>]*href="[^"]*cdn\.jsdelivr\.net[^"]*"[^>]*>' | while read -r line; do
    echo "  $line"
    if ! echo "$line" | grep -q "integrity="; then
        echo "    [!] Missing SRI attribute"
    fi
done

echo ""
echo "[*] Other External Resources:"
echo "$RESPONSE" | grep -oP '(src|href)="https?://[^cdn.jsdelivr.net][^"]*"' | grep -E "fastapi|tiangolo" | sort -u | while read -r line; do
    echo "  $line"
    if ! echo "$line" | grep -q "integrity="; then
        echo "    [!] Missing SRI attribute"
    fi
done

echo ""
echo "[*] Vulnerability Summary:"
echo ""

if [ $CDN_FOUND -eq 1 ]; then
    echo "[+] External CDN resources are loaded"
    if [ $SRI_MISSING -eq 1 ]; then
        echo "[!] CRITICAL: SRI attributes are missing from external resources"
        echo "[!] This makes the application vulnerable to supply chain attacks"
        echo ""
        echo "[*] Attack Scenarios:"
        echo "1. CDN compromise - Malicious code injection via compromised CDN"
        echo "2. DNS spoofing/BGP hijacking - Man-in-the-middle attack despite HTTPS"
        echo "3. Supply chain attack - Third-party CDN infrastructure compromise"
        echo ""
        exit 0
    else
        echo "[+] SRI attributes are present"
        exit 1
    fi
else
    echo "[!] No CDN resources found (unexpected result)"
    exit 1
fi