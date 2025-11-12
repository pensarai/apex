#!/bin/bash

# POC: Missing Subresource Integrity (SRI) on External CDN Resources
# This script verifies that external resources lack integrity attributes

TARGET="${1:-http://localhost:8080}"
TEMP_HTML=$(mktemp)
TEMP_CURL=$(mktemp)

echo "[*] Testing Missing Subresource Integrity (SRI) on External CDN Resources"
echo "[*] Target: $TARGET"
echo ""

# Fetch the HTML page
curl -s "$TARGET" > "$TEMP_HTML"

# Check if we got valid HTML content
if [ ! -s "$TEMP_HTML" ]; then
    echo "[-] Failed to retrieve HTML content from $TARGET"
    rm -f "$TEMP_HTML" "$TEMP_CURL"
    exit 1
fi

echo "[+] HTML page retrieved successfully"
echo ""

# Check for external resources without integrity attributes
echo "[*] Scanning for external CDN resources without SRI integrity..."
echo ""

# Arrays to store results
declare -a VULNERABLE_RESOURCES
declare -a resources_found=()

# Search for script tags with src attributes pointing to external CDNs
while IFS= read -r line; do
    if [[ $line =~ src=\"([^\"]+)\" ]]; then
        url="${BASH_REMATCH[1]}"
        # Check if it's an external resource
        if [[ $url =~ ^https?:// ]]; then
            # Check if it has integrity attribute
            if [[ ! $line =~ integrity ]]; then
                VULNERABLE_RESOURCES+=("$line")
                resources_found+=("$url")
                echo "[-] VULNERABLE (no SRI): $url"
            else
                echo "[+] PROTECTED (has SRI): $url"
            fi
        fi
    fi
done < <(grep -oP '<script[^>]*>' "$TEMP_HTML")

# Search for link tags with href attributes pointing to external CSS CDNs
while IFS= read -r line; do
    if [[ $line =~ href=\"([^\"]+)\" ]]; then
        url="${BASH_REMATCH[1]}"
        # Check if it's an external resource
        if [[ $url =~ ^https?:// ]]; then
            # Check if it has integrity attribute
            if [[ ! $line =~ integrity ]]; then
                VULNERABLE_RESOURCES+=("$line")
                resources_found+=("$url")
                echo "[-] VULNERABLE (no SRI): $url"
            else
                echo "[+] PROTECTED (has SRI): $url"
            fi
        fi
    fi
done < <(grep -oP '<link[^>]*>' "$TEMP_HTML")

echo ""
echo "[*] Summary:"
echo "    Total vulnerable resources found: ${#VULNERABLE_RESOURCES[@]}"

# Check for specific known CDNs mentioned in the evidence
echo ""
echo "[*] Checking for specific CDN resources from the evidence..."

SPECIFIC_CDNS=(
    "code.jquery.com"
    "cdn.jsdelivr.net"
    "stackpath.bootstrapcdn.com"
)

for cdn in "${SPECIFIC_CDNS[@]}"; do
    count=$(grep -c "$cdn" "$TEMP_HTML" || echo 0)
    if [ "$count" -gt 0 ]; then
        echo "[!] Found $count reference(s) to $cdn"
        grep -oP '<(?:script|link)[^>]*href?="[^"]*'"$cdn"'[^"]*"[^>]*>' "$TEMP_HTML" | while read -r resource; do
            if [[ ! $resource =~ integrity ]]; then
                echo "    [-] Missing SRI: $resource"
            else
                echo "    [+] Has SRI: $resource"
            fi
        done
    fi
done

echo ""

# Exit with success if vulnerabilities found
if [ ${#VULNERABLE_RESOURCES[@]} -gt 0 ]; then
    echo "[+] Missing SRI vulnerability confirmed - ${#VULNERABLE_RESOURCES[@]} external resource(s) without integrity attributes"
    rm -f "$TEMP_HTML" "$TEMP_CURL"
    exit 0
else
    echo "[*] No unprotected external resources detected"
    rm -f "$TEMP_HTML" "$TEMP_CURL"
    exit 1
fi