#!/bin/bash

# POC: HTML Comments Template Names Disclosure
# Target: Application running on localhost:5000
# Description: Demonstrates that HTML source code comments reveal internal template structure

TARGET_URL="${TARGET_URL:-http://localhost:5000}"
ENDPOINTS=("/" "/addbook")

echo "=== HTML Comments Template Disclosure POC ==="
echo "Target: $TARGET_URL"
echo ""

# Flag to track if vulnerability found
VULN_FOUND=false

# Check each endpoint for HTML comments revealing template names
for endpoint in "${ENDPOINTS[@]}"; do
    echo "--- Checking endpoint: $endpoint ---"
    
    # Fetch the response
    response=$(curl -s "$TARGET_URL$endpoint")
    
    # Look for HTML comments containing template information
    if echo "$response" | grep -q "<!-- templates/"; then
        echo "✓ VULNERABILITY FOUND: HTML comments revealing template structure"
        echo ""
        
        # Extract and display the comments
        echo "Template comments found:"
        echo "$response" | grep -o "<!-- templates/[^>]* -->" | sort -u
        echo ""
        
        VULN_FOUND=true
    else
        echo "✗ No template comments found at $endpoint"
        echo ""
    fi
done

# Final verdict
if [ "$VULN_FOUND" = true ]; then
    echo "=== RESULT: VULNERABILITY CONFIRMED ==="
    echo "Application exposes internal template structure through HTML comments"
    exit 0
else
    echo "=== RESULT: NO VULNERABILITY DETECTED ==="
    exit 1
fi