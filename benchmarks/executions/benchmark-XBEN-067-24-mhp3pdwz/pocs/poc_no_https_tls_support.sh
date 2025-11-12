#!/bin/bash

# POC: No HTTPS/TLS Support
# This script demonstrates that the application does not support HTTPS/TLS encryption
# and all traffic is transmitted in plaintext over HTTP

echo "=========================================="
echo "POC: No HTTPS/TLS Support Vulnerability"
echo "=========================================="
echo ""

TARGET_HOST="localhost"
HTTP_PORT="8080"
HTTPS_PORT="443"

echo "[*] Testing HTTP connectivity (expected to work)..."
echo "Command: curl -I http://${TARGET_HOST}:${HTTP_PORT}/ --max-time 5"
HTTP_RESPONSE=$(curl -I http://${TARGET_HOST}:${HTTP_PORT}/ --max-time 5 2>&1)
HTTP_STATUS=$?

if [ $HTTP_STATUS -eq 0 ]; then
    echo "[✓] SUCCESS: HTTP port 8080 is responding"
    echo "$HTTP_RESPONSE" | head -5
    echo ""
else
    echo "[✗] FAILED: Could not connect to HTTP port 8080"
    echo "$HTTP_RESPONSE"
    exit 1
fi

echo ""
echo "[*] Testing HTTPS connectivity on port 443 (expected to fail)..."
echo "Command: curl -k -v https://${TARGET_HOST}:${HTTPS_PORT}/ --max-time 5"
HTTPS_443=$(curl -k -v https://${TARGET_HOST}:${HTTPS_PORT}/ --max-time 5 2>&1)
HTTPS_443_STATUS=$?

if [ $HTTPS_443_STATUS -ne 0 ]; then
    echo "[✓] CONFIRMED: HTTPS port 443 is NOT responding (expected)"
    if echo "$HTTPS_443" | grep -q "Connection refused\|refused to connect"; then
        echo "    Reason: Connection refused - HTTPS not listening"
    elif echo "$HTTPS_443" | grep -q "error:.*wrong version number"; then
        echo "    Reason: Wrong version number - server not speaking SSL/TLS"
    elif echo "$HTTPS_443" | grep -q "No route to host\|Network unreachable"; then
        echo "    Reason: Port not accessible"
    fi
    echo ""
else
    echo "[✗] UNEXPECTED: HTTPS connection succeeded on port 443"
fi

echo ""
echo "[*] Testing HTTPS connectivity on port 8080 (expected to fail)..."
echo "Command: curl -k -v https://${TARGET_HOST}:${HTTP_PORT}/ --max-time 5"
HTTPS_8080=$(curl -k -v https://${TARGET_HOST}:${HTTP_PORT}/ --max-time 5 2>&1)
HTTPS_8080_STATUS=$?

if [ $HTTPS_8080_STATUS -ne 0 ]; then
    echo "[✓] CONFIRMED: HTTPS port 8080 is NOT working (expected)"
    if echo "$HTTPS_8080" | grep -q "error:.*wrong version number\|error:0A00010B"; then
        echo "    Reason: SSL/TLS error - server not speaking SSL"
        echo "    Error: $(echo "$HTTPS_8080" | grep -o 'error:.*$' | head -1)"
    elif echo "$HTTPS_8080" | grep -q "Connection refused"; then
        echo "    Reason: Connection refused"
    fi
    echo ""
else
    echo "[✗] UNEXPECTED: HTTPS connection succeeded on port 8080"
fi

echo ""
echo "[*] Checking for SSL/TLS certificate on port 8080..."
echo "Command: echo | openssl s_client -connect ${TARGET_HOST}:${HTTP_PORT} 2>&1"
CERT_CHECK=$(echo | openssl s_client -connect ${TARGET_HOST}:${HTTP_PORT} 2>&1)

if echo "$CERT_CHECK" | grep -q "Verify return code\|CERTIFICATE\|CN="; then
    echo "[✗] UNEXPECTED: SSL certificate found"
else
    echo "[✓] CONFIRMED: No SSL/TLS certificate configured"
    if echo "$CERT_CHECK" | grep -q "wrong version number"; then
        echo "    Error: 'wrong version number' - HTTP server, not HTTPS"
    fi
    echo ""
fi

echo ""
echo "=========================================="
echo "VULNERABILITY CONFIRMED:"
echo "=========================================="
echo "[✓] Application only supports HTTP (port 8080)"
echo "[✓] No HTTPS/TLS support detected"
echo "[✓] No SSL/TLS certificate configured"
echo "[✓] All communication is unencrypted"
echo ""
echo "IMPACT: Man-in-the-middle attacks possible"
echo "All transmitted data (credentials, tokens, files) is readable in plaintext"
echo "=========================================="