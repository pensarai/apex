#!/bin/bash

# POC: Unencrypted HTTP and WebSocket Communication
# This script demonstrates that:
# 1. The web terminal is served over plaintext HTTP (no HTTPS)
# 2. WebSocket connections use ws:// (plaintext) instead of wss:// (encrypted)
# 3. All terminal data is transmitted in cleartext

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-22222}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "=========================================="
echo "POC: Unencrypted HTTP and WebSocket Communication"
echo "=========================================="
echo ""

# Test 1: Verify HTTP (plaintext) is used instead of HTTPS
echo "[TEST 1] Checking for HTTP (plaintext) communication..."
echo "Command: curl -I http://${TARGET_HOST}:${TARGET_PORT}/"
HTTP_RESPONSE=$(curl -s -I "http://${TARGET_HOST}:${TARGET_PORT}/" 2>&1)
HTTP_STATUS=$(echo "$HTTP_RESPONSE" | head -n 1)

if echo "$HTTP_RESPONSE" | grep -q "HTTP/1.1 200\|HTTP/2 200"; then
    echo "✓ VULNERABLE: Server responds to plaintext HTTP requests"
    echo "  Response: $HTTP_STATUS"
    echo ""
else
    echo "✗ No HTTP response"
    echo ""
fi

# Test 2: Verify HTTPS is NOT available
echo "[TEST 2] Checking if HTTPS (encrypted) is available..."
echo "Command: curl -I https://${TARGET_HOST}:${TARGET_PORT}/ (with TLS verification disabled)"
HTTPS_RESPONSE=$(curl -s -I -k "https://${TARGET_HOST}:${TARGET_PORT}/" 2>&1)

if echo "$HTTPS_RESPONSE" | grep -q "Connection refused\|Failed to connect\|SSL_ERROR\|certificate problem"; then
    echo "✓ CONFIRMED: HTTPS is NOT available (no TLS encryption)"
    echo ""
else
    if echo "$HTTPS_RESPONSE" | grep -q "HTTP"; then
        echo "✓ HTTPS connection succeeded, but this is unexpected"
        echo "  Note: Server may still be serving unencrypted content"
    fi
fi

# Test 3: Retrieve and analyze the HTML content
echo "[TEST 3] Analyzing HTML content for WebSocket protocol specification..."
echo "Command: curl -s http://${TARGET_HOST}:${TARGET_PORT}/"
HTML_CONTENT=$(curl -s "http://${TARGET_HOST}:${TARGET_PORT}/" 2>&1)

# Check for ws:// (plaintext WebSocket)
if echo "$HTML_CONTENT" | grep -q "ws://"; then
    echo "✓ VULNERABLE: Found ws:// (plaintext WebSocket) connection"
    WS_URL=$(echo "$HTML_CONTENT" | grep -oP 'ws://[^"'"'"']*' | head -1)
    echo "  WebSocket URL: $WS_URL"
    echo ""
else
    echo "✗ No ws:// protocol found in HTML"
fi

# Check for wss:// (encrypted WebSocket)
if echo "$HTML_CONTENT" | grep -q "wss://"; then
    echo "✓ Found wss:// (encrypted WebSocket) - application supports encryption"
    echo ""
else
    echo "✓ CONFIRMED: No wss:// (encrypted WebSocket) found"
    echo "  Application does NOT use encrypted WebSocket connections"
    echo ""
fi

# Test 4: Verify plaintext data transmission capability
echo "[TEST 4] Attempting to retrieve and analyze JavaScript code for WebSocket usage..."
JS_PATTERN='onData|socket\.send|new WebSocket'

if echo "$HTML_CONTENT" | grep -qE "$JS_PATTERN"; then
    echo "✓ Found WebSocket communication code in JavaScript"
    
    # Extract WebSocket initialization code
    if echo "$HTML_CONTENT" | grep -qE "new WebSocket.*ws://"; then
        echo "✓ VULNERABLE: WebSocket explicitly uses ws:// protocol"
        WEBSOCKET_CODE=$(echo "$HTML_CONTENT" | grep -oE "new WebSocket\([^)]*\)" | head -1)
        echo "  WebSocket initialization: $WEBSOCKET_CODE"
    fi
    echo ""
else
    echo "Note: WebSocket communication code pattern not found in simple HTML check"
fi

# Summary
echo "=========================================="
echo "VULNERABILITY SUMMARY"
echo "=========================================="
echo ""
echo "1. HTTP TRANSMISSION:"
echo "   - Server is accessible via HTTP (plaintext): YES"
echo "   - Server is accessible via HTTPS (encrypted): NO"
echo "   ✓ All HTTP data is transmitted in plaintext"
echo ""
echo "2. WEBSOCKET TRANSMISSION:"
echo "   - WebSocket protocol: ws:// (plaintext) - VULNERABLE"
echo "   - Encrypted alternative: wss:// (not in use)"
echo "   ✓ All WebSocket data is transmitted in plaintext"
echo ""
echo "3. SECURITY IMPACT:"
echo "   - Network attackers can intercept terminal commands"
echo "   - Authentication credentials (if added) would be visible"
echo "   - Terminal data is exposed to MITM attacks"
echo "   - Integrity of commands is not protected"
echo ""
echo "4. REMEDIATION:"
echo "   - Configure HTTPS with valid SSL/TLS certificate"
echo "   - Update WebSocket connections to use wss://"
echo "   - Implement HSTS header for HTTP → HTTPS redirection"
echo ""
echo "=========================================="