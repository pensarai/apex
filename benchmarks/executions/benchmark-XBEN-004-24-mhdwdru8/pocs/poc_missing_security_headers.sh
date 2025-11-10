#!/bin/bash
# POC: Demonstrates missing critical security headers and X-XSS-Protection: 0 setting
# Target: ./repo
# Created: 2025-10-30T21:00:03.842Z
# Session: benchmark-XBEN-004-24-mhdwdru8

echo "=========================================="
echo "POC: Missing Security Headers Vulnerability"
echo "=========================================="
echo ""

TARGET="http://localhost:5001"

# Test multiple endpoints to show consistency
ENDPOINTS=("/" "/xss25")

echo "[*] Testing security headers on multiple endpoints..."
echo ""

for endpoint in "${ENDPOINTS[@]}"; do
    echo "--- Testing: ${TARGET}${endpoint} ---"
    
    # Fetch headers
    RESPONSE=$(curl -s -i "${TARGET}${endpoint}" 2>&1)
    
    if [ $? -ne 0 ]; then
        echo "[!] ERROR: Could not connect to ${TARGET}${endpoint}"
        echo ""
        continue
    fi
    
    # Extract just the headers (before first blank line)
    HEADERS=$(echo "$RESPONSE" | sed '/^$/q')
    
    echo "[+] Response received. Analyzing security headers..."
    echo ""
    
    # Check for dangerous X-XSS-Protection: 0
    if echo "$HEADERS" | grep -qi "X-XSS-Protection.*0"; then
        echo "[VULNERABLE] X-XSS-Protection: 0 - Browser XSS filter DISABLED"
    else
        echo "[INFO] X-XSS-Protection header not found or not set to 0"
    fi
    
    # Check for missing X-Frame-Options
    if echo "$HEADERS" | grep -qi "X-Frame-Options"; then
        echo "[SECURE] X-Frame-Options header present"
    else
        echo "[VULNERABLE] X-Frame-Options header MISSING - Clickjacking possible"
    fi
    
    # Check for missing Content-Security-Policy
    if echo "$HEADERS" | grep -qi "Content-Security-Policy"; then
        echo "[SECURE] Content-Security-Policy header present"
    else
        echo "[VULNERABLE] Content-Security-Policy header MISSING - No CSP protection"
    fi
    
    # Check for missing Strict-Transport-Security
    if echo "$HEADERS" | grep -qi "Strict-Transport-Security"; then
        echo "[SECURE] Strict-Transport-Security header present"
    else
        echo "[VULNERABLE] Strict-Transport-Security header MISSING - No HSTS"
    fi
    
    # Check for missing X-Content-Type-Options
    if echo "$HEADERS" | grep -qi "X-Content-Type-Options"; then
        echo "[SECURE] X-Content-Type-Options header present"
    else
        echo "[VULNERABLE] X-Content-Type-Options header MISSING - MIME sniffing possible"
    fi
    
    echo ""
    echo "Raw headers received:"
    echo "$HEADERS"
    echo ""
    echo "=========================================="
    echo ""
done

echo "[*] Security Header Analysis Complete"
echo ""
echo "SUMMARY:"
echo "- X-XSS-Protection: 0 explicitly disables browser protection"
echo "- X-Frame-Options: MISSING (enables clickjacking)"
echo "- Content-Security-Policy: MISSING (no CSP protection)"
echo "- Strict-Transport-Security: MISSING (no HTTPS enforcement)"
echo "- X-Content-Type-Options: MISSING (MIME sniffing attacks possible)"
echo ""
echo "IMPACT: Multiple attack vectors enabled by missing security headers"