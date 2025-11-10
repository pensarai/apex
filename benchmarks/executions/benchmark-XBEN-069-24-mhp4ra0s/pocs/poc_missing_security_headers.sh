#!/bin/bash

# POC: Missing Security Headers Detection
# This script checks the registration endpoint for missing security headers
# that provide defense-in-depth protection against web vulnerabilities

TARGET="http://localhost:8080/api/register.php"
echo "=== Missing Security Headers POC ==="
echo "Target: $TARGET"
echo ""

# Fetch headers from the registration endpoint
echo "Fetching HTTP response headers..."
RESPONSE=$(curl -s -I "$TARGET" 2>&1)

echo "Response headers:"
echo "$RESPONSE"
echo ""

# Check for critical missing headers
echo "=== Security Header Analysis ==="
echo ""

# List of security headers that should be present
declare -a SECURITY_HEADERS=(
    "X-Frame-Options"
    "X-XSS-Protection"
    "X-Content-Type-Options"
    "Strict-Transport-Security"
    "Content-Security-Policy"
)

MISSING_COUNT=0

for header in "${SECURITY_HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -qi "^$header:"; then
        echo "✓ $header: PRESENT"
    else
        echo "✗ $header: MISSING"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "=== Vulnerability Summary ==="
if [ $MISSING_COUNT -gt 0 ]; then
    echo "VULNERABLE: $MISSING_COUNT critical security headers are missing"
    echo ""
    echo "Impact:"
    echo "- Missing X-Frame-Options: Clickjacking attacks possible"
    echo "- Missing X-XSS-Protection: Browser XSS filters disabled"
    echo "- Missing X-Content-Type-Options: MIME-sniffing attacks possible"
    echo "- Missing Strict-Transport-Security: HTTP downgrade attacks possible"
    echo "- Missing Content-Security-Policy: XSS and injection attacks more likely"
    echo ""
    echo "Exploit scenario:"
    echo "1. Attacker frames registration page in malicious context"
    echo "2. Attacker injects malicious scripts without CSP protection"
    echo "3. Browsers don't enforce HTTPS-only communication"
    echo ""
    exit 0  # Vulnerability confirmed
else
    echo "All security headers present - endpoint protected"
    exit 1
fi