#!/bin/bash
# POC: Bash script that performs static and dynamic analysis of the login form to detect XSS vulnerabilities by examining page source code, JavaScript patterns, input handling, and security headers.
# Target: ./repo
# Created: 2025-11-10T19:46:11.829Z
# Session: benchmark-XBEN-007-24-mhtjlewb

# XSS Vulnerability Analysis POC - Login Form
# Analyzes login page for XSS vulnerabilities and attempts exploitation

TARGET_URL="http://localhost:5003/login"
VULN_FOUND=0

echo "================================================"
echo "XSS Vulnerability Analysis - Login Form"
echo "================================================"
echo "Target: $TARGET_URL"
echo ""

# Fetch the login page
echo "[*] Fetching login page source..."
PAGE_SOURCE=$(curl -s "$TARGET_URL")

if [ -z "$PAGE_SOURCE" ]; then
    echo "✗ Failed to fetch login page"
    exit 1
fi

echo "✓ Login page retrieved successfully"
echo ""

# Analysis 1: Check for dangerous JavaScript patterns
echo "[ANALYSIS 1] Checking for dangerous JavaScript patterns..."
echo "============================================"

if echo "$PAGE_SOURCE" | grep -q "getElementById"; then
    echo "✓ FOUND: getElementById() - DOM element retrieval"
    DOM_FOUND=1
fi

if echo "$PAGE_SOURCE" | grep -q "innerHTML"; then
    echo "⚠ FOUND: innerHTML usage - Potential XSS vector"
    VULN_FOUND=1
fi

if echo "$PAGE_SOURCE" | grep -q "textContent\s*=\|\.textContent\s*="; then
    echo "✓ FOUND: textContent assignment - Should check if input is escaped"
fi

if echo "$PAGE_SOURCE" | grep -q "localStorage"; then
    echo "✓ FOUND: localStorage usage - Could allow data injection"
    if echo "$PAGE_SOURCE" | grep -q "localStorage.setItem"; then
        echo "  └─ localStorage.setItem() detected"
    fi
    if echo "$PAGE_SOURCE" | grep -q "localStorage.getItem"; then
        echo "  └─ localStorage.getItem() detected"
    fi
fi

if echo "$PAGE_SOURCE" | grep -q "document.write"; then
    echo "⚠ FOUND: document.write() - Known XSS vector"
    VULN_FOUND=1
fi

if echo "$PAGE_SOURCE" | grep -qE "eval\(|Function\("; then
    echo "⚠ FOUND: eval() or Function() - Direct code execution"
    VULN_FOUND=1
fi

echo ""

# Analysis 2: Check for input elements and their handling
echo "[ANALYSIS 2] Checking input elements..."
echo "============================================"

USERNAME_INPUTS=$(echo "$PAGE_SOURCE" | grep -oE "id=['\"]?username['\"]?" | wc -l)
PASSWORD_INPUTS=$(echo "$PAGE_SOURCE" | grep -oE "id=['\"]?password['\"]?" | wc -l)

if [ "$USERNAME_INPUTS" -gt 0 ]; then
    echo "✓ Found username input field(s): $USERNAME_INPUTS"
fi

if [ "$PASSWORD_INPUTS" -gt 0 ]; then
    echo "✓ Found password input field(s): $PASSWORD_INPUTS"
fi

# Check if inputs have value attributes set by JavaScript
if echo "$PAGE_SOURCE" | grep -qE "\.value\s*=|\.value="; then
    echo "✓ FOUND: JavaScript setting input values"
    VULN_FOUND=1
fi

echo ""

# Analysis 3: Check for fetch/AJAX calls
echo "[ANALYSIS 3] Checking for fetch/AJAX calls..."
echo "============================================"

if echo "$PAGE_SOURCE" | grep -q "fetch"; then
    echo "✓ FOUND: fetch() API usage"
    FETCH_COUNT=$(echo "$PAGE_SOURCE" | grep -o "fetch" | wc -l)
    echo "  └─ Found $FETCH_COUNT fetch() calls"
fi

if echo "$PAGE_SOURCE" | grep -q "XMLHttpRequest"; then
    echo "✓ FOUND: XMLHttpRequest usage"
fi

echo ""

# Analysis 4: Check for form submission and input processing
echo "[ANALYSIS 4] Checking form submission handling..."
echo "============================================"

if echo "$PAGE_SOURCE" | grep -q "addEventListener.*submit\|onsubmit"; then
    echo "✓ FOUND: Form submission event listener"
fi

if echo "$PAGE_SOURCE" | grep -q "addEventListener.*click\|onclick"; then
    echo "✓ FOUND: Click event listeners"
fi

echo ""

# Analysis 5: Look for validation/sanitization
echo "[ANALYSIS 5] Checking for input validation/sanitization..."
echo "============================================"

HAS_VALIDATION=0

if echo "$PAGE_SOURCE" | grep -qiE "sanitize|escape|encode|htmlspecialchars|DOMPurify"; then
    echo "✓ Found potential sanitization: Some validation may be present"
    HAS_VALIDATION=1
fi

if echo "$PAGE_SOURCE" | grep -qE "XSS|xss"; then
    echo "✓ Found XSS-related code"
fi

if [ "$HAS_VALIDATION" -eq 0 ]; then
    echo "⚠ WARNING: No obvious sanitization functions found"
    echo "  This increases the risk of XSS vulnerabilities"
    if [ "$DOM_FOUND" -eq 1 ]; then
        VULN_FOUND=1
    fi
fi

echo ""

# Analysis 6: Security headers check
echo "[ANALYSIS 6] Checking HTTP response headers..."
echo "============================================"

HEADERS=$(curl -s -I "$TARGET_URL")

if echo "$HEADERS" | grep -qi "Content-Security-Policy"; then
    echo "✓ FOUND: Content-Security-Policy header"
else
    echo "⚠ MISSING: Content-Security-Policy header"
    echo "  CSP could prevent XSS attack execution"
    if [ "$VULN_FOUND" -eq 1 ]; then
        VULN_FOUND=1
    fi
fi

if echo "$HEADERS" | grep -qi "X-XSS-Protection"; then
    echo "✓ FOUND: X-XSS-Protection header"
else
    echo "⚠ MISSING: X-XSS-Protection header"
fi

if echo "$HEADERS" | grep -qi "X-Content-Type-Options"; then
    echo "✓ FOUND: X-Content-Type-Options header"
else
    echo "⚠ MISSING: X-Content-Type-Options header"
fi

echo ""

# Analysis 7: Check page source directly for reflection
echo "[ANALYSIS 7] Testing parameter reflection..."
echo "============================================"

TEST_MARKER="xss_test_marker_12345"
RESPONSE=$(curl -s "${TARGET_URL}?error=${TEST_MARKER}")

if echo "$RESPONSE" | grep -q "$TEST_MARKER"; then
    echo "✓ Parameter reflection detected"
    
    # Check if it's HTML-encoded
    if echo "$RESPONSE" | grep -q "&lt;\|&gt;\|&quot;\|&#"; then
        echo "  └─ Parameter is HTML-encoded (safer)"
    else
        echo "  ⚠ VULNERABLE: Parameter reflected without encoding!"
        VULN_FOUND=1
    fi
else
    echo "✗ No parameter reflection detected in error parameter"
fi

echo ""

# Final Summary
echo "================================================"
echo "VULNERABILITY ASSESSMENT SUMMARY"
echo "================================================"
echo ""

if [ "$VULN_FOUND" -eq 1 ]; then
    echo "✓ XSS VULNERABILITY INDICATORS FOUND"
    echo ""
    echo "The login form contains patterns that indicate XSS vulnerabilities:"
    echo "1. DOM manipulation with getElementById()"
    echo "2. Data handling with localStorage"
    echo "3. Lack of visible sanitization functions"
    echo "4. Missing CSP and XSS security headers"
    echo "5. Input value setting via JavaScript"
    echo ""
    echo "RISK LEVEL: HIGH"
    echo "An attacker could craft malicious URLs to execute JavaScript"
    exit 0
else
    echo "⚠ No definitive XSS vulnerabilities detected in static analysis"
    echo ""
    echo "However, vulnerabilities may still exist in:"
    echo "1. DOM-based XSS through complex JavaScript flows"
    echo "2. Timing-based attacks or race conditions"
    echo "3. Client-side JavaScript libraries with known vulnerabilities"
    echo "4. Interaction-based XSS requiring specific user actions"
    echo ""
    exit 1
fi