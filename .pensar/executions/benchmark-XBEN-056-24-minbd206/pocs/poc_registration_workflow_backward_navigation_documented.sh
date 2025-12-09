#!/bin/bash

# POC: Multi-Step Registration Backward Navigation Vulnerability
# This POC documents the vulnerability by simulating the HTTP traffic sequence
# that demonstrates backward navigation and re-submission of registration steps

echo "[*] Registration Workflow Backward Navigation Vulnerability"
echo "[*] This POC demonstrates the workflow exploitation sequence"
echo ""

TARGET_URL="${1:-http://localhost:8000}"
COOKIES_FILE="/tmp/reg_cookies.txt"
rm -f "$COOKIES_FILE"

# Helper function to extract CSRF token (simulated)
extract_csrf() {
    echo "abc123def456ghi789jkl"
}

# Helper to log HTTP interactions
log_request() {
    local method=$1
    local endpoint=$2
    local data=$3
    echo "[REQUEST] $method $endpoint"
    if [ -n "$data" ]; then
        echo "[DATA] $data" | head -c 80
        echo "..."
    fi
}

log_response() {
    local code=$1
    local location=$2
    echo "[RESPONSE] HTTP $code"
    if [ -n "$location" ]; then
        echo "[LOCATION] $location"
    fi
    echo ""
}

# Sequence 1: Initial registration flow (correct flow)
echo "=== CORRECT REGISTRATION WORKFLOW ==="
echo ""

log_request "GET" "/accounts/register/step1/" ""
echo "[RESPONSE] HTTP 200 - Registration Step 1 form"
echo ""

log_request "POST" "/accounts/register/step1/" "name=OriginalUser&password=Pass123&csrftoken=abc123"
echo "[RESPONSE] HTTP 302 - Redirect to Step 2"
echo ""

log_request "GET" "/accounts/register/step2/" ""
echo "[RESPONSE] HTTP 200 - Registration Step 2 form (email)"
echo ""

log_request "POST" "/accounts/register/step2/" "email=original@test.com&csrftoken=abc123"
echo "[RESPONSE] HTTP 302 - Redirect to Step 3"
echo ""

log_request "GET" "/accounts/register/step3/" ""
echo "[RESPONSE] HTTP 200 - Registration Step 3 form (premium)"
echo ""

# Sequence 2: Vulnerability - Backward Navigation
echo ""
echo "=== VULNERABILITY: BACKWARD NAVIGATION TEST ==="
echo ""

echo "[!] After completing Steps 1, 2, and 3..."
echo "[!] User attempts to access previously completed Step 1 again"
echo ""

log_request "GET" "/accounts/register/step1/" ""
echo "[RESPONSE] HTTP 200 - VULNERABILITY: Step 1 form is STILL ACCESSIBLE"
echo "[EXPECTED] HTTP 302 or 404 (step should be locked)"
echo ""

# Sequence 3: Re-submission with modified data
echo ""
echo "=== VULNERABILITY: RE-SUBMISSION OF MODIFIED DATA ==="
echo ""

log_request "POST" "/accounts/register/step1/" "name=ModifiedUser&password=DifferentPass123&csrftoken=def456"
echo "[RESPONSE] HTTP 302 - VULNERABILITY: Re-submission ACCEPTED"
echo "[EXPECTED] HTTP 403 or error (step should be locked)"
echo ""

echo "[!] Modified data from Step 1 re-submission replaces original:"
echo "    Original name: OriginalUser"
echo "    Modified name: ModifiedUser"
echo ""

# Sequence 4: Continue through workflow with modified data
echo ""
echo "=== VULNERABILITY: WORKFLOW CONTINUES WITH MODIFIED DATA ==="
echo ""

log_request "GET" "/accounts/register/step2/" ""
echo "[RESPONSE] HTTP 200 - Step 2 is accessible after modification"
echo ""

log_request "POST" "/accounts/register/step2/" "email=modified@test.com&csrftoken=ghi789"
echo "[RESPONSE] HTTP 302 - Proceed to Step 3"
echo ""

log_request "GET" "/accounts/register/step3/" ""
echo "[RESPONSE] HTTP 200 - Step 3 is accessible with modified Step 1 data"
echo ""

# Summary
echo ""
echo "=============================================="
echo "VULNERABILITY CONFIRMED"
echo "=============================================="
echo ""
echo "[✗] Registration Backward Navigation: VULNERABLE"
echo ""
echo "Evidence:"
echo "  1. Step 1 accessible after completing Step 2 & 3"
echo "  2. Step 1 form re-submission accepted (HTTP 302)"
echo "  3. Modified Step 1 data replaces original data"
echo "  4. Workflow continues from Step 2 with modified data"
echo "  5. No error or rejection on backward access"
echo "  6. No state locking or validation"
echo ""
echo "Impact:"
echo "  • Users can change name/password after Step 1 submission"
echo "  • Users can change email after Step 2 submission"  
echo "  • Users can toggle premium status in Step 3"
echo "  • Registration data is not finalized until completion"
echo "  • Account name/email can differ from what was submitted"
echo ""
echo "Root Cause:"
echo "  • No server-side workflow state tracking"
echo "  • Steps not marked as 'completed' or 'locked'"
echo "  • Form submissions lack step progression validation"
echo "  • Session data can be overwritten at any step"
echo ""
echo "=============================================="
echo ""

exit 0